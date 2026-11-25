//! Anthropic Messages (`POST /v1/messages`) adapter.
//!
//! `schemas/anthropic_messages_request.schema.json` is derived from the official SDK request
//! types and names its source in `x-airlock-source` (Anthropic publishes no standalone
//! OpenAPI document). Keep `TRANSPORT_KEYS` aligned with that schema's top-level properties;
//! `tests/adapter_wire_format.rs` fails when they drift.

use serde_json::{Map, Value, json};

use super::{
    Adapter, PartKind, ScreenablePart, TransportConfig, apply_additional_params, pointer_child,
    prompt_message, prompt_messages, validated_model_id, walk_request,
};
use crate::output::{canonical_json, sort_value};
use crate::refusal::RefusalEnvelope;

pub const ANTHROPIC_MESSAGES_ADAPTER_NAME: &str = "anthropic_messages";

const ADAPTER_LABEL: &str = "Anthropic Messages";

const TRANSPORT_KEYS: &[&str] = &[
    "cache_control",
    "container",
    "diagnostics",
    "inference_geo",
    "max_tokens",
    "messages",
    "metadata",
    "model",
    "output_config",
    "service_tier",
    "speed",
    "stop_sequences",
    "stream",
    "system",
    "thinking",
    "tool_choice",
    "tools",
    "user_profile_id",
    "workspace_id",
];

const RESERVED_REQUEST_KEYS: &[&str] = &["max_tokens", "messages", "model", "system"];

/// Roles a prompt message may use. Anthropic accepts `system` inside `messages` as well as in
/// the top-level `system` field.
const PROMPT_ROLES: &[&str] = &["assistant", "system", "user"];

#[derive(Debug, Default, Clone, Copy)]
pub struct AnthropicMessagesAdapter;

impl Adapter for AnthropicMessagesAdapter {
    fn name(&self) -> &str {
        ANTHROPIC_MESSAGES_ADAPTER_NAME
    }

    fn transport_keys(&self) -> Vec<&str> {
        TRANSPORT_KEYS.to_vec()
    }

    fn wrap(
        &self,
        prompt_payload: &Value,
        config: &TransportConfig,
    ) -> Result<Value, RefusalEnvelope> {
        let model_id = validated_model_id(config)?;

        // The current Messages request type declares no sampling parameters at all, so a
        // temperature cannot be sent. Refuse instead of silently dropping the caller's intent.
        if config.temperature.is_some() {
            return Err(RefusalEnvelope::bad_request(
                "Anthropic Messages requests declare no temperature field",
                json!({ "field": "temperature" }),
            ));
        }
        if config.response_format.is_some() {
            return Err(RefusalEnvelope::bad_request(
                "Anthropic Messages requests declare no response_format field",
                json!({ "field": "response_format", "hint": "use additional_params.output_config" }),
            ));
        }
        let max_tokens = match config.max_tokens {
            Some(max_tokens) if max_tokens >= 1 => max_tokens,
            Some(max_tokens) => {
                return Err(RefusalEnvelope::bad_request(
                    "Anthropic Messages max_tokens must be at least 1",
                    json!({ "field": "max_tokens", "value": max_tokens }),
                ));
            }
            None => {
                return Err(RefusalEnvelope::bad_request(
                    "Anthropic Messages requires max_tokens",
                    json!({ "field": "max_tokens" }),
                ));
            }
        };

        let mut system_texts: Vec<String> = Vec::new();
        let mut wire_messages = Vec::new();
        let mut leading = true;
        for (index, message) in prompt_messages(prompt_payload)?.iter().enumerate() {
            let parsed = prompt_message(message, index, PROMPT_ROLES, ADAPTER_LABEL)?;
            if leading && parsed.role == "system" {
                let text = parsed.content.as_str().ok_or_else(|| {
                    RefusalEnvelope::bad_prompt(
                        "Anthropic Messages system content must be a string",
                        json!({ "field": format!("messages[{index}].content") }),
                    )
                })?;
                system_texts.push(text.to_string());
                continue;
            }
            leading = false;
            wire_messages.push(json!({
                "role": parsed.role,
                "content": encode_content(parsed.content),
            }));
        }
        if wire_messages.is_empty() {
            return Err(RefusalEnvelope::bad_prompt(
                "Anthropic Messages needs at least one message besides the system prompt",
                json!({ "field": "messages" }),
            ));
        }

        let mut request = Map::new();
        request.insert("model".to_string(), Value::String(model_id));
        request.insert("max_tokens".to_string(), json!(max_tokens));
        request.insert("messages".to_string(), Value::Array(wire_messages));
        match system_texts.as_slice() {
            [] => {}
            [only] => {
                request.insert("system".to_string(), Value::String(only.clone()));
            }
            many => {
                let blocks = many
                    .iter()
                    .map(|text| json!({ "type": "text", "text": text }))
                    .collect();
                request.insert("system".to_string(), Value::Array(blocks));
            }
        }

        apply_additional_params(
            &mut request,
            config.additional_params.as_ref(),
            RESERVED_REQUEST_KEYS,
            TRANSPORT_KEYS,
            ADAPTER_LABEL,
        )?;

        Ok(sort_value(Value::Object(request)))
    }

    fn unwrap(&self, request_payload: &Value) -> Result<Value, RefusalEnvelope> {
        let wire_messages = request_payload
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RefusalEnvelope::bad_request(
                    "Anthropic Messages request must contain a messages array",
                    json!({ "field": "messages" }),
                )
            })?;

        let mut messages = Vec::new();

        // The top-level system prompt comes first. Anything that is not the exact wire form
        // `wrap` produces is kept as it is, so the binding comparison sees the difference.
        match request_payload.get("system") {
            None => {}
            Some(Value::String(text)) => {
                messages.push(json!({ "role": "system", "content": text }));
            }
            Some(Value::Array(blocks)) => {
                for block in blocks {
                    match plain_text_block(block) {
                        Some(text) => messages.push(json!({ "role": "system", "content": text })),
                        None => messages.push(json!({ "role": "system", "content": block })),
                    }
                }
            }
            Some(other) => messages.push(json!({ "role": "system", "content": other })),
        }

        for message in wire_messages {
            let mut message = message.as_object().cloned().ok_or_else(|| {
                RefusalEnvelope::bad_request(
                    "Anthropic Messages messages must be objects",
                    json!({ "field": "messages" }),
                )
            })?;
            if let Some(content) = message.get_mut("content") {
                *content = decode_content(content);
            }
            messages.push(Value::Object(message));
        }

        Ok(sort_value(json!({ "messages": messages })))
    }

    fn extract_screenable_parts(
        &self,
        request_payload: &Value,
    ) -> Result<Vec<ScreenablePart>, RefusalEnvelope> {
        walk_request(request_payload, &media_parts)
    }
}

/// Structured content has no string form on this wire, so it travels as one text block holding
/// its canonical JSON. Plain string content is sent as a plain string, which keeps the two
/// forms distinguishable for `unwrap`.
fn encode_content(content: &Value) -> Value {
    if content.is_string() {
        return content.clone();
    }
    json!([{ "type": "text", "text": canonical_json(content) }])
}

fn decode_content(content: &Value) -> Value {
    let Some([block]) = content.as_array().map(Vec::as_slice) else {
        return content.clone();
    };
    let Some(text) = plain_text_block(block) else {
        return content.clone();
    };
    match serde_json::from_str::<Value>(text) {
        Ok(decoded) if !decoded.is_string() && canonical_json(&decoded) == text => decoded,
        _ => content.clone(),
    }
}

/// The text of a block that is exactly `{"type":"text","text":<string>}` and nothing else.
fn plain_text_block(block: &Value) -> Option<&str> {
    let object = block.as_object()?;
    if object.len() != 2 || object.get("type").and_then(Value::as_str) != Some("text") {
        return None;
    }
    object.get("text").and_then(Value::as_str)
}

/// Classify the payload of `image` and `document` blocks whose bytes arrive as base64 or by
/// reference. Plain text and nested content sources, and any shape not recognised here, are
/// reported as text by the walk.
fn media_parts(object: &Map<String, Value>, pointer: &str, out: &mut Vec<ScreenablePart>) -> bool {
    if !matches!(
        object.get("type").and_then(Value::as_str),
        Some("image" | "document")
    ) {
        return false;
    }
    let Some(source) = object.get("source").and_then(Value::as_object) else {
        return false;
    };
    let string_field = |name: &str| source.get(name).and_then(Value::as_str);
    let (field, kind) = match source.get("type").and_then(Value::as_str) {
        Some("base64") => (
            "data",
            PartKind::Base64Media {
                media_type: string_field("media_type")
                    .unwrap_or("application/octet-stream")
                    .to_string(),
            },
        ),
        Some("url") => ("url", PartKind::RemoteReference),
        Some("file") => ("file_id", PartKind::RemoteReference),
        _ => return false,
    };
    let Some(payload) = string_field(field) else {
        return false;
    };

    out.push(ScreenablePart {
        pointer: pointer_child(&pointer_child(pointer, "source"), field),
        kind,
        data: payload.to_string(),
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_prompt() -> Value {
        json!({
            "messages": [
                {"role": "system", "content": "You are a careful boundary verifier."},
                {
                    "role": "user",
                    "content": {
                        "benchmark_summary": {"coverage": 0.98},
                        "challenge_profile": {"page_count": 12}
                    }
                }
            ]
        })
    }

    fn config() -> TransportConfig {
        TransportConfig {
            max_tokens: Some(4096),
            ..TransportConfig::new("claude-sonnet-5-5")
        }
    }

    fn refusal_code(error: &RefusalEnvelope) -> &'static str {
        error.refusal.code.as_str()
    }

    #[test]
    fn transport_keys_are_sorted_and_unique() {
        let mut sorted = TRANSPORT_KEYS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, TRANSPORT_KEYS);
    }

    #[test]
    fn wrap_lifts_the_system_prompt_and_encodes_structured_content_as_a_text_block() {
        let request = AnthropicMessagesAdapter
            .wrap(&sample_prompt(), &config())
            .unwrap();

        assert_eq!(request["model"], "claude-sonnet-5-5");
        assert_eq!(request["max_tokens"], 4096);
        assert_eq!(request["system"], "You are a careful boundary verifier.");
        assert_eq!(request["messages"].as_array().unwrap().len(), 1);
        assert_eq!(request["messages"][0]["role"], "user");
        assert_eq!(
            request["messages"][0]["content"],
            json!([{
                "type": "text",
                "text": r#"{"benchmark_summary":{"coverage":0.98},"challenge_profile":{"page_count":12}}"#
            }])
        );
    }

    #[test]
    fn unwrap_reverses_wrap_exactly() {
        let prompt = sample_prompt();
        let request = AnthropicMessagesAdapter.wrap(&prompt, &config()).unwrap();

        assert_eq!(
            AnthropicMessagesAdapter.unwrap(&request).unwrap(),
            sort_value(prompt)
        );
    }

    #[test]
    fn several_leading_system_messages_round_trip_as_text_blocks() {
        let prompt = json!({"messages": [
            {"role": "system", "content": "first"},
            {"role": "system", "content": "second"},
            {"role": "user", "content": "hello"},
        ]});
        let request = AnthropicMessagesAdapter.wrap(&prompt, &config()).unwrap();

        assert_eq!(
            request["system"],
            json!([
                {"type": "text", "text": "first"},
                {"type": "text", "text": "second"}
            ])
        );
        assert_eq!(
            AnthropicMessagesAdapter.unwrap(&request).unwrap(),
            sort_value(prompt)
        );
    }

    #[test]
    fn a_system_message_after_the_first_turn_stays_in_messages() {
        let prompt = json!({"messages": [
            {"role": "system", "content": "lead"},
            {"role": "user", "content": "hello"},
            {"role": "system", "content": "mid-conversation"},
            {"role": "assistant", "content": "ok"},
        ]});
        let request = AnthropicMessagesAdapter.wrap(&prompt, &config()).unwrap();

        assert_eq!(request["system"], "lead");
        assert_eq!(request["messages"][1]["role"], "system");
        assert_eq!(
            AnthropicMessagesAdapter.unwrap(&request).unwrap(),
            sort_value(prompt)
        );
    }

    #[test]
    fn a_prompt_without_a_system_message_sends_no_system_field() {
        let prompt = json!({"messages": [{"role": "user", "content": "hello"}]});
        let request = AnthropicMessagesAdapter.wrap(&prompt, &config()).unwrap();

        assert!(request.get("system").is_none());
        assert_eq!(
            AnthropicMessagesAdapter.unwrap(&request).unwrap(),
            sort_value(prompt)
        );
    }

    #[test]
    fn wrap_refuses_what_the_wire_format_cannot_carry() {
        let adapter = AnthropicMessagesAdapter;
        let user_only = json!({"messages": [{"role": "user", "content": "hi"}]});

        let missing_max_tokens = adapter
            .wrap(&user_only, &TransportConfig::new("claude-sonnet-5-5"))
            .unwrap_err();
        assert_eq!(refusal_code(&missing_max_tokens), "E_BAD_REQUEST");
        assert!(missing_max_tokens.refusal.message.contains("max_tokens"));

        let zero_max_tokens = TransportConfig {
            max_tokens: Some(0),
            ..TransportConfig::new("claude-sonnet-5-5")
        };
        assert_eq!(
            refusal_code(&adapter.wrap(&user_only, &zero_max_tokens).unwrap_err()),
            "E_BAD_REQUEST"
        );

        let with_temperature = TransportConfig {
            temperature: Some(0.0),
            ..config()
        };
        assert!(
            adapter
                .wrap(&user_only, &with_temperature)
                .unwrap_err()
                .refusal
                .message
                .contains("temperature")
        );

        let with_format = TransportConfig {
            response_format: Some(json!({"type": "json_object"})),
            ..config()
        };
        assert!(
            adapter
                .wrap(&user_only, &with_format)
                .unwrap_err()
                .refusal
                .message
                .contains("response_format")
        );

        let blank_model = TransportConfig {
            max_tokens: Some(1),
            ..TransportConfig::new("  ")
        };
        assert!(
            adapter
                .wrap(&user_only, &blank_model)
                .unwrap_err()
                .refusal
                .message
                .contains("model_id")
        );
    }

    #[test]
    fn wrap_refuses_unrepresentable_prompt_messages() {
        let adapter = AnthropicMessagesAdapter;
        let cases = [
            (
                json!({"messages": [{"role": "tool", "content": "x"}]}),
                "does not accept this message role",
            ),
            (
                json!({"messages": [{"role": "user", "content": "x", "name": "n"}]}),
                "carry only role and content",
            ),
            (
                json!({"messages": [{"role": "system", "content": {"a": 1}}, {"role": "user", "content": "x"}]}),
                "system content must be a string",
            ),
            (
                json!({"messages": [{"role": "system", "content": "only a system prompt"}]}),
                "at least one message",
            ),
            (json!({"user": "no messages"}), "messages array"),
        ];
        for (prompt, expected) in cases {
            let error = adapter.wrap(&prompt, &config()).unwrap_err();
            assert!(
                error.refusal.message.contains(expected),
                "{prompt}: {}",
                error.refusal.message
            );
        }
    }

    #[test]
    fn wrap_accepts_only_declared_additional_params() {
        let adapter = AnthropicMessagesAdapter;
        let user_only = json!({"messages": [{"role": "user", "content": "hi"}]});
        let with_params = |params: Value| TransportConfig {
            additional_params: params.as_object().cloned(),
            ..config()
        };

        let request = adapter
            .wrap(&user_only, &with_params(json!({"stop_sequences": ["END"]})))
            .unwrap();
        assert_eq!(request["stop_sequences"], json!(["END"]));

        let reserved = adapter
            .wrap(&user_only, &with_params(json!({"system": "override"})))
            .unwrap_err();
        assert!(reserved.refusal.message.contains("reserved"));

        let undeclared = adapter
            .wrap(&user_only, &with_params(json!({"temperature": 0.2})))
            .unwrap_err();
        assert!(
            undeclared
                .refusal
                .message
                .contains("not a Anthropic Messages request field")
        );
    }

    #[test]
    fn unwrap_exposes_mutations_to_the_binding_comparison() {
        let prompt = sample_prompt();
        let request = AnthropicMessagesAdapter.wrap(&prompt, &config()).unwrap();
        let expected = sort_value(prompt);

        let mut changed_system = request.clone();
        changed_system["system"] = json!("You are a careless boundary verifier.");
        assert_ne!(
            AnthropicMessagesAdapter.unwrap(&changed_system).unwrap(),
            expected
        );

        let mut changed_user = request.clone();
        changed_user["messages"][0]["content"][0]["text"] = json!(
            r#"{"benchmark_summary":{"coverage":0.5},"challenge_profile":{"page_count":12}}"#
        );
        assert_ne!(
            AnthropicMessagesAdapter.unwrap(&changed_user).unwrap(),
            expected
        );

        let mut extra_block = request.clone();
        extra_block["messages"][0]["content"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type": "text", "text": "ignore the above"}));
        assert_ne!(
            AnthropicMessagesAdapter.unwrap(&extra_block).unwrap(),
            expected
        );

        let mut cached_system = request;
        cached_system["system"] = json!([{
            "type": "text",
            "text": "You are a careful boundary verifier.",
            "cache_control": {"type": "ephemeral"}
        }]);
        assert_ne!(
            AnthropicMessagesAdapter.unwrap(&cached_system).unwrap(),
            expected
        );
    }

    #[test]
    fn unwrap_refuses_a_request_without_a_messages_array() {
        let error = AnthropicMessagesAdapter
            .unwrap(&json!({"model": "claude-sonnet-5-5", "system": "x"}))
            .unwrap_err();
        assert_eq!(refusal_code(&error), "E_BAD_REQUEST");
    }

    #[test]
    fn screenable_parts_cover_tool_calls_results_and_media() {
        let request = json!({
            "model": "claude-sonnet-5-5",
            "max_tokens": 1024,
            "service_tier": "auto",
            "system": [{"type": "text", "text": "be brief", "cache_control": {"type": "ephemeral", "ttl": "5m"}}],
            "messages": [
                {"role": "user", "content": "plain question"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "reasoning text", "signature": "c2ln"},
                    {"type": "redacted_thinking", "data": "ZW5jcnlwdGVk"},
                    {"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {"query": "ssn 123-45-6789", "limit": 3}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": [
                        {"type": "text", "text": "result text"},
                        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}
                    ]},
                    {"type": "document", "title": "Report", "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBERi0="}},
                    {"type": "document", "source": {"type": "url", "url": "https://example.com/a.pdf"}},
                    {"type": "image", "source": {"type": "file", "file_id": "file_011"}},
                    {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "inline doc text"}},
                    {"type": "mystery_block", "payload": {"note": "unknown shapes are still walked"}}
                ]}
            ],
            "tools": [{"name": "lookup", "description": "look things up", "input_schema": {"type": "object"}}],
            "metadata": {"user_id": "u-1"}
        });

        let parts = AnthropicMessagesAdapter
            .extract_screenable_parts(&request)
            .unwrap();
        let find = |pointer: &str| parts.iter().find(|part| part.pointer == pointer);

        assert_eq!(find("/system/0/text").unwrap().data, "be brief");
        assert_eq!(find("/messages/0/content").unwrap().kind, PartKind::Text);
        assert_eq!(
            find("/messages/1/content/0/thinking").unwrap().data,
            "reasoning text"
        );
        assert_eq!(
            find("/messages/1/content/2/input/query").unwrap().data,
            "ssn 123-45-6789"
        );
        assert_eq!(
            find("/messages/2/content/0/content/0/text").unwrap().data,
            "result text"
        );
        assert_eq!(
            find("/messages/2/content/0/content/1/source/data").unwrap(),
            &ScreenablePart {
                pointer: "/messages/2/content/0/content/1/source/data".to_string(),
                kind: PartKind::Base64Media {
                    media_type: "image/png".to_string()
                },
                data: "iVBORw0KGgo=".to_string(),
            }
        );
        assert_eq!(
            find("/messages/2/content/1/source/data").unwrap().kind,
            PartKind::Base64Media {
                media_type: "application/pdf".to_string()
            }
        );
        assert_eq!(find("/messages/2/content/1/title").unwrap().data, "Report");
        assert_eq!(
            find("/messages/2/content/2/source/url").unwrap().kind,
            PartKind::RemoteReference
        );
        assert_eq!(
            find("/messages/2/content/3/source/file_id").unwrap().data,
            "file_011"
        );
        assert_eq!(
            find("/messages/2/content/4/source/data").unwrap().kind,
            PartKind::Text
        );
        assert_eq!(
            find("/messages/2/content/5/payload/note").unwrap().data,
            "unknown shapes are still walked"
        );
        assert_eq!(find("/tools/0/description").unwrap().data, "look things up");
        assert_eq!(find("/metadata/user_id").unwrap().data, "u-1");

        // Nothing is skipped by key name: identifiers, signatures, ciphertext, tags and
        // configuration strings are all caller-controlled, so all are reported as text.
        for screened in [
            "/model",
            "/service_tier",
            "/system/0/type",
            "/system/0/cache_control/ttl",
            "/messages/0/role",
            "/messages/1/content/0/signature",
            "/messages/1/content/1/data",
            "/messages/1/content/2/id",
            "/messages/1/content/2/type",
            "/messages/2/content/0/tool_use_id",
            "/messages/2/content/0/content/1/source/type",
            "/messages/2/content/0/content/1/source/media_type",
        ] {
            assert_eq!(
                find(screened).map(|part| &part.kind),
                Some(&PartKind::Text),
                "{screened} should be screened as text"
            );
        }
    }

    #[test]
    fn free_text_under_a_tag_named_key_is_still_screened() {
        // `type` and `role` are tags in message blocks but ordinary keys inside a tool input.
        let request = json!({
            "model": "claude-sonnet-5-5",
            "max_tokens": 16,
            "messages": [{"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "n", "input": {"type": "ssn 123-45-6789", "role": "x"}}
            ]}]
        });
        let parts = AnthropicMessagesAdapter
            .extract_screenable_parts(&request)
            .unwrap();

        assert!(parts.iter().any(|part| {
            part.pointer == "/messages/0/content/0/input/type" && part.data == "ssn 123-45-6789"
        }));
    }

    #[test]
    fn an_unrecognised_media_source_is_walked_like_any_other_object() {
        let request = json!({
            "model": "m",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": [
                {"type": "image", "source": {"type": "future_kind", "blob": "AAAA", "note": "hi"}},
                {"type": "document", "source": {"type": "base64", "media_type": "application/pdf"}}
            ]}]
        });
        let parts = AnthropicMessagesAdapter
            .extract_screenable_parts(&request)
            .unwrap();

        // No payload field to classify, so every string is reported as text instead.
        for pointer in [
            "/messages/0/content/0/source/blob",
            "/messages/0/content/0/source/note",
            "/messages/0/content/1/source/media_type",
        ] {
            assert!(
                parts
                    .iter()
                    .any(|part| part.pointer == pointer && part.kind == PartKind::Text),
                "{pointer}"
            );
        }
    }

    #[test]
    fn screenable_parts_refuse_a_non_object_request() {
        let error = AnthropicMessagesAdapter
            .extract_screenable_parts(&json!(["not", "an", "object"]))
            .unwrap_err();
        assert_eq!(refusal_code(&error), "E_BAD_REQUEST");
    }
}
