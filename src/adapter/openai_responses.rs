//! OpenAI Responses (`POST /v1/responses`) adapter.
//!
//! `schemas/openai_responses_request.schema.json` is generated from the OpenAI OpenAPI schema
//! (`CreateResponse`) and names its source commit in `x-airlock-source`. Keep `TRANSPORT_KEYS`
//! aligned with that schema's top-level properties; `tests/adapter_wire_format.rs` fails when
//! they drift.

use serde_json::{Map, Value, json};

use super::{
    Adapter, PartKind, ResponsePart, ScreenablePart, TransportConfig, apply_additional_params,
    chat_media_parts, classify_inline_file, classify_reference, pointer_child, prompt_message,
    prompt_messages, validated_model_id, validated_temperature, walk_request,
};
use crate::output::{canonical_json, sort_value};
use crate::refusal::RefusalEnvelope;

pub const OPENAI_RESPONSES_ADAPTER_NAME: &str = "openai_responses";

const ADAPTER_LABEL: &str = "OpenAI Responses";

const TRANSPORT_KEYS: &[&str] = &[
    "access_programs",
    "background",
    "background_options",
    "context_management",
    "conversation",
    "image",
    "include",
    "input",
    "instructions",
    "max_output_tokens",
    "max_tool_calls",
    "metadata",
    "model",
    "moderation",
    "parallel_tool_calls",
    "previous_response_id",
    "prompt",
    "prompt_cache_key",
    "prompt_cache_options",
    "prompt_cache_retention",
    "reasoning",
    "safety_identifier",
    "service_tier",
    "store",
    "stream",
    "stream_options",
    "temperature",
    "text",
    "tool_choice",
    "tools",
    "top_logprobs",
    "top_p",
    "truncation",
    "user",
];

const RESERVED_REQUEST_KEYS: &[&str] =
    &["input", "max_output_tokens", "model", "temperature", "text"];

const PROMPT_ROLES: &[&str] = &["assistant", "developer", "system", "user"];

/// The schema bounds `max_output_tokens` below at 16 and `temperature` to 0 through 2.
const MIN_OUTPUT_TOKENS: u32 = 16;
const MAX_TEMPERATURE: f64 = 2.0;

#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiResponsesAdapter;

impl Adapter for OpenAiResponsesAdapter {
    fn name(&self) -> &str {
        OPENAI_RESPONSES_ADAPTER_NAME
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
        let temperature = validated_temperature(config)?;
        if let Some(temperature) = temperature
            && !(0.0..=MAX_TEMPERATURE).contains(&temperature)
        {
            return Err(RefusalEnvelope::bad_request(
                "OpenAI Responses temperature must be between 0 and 2",
                json!({ "field": "temperature", "value": temperature.to_string() }),
            ));
        }
        if let Some(max_tokens) = config.max_tokens
            && max_tokens < MIN_OUTPUT_TOKENS
        {
            return Err(RefusalEnvelope::bad_request(
                "OpenAI Responses max_output_tokens must be at least 16",
                json!({ "field": "max_tokens", "value": max_tokens }),
            ));
        }

        let mut input = Vec::new();
        for (index, message) in prompt_messages(prompt_payload)?.iter().enumerate() {
            let parsed = prompt_message(message, index, PROMPT_ROLES, ADAPTER_LABEL)?;
            let content = match parsed.content {
                Value::String(_) => parsed.content.clone(),
                structured => {
                    if parsed.role == "assistant" {
                        // The schema allows input_text parts here but the API accepts only
                        // output_text and refusal parts on assistant messages.
                        return Err(RefusalEnvelope::bad_prompt(
                            "OpenAI Responses cannot carry structured assistant content",
                            json!({ "field": format!("messages[{index}].content") }),
                        ));
                    }
                    json!([{ "type": "input_text", "text": canonical_json(structured) }])
                }
            };
            input.push(json!({ "role": parsed.role, "content": content }));
        }

        let mut request = Map::new();
        request.insert("model".to_string(), Value::String(model_id));
        request.insert("input".to_string(), Value::Array(input));
        if let Some(temperature) = temperature {
            request.insert("temperature".to_string(), json!(temperature));
        }
        if let Some(max_tokens) = config.max_tokens {
            request.insert("max_output_tokens".to_string(), json!(max_tokens));
        }
        if let Some(format) = &config.response_format {
            // Interpreted as the Responses `text.format` object, not the Chat Completions
            // `response_format` shape.
            request.insert("text".to_string(), json!({ "format": format }));
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

    /// Read assistant `output_text` and `function_call` items from a Responses object. Reasoning
    /// items, refusals and every other item type are left out, as is empty text. A function call's
    /// `arguments` string is parsed when it is valid JSON and kept as a string when it is not, so
    /// it is screened either way. An error body or a response with nothing to admit is refused.
    fn unwrap_response(&self, response: &Value) -> Result<Vec<ResponsePart>, RefusalEnvelope> {
        let bad = |message: &str, field: &str| {
            RefusalEnvelope::bad_input(
                message.to_string(),
                json!({ "field": field, "adapter": OPENAI_RESPONSES_ADAPTER_NAME }),
            )
        };
        let object = response
            .as_object()
            .ok_or_else(|| bad("response must be a JSON object", ""))?;
        if object.get("object").and_then(Value::as_str) != Some("response") {
            return Err(bad("response is not an OpenAI Responses object", "object"));
        }
        if object.get("error").is_some_and(|error| !error.is_null()) {
            return Err(bad(
                "response carries an error and is not model output",
                "error",
            ));
        }
        let output = object
            .get("output")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("response must carry an output array", "output"))?;

        let mut parts = Vec::new();
        for (index, item) in output.iter().enumerate() {
            let source_path = format!("output[{index}]");
            match item.get("type").and_then(Value::as_str) {
                Some("message")
                    if item.get("role").and_then(Value::as_str) == Some("assistant") =>
                {
                    let content =
                        item.get("content")
                            .and_then(Value::as_array)
                            .ok_or_else(|| {
                                bad(
                                    "message item must carry a content array",
                                    &format!("{source_path}.content"),
                                )
                            })?;
                    for (part_index, part) in content.iter().enumerate() {
                        if part.get("type").and_then(Value::as_str) != Some("output_text") {
                            continue;
                        }
                        let part_path = format!("{source_path}.content[{part_index}]");
                        let text = part.get("text").and_then(Value::as_str).ok_or_else(|| {
                            bad(
                                "output_text part must carry a string text",
                                &format!("{part_path}.text"),
                            )
                        })?;
                        if !text.is_empty() {
                            parts.push(ResponsePart::Text {
                                source_path: part_path,
                                text: text.to_string(),
                            });
                        }
                    }
                }
                Some("function_call") => {
                    let name = item.get("name").and_then(Value::as_str).ok_or_else(|| {
                        bad(
                            "function_call item must carry a string name",
                            &format!("{source_path}.name"),
                        )
                    })?;
                    let arguments =
                        item.get("arguments")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                bad(
                                    "function_call item must carry string arguments",
                                    &format!("{source_path}.arguments"),
                                )
                            })?;
                    let input = serde_json::from_str::<Value>(arguments)
                        .unwrap_or_else(|_| Value::String(arguments.to_string()));
                    parts.push(ResponsePart::ToolUse {
                        id: item
                            .get("call_id")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        id_source_path: format!("{source_path}.call_id"),
                        name: name.to_string(),
                        input,
                        input_source_path: format!("{source_path}.arguments"),
                        source_path,
                    });
                }
                _ => {}
            }
        }
        if parts.is_empty() {
            return Err(bad(
                "response carries no assistant text or function_call item to admit",
                "output",
            ));
        }
        Ok(parts)
    }

    fn unwrap(&self, request_payload: &Value) -> Result<Value, RefusalEnvelope> {
        let mut messages = Vec::new();

        // `instructions` is the system prompt; a null value means none was given.
        match request_payload.get("instructions") {
            None | Some(Value::Null) => {}
            Some(Value::String(text)) => {
                messages.push(json!({ "role": "system", "content": text }));
            }
            Some(other) => messages.push(json!({ "role": "system", "content": other })),
        }

        match request_payload.get("input") {
            Some(Value::String(text)) => {
                messages.push(json!({ "role": "user", "content": text }));
            }
            Some(Value::Array(items)) => {
                for item in items {
                    messages.push(unwrap_item(item));
                }
            }
            _ => {
                return Err(RefusalEnvelope::bad_request(
                    "OpenAI Responses request must contain an input string or array",
                    json!({ "field": "input" }),
                ));
            }
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

/// An input item that is a plain `{role, content}` message becomes a canonical message with its
/// content decoded. Any other item (tool calls, reasoning, references, messages with extra
/// fields) is returned as it is, so the binding comparison sees it as a difference.
fn unwrap_item(item: &Value) -> Value {
    let Some(object) = item.as_object() else {
        return item.clone();
    };
    if !object.contains_key("role") || !object.contains_key("content") {
        return item.clone();
    }
    let mut message = object.clone();
    // `type: "message"` is the optional tag on a message item, not content.
    if message.get("type").and_then(Value::as_str) == Some("message") {
        message.remove("type");
    }
    if let Some(content) = message.get_mut("content") {
        *content = decode_content(content);
    }
    Value::Object(message)
}

fn decode_content(content: &Value) -> Value {
    let Some([part]) = content.as_array().map(Vec::as_slice) else {
        return content.clone();
    };
    let Some(part) = part.as_object() else {
        return content.clone();
    };
    if part.len() != 2 || part.get("type").and_then(Value::as_str) != Some("input_text") {
        return content.clone();
    }
    let Some(text) = part.get("text").and_then(Value::as_str) else {
        return content.clone();
    };
    match serde_json::from_str::<Value>(text) {
        Ok(decoded) if !decoded.is_string() && canonical_json(&decoded) == text => decoded,
        _ => content.clone(),
    }
}

/// Classify `input_image` and `input_file` parts; audio falls through to the shared handler.
fn media_parts(object: &Map<String, Value>, pointer: &str, out: &mut Vec<ScreenablePart>) -> bool {
    match object.get("type").and_then(Value::as_str) {
        Some("input_image") => {
            let mut handled = false;
            if let Some(url) = object.get("image_url").and_then(Value::as_str) {
                out.push(classify_reference(pointer_child(pointer, "image_url"), url));
                handled = true;
            }
            if let Some(file_id) = object.get("file_id").and_then(Value::as_str) {
                out.push(remote(pointer_child(pointer, "file_id"), file_id));
                handled = true;
            }
            handled
        }
        Some("input_file") => {
            let mut handled = false;
            if let Some(data) = object.get("file_data").and_then(Value::as_str) {
                out.push(classify_inline_file(
                    pointer_child(pointer, "file_data"),
                    data,
                ));
                handled = true;
            }
            if let Some(url) = object.get("file_url").and_then(Value::as_str) {
                out.push(remote(pointer_child(pointer, "file_url"), url));
                handled = true;
            }
            if let Some(file_id) = object.get("file_id").and_then(Value::as_str) {
                out.push(remote(pointer_child(pointer, "file_id"), file_id));
                handled = true;
            }
            handled
        }
        _ => chat_media_parts(object, pointer, out),
    }
}

fn remote(pointer: String, data: &str) -> ScreenablePart {
    ScreenablePart {
        pointer,
        kind: PartKind::RemoteReference,
        data: data.to_string(),
    }
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

    #[test]
    fn transport_keys_are_sorted_and_unique() {
        let mut sorted = TRANSPORT_KEYS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, TRANSPORT_KEYS);
    }

    #[test]
    fn wrap_builds_easy_input_messages_and_maps_transport_fields() {
        let config = TransportConfig {
            temperature: Some(0.0),
            max_tokens: Some(2048),
            response_format: Some(json!({"type": "json_object"})),
            ..TransportConfig::new("gpt-5")
        };
        let request = OpenAiResponsesAdapter
            .wrap(&sample_prompt(), &config)
            .unwrap();

        assert_eq!(request["model"], "gpt-5");
        assert_eq!(request["temperature"], 0.0);
        assert_eq!(request["max_output_tokens"], 2048);
        assert_eq!(request["text"], json!({"format": {"type": "json_object"}}));
        assert!(request.get("instructions").is_none());
        assert_eq!(
            request["input"][0],
            json!({"role": "system", "content": "You are a careful boundary verifier."})
        );
        assert_eq!(
            request["input"][1],
            json!({
                "role": "user",
                "content": [{
                    "type": "input_text",
                    "text": r#"{"benchmark_summary":{"coverage":0.98},"challenge_profile":{"page_count":12}}"#
                }]
            })
        );
    }

    #[test]
    fn unwrap_reverses_wrap_exactly() {
        let prompt = sample_prompt();
        let request = OpenAiResponsesAdapter
            .wrap(&prompt, &TransportConfig::new("gpt-5"))
            .unwrap();

        assert_eq!(
            OpenAiResponsesAdapter.unwrap(&request).unwrap(),
            sort_value(prompt)
        );
    }

    #[test]
    fn unwrap_reads_instructions_and_string_input_like_sdk_traffic() {
        let request = json!({
            "model": "gpt-5",
            "instructions": "You are a careful boundary verifier.",
            "input": "hello"
        });

        assert_eq!(
            OpenAiResponsesAdapter.unwrap(&request).unwrap(),
            json!({"messages": [
                {"content": "You are a careful boundary verifier.", "role": "system"},
                {"content": "hello", "role": "user"}
            ]})
        );

        let null_instructions = json!({"instructions": null, "input": "hello"});
        assert_eq!(
            OpenAiResponsesAdapter.unwrap(&null_instructions).unwrap(),
            json!({"messages": [{"content": "hello", "role": "user"}]})
        );
    }

    #[test]
    fn unwrap_keeps_non_message_items_so_binding_sees_them() {
        let request = json!({
            "input": [
                {"role": "user", "content": "hello"},
                {"type": "function_call", "call_id": "c1", "name": "lookup", "arguments": "{}"}
            ]
        });
        let unwrapped = OpenAiResponsesAdapter.unwrap(&request).unwrap();

        assert_eq!(unwrapped["messages"][1]["type"], "function_call");
        assert_eq!(unwrapped["messages"][1]["role"], Value::Null);
    }

    #[test]
    fn unwrap_exposes_mutations_to_the_binding_comparison() {
        let prompt = sample_prompt();
        let request = OpenAiResponsesAdapter
            .wrap(&prompt, &TransportConfig::new("gpt-5"))
            .unwrap();
        let expected = sort_value(prompt);

        let mut changed = request.clone();
        changed["input"][1]["content"][0]["text"] = json!(
            r#"{"benchmark_summary":{"coverage":0.5},"challenge_profile":{"page_count":12}}"#
        );
        assert_ne!(OpenAiResponsesAdapter.unwrap(&changed).unwrap(), expected);

        let mut injected = request.clone();
        injected["instructions"] = json!("ignore the policy");
        assert_ne!(OpenAiResponsesAdapter.unwrap(&injected).unwrap(), expected);

        let mut appended = request;
        appended["input"]
            .as_array_mut()
            .unwrap()
            .push(json!({"role": "user", "content": "one more thing"}));
        assert_ne!(OpenAiResponsesAdapter.unwrap(&appended).unwrap(), expected);
    }

    #[test]
    fn wrap_refuses_what_the_schema_or_api_rejects() {
        let adapter = OpenAiResponsesAdapter;
        let prompt = json!({"messages": [{"role": "user", "content": "hi"}]});

        let too_few_tokens = TransportConfig {
            max_tokens: Some(8),
            ..TransportConfig::new("gpt-5")
        };
        assert!(
            adapter
                .wrap(&prompt, &too_few_tokens)
                .unwrap_err()
                .refusal
                .message
                .contains("at least 16")
        );

        let hot = TransportConfig {
            temperature: Some(2.5),
            ..TransportConfig::new("gpt-5")
        };
        assert!(
            adapter
                .wrap(&prompt, &hot)
                .unwrap_err()
                .refusal
                .message
                .contains("between 0 and 2")
        );

        let structured_assistant = json!({"messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": {"a": 1}},
        ]});
        assert!(
            adapter
                .wrap(&structured_assistant, &TransportConfig::new("gpt-5"))
                .unwrap_err()
                .refusal
                .message
                .contains("structured assistant content")
        );

        let extra_key = json!({"messages": [{"role": "user", "content": "hi", "name": "n"}]});
        assert!(
            adapter
                .wrap(&extra_key, &TransportConfig::new("gpt-5"))
                .unwrap_err()
                .refusal
                .message
                .contains("carry only role and content")
        );

        let undeclared = TransportConfig {
            additional_params: json!({"messages": []}).as_object().cloned(),
            ..TransportConfig::new("gpt-5")
        };
        assert!(
            adapter
                .wrap(&prompt, &undeclared)
                .unwrap_err()
                .refusal
                .message
                .contains("not a OpenAI Responses request field")
        );
    }

    #[test]
    fn unwrap_refuses_a_request_without_input() {
        let error = OpenAiResponsesAdapter
            .unwrap(&json!({"model": "gpt-5"}))
            .unwrap_err();
        assert_eq!(error.refusal.code.as_str(), "E_BAD_REQUEST");
    }

    #[test]
    fn screenable_parts_cover_images_files_and_function_calls() {
        let request = json!({
            "model": "gpt-5",
            "instructions": "be brief",
            "previous_response_id": "resp_1",
            "input": [
                {"role": "user", "content": [
                    {"type": "input_text", "text": "describe these"},
                    {"type": "input_image", "image_url": "data:image/png;base64,iVBORw0KGgo=", "detail": "high"},
                    {"type": "input_image", "image_url": "https://example.com/a.png"},
                    {"type": "input_image", "file_id": "file-img"},
                    {"type": "input_file", "file_data": "JVBERi0=", "filename": "report.pdf"},
                    {"type": "input_file", "file_url": "https://example.com/r.pdf"},
                    {"type": "input_audio", "input_audio": {"data": "UklGRg==", "format": "wav"}}
                ]},
                {"type": "function_call", "call_id": "c1", "name": "lookup", "arguments": "{\"q\":\"secret\"}"},
                {"type": "function_call_output", "call_id": "c1", "output": "found it"}
            ],
            "tools": [{"type": "function", "name": "lookup", "description": "look up", "parameters": {"type": "object"}}]
        });

        let parts = OpenAiResponsesAdapter
            .extract_screenable_parts(&request)
            .unwrap();
        let find = |pointer: &str| parts.iter().find(|part| part.pointer == pointer);

        assert_eq!(find("/instructions").unwrap().data, "be brief");
        assert_eq!(
            find("/input/0/content/0/text").unwrap().data,
            "describe these"
        );
        assert_eq!(
            find("/input/0/content/1/image_url").unwrap().kind,
            PartKind::Base64Media {
                media_type: "image/png".to_string()
            }
        );
        assert_eq!(
            find("/input/0/content/1/image_url").unwrap().data,
            "iVBORw0KGgo="
        );
        assert_eq!(
            find("/input/0/content/2/image_url").unwrap().kind,
            PartKind::RemoteReference
        );
        assert_eq!(find("/input/0/content/3/file_id").unwrap().data, "file-img");
        assert_eq!(
            find("/input/0/content/4/file_data").unwrap().kind,
            PartKind::Base64Media {
                media_type: "application/octet-stream".to_string()
            }
        );
        assert_eq!(
            find("/input/0/content/4/filename").unwrap().data,
            "report.pdf"
        );
        assert_eq!(
            find("/input/0/content/5/file_url").unwrap().kind,
            PartKind::RemoteReference
        );
        assert_eq!(
            find("/input/0/content/6/input_audio/data").unwrap().kind,
            PartKind::Base64Media {
                media_type: "audio/wav".to_string()
            }
        );
        assert_eq!(
            find("/input/1/arguments").unwrap().data,
            "{\"q\":\"secret\"}"
        );
        assert_eq!(find("/input/2/output").unwrap().data, "found it");
        assert_eq!(find("/tools/0/description").unwrap().data, "look up");

        // Nothing is skipped by key name: tags, identifiers and configuration strings are all
        // caller-controlled, so all are reported as text.
        for (pointer, data) in [
            ("/model", "gpt-5"),
            ("/previous_response_id", "resp_1"),
            ("/input/0/role", "user"),
            ("/input/0/content/1/detail", "high"),
            ("/input/1/type", "function_call"),
            ("/input/1/call_id", "c1"),
            ("/input/0/content/6/type", "input_audio"),
            ("/input/0/content/6/input_audio/format", "wav"),
        ] {
            assert_eq!(
                find(pointer).map(|part| (&part.kind, part.data.as_str())),
                Some((&PartKind::Text, data)),
                "{pointer}"
            );
        }
    }

    #[test]
    fn every_string_is_reported_exactly_once() {
        let request = json!({
            "model": "gpt-5",
            "input": [{"role": "user", "content": [
                {"type": "input_image", "image_url": "data:image/png;base64,AAAA", "detail": "low", "file_id": "f1"},
                {"type": "input_file", "file_data": "BBBB", "filename": "a.pdf", "file_url": "https://e.com/a"},
                {"type": "input_audio", "input_audio": {"data": "CCCC", "format": "mp3"}}
            ]}]
        });
        let parts = OpenAiResponsesAdapter
            .extract_screenable_parts(&request)
            .unwrap();
        let mut pointers: Vec<&str> = parts.iter().map(|part| part.pointer.as_str()).collect();
        let total = pointers.len();
        pointers.sort_unstable();
        pointers.dedup();

        assert_eq!(pointers.len(), total, "no string is reported twice");
        assert_eq!(total, 13, "{pointers:?}");
    }
}
