//! Google Gemini `generateContent` / `streamGenerateContent` adapter.
//!
//! `schemas/gemini_generate_content_request.schema.json` is converted from Google's public API
//! discovery document (`GenerateContentRequest`) and names the document revision in
//! `x-airlock-source`. Keep `TRANSPORT_KEYS` aligned with that schema's top-level properties;
//! `tests/adapter_wire_format.rs` fails when they drift.
//!
//! Gemini has no system role inside `contents` and no marker that tells structured content
//! from a plain string (both are one text part). `wrap` therefore encodes structured content
//! as the canonical JSON text of an object or array, and refuses a plain string that is itself
//! such an encoding, so `unwrap` can reverse everything `wrap` accepts.

use serde_json::{Map, Value, json};

use super::{
    Adapter, PartKind, ScreenablePart, TransportConfig, apply_additional_params,
    decode_structured_container, pointer_child, prompt_message, prompt_messages,
    validated_model_id, validated_temperature, walk_request,
};
use crate::output::{canonical_json, sort_value};
use crate::refusal::RefusalEnvelope;

pub const GEMINI_GENERATE_CONTENT_ADAPTER_NAME: &str = "gemini_generate_content";

const ADAPTER_LABEL: &str = "Gemini generateContent";

const TRANSPORT_KEYS: &[&str] = &[
    "cachedContent",
    "contents",
    "continuationToken",
    "generationConfig",
    "labels",
    "model",
    "safetySettings",
    "serviceTier",
    "store",
    "systemInstruction",
    "toolConfig",
    "tools",
];

const RESERVED_REQUEST_KEYS: &[&str] = &["contents", "model", "systemInstruction"];

const PROMPT_ROLES: &[&str] = &["assistant", "system", "user"];

#[derive(Debug, Default, Clone, Copy)]
pub struct GeminiGenerateContentAdapter;

impl Adapter for GeminiGenerateContentAdapter {
    fn name(&self) -> &str {
        GEMINI_GENERATE_CONTENT_ADAPTER_NAME
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

        let mut system_texts: Vec<String> = Vec::new();
        let mut contents = Vec::new();
        let mut leading = true;
        for (index, message) in prompt_messages(prompt_payload)?.iter().enumerate() {
            let parsed = prompt_message(message, index, PROMPT_ROLES, ADAPTER_LABEL)?;
            let field = format!("messages[{index}].content");

            if parsed.role == "system" {
                if !leading {
                    return Err(RefusalEnvelope::bad_prompt(
                        "Gemini generateContent has no system role after the first turn",
                        json!({ "field": format!("messages[{index}].role") }),
                    ));
                }
                // System parts are read back as plain strings and never decoded, so any
                // string is reversible here.
                let text = parsed.content.as_str().ok_or_else(|| {
                    RefusalEnvelope::bad_prompt(
                        "Gemini generateContent system content must be a string",
                        json!({ "field": field.clone() }),
                    )
                })?;
                system_texts.push(text.to_string());
                continue;
            }
            leading = false;

            let text = match parsed.content {
                Value::String(text) => {
                    reject_ambiguous_string(text, &field)?;
                    text.clone()
                }
                structured @ (Value::Object(_) | Value::Array(_)) => canonical_json(structured),
                _ => {
                    return Err(RefusalEnvelope::bad_prompt(
                        "Gemini generateContent content must be a string, object or array",
                        json!({ "field": field }),
                    ));
                }
            };
            let role = if parsed.role == "assistant" {
                "model"
            } else {
                "user"
            };
            contents.push(json!({ "role": role, "parts": [{ "text": text }] }));
        }
        if contents.is_empty() {
            return Err(RefusalEnvelope::bad_prompt(
                "Gemini generateContent needs at least one message besides the system prompt",
                json!({ "field": "messages" }),
            ));
        }

        let mut request = Map::new();
        request.insert(
            "model".to_string(),
            Value::String(model_resource(&model_id)),
        );
        request.insert("contents".to_string(), Value::Array(contents));
        if !system_texts.is_empty() {
            let parts: Vec<Value> = system_texts
                .iter()
                .map(|text| json!({ "text": text }))
                .collect();
            request.insert("systemInstruction".to_string(), json!({ "parts": parts }));
        }

        let mut generation_config = Map::new();
        if let Some(temperature) = temperature {
            generation_config.insert("temperature".to_string(), json!(temperature));
        }
        if let Some(max_tokens) = config.max_tokens {
            generation_config.insert("maxOutputTokens".to_string(), json!(max_tokens));
        }
        if let Some(format) = &config.response_format {
            let mime_type = match format.get("type").and_then(Value::as_str) {
                Some("json_object") => "application/json",
                Some("text") => "text/plain",
                _ => {
                    return Err(RefusalEnvelope::bad_request(
                        "Gemini generateContent supports only response_format json_object or text",
                        json!({
                            "field": "response_format",
                            "hint": "use additional_params.generationConfig",
                        }),
                    ));
                }
            };
            generation_config.insert("responseMimeType".to_string(), json!(mime_type));
        }
        if !generation_config.is_empty() {
            request.insert(
                "generationConfig".to_string(),
                Value::Object(generation_config),
            );
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
        let contents = request_payload
            .get("contents")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RefusalEnvelope::bad_request(
                    "Gemini generateContent request must contain a contents array",
                    json!({ "field": "contents" }),
                )
            })?;

        let mut messages = Vec::new();

        // The system instruction comes first. A part that is not exactly `{"text": <string>}`
        // is kept as it is, so the binding comparison sees the difference.
        match request_payload.get("systemInstruction") {
            None => {}
            Some(instruction) => match instruction.get("parts").and_then(Value::as_array) {
                Some(parts) if instruction.as_object().is_some_and(|o| o.len() == 1) => {
                    for part in parts {
                        match plain_text_part(part) {
                            Some(text) => {
                                messages.push(json!({ "role": "system", "content": text }));
                            }
                            None => messages.push(json!({ "role": "system", "content": part })),
                        }
                    }
                }
                _ => messages.push(json!({ "role": "system", "content": instruction })),
            },
        }

        for content in contents {
            messages.push(unwrap_content(content));
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

/// `models/<id>` is the form the schema documents; a name that already has a collection prefix
/// (`models/...`, `tunedModels/...`) is kept.
fn model_resource(model_id: &str) -> String {
    if model_id.contains('/') {
        model_id.to_string()
    } else {
        format!("models/{model_id}")
    }
}

fn reject_ambiguous_string(text: &str, field: &str) -> Result<(), RefusalEnvelope> {
    if decode_structured_container(text).is_some() {
        return Err(RefusalEnvelope::bad_prompt(
            "Gemini generateContent cannot tell this string from structured content",
            json!({
                "field": field,
                "hint": "pass structured content as a JSON object or array, not a pre-serialized string",
            }),
        ));
    }
    Ok(())
}

/// The text of a part that is exactly `{"text": <string>}` and nothing else.
fn plain_text_part(part: &Value) -> Option<&str> {
    let object = part.as_object()?;
    if object.len() != 1 {
        return None;
    }
    object.get("text").and_then(Value::as_str)
}

/// A content that is `{role, parts: [{text}]}` becomes a canonical message; anything else is
/// returned as it is.
fn unwrap_content(content: &Value) -> Value {
    let Some(object) = content.as_object() else {
        return content.clone();
    };
    let role = match object.get("role").and_then(Value::as_str) {
        Some("user") => "user",
        Some("model") => "assistant",
        _ => return content.clone(),
    };
    if object.len() != 2 {
        return content.clone();
    }
    let Some(parts) = object.get("parts").and_then(Value::as_array) else {
        return content.clone();
    };
    let decoded_content = match parts.as_slice() {
        [part] => match plain_text_part(part) {
            Some(text) => {
                decode_structured_container(text).unwrap_or_else(|| Value::String(text.to_string()))
            }
            None => Value::Array(parts.clone()),
        },
        _ => Value::Array(parts.clone()),
    };
    json!({ "role": role, "content": decoded_content })
}

/// Classify the payload of `inlineData` and `fileData`; the walk reports everything else.
fn media_parts(object: &Map<String, Value>, pointer: &str, out: &mut Vec<ScreenablePart>) -> bool {
    let inline = object
        .get("inlineData")
        .and_then(Value::as_object)
        .filter(|blob| blob.get("data").and_then(Value::as_str).is_some());
    let file = object
        .get("fileData")
        .and_then(Value::as_object)
        .filter(|file| file.get("fileUri").and_then(Value::as_str).is_some());
    if inline.is_none() && file.is_none() {
        return false;
    }

    if let Some(blob) = inline {
        out.push(ScreenablePart {
            pointer: pointer_child(&pointer_child(pointer, "inlineData"), "data"),
            kind: PartKind::Base64Media {
                media_type: blob
                    .get("mimeType")
                    .and_then(Value::as_str)
                    .unwrap_or("application/octet-stream")
                    .to_string(),
            },
            data: blob["data"].as_str().unwrap_or_default().to_string(),
        });
    }
    if let Some(file) = file {
        out.push(ScreenablePart {
            pointer: pointer_child(&pointer_child(pointer, "fileData"), "fileUri"),
            kind: PartKind::RemoteReference,
            data: file["fileUri"].as_str().unwrap_or_default().to_string(),
        });
    }
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

    #[test]
    fn transport_keys_are_sorted_and_unique() {
        let mut sorted = TRANSPORT_KEYS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, TRANSPORT_KEYS);
    }

    #[test]
    fn wrap_builds_contents_system_instruction_and_generation_config() {
        let config = TransportConfig {
            temperature: Some(0.0),
            max_tokens: Some(2048),
            response_format: Some(json!({"type": "json_object"})),
            ..TransportConfig::new("gemini-2.5-pro")
        };
        let request = GeminiGenerateContentAdapter
            .wrap(&sample_prompt(), &config)
            .unwrap();

        assert_eq!(request["model"], "models/gemini-2.5-pro");
        assert_eq!(
            request["systemInstruction"],
            json!({"parts": [{"text": "You are a careful boundary verifier."}]})
        );
        assert_eq!(
            request["generationConfig"],
            json!({"maxOutputTokens": 2048, "responseMimeType": "application/json", "temperature": 0.0})
        );
        assert_eq!(request["contents"].as_array().unwrap().len(), 1);
        assert_eq!(request["contents"][0]["role"], "user");
        assert_eq!(
            request["contents"][0]["parts"],
            json!([{"text": r#"{"benchmark_summary":{"coverage":0.98},"challenge_profile":{"page_count":12}}"#}])
        );
    }

    #[test]
    fn unwrap_reverses_wrap_exactly() {
        let prompt = json!({"messages": [
            {"role": "system", "content": "lead"},
            {"role": "system", "content": "second"},
            {"role": "user", "content": {"a": [1, 2, {"b": null}]}},
            {"role": "assistant", "content": "plain reply"},
            {"role": "user", "content": ["a", "list"]},
            {"role": "user", "content": "42"},
        ]});
        let request = GeminiGenerateContentAdapter
            .wrap(&prompt, &TransportConfig::new("gemini-2.5-pro"))
            .unwrap();

        assert_eq!(request["contents"][1]["role"], "model");
        assert_eq!(
            GeminiGenerateContentAdapter.unwrap(&request).unwrap(),
            sort_value(prompt)
        );
    }

    #[test]
    fn model_names_with_a_collection_prefix_are_kept() {
        let prompt = json!({"messages": [{"role": "user", "content": "hi"}]});
        let request = GeminiGenerateContentAdapter
            .wrap(&prompt, &TransportConfig::new("tunedModels/my-tune"))
            .unwrap();
        assert_eq!(request["model"], "tunedModels/my-tune");
    }

    #[test]
    fn wrap_refuses_strings_that_would_be_misread_as_structured_content() {
        let adapter = GeminiGenerateContentAdapter;
        for ambiguous in [r#"{"a":1}"#, "[1,2]", r#"["x"]"#] {
            let prompt = json!({"messages": [{"role": "user", "content": ambiguous}]});
            let error = adapter
                .wrap(&prompt, &TransportConfig::new("gemini-2.5-pro"))
                .unwrap_err();
            assert!(
                error.refusal.message.contains("cannot tell this string"),
                "{ambiguous}"
            );
        }

        // Strings that merely look like JSON but would not round-trip are fine as they are.
        for plain in ["{ \"a\" : 1 }", "42", "true", "null", "\"quoted\"", "hello"] {
            let prompt = json!({"messages": [{"role": "user", "content": plain}]});
            let request = adapter
                .wrap(&prompt, &TransportConfig::new("gemini-2.5-pro"))
                .unwrap();
            assert_eq!(
                adapter.unwrap(&request).unwrap(),
                sort_value(prompt),
                "{plain}"
            );
        }
    }

    #[test]
    fn wrap_refuses_what_gemini_cannot_carry() {
        let adapter = GeminiGenerateContentAdapter;
        let config = TransportConfig::new("gemini-2.5-pro");
        let cases = [
            (
                json!({"messages": [
                    {"role": "user", "content": "hi"},
                    {"role": "system", "content": "late"},
                ]}),
                "no system role after the first turn",
            ),
            (
                json!({"messages": [{"role": "tool", "content": "x"}]}),
                "does not accept this message role",
            ),
            (
                json!({"messages": [{"role": "user", "content": 7}]}),
                "must be a string, object or array",
            ),
            (
                json!({"messages": [{"role": "system", "content": {"a": 1}}, {"role": "user", "content": "x"}]}),
                "system content must be a string",
            ),
            (
                json!({"messages": [{"role": "system", "content": "only system"}]}),
                "at least one message",
            ),
            (
                json!({"messages": [{"role": "user", "content": "x", "name": "n"}]}),
                "carry only role and content",
            ),
        ];
        for (prompt, expected) in cases {
            let error = adapter.wrap(&prompt, &config).unwrap_err();
            assert!(
                error.refusal.message.contains(expected),
                "{prompt}: {}",
                error.refusal.message
            );
        }

        let bad_format = TransportConfig {
            response_format: Some(json!({"type": "json_schema"})),
            ..config.clone()
        };
        let prompt = json!({"messages": [{"role": "user", "content": "hi"}]});
        assert!(
            adapter
                .wrap(&prompt, &bad_format)
                .unwrap_err()
                .refusal
                .message
                .contains("json_object or text")
        );

        let conflicting = TransportConfig {
            temperature: Some(0.1),
            additional_params: json!({"generationConfig": {"topK": 4}})
                .as_object()
                .cloned(),
            ..config
        };
        assert!(
            adapter
                .wrap(&prompt, &conflicting)
                .unwrap_err()
                .refusal
                .message
                .contains("reserved")
        );
    }

    #[test]
    fn unwrap_exposes_mutations_to_the_binding_comparison() {
        let prompt = sample_prompt();
        let request = GeminiGenerateContentAdapter
            .wrap(&prompt, &TransportConfig::new("gemini-2.5-pro"))
            .unwrap();
        let expected = sort_value(prompt);

        let mut changed = request.clone();
        changed["contents"][0]["parts"][0]["text"] = json!(
            r#"{"benchmark_summary":{"coverage":0.5},"challenge_profile":{"page_count":12}}"#
        );
        assert_ne!(
            GeminiGenerateContentAdapter.unwrap(&changed).unwrap(),
            expected
        );

        let mut extra_part = request.clone();
        extra_part["contents"][0]["parts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"inlineData": {"mimeType": "image/png", "data": "iVBORw0KGgo="}}));
        assert_ne!(
            GeminiGenerateContentAdapter.unwrap(&extra_part).unwrap(),
            expected
        );

        let mut other_system = request.clone();
        other_system["systemInstruction"] = json!({"parts": [{"text": "be careless"}]});
        assert_ne!(
            GeminiGenerateContentAdapter.unwrap(&other_system).unwrap(),
            expected
        );

        let mut role_flip = request;
        role_flip["contents"][0]["role"] = json!("model");
        assert_ne!(
            GeminiGenerateContentAdapter.unwrap(&role_flip).unwrap(),
            expected
        );
    }

    #[test]
    fn unwrap_refuses_a_request_without_contents() {
        let error = GeminiGenerateContentAdapter
            .unwrap(&json!({"model": "models/gemini-2.5-pro"}))
            .unwrap_err();
        assert_eq!(error.refusal.code.as_str(), "E_BAD_REQUEST");
    }

    #[test]
    fn screenable_parts_cover_inline_data_file_data_and_function_calls() {
        let request = json!({
            "model": "models/gemini-2.5-pro",
            "systemInstruction": {"parts": [{"text": "be brief"}]},
            "contents": [
                {"role": "user", "parts": [
                    {"text": "describe this"},
                    {"inlineData": {"mimeType": "image/png", "data": "iVBORw0KGgo=", "displayName": "chart"}},
                    {"fileData": {"mimeType": "application/pdf", "fileUri": "https://generativelanguage.googleapis.com/v1beta/files/abc"}}
                ]},
                {"role": "model", "parts": [
                    {"functionCall": {"name": "lookup", "args": {"query": "ssn 123-45-6789"}}, "thoughtSignature": "c2ln"}
                ]},
                {"role": "user", "parts": [
                    {"functionResponse": {"name": "lookup", "response": {"result": "found it"}}}
                ]}
            ],
            "tools": [{"functionDeclarations": [{"name": "lookup", "description": "look up"}]}],
            "labels": {"team": "risk"}
        });

        let parts = GeminiGenerateContentAdapter
            .extract_screenable_parts(&request)
            .unwrap();
        let find = |pointer: &str| parts.iter().find(|part| part.pointer == pointer);

        assert_eq!(
            find("/systemInstruction/parts/0/text").unwrap().data,
            "be brief"
        );
        assert_eq!(
            find("/contents/0/parts/0/text").unwrap().data,
            "describe this"
        );
        assert_eq!(
            find("/contents/0/parts/1/inlineData/data").unwrap(),
            &ScreenablePart {
                pointer: "/contents/0/parts/1/inlineData/data".to_string(),
                kind: PartKind::Base64Media {
                    media_type: "image/png".to_string()
                },
                data: "iVBORw0KGgo=".to_string(),
            }
        );
        assert_eq!(
            find("/contents/0/parts/1/inlineData/displayName")
                .unwrap()
                .data,
            "chart"
        );
        assert_eq!(
            find("/contents/0/parts/2/fileData/fileUri").unwrap().kind,
            PartKind::RemoteReference
        );
        assert_eq!(
            find("/contents/1/parts/0/functionCall/args/query")
                .unwrap()
                .data,
            "ssn 123-45-6789"
        );
        assert_eq!(
            find("/contents/2/parts/0/functionResponse/response/result")
                .unwrap()
                .data,
            "found it"
        );
        assert_eq!(
            find("/tools/0/functionDeclarations/0/description")
                .unwrap()
                .data,
            "look up"
        );
        assert_eq!(find("/labels/team").unwrap().data, "risk");

        // Nothing is skipped by key name: tags, signatures and configuration strings are all
        // caller-controlled, so all are reported as text.
        for (pointer, data) in [
            ("/model", "models/gemini-2.5-pro"),
            ("/contents/0/role", "user"),
            ("/contents/0/parts/1/inlineData/mimeType", "image/png"),
            ("/contents/1/parts/0/thoughtSignature", "c2ln"),
        ] {
            assert_eq!(
                find(pointer).map(|part| (&part.kind, part.data.as_str())),
                Some((&PartKind::Text, data)),
                "{pointer}"
            );
        }
        // The base64 payload is classified as media only, never also as text.
        assert_eq!(
            parts
                .iter()
                .filter(|part| part.data == "iVBORw0KGgo=")
                .count(),
            1
        );
    }
}
