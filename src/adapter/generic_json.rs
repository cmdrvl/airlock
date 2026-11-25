//! Generic JSON-pointer adapter: binds a vendor request without a bespoke adapter.
//!
//! The transport declaration says where the messages array and the system prompt live (RFC
//! 6901 pointers) and which top-level request keys the vendor declares. It suits vendors whose
//! messages are already `{role, content}` objects with string content, such as the many
//! OpenAI-compatible APIs that relocate or rename a top-level field. It does not suit vendors
//! with another message structure: Gemini `contents` items are `{role, parts}`, so Gemini has
//! its own adapter.
//!
//! The adapter cannot know a vendor's content format, so it only emits string content.
//! Structured content becomes its canonical JSON string, and a plain string that is itself
//! such an encoding is refused, which keeps `unwrap` able to reverse everything `wrap` emits.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use super::{
    Adapter, ScreenablePart, TransportConfig, TransportDeclaration, apply_additional_params,
    chat_media_parts, decode_structured_container, prompt_message, prompt_messages,
    validated_model_id, walk_request,
};
use crate::output::{canonical_json, sort_value};
use crate::refusal::RefusalEnvelope;

pub const GENERIC_JSON_ADAPTER_NAME: &str = "generic_json";

const ADAPTER_LABEL: &str = "generic_json";
const DEFAULT_MODEL_POINTER: &str = "/model";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericJsonAdapter {
    messages_pointer: String,
    system_pointer: Option<String>,
    model_pointer: String,
    transport_keys: Vec<String>,
}

impl GenericJsonAdapter {
    /// Build the adapter from a transport declaration, refusing an inconsistent one up front.
    pub fn from_declaration(declaration: &TransportDeclaration) -> Result<Self, RefusalEnvelope> {
        let messages_pointer = declaration
            .messages_pointer
            .clone()
            .ok_or_else(|| missing_field("messages_pointer"))?;
        let transport_keys = declaration
            .transport_keys
            .clone()
            .ok_or_else(|| missing_field("transport_keys"))?;
        let system_pointer = declaration.system_pointer.clone();
        let model_pointer = declaration
            .model_pointer
            .clone()
            .unwrap_or_else(|| DEFAULT_MODEL_POINTER.to_string());

        let mut declared_keys = BTreeSet::new();
        for key in &transport_keys {
            if key.is_empty() || !declared_keys.insert(key.as_str()) {
                return Err(RefusalEnvelope::bad_input(
                    "generic_json transport_keys must be non-empty and unique",
                    json!({ "field": "transport_keys", "key": key }),
                ));
            }
        }
        if declared_keys.is_empty() {
            return Err(RefusalEnvelope::bad_input(
                "generic_json transport_keys must name at least one key",
                json!({ "field": "transport_keys" }),
            ));
        }

        let mut pointers = vec![
            ("messages_pointer", &messages_pointer),
            ("model_pointer", &model_pointer),
        ];
        if let Some(pointer) = &system_pointer {
            pointers.push(("system_pointer", pointer));
        }
        for (field, pointer) in &pointers {
            let segments = pointer_segments(pointer).ok_or_else(|| {
                RefusalEnvelope::bad_input(
                    "generic_json pointers must be RFC 6901 pointers with non-empty segments",
                    json!({ "field": field, "pointer": pointer }),
                )
            })?;
            if !declared_keys.contains(segments[0].as_str()) {
                return Err(RefusalEnvelope::bad_input(
                    "generic_json pointer starts at a key missing from transport_keys",
                    json!({ "field": field, "pointer": pointer, "key": segments[0] }),
                ));
            }
        }
        for (index, (left_field, left)) in pointers.iter().enumerate() {
            for (right_field, right) in &pointers[index + 1..] {
                if overlaps(left, right) {
                    return Err(RefusalEnvelope::bad_input(
                        "generic_json pointers must not be equal or nested",
                        json!({ "fields": [left_field, right_field] }),
                    ));
                }
            }
        }

        Ok(Self {
            messages_pointer,
            system_pointer,
            model_pointer,
            transport_keys,
        })
    }
}

impl Adapter for GenericJsonAdapter {
    fn name(&self) -> &str {
        GENERIC_JSON_ADAPTER_NAME
    }

    fn transport_keys(&self) -> Vec<&str> {
        self.transport_keys.iter().map(String::as_str).collect()
    }

    fn wrap(
        &self,
        prompt_payload: &Value,
        config: &TransportConfig,
    ) -> Result<Value, RefusalEnvelope> {
        let model_id = validated_model_id(config)?;
        for (field, present) in [
            ("temperature", config.temperature.is_some()),
            ("max_tokens", config.max_tokens.is_some()),
            ("response_format", config.response_format.is_some()),
        ] {
            if present {
                return Err(RefusalEnvelope::bad_request(
                    format!("generic_json cannot place {field}: the vendor field name is unknown"),
                    json!({
                        "field": field,
                        "hint": "pass the vendor field through additional_params",
                    }),
                ));
            }
        }

        let mut system_texts: Vec<String> = Vec::new();
        let mut messages = Vec::new();
        let mut leading = true;
        for (index, message) in prompt_messages(prompt_payload)?.iter().enumerate() {
            let parsed = prompt_message(message, index, &[], ADAPTER_LABEL)?;
            let field = format!("messages[{index}].content");

            if self.system_pointer.is_some() && leading && parsed.role == "system" {
                let text = parsed.content.as_str().ok_or_else(|| {
                    RefusalEnvelope::bad_prompt(
                        "generic_json system content must be a string",
                        json!({ "field": field.clone() }),
                    )
                })?;
                system_texts.push(text.to_string());
                continue;
            }
            leading = false;

            let content = match parsed.content {
                Value::String(text) => {
                    if decode_structured_container(text).is_some() {
                        return Err(RefusalEnvelope::bad_prompt(
                            "generic_json cannot tell this string from structured content",
                            json!({
                                "field": field,
                                "hint": "pass structured content as a JSON object or array, not a pre-serialized string",
                            }),
                        ));
                    }
                    Value::String(text.clone())
                }
                structured @ (Value::Object(_) | Value::Array(_)) => {
                    Value::String(canonical_json(structured))
                }
                _ => {
                    return Err(RefusalEnvelope::bad_prompt(
                        "generic_json content must be a string, object or array",
                        json!({ "field": field }),
                    ));
                }
            };
            messages.push(json!({ "role": parsed.role, "content": content }));
        }
        if messages.is_empty() {
            return Err(RefusalEnvelope::bad_prompt(
                "generic_json needs at least one message besides a lifted system prompt",
                json!({ "field": "messages" }),
            ));
        }

        let mut root = Value::Object(Map::new());
        set_pointer(&mut root, &self.model_pointer, Value::String(model_id));
        set_pointer(&mut root, &self.messages_pointer, Value::Array(messages));
        if let Some(system_pointer) = &self.system_pointer {
            match system_texts.as_slice() {
                [] => {}
                [only] => set_pointer(&mut root, system_pointer, Value::String(only.clone())),
                _ => {
                    return Err(RefusalEnvelope::bad_prompt(
                        "generic_json carries one system string at the system pointer",
                        json!({ "field": "messages", "system_messages": system_texts.len() }),
                    ));
                }
            }
        }

        let Value::Object(mut request) = root else {
            return Err(RefusalEnvelope::internal(
                "generic_json request root was not an object",
                json!({}),
            ));
        };
        let allowed = self.transport_keys();
        apply_additional_params(
            &mut request,
            config.additional_params.as_ref(),
            &[],
            &allowed,
            ADAPTER_LABEL,
        )?;

        Ok(sort_value(Value::Object(request)))
    }

    fn unwrap(&self, request_payload: &Value) -> Result<Value, RefusalEnvelope> {
        let wire_messages = request_payload
            .pointer(&self.messages_pointer)
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RefusalEnvelope::bad_request(
                    "generic_json request must contain a messages array at the declared pointer",
                    json!({ "pointer": self.messages_pointer }),
                )
            })?;

        let mut messages = Vec::new();
        if let Some(system_pointer) = &self.system_pointer {
            match request_payload.pointer(system_pointer) {
                None => {}
                Some(system) => messages.push(json!({ "role": "system", "content": system })),
            }
        }

        for message in wire_messages {
            let mut message = message.as_object().cloned().ok_or_else(|| {
                RefusalEnvelope::bad_request(
                    "generic_json messages must be objects",
                    json!({ "pointer": self.messages_pointer }),
                )
            })?;
            if let Some(Value::String(text)) = message.get("content") {
                if let Some(decoded) = decode_structured_container(text) {
                    message.insert("content".to_string(), decoded);
                }
            }
            messages.push(Value::Object(message));
        }

        Ok(sort_value(json!({ "messages": messages })))
    }

    fn model_id(&self, request_payload: &Value) -> Option<String> {
        request_payload
            .pointer(&self.model_pointer)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .map(str::to_string)
    }

    fn extract_screenable_parts(
        &self,
        request_payload: &Value,
    ) -> Result<Vec<ScreenablePart>, RefusalEnvelope> {
        // The vendor's content format is unknown, so recognise the common OpenAI-style media
        // parts and report every other string as text.
        walk_request(request_payload, &chat_media_parts)
    }
}

fn missing_field(field: &str) -> RefusalEnvelope {
    RefusalEnvelope::bad_input(
        "generic_json transport declaration is missing a required field",
        json!({ "field": field }),
    )
}

/// Split an RFC 6901 pointer into unescaped segments. `None` for a pointer that does not start
/// with `/`, has an empty segment, or has a `~` not followed by `0` or `1`.
fn pointer_segments(pointer: &str) -> Option<Vec<String>> {
    let rest = pointer.strip_prefix('/')?;
    rest.split('/')
        .map(|segment| {
            if segment.is_empty() {
                return None;
            }
            let mut unescaped = String::with_capacity(segment.len());
            let mut chars = segment.chars();
            while let Some(character) = chars.next() {
                if character != '~' {
                    unescaped.push(character);
                    continue;
                }
                match chars.next() {
                    Some('0') => unescaped.push('~'),
                    Some('1') => unescaped.push('/'),
                    _ => return None,
                }
            }
            Some(unescaped)
        })
        .collect()
}

/// Whether two pointers are equal or one is an ancestor of the other.
fn overlaps(left: &str, right: &str) -> bool {
    left == right
        || left.starts_with(&format!("{right}/"))
        || right.starts_with(&format!("{left}/"))
}

/// Insert `value` at an object-key pointer, creating intermediate objects as needed.
fn set_pointer(root: &mut Value, pointer: &str, value: Value) {
    let Some(segments) = pointer_segments(pointer) else {
        return;
    };
    let Some((leaf, parents)) = segments.split_last() else {
        return;
    };
    let mut current = root;
    for segment in parents {
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }
        let Some(object) = current.as_object_mut() else {
            return;
        };
        current = object
            .entry(segment.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if !current.is_object() {
        *current = Value::Object(Map::new());
    }
    if let Some(object) = current.as_object_mut() {
        object.insert(leaf.clone(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::PartKind;

    fn declaration() -> TransportDeclaration {
        TransportDeclaration {
            adapter: Some(GENERIC_JSON_ADAPTER_NAME.to_string()),
            messages_pointer: Some("/input/messages".to_string()),
            system_pointer: Some("/preamble".to_string()),
            model_pointer: None,
            transport_keys: Some(vec![
                "input".to_string(),
                "model".to_string(),
                "preamble".to_string(),
                "seed".to_string(),
            ]),
        }
    }

    fn adapter() -> GenericJsonAdapter {
        GenericJsonAdapter::from_declaration(&declaration()).unwrap()
    }

    fn sample_prompt() -> Value {
        json!({
            "messages": [
                {"role": "system", "content": "You are a careful boundary verifier."},
                {"role": "user", "content": {"benchmark_summary": {"coverage": 0.98}}},
                {"role": "assistant", "content": "plain reply"},
            ]
        })
    }

    #[test]
    fn wrap_places_messages_system_and_model_at_the_declared_pointers() {
        let request = adapter()
            .wrap(&sample_prompt(), &TransportConfig::new("vendor-large"))
            .unwrap();

        assert_eq!(
            request,
            json!({
                "input": {"messages": [
                    {"content": r#"{"benchmark_summary":{"coverage":0.98}}"#, "role": "user"},
                    {"content": "plain reply", "role": "assistant"}
                ]},
                "model": "vendor-large",
                "preamble": "You are a careful boundary verifier."
            })
        );
    }

    #[test]
    fn unwrap_reverses_wrap_exactly_with_and_without_a_system_pointer() {
        let prompt = sample_prompt();
        let with_system = adapter();
        let request = with_system
            .wrap(&prompt, &TransportConfig::new("vendor-large"))
            .unwrap();
        assert_eq!(
            with_system.unwrap(&request).unwrap(),
            sort_value(prompt.clone())
        );

        let without_system = GenericJsonAdapter::from_declaration(&TransportDeclaration {
            system_pointer: None,
            ..declaration()
        })
        .unwrap();
        let request = without_system
            .wrap(&prompt, &TransportConfig::new("vendor-large"))
            .unwrap();
        assert_eq!(request["input"]["messages"][0]["role"], "system");
        assert_eq!(without_system.unwrap(&request).unwrap(), sort_value(prompt));
    }

    #[test]
    fn model_id_follows_the_declared_pointer() {
        let adapter = GenericJsonAdapter::from_declaration(&TransportDeclaration {
            model_pointer: Some("/input/model".to_string()),
            ..declaration()
        })
        .unwrap();
        let request = adapter
            .wrap(&sample_prompt(), &TransportConfig::new("vendor-large"))
            .unwrap();

        assert_eq!(request["input"]["model"], "vendor-large");
        assert_eq!(adapter.model_id(&request).as_deref(), Some("vendor-large"));
        assert_eq!(adapter.model_id(&json!({"model": "elsewhere"})), None);
    }

    #[test]
    fn unwrap_exposes_mutations_to_the_binding_comparison() {
        let adapter = adapter();
        let prompt = sample_prompt();
        let request = adapter
            .wrap(&prompt, &TransportConfig::new("vendor-large"))
            .unwrap();
        let expected = sort_value(prompt);

        let mut changed = request.clone();
        changed["input"]["messages"][0]["content"] =
            json!(r#"{"benchmark_summary":{"coverage":0.5}}"#);
        assert_ne!(adapter.unwrap(&changed).unwrap(), expected);

        let mut other_system = request.clone();
        other_system["preamble"] = json!("be careless");
        assert_ne!(adapter.unwrap(&other_system).unwrap(), expected);

        let mut extra_message = request;
        extra_message["input"]["messages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"role": "user", "content": "one more"}));
        assert_ne!(adapter.unwrap(&extra_message).unwrap(), expected);
    }

    #[test]
    fn wrap_refuses_what_it_cannot_place_or_reverse() {
        let adapter = adapter();
        let prompt = json!({"messages": [{"role": "user", "content": "hi"}]});

        for (config, field) in [
            (
                TransportConfig {
                    temperature: Some(0.0),
                    ..TransportConfig::new("m")
                },
                "temperature",
            ),
            (
                TransportConfig {
                    max_tokens: Some(10),
                    ..TransportConfig::new("m")
                },
                "max_tokens",
            ),
            (
                TransportConfig {
                    response_format: Some(json!({})),
                    ..TransportConfig::new("m")
                },
                "response_format",
            ),
        ] {
            let error = adapter.wrap(&prompt, &config).unwrap_err();
            assert!(error.refusal.message.contains(field), "{field}");
        }

        let ambiguous = json!({"messages": [{"role": "user", "content": r#"{"a":1}"#}]});
        assert!(
            adapter
                .wrap(&ambiguous, &TransportConfig::new("m"))
                .unwrap_err()
                .refusal
                .message
                .contains("cannot tell this string")
        );

        let two_system = json!({"messages": [
            {"role": "system", "content": "a"},
            {"role": "system", "content": "b"},
            {"role": "user", "content": "hi"},
        ]});
        assert!(
            adapter
                .wrap(&two_system, &TransportConfig::new("m"))
                .unwrap_err()
                .refusal
                .message
                .contains("one system string")
        );

        let scalar = json!({"messages": [{"role": "user", "content": 7}]});
        assert!(
            adapter
                .wrap(&scalar, &TransportConfig::new("m"))
                .unwrap_err()
                .refusal
                .message
                .contains("string, object or array")
        );

        let undeclared = TransportConfig {
            additional_params: json!({"temperature": 0.1}).as_object().cloned(),
            ..TransportConfig::new("m")
        };
        assert!(
            adapter
                .wrap(&prompt, &undeclared)
                .unwrap_err()
                .refusal
                .message
                .contains("not a generic_json request field")
        );

        let allowed = TransportConfig {
            additional_params: json!({"seed": 7}).as_object().cloned(),
            ..TransportConfig::new("m")
        };
        assert_eq!(adapter.wrap(&prompt, &allowed).unwrap()["seed"], 7);

        let shadowing = TransportConfig {
            additional_params: json!({"input": {}}).as_object().cloned(),
            ..TransportConfig::new("m")
        };
        assert!(
            adapter
                .wrap(&prompt, &shadowing)
                .unwrap_err()
                .refusal
                .message
                .contains("reserved")
        );
    }

    #[test]
    fn unwrap_refuses_a_request_without_the_declared_messages_array() {
        let error = adapter()
            .unwrap(&json!({"input": {}, "model": "m"}))
            .unwrap_err();
        assert_eq!(error.refusal.code.as_str(), "E_BAD_REQUEST");
    }

    #[test]
    fn declarations_are_validated_up_front() {
        let cases: [(TransportDeclaration, &str); 8] = [
            (
                TransportDeclaration {
                    messages_pointer: None,
                    ..declaration()
                },
                "missing a required field",
            ),
            (
                TransportDeclaration {
                    transport_keys: None,
                    ..declaration()
                },
                "missing a required field",
            ),
            (
                TransportDeclaration {
                    transport_keys: Some(vec![]),
                    ..declaration()
                },
                "at least one key",
            ),
            (
                TransportDeclaration {
                    transport_keys: Some(vec!["a".into(), "a".into()]),
                    ..declaration()
                },
                "non-empty and unique",
            ),
            (
                TransportDeclaration {
                    messages_pointer: Some("input/messages".to_string()),
                    ..declaration()
                },
                "RFC 6901",
            ),
            (
                TransportDeclaration {
                    messages_pointer: Some("/input//messages".to_string()),
                    ..declaration()
                },
                "RFC 6901",
            ),
            (
                TransportDeclaration {
                    messages_pointer: Some("/other/messages".to_string()),
                    ..declaration()
                },
                "missing from transport_keys",
            ),
            (
                TransportDeclaration {
                    system_pointer: Some("/input".to_string()),
                    ..declaration()
                },
                "equal or nested",
            ),
        ];
        for (declaration, expected) in cases {
            let error = GenericJsonAdapter::from_declaration(&declaration).unwrap_err();
            assert_eq!(error.refusal.code.as_str(), "E_BAD_INPUT");
            assert!(
                error.refusal.message.contains(expected),
                "expected {expected:?}, got {:?}",
                error.refusal.message
            );
        }
    }

    #[test]
    fn pointer_segments_unescape_and_reject_bad_escapes() {
        assert_eq!(
            pointer_segments("/a~1b/c~0d"),
            Some(vec!["a/b".to_string(), "c~d".to_string()])
        );
        assert_eq!(pointer_segments("/a~2"), None);
        assert_eq!(pointer_segments("/a~"), None);
        assert_eq!(pointer_segments(""), None);
    }

    #[test]
    fn screenable_parts_walk_the_request_and_classify_media() {
        let request = json!({
            "model": "vendor-large",
            "preamble": "be brief",
            "input": {"messages": [{"role": "user", "content": [
                {"type": "text", "text": "look"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}
            ]}]}
        });
        let parts = adapter().extract_screenable_parts(&request).unwrap();
        let find = |pointer: &str| parts.iter().find(|part| part.pointer == pointer);

        assert_eq!(find("/preamble").unwrap().data, "be brief");
        assert_eq!(
            find("/input/messages/0/content/0/text").unwrap().data,
            "look"
        );
        assert_eq!(
            find("/input/messages/0/content/1/image_url/url")
                .unwrap()
                .kind,
            PartKind::Base64Media {
                media_type: "image/png".to_string()
            }
        );
        // Nothing is skipped by key name.
        assert_eq!(find("/model").unwrap().data, "vendor-large");
        assert_eq!(find("/input/messages/0/role").unwrap().data, "user");
        assert_eq!(
            find("/input/messages/0/content/1/type").unwrap().kind,
            PartKind::Text
        );
    }
}
