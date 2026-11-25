use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::output::{canonical_json, sort_value};
use crate::refusal::RefusalEnvelope;

pub const OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME: &str = "openai_chat_completions";

const RESERVED_REQUEST_KEYS: [&str; 5] = [
    "messages",
    "model",
    "temperature",
    "max_tokens",
    "response_format",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransportConfig {
    pub model_id: String,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub response_format: Option<Value>,
    pub additional_params: Option<Map<String, Value>>,
}

impl TransportConfig {
    pub fn new(model_id: impl Into<String>) -> Self {
        Self {
            model_id: model_id.into(),
            temperature: None,
            max_tokens: None,
            response_format: None,
            additional_params: None,
        }
    }
}

pub trait Adapter {
    fn name(&self) -> &str;

    fn wrap(
        &self,
        prompt_payload: &Value,
        config: &TransportConfig,
    ) -> Result<Value, RefusalEnvelope>;

    /// Restore the canonical prompt messages from a vendor request envelope.
    fn unwrap(&self, request_payload: &Value) -> Result<Value, RefusalEnvelope>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiChatCompletionsAdapter;

impl Adapter for OpenAiChatCompletionsAdapter {
    fn name(&self) -> &str {
        OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME
    }

    fn wrap(
        &self,
        prompt_payload: &Value,
        config: &TransportConfig,
    ) -> Result<Value, RefusalEnvelope> {
        let model_id = config.model_id.trim();
        if model_id.is_empty() {
            return Err(RefusalEnvelope::bad_request(
                "transport config requires a non-empty model_id",
                json!({ "field": "model_id" }),
            ));
        }

        if let Some(temperature) = config.temperature {
            if !temperature.is_finite() {
                return Err(RefusalEnvelope::bad_request(
                    "transport config temperature must be finite",
                    json!({
                        "field": "temperature",
                        "value": temperature.to_string(),
                    }),
                ));
            }
        }

        let messages = prompt_payload
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RefusalEnvelope::bad_prompt(
                    "prompt payload must contain a messages array",
                    json!({ "field": "messages" }),
                )
            })?;

        let messages = messages
            .iter()
            .enumerate()
            .map(|(index, message)| encode_message(message, index))
            .collect::<Result<Vec<_>, _>>()?;

        let mut request = Map::new();
        request.insert("model".to_string(), Value::String(model_id.to_string()));
        request.insert("messages".to_string(), Value::Array(messages));

        if let Some(temperature) = config.temperature {
            request.insert("temperature".to_string(), json!(temperature));
        }
        if let Some(max_tokens) = config.max_tokens {
            request.insert("max_tokens".to_string(), json!(max_tokens));
        }
        if let Some(response_format) = &config.response_format {
            request.insert("response_format".to_string(), response_format.clone());
        }

        if let Some(additional_params) = &config.additional_params {
            for (key, value) in additional_params {
                if RESERVED_REQUEST_KEYS.contains(&key.as_str()) {
                    return Err(RefusalEnvelope::bad_request(
                        "additional_params may not override reserved request fields",
                        json!({ "field": key }),
                    ));
                }
                request.insert(key.clone(), value.clone());
            }
        }

        Ok(sort_value(Value::Object(request)))
    }

    fn unwrap(&self, request_payload: &Value) -> Result<Value, RefusalEnvelope> {
        let messages = request_payload
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RefusalEnvelope::bad_request(
                    "OpenAI Chat Completions request must contain a messages array",
                    json!({ "field": "messages" }),
                )
            })?;

        let messages = messages
            .iter()
            .map(|message| {
                let mut message = message.as_object().cloned().ok_or_else(|| {
                    RefusalEnvelope::bad_request(
                        "OpenAI Chat Completions messages must be objects",
                        json!({ "field": "messages" }),
                    )
                })?;

                if message.get("role").and_then(Value::as_str) == Some("user") {
                    if let Some(content) = message.get_mut("content") {
                        *content = decode_user_content(content);
                    }
                }

                Ok(Value::Object(message))
            })
            .collect::<Result<Vec<_>, RefusalEnvelope>>()?;

        Ok(sort_value(json!({ "messages": messages })))
    }
}

fn encode_message(message: &Value, index: usize) -> Result<Value, RefusalEnvelope> {
    let mut message = message.as_object().cloned().ok_or_else(|| {
        RefusalEnvelope::bad_prompt(
            "prompt messages must be objects",
            json!({ "field": "messages", "index": index }),
        )
    })?;

    let role = message.get("role").and_then(Value::as_str).ok_or_else(|| {
        RefusalEnvelope::bad_prompt(
            "prompt messages must include a string role",
            json!({ "field": format!("messages[{index}].role") }),
        )
    })?;

    let content = message.get("content").ok_or_else(|| {
        RefusalEnvelope::bad_prompt(
            "prompt messages must include content",
            json!({ "field": format!("messages[{index}].content") }),
        )
    })?;

    if !content.is_string() {
        let encoded = canonical_json(content);
        let wire_content = if role == "user" {
            // Chat Completions accepts text content parts for user messages.
            // A single text part keeps the structured payload deterministic and
            // gives unwrap() an unambiguous transport marker to reverse.
            json!([{ "type": "text", "text": encoded }])
        } else {
            // Non-user message roles accept string content. Keep their values
            // JSON-encoded without adding a user-only content part.
            Value::String(encoded)
        };
        message.insert("content".to_string(), wire_content);
    }

    Ok(sort_value(Value::Object(message)))
}

fn decode_user_content(content: &Value) -> Value {
    let Some(parts) = content.as_array() else {
        return content.clone();
    };
    let [part] = parts.as_slice() else {
        return content.clone();
    };
    let Some(part) = part.as_object() else {
        return content.clone();
    };
    if part.len() != 2 || part.get("type").and_then(Value::as_str) != Some("text") {
        return content.clone();
    }
    let Some(encoded) = part.get("text").and_then(Value::as_str) else {
        return content.clone();
    };

    let Ok(decoded) = serde_json::from_str::<Value>(encoded) else {
        return content.clone();
    };
    if canonical_json(&decoded) == encoded {
        decoded
    } else {
        content.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::canonical_json;

    fn sample_prompt_payload() -> Value {
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
    fn adapter_name_matches_expected_constant() {
        let adapter = OpenAiChatCompletionsAdapter;
        assert_eq!(adapter.name(), OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME);
    }

    #[test]
    fn wrap_builds_openai_chat_completions_request() {
        let adapter = OpenAiChatCompletionsAdapter;
        let mut additional_params = Map::new();
        additional_params.insert("logprobs".to_string(), json!(true));
        let config = TransportConfig {
            model_id: "gpt-5".to_string(),
            temperature: Some(0.0),
            max_tokens: Some(4096),
            response_format: Some(json!({"type": "json_object"})),
            additional_params: Some(additional_params),
        };

        let request = adapter.wrap(&sample_prompt_payload(), &config).unwrap();

        assert_eq!(request["model"], "gpt-5");
        assert_eq!(request["temperature"], 0.0);
        assert_eq!(request["max_tokens"], 4096);
        assert_eq!(request["response_format"], json!({"type": "json_object"}));
        assert_eq!(request["logprobs"], true);
        assert_eq!(
            request["messages"][0],
            sample_prompt_payload()["messages"][0]
        );
        assert_eq!(
            request["messages"][1]["content"],
            json!([{
                "type": "text",
                "text": r#"{"benchmark_summary":{"coverage":0.98},"challenge_profile":{"page_count":12}}"#
            }])
        );
    }

    #[test]
    fn wrap_preserves_prompt_payload_content_without_injection() {
        let adapter = OpenAiChatCompletionsAdapter;
        let prompt_payload = sample_prompt_payload();
        let config = TransportConfig::new("gpt-5");

        let request = adapter.wrap(&prompt_payload, &config).unwrap();
        let keys = request
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();

        assert_ne!(request["messages"], prompt_payload["messages"]);
        assert_eq!(
            adapter.unwrap(&request).unwrap(),
            sort_value(prompt_payload)
        );
        assert_eq!(keys, vec!["messages", "model"]);
    }

    #[test]
    fn wrap_never_emits_object_message_content() {
        let adapter = OpenAiChatCompletionsAdapter;
        let request = adapter
            .wrap(&sample_prompt_payload(), &TransportConfig::new("gpt-5"))
            .unwrap();

        assert!(
            request["messages"]
                .as_array()
                .unwrap()
                .iter()
                .all(|message| !message["content"].is_object())
        );
    }

    #[test]
    fn unwrap_preserves_string_content_and_decodes_canonical_user_text_part() {
        let adapter = OpenAiChatCompletionsAdapter;
        let prompt = sample_prompt_payload();
        let request = adapter
            .wrap(&prompt, &TransportConfig::new("gpt-5"))
            .unwrap();

        assert_eq!(adapter.unwrap(&request).unwrap(), sort_value(prompt));
    }

    #[test]
    fn unwrap_leaves_noncanonical_user_text_parts_unmodified() {
        let adapter = OpenAiChatCompletionsAdapter;
        let request = json!({
            "model": "gpt-5",
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": "{ \"a\" : 1 }"}]
            }]
        });

        assert_eq!(
            adapter.unwrap(&request).unwrap()["messages"][0]["content"],
            request["messages"][0]["content"]
        );
    }

    #[test]
    fn wrap_rejects_missing_model_id() {
        let adapter = OpenAiChatCompletionsAdapter;
        let config = TransportConfig::new("   ");

        let refusal = adapter.wrap(&sample_prompt_payload(), &config).unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_REQUEST");
        assert!(refusal.refusal.message.contains("model_id"));
    }

    #[test]
    fn wrap_rejects_prompt_payload_without_messages_array() {
        let adapter = OpenAiChatCompletionsAdapter;
        let config = TransportConfig::new("gpt-5");

        let refusal = adapter
            .wrap(&json!({"user": "missing messages"}), &config)
            .unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_PROMPT");
        assert!(refusal.refusal.message.contains("messages array"));
    }

    #[test]
    fn wrap_rejects_reserved_additional_params() {
        let adapter = OpenAiChatCompletionsAdapter;
        let mut additional_params = Map::new();
        additional_params.insert("messages".to_string(), json!(["should not override"]));
        let config = TransportConfig {
            model_id: "gpt-5".to_string(),
            temperature: None,
            max_tokens: None,
            response_format: None,
            additional_params: Some(additional_params),
        };

        let refusal = adapter.wrap(&sample_prompt_payload(), &config).unwrap_err();

        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_REQUEST");
        assert!(refusal.refusal.message.contains("reserved request fields"));
    }

    #[test]
    fn wrap_returns_canonical_json_key_order() {
        let adapter = OpenAiChatCompletionsAdapter;
        let config = TransportConfig {
            model_id: "gpt-5".to_string(),
            temperature: Some(0.0),
            max_tokens: Some(1024),
            response_format: Some(json!({"type": "json_object"})),
            additional_params: None,
        };

        let request = adapter.wrap(&sample_prompt_payload(), &config).unwrap();
        let serialized = serde_json::to_string(&request).unwrap();

        assert_eq!(request, sort_value(request.clone()));
        assert_eq!(serialized, canonical_json(&request));
    }
}
