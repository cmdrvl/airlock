use std::fs;

use airlock::adapter::{Adapter, OpenAiChatCompletionsAdapter, TransportConfig};
use airlock::output::sort_value;
use jsonschema::validator_for;
use serde_json::{Value, json};

fn read_json(path: &str) -> Value {
    let bytes = fs::read(path).expect("fixture file should be readable");
    serde_json::from_slice(&bytes).expect("fixture JSON should parse")
}

fn prompt_payload() -> Value {
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
fn openai_chat_request_matches_golden_and_official_schema() {
    let adapter = OpenAiChatCompletionsAdapter;
    let request = adapter
        .wrap(&prompt_payload(), &TransportConfig::new("gpt-5"))
        .unwrap();
    let golden = read_json("fixtures/openai_chat_completions/request.json");
    let schema = read_json("schemas/openai_chat_completions_request.schema.json");
    let validator = validator_for(&schema).expect("official OpenAI request schema is valid");

    assert_eq!(request, golden);
    assert!(validator.is_valid(&request), "generated request: {request}");
    assert!(request["messages"][1]["content"].is_array());
    assert_eq!(
        adapter.unwrap(&request).unwrap(),
        sort_value(prompt_payload())
    );
}

#[test]
fn unwrap_exposes_wire_mutations_to_prompt_binding() {
    let adapter = OpenAiChatCompletionsAdapter;
    let prompt = sort_value(prompt_payload());
    let mut request = adapter
        .wrap(&prompt, &TransportConfig::new("gpt-5"))
        .unwrap();
    let user_text = request
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .and_then(|messages| messages.get_mut(1))
        .and_then(|message| message.get_mut("content"))
        .and_then(Value::as_array_mut)
        .and_then(|parts| parts.get_mut(0))
        .and_then(|part| part.get_mut("text"))
        .expect("wrapped user content is one text part");
    *user_text =
        json!(r#"{"benchmark_summary":{"coverage":0.5},"challenge_profile":{"page_count":12}}"#);

    assert_ne!(adapter.unwrap(&request).unwrap(), prompt);
}
