use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use airlock::adapter::{
    ADAPTER_NAMES, Adapter, AnthropicMessagesAdapter, GeminiGenerateContentAdapter,
    OpenAiChatCompletionsAdapter, OpenAiResponsesAdapter, PartKind, TransportConfig,
};
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

// ---------------------------------------------------------------------------------------------
// Every vendor adapter against its vendor's published request schema
// ---------------------------------------------------------------------------------------------

/// A media payload expected in a multimodal request: pointer, kind (`remote` or
/// `base64:<media type>`) and the payload string.
type MediaRow = (&'static str, &'static str, &'static str);

/// One vendor wire format: its adapter, the config that produces its golden request, and the
/// vendor schema, golden request, multimodal request and known-bad requests that go with it.
struct WireCase {
    name: &'static str,
    adapter: Box<dyn Adapter>,
    config: TransportConfig,
    schema: &'static str,
    golden: &'static str,
    multimodal: &'static str,
    media: Vec<MediaRow>,
    invalid_requests: Vec<Value>,
}

fn wire_cases() -> Vec<WireCase> {
    vec![
        WireCase {
            name: "openai_chat_completions",
            adapter: Box::new(OpenAiChatCompletionsAdapter),
            config: TransportConfig::new("gpt-5"),
            schema: "schemas/openai_chat_completions_request.schema.json",
            golden: "fixtures/openai_chat_completions/request.json",
            multimodal: "fixtures/openai_chat_completions/screenable_request.json",
            media: vec![
                (
                    "/messages/1/content/1/image_url/url",
                    "base64:image/png",
                    "iVBORw0KGgo=",
                ),
                (
                    "/messages/1/content/2/input_audio/data",
                    "base64:audio/wav",
                    "UklGRg==",
                ),
                (
                    "/messages/1/content/3/file/file_data",
                    "base64:application/pdf",
                    "JVBERi0xLjQK",
                ),
            ],
            invalid_requests: vec![
                json!({"model": "gpt-5"}),
                json!({"model": "gpt-5", "messages": "hello"}),
                json!({"model": "gpt-5", "messages": [{"role": "user", "content": "hi"}], "temperature": "hot"}),
            ],
        },
        WireCase {
            name: "openai_responses",
            adapter: Box::new(OpenAiResponsesAdapter),
            config: TransportConfig {
                temperature: Some(0.0),
                max_tokens: Some(2048),
                ..TransportConfig::new("gpt-5")
            },
            schema: "schemas/openai_responses_request.schema.json",
            golden: "fixtures/openai_responses/request.json",
            multimodal: "fixtures/openai_responses/screenable_request.json",
            media: vec![
                (
                    "/input/0/content/1/image_url",
                    "base64:image/png",
                    "iVBORw0KGgo=",
                ),
                (
                    "/input/0/content/2/file_data",
                    "base64:application/pdf",
                    "JVBERi0xLjQK",
                ),
            ],
            invalid_requests: vec![
                json!({"model": "gpt-5", "input": 42}),
                json!({"model": "gpt-5", "input": "hi", "temperature": "hot"}),
                json!({"model": "gpt-5", "input": "hi", "max_output_tokens": 4}),
            ],
        },
        WireCase {
            name: "anthropic_messages",
            adapter: Box::new(AnthropicMessagesAdapter),
            config: TransportConfig {
                max_tokens: Some(4096),
                ..TransportConfig::new("claude-sonnet-5-5")
            },
            schema: "schemas/anthropic_messages_request.schema.json",
            golden: "fixtures/anthropic_messages/request.json",
            multimodal: "fixtures/anthropic_messages/screenable_request.json",
            media: vec![
                (
                    "/messages/0/content/1/source/data",
                    "base64:image/png",
                    "iVBORw0KGgo=",
                ),
                (
                    "/messages/0/content/2/source/data",
                    "base64:application/pdf",
                    "JVBERi0xLjQK",
                ),
            ],
            invalid_requests: vec![
                json!({"model": "claude-sonnet-5-5", "messages": [{"role": "user", "content": "hi"}]}),
                json!({"model": "claude-sonnet-5-5", "max_tokens": 1, "messages": [{"role": "robot", "content": "hi"}]}),
                json!({"model": "claude-sonnet-5-5", "max_tokens": "many", "messages": [{"role": "user", "content": "hi"}]}),
            ],
        },
        WireCase {
            name: "gemini_generate_content",
            adapter: Box::new(GeminiGenerateContentAdapter),
            config: TransportConfig {
                temperature: Some(0.0),
                max_tokens: Some(2048),
                ..TransportConfig::new("gemini-2.5-pro")
            },
            schema: "schemas/gemini_generate_content_request.schema.json",
            golden: "fixtures/gemini_generate_content/request.json",
            multimodal: "fixtures/gemini_generate_content/screenable_request.json",
            media: vec![
                (
                    "/contents/0/parts/1/inlineData/data",
                    "base64:image/png",
                    "iVBORw0KGgo=",
                ),
                (
                    "/contents/0/parts/2/fileData/fileUri",
                    "remote",
                    "https://generativelanguage.googleapis.com/v1beta/files/abc-123",
                ),
            ],
            invalid_requests: vec![
                json!({"contents": "hello"}),
                json!({"contents": [{"role": "user", "parts": "hello"}]}),
                json!({"contents": [{"role": "user", "parts": [{"text": 7}]}]}),
            ],
        },
    ]
}

/// The top-level properties a request schema declares, following `$ref` and the composition
/// keywords (`allOf`, `anyOf`, `oneOf`) from the root.
fn schema_top_level_properties(schema: &Value) -> BTreeSet<String> {
    fn collect(
        root: &Value,
        node: &Value,
        seen: &mut BTreeSet<String>,
        keys: &mut BTreeSet<String>,
    ) {
        if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
            if !seen.insert(reference.to_string()) {
                return;
            }
            let pointer = reference
                .strip_prefix('#')
                .expect("schema refs in this repository are local");
            let target = root.pointer(pointer).expect("schema ref should resolve");
            collect(root, target, seen, keys);
        }
        if let Some(properties) = node.get("properties").and_then(Value::as_object) {
            keys.extend(properties.keys().cloned());
        }
        for keyword in ["allOf", "anyOf", "oneOf"] {
            for child in node
                .get(keyword)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                collect(root, child, seen, keys);
            }
        }
    }
    let mut keys = BTreeSet::new();
    collect(schema, schema, &mut BTreeSet::new(), &mut keys);
    keys
}

/// The Responses schema comes from an OpenAPI document that discriminates `InputItem` by its
/// `type` property. Plain JSON Schema ignores `discriminator`, so a message whose content is an
/// array matches both `EasyInputMessage` and `Item` (`InputMessage`), and `oneOf` rejects it
/// although the API documents and accepts exactly that request.
/// `responses_schema_ambiguity_is_the_only_reason_array_content_fails_strict_validation` proves
/// that diagnosis; this repair, `oneOf` to `anyOf` on `InputItem` alone, stands in for the
/// discriminator. Delete it, and the test, when the strict schema accepts such messages.
fn relax_responses_input_item(schema: &mut Value) {
    let input_item = schema
        .pointer_mut("/components/schemas/InputItem")
        .and_then(Value::as_object_mut)
        .expect("Responses schema defines components/schemas/InputItem");
    let branches = input_item
        .remove("oneOf")
        .expect("InputItem is a oneOf; if the schema changed, drop this repair");
    input_item.insert("anyOf".to_string(), branches);
}

fn vendor_validator(case: &WireCase) -> jsonschema::Validator {
    let mut schema = read_json(case.schema);
    if case.name == "openai_responses" {
        relax_responses_input_item(&mut schema);
    }
    validator_for(&schema)
        .unwrap_or_else(|error| panic!("{}: vendor schema should compile: {error}", case.name))
}

fn schema_errors(validator: &jsonschema::Validator, instance: &Value) -> Vec<String> {
    validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect()
}

#[test]
fn every_adapter_is_listed_and_named_consistently() {
    let cases = wire_cases();
    let names: Vec<&str> = cases.iter().map(|case| case.adapter.name()).collect();

    for case in &cases {
        assert_eq!(case.adapter.name(), case.name);
        assert!(ADAPTER_NAMES.contains(&case.name), "{}", case.name);
    }
    assert!(
        ADAPTER_NAMES
            .iter()
            .all(|name| names.contains(name) || *name == "generic_json"),
        "every vendor adapter in ADAPTER_NAMES has a wire case: {names:?}"
    );
}

#[test]
fn golden_requests_are_what_wrap_emits_and_validate_against_the_vendor_schema() {
    for case in wire_cases() {
        let golden = read_json(case.golden);
        let validator = vendor_validator(&case);

        let request = case
            .adapter
            .wrap(&prompt_payload(), &case.config)
            .unwrap_or_else(|error| panic!("{}: wrap should succeed: {error:?}", case.name));

        assert_eq!(
            request, golden,
            "{}: wrap output differs from golden",
            case.name
        );
        assert!(
            validator.is_valid(&golden),
            "{}: golden request violates the vendor schema: {:?}",
            case.name,
            schema_errors(&validator, &golden)
        );
        assert!(
            validator.is_valid(&request),
            "{}: generated request violates the vendor schema",
            case.name
        );
        assert_eq!(
            case.adapter.unwrap(&request).unwrap(),
            sort_value(prompt_payload()),
            "{}: unwrap does not reverse wrap",
            case.name
        );
        // Gemini names the model as a resource (`models/<id>`); the others send the bare id.
        let expected_model = if case.name == "gemini_generate_content" {
            format!("models/{}", case.config.model_id)
        } else {
            case.config.model_id.clone()
        };
        assert_eq!(
            case.adapter.model_id(&request).as_deref(),
            Some(expected_model.as_str()),
            "{}: model_id",
            case.name
        );
    }
}

#[test]
fn vendor_schemas_reject_malformed_requests() {
    // A validator that accepts everything would let the conformance test above pass for any
    // output, so show that each schema discriminates.
    for case in wire_cases() {
        let validator = vendor_validator(&case);
        for invalid in &case.invalid_requests {
            assert!(
                !validator.is_valid(invalid),
                "{}: schema should reject {invalid}",
                case.name
            );
        }
    }
}

#[test]
fn transport_keys_equal_the_vendor_schema_top_level_properties() {
    for case in wire_cases() {
        let schema = read_json(case.schema);
        let schema_keys = schema_top_level_properties(&schema);
        let adapter_keys: BTreeSet<String> = case
            .adapter
            .transport_keys()
            .iter()
            .map(|key| (*key).to_string())
            .collect();

        assert!(!schema_keys.is_empty(), "{}", case.name);
        assert_eq!(
            adapter_keys, schema_keys,
            "{}: transport_keys drifted from the vendor schema",
            case.name
        );
    }
}

#[test]
fn undeclared_top_level_keys_are_not_in_any_transport_key_list() {
    // `additionalProperties` is not false in the vendor schemas, so a schema-valid request can
    // still carry a key the vendor does not declare. Binding relies on this list to refuse it.
    for case in wire_cases() {
        let keys = case.adapter.transport_keys();
        for smuggled in ["x_airlock_smuggled", "ignore_previous", "extra"] {
            assert!(!keys.contains(&smuggled), "{}: {smuggled}", case.name);
        }
    }
}

#[test]
fn multimodal_fixtures_validate_against_the_vendor_schema() {
    for case in wire_cases() {
        let request = read_json(case.multimodal);
        let validator = vendor_validator(&case);

        assert!(
            validator.is_valid(&request),
            "{}: multimodal fixture violates the vendor schema: {:?}",
            case.name,
            schema_errors(&validator, &request)
        );
    }
}

#[test]
fn responses_schema_ambiguity_is_the_only_reason_array_content_fails_strict_validation() {
    let schema = read_json("schemas/openai_responses_request.schema.json");
    let item = json!({
        "role": "user",
        "content": [{"type": "input_text", "text": "hello"}]
    });
    let request = json!({"model": "gpt-5", "input": [item.clone()]});
    let components = schema["components"].clone();
    let branch_accepts = |name: &str| {
        let branch = json!({
            "$ref": format!("#/components/schemas/{name}"),
            "components": components,
        });
        validator_for(&branch)
            .expect("branch schema should compile")
            .is_valid(&item)
    };

    // Each documented branch accepts the message on its own, so strict `oneOf` fails only
    // because two branches match.
    assert!(branch_accepts("EasyInputMessage"));
    assert!(branch_accepts("InputMessage"));
    assert!(
        !validator_for(&schema).unwrap().is_valid(&request),
        "the strict schema now accepts array content: delete relax_responses_input_item"
    );

    let case = wire_cases()
        .into_iter()
        .find(|case| case.name == "openai_responses")
        .unwrap();
    let relaxed = vendor_validator(&case);
    assert!(relaxed.is_valid(&request));
    // The repair does not make the schema permissive.
    assert!(!relaxed.is_valid(&json!({
        "model": "gpt-5",
        "input": [{"role": "robot", "content": [{"type": "input_text", "text": "hello"}]}]
    })));
    assert!(!relaxed.is_valid(&json!({
        "model": "gpt-5",
        "input": [{"role": "user", "content": [{"type": "input_text"}]}]
    })));
}

fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

/// Every string in a JSON value, keyed by RFC 6901 pointer. Independent of the adapters: it is
/// the oracle for "nothing in the request escaped screening".
fn string_leaves(value: &Value, pointer: &str, out: &mut BTreeMap<String, String>) {
    match value {
        Value::String(text) => {
            out.insert(pointer.to_string(), text.clone());
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                string_leaves(item, &format!("{pointer}/{index}"), out);
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                string_leaves(
                    child,
                    &format!("{pointer}/{}", escape_pointer_segment(key)),
                    out,
                );
            }
        }
        _ => {}
    }
}

#[test]
fn multimodal_requests_have_every_string_reported_exactly_once() {
    for case in wire_cases() {
        let request = read_json(case.multimodal);
        let parts = case
            .adapter
            .extract_screenable_parts(&request)
            .unwrap_or_else(|error| panic!("{}: extraction should succeed: {error:?}", case.name));
        let mut leaves = BTreeMap::new();
        string_leaves(&request, "", &mut leaves);

        let reported: Vec<&str> = parts.iter().map(|part| part.pointer.as_str()).collect();
        let unique: BTreeSet<&str> = reported.iter().copied().collect();
        assert_eq!(
            reported.len(),
            unique.len(),
            "{}: a pointer was reported twice: {reported:?}",
            case.name
        );
        assert_eq!(
            unique,
            leaves.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            "{}: reported pointers differ from the strings in the request",
            case.name
        );

        for part in &parts {
            let leaf = &leaves[&part.pointer];
            match &part.kind {
                PartKind::Text => assert_eq!(&part.data, leaf, "{}: {}", case.name, part.pointer),
                // A payload is the whole string or the part of a data URI after its comma.
                PartKind::Base64Media { .. } | PartKind::RemoteReference => assert!(
                    leaf.ends_with(&part.data),
                    "{}: {} reports {:?} for {leaf:?}",
                    case.name,
                    part.pointer,
                    part.data
                ),
            }
        }
    }
}

#[test]
fn multimodal_requests_classify_base64_media_and_references() {
    for case in wire_cases() {
        let request = read_json(case.multimodal);
        let mut media: Vec<(String, String, String)> = case
            .adapter
            .extract_screenable_parts(&request)
            .unwrap()
            .into_iter()
            .filter_map(|part| match part.kind {
                PartKind::Text => None,
                PartKind::RemoteReference => Some((part.pointer, "remote".to_string(), part.data)),
                PartKind::Base64Media { media_type } => {
                    Some((part.pointer, format!("base64:{media_type}"), part.data))
                }
            })
            .collect();
        media.sort();
        let mut expected: Vec<(String, String, String)> = case
            .media
            .iter()
            .map(|(pointer, kind, data)| (pointer.to_string(), kind.to_string(), data.to_string()))
            .collect();
        expected.sort();

        assert_eq!(media, expected, "{}", case.name);
    }
}

#[test]
fn multimodal_requests_expose_tool_call_and_tool_result_text() {
    // The fixtures carry a tool call for "acct 4417" and its result "balance 12.40" in each
    // vendor's own shape; both must reach the screener as text.
    for case in wire_cases() {
        let request = read_json(case.multimodal);
        let texts: Vec<String> = case
            .adapter
            .extract_screenable_parts(&request)
            .unwrap()
            .into_iter()
            .filter(|part| part.kind == PartKind::Text)
            .map(|part| part.data)
            .collect();

        for needle in ["acct 4417", "balance 12.40"] {
            assert!(
                texts.iter().any(|text| text.contains(needle)),
                "{}: {needle} is not reported",
                case.name
            );
        }
    }
}
