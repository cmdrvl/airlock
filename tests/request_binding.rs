use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use airlock::adapter::{Adapter, OpenAiChatCompletionsAdapter, TransportConfig};
use assert_cmd::Command;
use jsonschema::validator_for;
use serde_json::{Value, json};
use tempfile::tempdir;

fn repo_file(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&fs::read(repo_file(path)).expect("fixture should be readable"))
        .expect("fixture JSON should parse")
}

fn clean_request() -> Value {
    let prompt = read_json("fixtures/clean_telemetry_only/expected_prompt_payload.json");
    OpenAiChatCompletionsAdapter
        .wrap(&prompt, &TransportConfig::new("gpt-5"))
        .expect("assembled prompt should wrap as a Chat Completions request")
}

fn verify_request(request: &Value) -> Value {
    let dir = tempdir().expect("temporary directory should be created");
    verify_request_with_policy(
        request,
        &repo_file("fixtures/clean_telemetry_only/policy.yaml"),
        dir.path(),
    )
}

fn verify_request_with_policy(request: &Value, policy_path: &Path, output_dir: &Path) -> Value {
    let request_path = output_dir.join("request.json");
    let prompt_path = output_dir.join("prompt.json");
    let provenance_path = output_dir.join("provenance.json");
    let manifest_path = output_dir.join("manifest.json");
    fs::write(
        &request_path,
        serde_json::to_vec(request).expect("request should serialize"),
    )
    .expect("request should be written");

    Command::cargo_bin("airlock")
        .expect("airlock binary should build")
        .current_dir(repo_file("."))
        .args(["assemble", "--policy"])
        .arg(policy_path)
        .arg("--input")
        .arg(repo_file(
            "fixtures/clean_telemetry_only/strategy_space.json",
        ))
        .arg("--system-prompt")
        .arg(repo_file("fixtures/clean_telemetry_only/system_prompt.txt"))
        .args(["--boundary-mode", "TELEMETRY_ONLY", "--out"])
        .arg(&prompt_path)
        .arg("--provenance-out")
        .arg(&provenance_path)
        .arg("--no-witness")
        .assert()
        .success();

    let output = Command::cargo_bin("airlock")
        .expect("airlock binary should build")
        .current_dir(repo_file("."))
        .arg("verify")
        .arg("--no-sign")
        .arg("--policy")
        .arg(policy_path)
        .arg("--prompt")
        .arg(&prompt_path)
        .arg("--provenance")
        .arg(&provenance_path)
        .arg("--request")
        .arg(&request_path)
        .arg("--out")
        .arg(&manifest_path)
        .arg("--no-witness")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let manifest: Value = serde_json::from_slice(&output).expect("verify should emit JSON");
    let schema = read_json("schemas/airlock.v0.schema.json");
    validator_for(&schema)
        .expect("manifest schema should compile")
        .validate(&manifest)
        .expect("verify output should satisfy the manifest schema");
    assert_eq!(
        fs::read(&manifest_path).expect("manifest should be written"),
        output
    );
    manifest
}

fn assert_unbound(request: &Value) {
    let manifest = verify_request(request);
    assert_eq!(manifest["binding_status"], "UNBOUND");
    assert_eq!(manifest["achieved_claim"], "BOUNDARY_FAILED");
    assert!(
        manifest["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| { finding["artifact_class"] == "REQUEST_UNBOUND" })
    );
}

fn collect_schema_properties(schema: &Value, node: &Value, keys: &mut BTreeSet<String>) {
    if let Some(properties) = node.get("properties").and_then(Value::as_object) {
        keys.extend(properties.keys().cloned());
    }
    if let Some(all_of) = node.get("allOf").and_then(Value::as_array) {
        for child in all_of {
            collect_schema_properties(schema, child, keys);
            if let Some(reference) = child.get("$ref").and_then(Value::as_str) {
                let pointer = reference.strip_prefix("#").expect("schema ref is local");
                let referenced = schema.pointer(pointer).expect("schema ref should resolve");
                collect_schema_properties(schema, referenced, keys);
            }
        }
    }
}

#[test]
fn adapter_transport_allowlist_matches_openapi_schema() {
    let schema = read_json("schemas/openai_chat_completions_request.schema.json");
    let request_schema = schema
        .pointer("/components/schemas/CreateChatCompletionRequest")
        .expect("official schema should define Chat Completions create request");
    let mut schema_keys = BTreeSet::new();
    collect_schema_properties(&schema, request_schema, &mut schema_keys);
    let adapter_keys = OpenAiChatCompletionsAdapter
        .transport_keys()
        .iter()
        .map(|key| (*key).to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(adapter_keys, schema_keys);
}

#[test]
fn unchanged_wrapped_request_is_bound_and_schema_valid() {
    let mut request = clean_request();
    request["logprobs"] = json!(true);
    let manifest = verify_request(&request);

    assert_eq!(manifest["binding_status"], "BOUND");
    assert_eq!(manifest["manifest_version"], "airlock.v0.3");
    assert_eq!(manifest["achieved_claim"], "STRICT_TELEMETRY_ONLY");
    assert!(manifest["findings"].as_array().unwrap().is_empty());
}

#[test]
fn appended_pii_fixture_is_unbound_without_echoing_the_pii() {
    let request = read_json("fixtures/request_unbound_pii/request.json");
    let temp = tempdir().expect("temporary directory should be created");
    let policy_path = temp.path().join("detector-policy.yaml");
    let base_policy = fs::read_to_string(repo_file("fixtures/clean_telemetry_only/policy.yaml"))
        .expect("baseline policy should be readable");
    fs::write(
        &policy_path,
        format!("{base_policy}\ndetectors:\n  - pii\n"),
    )
    .expect("detector policy should be written");
    let manifest = verify_request_with_policy(&request, &policy_path, temp.path());
    let rendered = serde_json::to_string(&manifest).unwrap();

    assert_eq!(manifest["binding_status"], "UNBOUND");
    assert_eq!(manifest["achieved_claim"], "BOUNDARY_FAILED");
    assert!(
        manifest["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["artifact_class"] == "REQUEST_UNBOUND"
                    && finding["key_path"] == "messages[2]"
            })
    );
    let detector_finding = manifest["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["artifact_class"] == "DETECTED_SENSITIVE")
        .expect("enabled PII detector should flag the appended value");
    assert_eq!(detector_finding["matched_rule"], "PII_US_SSN");
    assert!(
        detector_finding["span_hash"]
            .as_str()
            .unwrap()
            .starts_with("blake3:")
    );
    assert!(!rendered.contains("123-45-6789"));
    assert!(!rendered.contains("alice"));

    let explanation = Command::cargo_bin("airlock")
        .unwrap()
        .args(["explain", "--manifest"])
        .arg(temp.path().join("manifest.json"))
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let explanation: Value = serde_json::from_slice(&explanation).unwrap();
    assert!(
        explanation["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["artifact_class"] == "DETECTED_SENSITIVE")
    );
    let rendered_explanation = serde_json::to_string(&explanation).unwrap();
    assert!(!rendered_explanation.contains("123-45-6789"));
    assert!(!rendered_explanation.contains("alice"));
}

#[test]
fn clean_telemetry_fixture_has_no_hits_when_all_detector_packs_are_enabled() {
    let temp = tempdir().expect("temporary directory should be created");
    let policy_path = temp.path().join("detector-policy.yaml");
    let base_policy = fs::read_to_string(repo_file("fixtures/clean_telemetry_only/policy.yaml"))
        .expect("baseline policy should be readable");
    fs::write(
        &policy_path,
        format!(
            "{base_policy}\ndetectors:\n  - secrets\n  - pii\n  - tabular\n  - blobs\n  - paths\n"
        ),
    )
    .expect("detector policy should be written");
    let manifest = verify_request_with_policy(&clean_request(), &policy_path, temp.path());
    assert_eq!(manifest["achieved_claim"], "STRICT_TELEMETRY_ONLY");
    assert!(manifest["findings"].as_array().unwrap().is_empty());
}

#[test]
fn removed_reordered_altered_messages_and_unknown_transport_keys_are_unbound() {
    let clean = clean_request();

    let mut removed = clean.clone();
    removed["messages"].as_array_mut().unwrap().pop();
    assert_unbound(&removed);

    let mut reordered = clean.clone();
    reordered["messages"].as_array_mut().unwrap().reverse();
    assert_unbound(&reordered);

    let mut altered = clean.clone();
    altered["messages"][1]["content"][0]["text"] = json!("{\"tampered\":true}");
    assert_unbound(&altered);

    let mut altered_system_prompt = clean.clone();
    altered_system_prompt["messages"][0]["content"] = json!("a different system prompt");
    assert_unbound(&altered_system_prompt);

    let mut extra_transport_key = clean;
    extra_transport_key["hidden_enrichment"] = json!({"content": "not in the adapter schema"});
    assert_unbound(&extra_transport_key);
}
