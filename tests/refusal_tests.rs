use airlock::cli::REFUSAL;
use airlock::refusal::{RefusalCode, RefusalEnvelope, AIRLOCK_VERSION, REFUSAL_OUTCOME};
use serde_json::json;

fn sample_envelopes() -> Vec<(RefusalCode, RefusalEnvelope, Option<&'static str>)> {
    vec![
        (
            RefusalCode::EBadPolicy,
            RefusalEnvelope::bad_policy("bad policy", json!({"path": "policy.yaml"})),
            Some("airlock --schema"),
        ),
        (
            RefusalCode::EBadInput,
            RefusalEnvelope::bad_input("bad input", json!({"path": "input.json"})),
            Some("airlock --help"),
        ),
        (
            RefusalCode::EBadPrompt,
            RefusalEnvelope::bad_prompt("bad prompt", json!({"field": "messages"})),
            Some("airlock assemble --help"),
        ),
        (
            RefusalCode::EBadRequest,
            RefusalEnvelope::bad_request("bad request", json!({"field": "model"})),
            Some("airlock verify --help"),
        ),
        (
            RefusalCode::EBadProvenance,
            RefusalEnvelope::bad_provenance("bad provenance", json!({"field": "policy_hash"})),
            Some("airlock assemble --help"),
        ),
        (
            RefusalCode::EBadManifest,
            RefusalEnvelope::bad_manifest("bad manifest", json!({"path": "manifest.json"})),
            Some("airlock explain --help"),
        ),
        (
            RefusalCode::EMissingFile,
            RefusalEnvelope::missing_file("missing.json"),
            None,
        ),
        (
            RefusalCode::EWitnessError,
            RefusalEnvelope::witness_error("witness failed", json!({"path": "witness.jsonl"})),
            Some("airlock witness query --help"),
        ),
        (
            RefusalCode::EInternal,
            RefusalEnvelope::internal("unexpected state", json!({"phase": "test"})),
            None,
        ),
    ]
}

#[test]
fn test_each_refusal_code_produces_correct_json_shape() {
    for (code, envelope, expected_next_command) in sample_envelopes() {
        let value: serde_json::Value = serde_json::from_str(&envelope.to_canonical_json()).unwrap();

        assert_eq!(value["version"], AIRLOCK_VERSION);
        assert_eq!(value["outcome"], REFUSAL_OUTCOME);
        assert_eq!(value["refusal"]["code"], code.as_str());
        assert!(!value["refusal"]["message"].as_str().unwrap().is_empty());
        assert!(value["refusal"].get("detail").is_some());

        match expected_next_command {
            Some(command) => assert_eq!(value["refusal"]["next_command"], command),
            None => assert!(value["refusal"].get("next_command").is_none()),
        }
    }
}

#[test]
fn test_refusal_envelope_always_contains_required_fields() {
    for (_, envelope, _) in sample_envelopes() {
        let value: serde_json::Value = serde_json::from_str(&envelope.to_canonical_json()).unwrap();
        let object = value.as_object().unwrap();
        let refusal = value["refusal"].as_object().unwrap();

        assert!(object.contains_key("version"));
        assert!(object.contains_key("outcome"));
        assert!(object.contains_key("refusal"));
        assert!(refusal.contains_key("code"));
        assert!(refusal.contains_key("message"));
        assert!(refusal.contains_key("detail"));
    }
}

#[test]
fn test_next_command_is_present_when_applicable() {
    for (code, envelope, expected_next_command) in sample_envelopes() {
        let value: serde_json::Value = serde_json::from_str(&envelope.to_canonical_json()).unwrap();
        let next_command = value["refusal"]
            .get("next_command")
            .and_then(|value| value.as_str());

        match code {
            RefusalCode::EMissingFile | RefusalCode::EInternal => {
                assert_eq!(next_command, None);
            }
            _ => assert_eq!(next_command, expected_next_command),
        }
    }
}

#[test]
fn test_refusal_write_to_uses_refusal_exit_code() {
    let envelope = RefusalEnvelope::bad_input("bad input", json!({"path": "input.json"}));
    let mut stdout = Vec::new();

    let exit_code = envelope.write_to(&mut stdout);

    assert_eq!(exit_code, REFUSAL);
    assert_eq!(
        String::from_utf8(stdout).unwrap(),
        envelope.to_canonical_json()
    );
}
