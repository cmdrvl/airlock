use std::io::Write;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cli::REFUSAL;
use crate::output::canonical_json;

pub const AIRLOCK_VERSION: &str = "airlock.v0";
pub const REFUSAL_OUTCOME: &str = "REFUSAL";

/// Structured refusal codes emitted by airlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RefusalCode {
    #[serde(rename = "E_BAD_POLICY")]
    EBadPolicy,
    #[serde(rename = "E_BAD_INPUT")]
    EBadInput,
    #[serde(rename = "E_BAD_PROMPT")]
    EBadPrompt,
    #[serde(rename = "E_BAD_REQUEST")]
    EBadRequest,
    #[serde(rename = "E_BAD_PROVENANCE")]
    EBadProvenance,
    #[serde(rename = "E_BAD_MANIFEST")]
    EBadManifest,
    #[serde(rename = "E_MISSING_FILE")]
    EMissingFile,
    #[serde(rename = "E_WITNESS_ERROR")]
    EWitnessError,
    #[serde(rename = "E_INTERNAL")]
    EInternal,
}

impl RefusalCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EBadPolicy => "E_BAD_POLICY",
            Self::EBadInput => "E_BAD_INPUT",
            Self::EBadPrompt => "E_BAD_PROMPT",
            Self::EBadRequest => "E_BAD_REQUEST",
            Self::EBadProvenance => "E_BAD_PROVENANCE",
            Self::EBadManifest => "E_BAD_MANIFEST",
            Self::EMissingFile => "E_MISSING_FILE",
            Self::EWitnessError => "E_WITNESS_ERROR",
            Self::EInternal => "E_INTERNAL",
        }
    }
}

/// Inner refusal payload for structured error emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub code: RefusalCode,
    pub message: String,
    pub detail: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_command: Option<String>,
}

/// Canonical refusal envelope emitted on stdout for exit code 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalEnvelope {
    pub version: String,
    pub outcome: String,
    pub refusal: Refusal,
}

impl RefusalEnvelope {
    pub fn new(
        code: RefusalCode,
        message: impl Into<String>,
        detail: Value,
        next_command: Option<impl Into<String>>,
    ) -> Self {
        Self {
            version: AIRLOCK_VERSION.to_string(),
            outcome: REFUSAL_OUTCOME.to_string(),
            refusal: Refusal {
                code,
                message: message.into(),
                detail,
                next_command: next_command.map(Into::into),
            },
        }
    }

    pub fn to_canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("refusal envelope should serialize");
        canonical_json(&value)
    }

    pub fn write_to(&self, w: &mut impl Write) -> u8 {
        let json = self.to_canonical_json();
        let _ = w.write_all(json.as_bytes());
        let _ = w.flush();
        Self::exit_code()
    }

    pub const fn exit_code() -> u8 {
        REFUSAL
    }

    pub fn bad_policy(message: impl Into<String>, detail: Value) -> Self {
        Self::new(
            RefusalCode::EBadPolicy,
            message,
            detail,
            Some("airlock --schema"),
        )
    }

    pub fn bad_input(message: impl Into<String>, detail: Value) -> Self {
        Self::new(
            RefusalCode::EBadInput,
            message,
            detail,
            Some("airlock --help"),
        )
    }

    pub fn bad_prompt(message: impl Into<String>, detail: Value) -> Self {
        Self::new(
            RefusalCode::EBadPrompt,
            message,
            detail,
            Some("airlock assemble --help"),
        )
    }

    pub fn bad_request(message: impl Into<String>, detail: Value) -> Self {
        Self::new(
            RefusalCode::EBadRequest,
            message,
            detail,
            Some("airlock verify --help"),
        )
    }

    pub fn bad_provenance(message: impl Into<String>, detail: Value) -> Self {
        Self::new(
            RefusalCode::EBadProvenance,
            message,
            detail,
            Some("airlock assemble --help"),
        )
    }

    pub fn bad_manifest(message: impl Into<String>, detail: Value) -> Self {
        Self::new(
            RefusalCode::EBadManifest,
            message,
            detail,
            Some("airlock explain --help"),
        )
    }

    pub fn missing_file(path: impl Into<String>) -> Self {
        let path = path.into();
        Self::new(
            RefusalCode::EMissingFile,
            format!("required file does not exist: {path}"),
            json!({ "path": path }),
            None::<String>,
        )
    }

    pub fn witness_error(message: impl Into<String>, detail: Value) -> Self {
        Self::new(
            RefusalCode::EWitnessError,
            message,
            detail,
            Some("airlock witness query --help"),
        )
    }

    pub fn internal(message: impl Into<String>, detail: Value) -> Self {
        Self::new(RefusalCode::EInternal, message, detail, None::<String>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn refusal_code_round_trips_through_serde() {
        let codes = [
            (RefusalCode::EBadPolicy, "\"E_BAD_POLICY\""),
            (RefusalCode::EBadInput, "\"E_BAD_INPUT\""),
            (RefusalCode::EBadPrompt, "\"E_BAD_PROMPT\""),
            (RefusalCode::EBadRequest, "\"E_BAD_REQUEST\""),
            (RefusalCode::EBadProvenance, "\"E_BAD_PROVENANCE\""),
            (RefusalCode::EBadManifest, "\"E_BAD_MANIFEST\""),
            (RefusalCode::EMissingFile, "\"E_MISSING_FILE\""),
            (RefusalCode::EWitnessError, "\"E_WITNESS_ERROR\""),
            (RefusalCode::EInternal, "\"E_INTERNAL\""),
        ];

        for (code, expected_json) in codes {
            let json = serde_json::to_string(&code).unwrap();
            let back: RefusalCode = serde_json::from_str(&json).unwrap();
            assert_eq!(json, expected_json);
            assert_eq!(back, code);
            assert_eq!(code.as_str(), expected_json.trim_matches('"'));
        }
    }

    #[test]
    fn refusal_envelope_serializes_to_canonical_json() {
        let refusal = RefusalEnvelope::bad_policy(
            "policy file failed schema validation",
            json!({
                "error": "missing field",
                "path": "policy.yaml",
            }),
        );

        assert_eq!(
            refusal.to_canonical_json(),
            r#"{"outcome":"REFUSAL","refusal":{"code":"E_BAD_POLICY","detail":{"error":"missing field","path":"policy.yaml"},"message":"policy file failed schema validation","next_command":"airlock --schema"},"version":"airlock.v0"}"#
        );
    }

    #[test]
    fn write_to_emits_json_and_returns_refusal_exit_code() {
        let refusal = RefusalEnvelope::bad_input("bad input", json!({"path": "input.json"}));
        let mut buf = Vec::new();

        let exit_code = refusal.write_to(&mut buf);

        assert_eq!(exit_code, REFUSAL);
        assert_eq!(String::from_utf8(buf).unwrap(), refusal.to_canonical_json());
    }

    #[test]
    fn next_command_is_omitted_when_none() {
        let refusal = RefusalEnvelope::internal("unexpected state", json!(null));
        let json = refusal.to_canonical_json();

        assert!(!json.contains("next_command"));
    }

    #[test]
    fn detail_accepts_arbitrary_json_shapes() {
        let values = [
            json!("string detail"),
            json!({"path": "file.json", "error": "missing"}),
            json!(["a", "b", "c"]),
            json!(null),
        ];

        for detail in values {
            let refusal = RefusalEnvelope::new(
                RefusalCode::EBadInput,
                "bad input",
                detail.clone(),
                None::<String>,
            );
            let roundtrip: RefusalEnvelope =
                serde_json::from_str(&refusal.to_canonical_json()).unwrap();
            assert_eq!(roundtrip.refusal.detail, detail);
        }
    }

    #[test]
    fn convenience_constructors_set_expected_defaults() {
        let missing = RefusalEnvelope::missing_file("missing.json");
        assert_eq!(missing.refusal.code, RefusalCode::EMissingFile);
        assert_eq!(missing.refusal.next_command, None);
        assert_eq!(missing.refusal.detail, json!({"path": "missing.json"}));

        let witness = RefusalEnvelope::witness_error("ledger failed", json!({"path": "w.jsonl"}));
        assert_eq!(witness.refusal.code, RefusalCode::EWitnessError);
        assert_eq!(
            witness.refusal.next_command.as_deref(),
            Some("airlock witness query --help")
        );

        let manifest = RefusalEnvelope::bad_manifest("bad manifest", json!({"path": "m.json"}));
        assert_eq!(manifest.refusal.code, RefusalCode::EBadManifest);
        assert_eq!(
            manifest.refusal.next_command.as_deref(),
            Some("airlock explain --help")
        );
    }
}
