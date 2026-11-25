use std::io::{self, Write};

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Map, Value};

const OPERATOR_JSON: &str = include_str!("../operator.json");
const OUTPUT_SCHEMA: &str = include_str!("../schemas/airlock.v0.schema.json");

/// Environment variable that pins the instant stamped into reproducible output
/// (reproducible-builds.org convention: Unix seconds).
pub const SOURCE_DATE_EPOCH_ENV: &str = "SOURCE_DATE_EPOCH";

/// A `SOURCE_DATE_EPOCH` value that is not valid Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSourceDateEpoch {
    /// The offending value (lossy for non-UTF-8).
    pub value: String,
    /// Why it was rejected.
    pub reason: String,
}

/// The current UTC instant, or the fixed instant named by `SOURCE_DATE_EPOCH`.
///
/// A set-but-invalid value is an error, never a silent fallback to the wall
/// clock: falling back would quietly break the reproducibility the caller asked for.
pub fn now_utc() -> Result<DateTime<Utc>, InvalidSourceDateEpoch> {
    match std::env::var_os(SOURCE_DATE_EPOCH_ENV) {
        None => Ok(Utc::now()),
        Some(raw) => match raw.to_str() {
            Some(value) => fixed_instant(value),
            None => Err(InvalidSourceDateEpoch {
                value: raw.to_string_lossy().into_owned(),
                reason: "value is not valid UTF-8".to_owned(),
            }),
        },
    }
}

/// Parse a `SOURCE_DATE_EPOCH` value: whole Unix seconds, no surrounding whitespace.
pub fn fixed_instant(value: &str) -> Result<DateTime<Utc>, InvalidSourceDateEpoch> {
    let seconds = value
        .parse::<i64>()
        .map_err(|error| InvalidSourceDateEpoch {
            value: value.to_owned(),
            reason: format!("expected Unix seconds: {error}"),
        })?;
    Utc.timestamp_opt(seconds, 0)
        .single()
        .ok_or_else(|| InvalidSourceDateEpoch {
            value: value.to_owned(),
            reason: "Unix seconds out of range".to_owned(),
        })
}

/// Recursively sort all object keys in a JSON value.
///
/// This gives a deterministic key order at every nesting level (by UTF-8 bytes) for structural
/// comparison of values. Arrays preserve element order; only object keys are sorted. It is not
/// the canonical serialization: [`canonical_json`] sorts by UTF-16 code units as RFC 8785
/// requires and does not depend on this function.
pub fn sort_value(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: Map<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_value(v)))
                .collect::<Vec<_>>()
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_value).collect()),
        other => other,
    }
}

/// Serialize a JSON value as RFC 8785 (JCS) canonical JSON.
///
/// Total: it never fails, so it is safe on any value. Integers outside ±2^53, which RFC 8785
/// cannot represent, are written as exact decimal digits here; code that claims a hash is
/// recomputable by a third party must call [`crate::hash::jcs::canonicalize`] (or
/// [`crate::hash::jcs_blake3_hash`]) instead, which refuses them.
pub fn canonical_json(v: &Value) -> String {
    crate::hash::jcs::canonicalize_exact_integers(v)
}

/// Serialize a JSON value to RFC 8785 canonical JSON bytes (for hashing).
pub fn canonical_json_bytes(v: &Value) -> Vec<u8> {
    canonical_json(v).into_bytes()
}

/// Embedded `operator.v1` manifest. `--describe`, `capabilities --json` and the
/// `contract` inside `doctor capabilities --json` all render exactly this document.
pub fn operator_json() -> &'static str {
    OPERATOR_JSON
}

pub fn emit_describe(w: &mut impl Write) -> io::Result<()> {
    w.write_all(OPERATOR_JSON.as_bytes())
}

/// `capabilities --json`: the same document as `--describe`.
pub fn emit_capabilities(w: &mut impl Write) -> io::Result<()> {
    emit_describe(w)
}

pub fn emit_schema(w: &mut impl Write) -> io::Result<()> {
    w.write_all(OUTPUT_SCHEMA.as_bytes())
}

pub fn emit_version(w: &mut impl Write) -> io::Result<()> {
    writeln!(w, "airlock {}", env!("CARGO_PKG_VERSION"))
}

pub fn format_jsonl_line(v: &Value) -> String {
    let mut line = canonical_json(v);
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::validator_for;
    use serde_json::json;

    #[test]
    fn sort_value_sorts_top_level_keys() {
        let v = json!({"z": 1, "a": 2, "m": 3});
        let sorted = sort_value(v);
        let keys: Vec<&String> = sorted.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
    }

    #[test]
    fn sort_value_sorts_nested_keys() {
        let v = json!({"outer": {"z": 1, "a": 2}});
        let sorted = sort_value(v);
        let inner = sorted["outer"].as_object().unwrap();
        let keys: Vec<&String> = inner.keys().collect();
        assert_eq!(keys, vec!["a", "z"]);
    }

    #[test]
    fn sort_value_preserves_array_order() {
        let v = json!({"items": [3, 1, 2]});
        let sorted = sort_value(v);
        let arr: Vec<i64> = sorted["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_i64().unwrap())
            .collect();
        assert_eq!(arr, vec![3, 1, 2]);
    }

    #[test]
    fn sort_value_sorts_objects_inside_arrays() {
        let v = json!([{"z": 1, "a": 2}]);
        let sorted = sort_value(v);
        let inner = sorted[0].as_object().unwrap();
        let keys: Vec<&String> = inner.keys().collect();
        assert_eq!(keys, vec!["a", "z"]);
    }

    #[test]
    fn canonical_json_deterministic() {
        let v1 = json!({"z": 1, "a": 2, "m": {"x": 10, "b": 20}});
        let v2 = json!({"m": {"b": 20, "x": 10}, "a": 2, "z": 1});
        assert_eq!(canonical_json(&v1), canonical_json(&v2));
    }

    #[test]
    fn canonical_json_bytes_matches_string() {
        let v = json!({"key": "value"});
        assert_eq!(canonical_json_bytes(&v), canonical_json(&v).as_bytes());
    }

    #[test]
    fn sort_value_handles_deeply_nested() {
        let v = json!({
            "c": {
                "z": {
                    "q": 1,
                    "a": 2
                },
                "a": 3
            },
            "a": 4
        });
        let result = canonical_json(&v);
        // All keys sorted at every level
        assert_eq!(result, r#"{"a":4,"c":{"a":3,"z":{"a":2,"q":1}}}"#);
    }

    #[test]
    fn sort_value_handles_primitives() {
        assert_eq!(sort_value(json!(42)), json!(42));
        assert_eq!(sort_value(json!("hello")), json!("hello"));
        assert_eq!(sort_value(json!(true)), json!(true));
        assert_eq!(sort_value(json!(null)), json!(null));
    }

    #[test]
    fn emit_describe_writes_embedded_operator_json() {
        let mut buf = Vec::new();
        emit_describe(&mut buf).unwrap();
        let value: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(value["schema_version"], "operator.v1");
        assert_eq!(value["name"], "airlock");
        assert_eq!(value["tool_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            value["invocation"]["output_schema"],
            "airlock.v0.schema.json"
        );
    }

    #[test]
    fn fixed_instant_parses_unix_seconds() {
        let instant = fixed_instant("1700000000").unwrap();
        assert_eq!(instant.to_rfc3339(), "2023-11-14T22:13:20+00:00");
        assert_eq!(fixed_instant("0").unwrap().timestamp(), 0);
    }

    #[test]
    fn fixed_instant_rejects_malformed_and_out_of_range_values() {
        for bad in ["", " 1700000000", "1700000000 ", "1.5", "yesterday", "0x10"] {
            let error = fixed_instant(bad).unwrap_err();
            assert_eq!(error.value, bad);
            assert!(error.reason.starts_with("expected Unix seconds"), "{bad:?}");
        }
        let error = fixed_instant("9223372036854775807").unwrap_err();
        assert_eq!(error.reason, "Unix seconds out of range");
    }

    #[test]
    fn emit_capabilities_is_byte_identical_to_describe() {
        let mut describe = Vec::new();
        let mut capabilities = Vec::new();
        emit_describe(&mut describe).unwrap();
        emit_capabilities(&mut capabilities).unwrap();
        assert_eq!(describe, capabilities);
    }

    #[test]
    fn emit_schema_writes_valid_json_schema() {
        let mut buf = Vec::new();
        emit_schema(&mut buf).unwrap();
        let schema: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        validator_for(&schema).unwrap();
    }

    #[test]
    fn emit_version_writes_airlock_semver() {
        let mut buf = Vec::new();
        emit_version(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!("airlock {}\n", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn format_jsonl_line_returns_single_canonical_line() {
        let line = format_jsonl_line(&json!({"z": 1, "a": 2}));
        assert_eq!(line, "{\"a\":2,\"z\":1}\n");
        assert_eq!(line.matches('\n').count(), 1);
    }
}
