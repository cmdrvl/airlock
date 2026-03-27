use std::io::{self, Write};

use serde_json::{Map, Value};

const OPERATOR_JSON: &str = include_str!("../operator.json");
const OUTPUT_SCHEMA: &str = include_str!("../schemas/airlock.v0.schema.json");

/// Recursively sort all object keys in a JSON value.
///
/// This produces canonical JSON: deterministic key ordering at every nesting level.
/// Arrays preserve element order; only object keys are sorted.
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

/// Serialize a JSON value to canonical JSON (sorted keys, compact).
pub fn canonical_json(v: &Value) -> String {
    let sorted = sort_value(v.clone());
    serde_json::to_string(&sorted).expect("canonical JSON serialization should not fail")
}

/// Serialize a JSON value to canonical JSON bytes (for hashing).
pub fn canonical_json_bytes(v: &Value) -> Vec<u8> {
    canonical_json(v).into_bytes()
}

pub fn emit_describe(w: &mut impl Write) -> io::Result<()> {
    w.write_all(OPERATOR_JSON.as_bytes())
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
        assert_eq!(value["name"], "airlock");
        assert_eq!(value["output_schema"], "airlock.v0.schema.json");
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
