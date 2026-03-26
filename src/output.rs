use serde_json::{Map, Value};

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
