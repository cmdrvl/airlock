//! The unit tests of airlock's former `src/hash/jcs.rs`, kept with their expected values
//! unchanged when the module was replaced by `cmdrvl_core::jcs` (al-9ir). They now pin core's
//! canonicalizer from airlock. Only the function names changed: `canonicalize` is `to_string`,
//! `canonicalize_exact_integers` is `to_string_exact_integers`, `serialize_f64` is `format_f64`.

use cmdrvl_core::jcs::{format_f64, to_string, to_string_exact_integers};
use serde_json::{Value, json};

fn canon(text: &str) -> String {
    let value: Value = serde_json::from_str(text).unwrap();
    to_string(&value).unwrap()
}

#[test]
fn numbers_follow_ecmascript_formatting() {
    // value, expected: boundaries of every branch in format_f64.
    for (value, expected) in [
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (-1.5, "-1.5"),
        (0.5, "0.5"),
        (100.0, "100"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1.5e21, "1.5e+21"),
        (123456789012345680000.0, "123456789012345680000"),
        (0.000001, "0.000001"),
        (0.0000001, "1e-7"),
        (1.5e-7, "1.5e-7"),
        (5e-324, "5e-324"),
        (f64::MAX, "1.7976931348623157e+308"),
        (f64::MIN, "-1.7976931348623157e+308"),
    ] {
        assert_eq!(format_f64(value).as_deref(), Some(expected), "{value:e}");
    }
    assert_eq!(format_f64(f64::NAN), None);
    assert_eq!(format_f64(f64::INFINITY), None);
    assert_eq!(format_f64(f64::NEG_INFINITY), None);
}

#[test]
fn integers_and_floats_with_the_same_value_serialize_alike() {
    assert_eq!(canon("[1, 1.0, 1e0, 10e-1]"), "[1,1,1,1]");
    assert_eq!(canon("[-0, -0.0, 0, 0.0]"), "[0,0,0,0]");
}

#[test]
fn integers_beyond_two_to_the_53_are_refused_with_their_path() {
    let ok = json!({"edge": 9_007_199_254_740_992_u64, "neg": -9_007_199_254_740_992_i64});
    assert_eq!(
        to_string(&ok).unwrap(),
        r#"{"edge":9007199254740992,"neg":-9007199254740992}"#
    );

    let too_big = json!({"a": [1, {"b/c~d": 9_007_199_254_740_993_u64}]});
    let error = to_string(&too_big).unwrap_err();
    assert_eq!(error.pointer, "/a/1/b~1c~0d");
    assert_eq!(error.number, "9007199254740993");
    assert!(
        error
            .to_string()
            .contains("write the value as a JSON string")
    );

    let max = json!(u64::MAX);
    assert_eq!(to_string(&max).unwrap_err().pointer, "");
    let min = json!(i64::MIN);
    assert_eq!(to_string(&min).unwrap_err().number, "-9223372036854775808");
}

#[test]
fn exact_integer_mode_keeps_distinct_integers_distinct() {
    let a = json!([9_007_199_254_740_993_u64]);
    let b = json!([9_007_199_254_740_992_u64]);
    assert_eq!(to_string_exact_integers(&a), "[9007199254740993]");
    assert_ne!(to_string_exact_integers(&a), to_string_exact_integers(&b));
    assert_eq!(
        to_string_exact_integers(&json!([u64::MAX, i64::MIN])),
        "[18446744073709551615,-9223372036854775808]"
    );
    // Identical to the strict form wherever the strict form succeeds.
    let ordinary = json!({"b": [1, 2.5, "x"], "a": null});
    assert_eq!(
        to_string_exact_integers(&ordinary),
        to_string(&ordinary).unwrap()
    );
}

#[test]
fn keys_sort_by_utf16_code_units_not_utf8_bytes() {
    // U+1F600 is the surrogate pair D83D DE00; U+FB33 is the single unit FB33. UTF-16 order
    // puts the emoji first, UTF-8 / code point order puts it last.
    let value = json!({"\u{fb33}": 1, "\u{1f600}": 2, "\u{20ac}": 3, "a": 4, "\u{80}": 5});
    assert_eq!(
        to_string(&value).unwrap(),
        "{\"a\":4,\"\u{80}\":5,\"\u{20ac}\":3,\"\u{1f600}\":2,\"\u{fb33}\":1}"
    );
}

#[test]
fn strings_escape_exactly_the_rfc_set() {
    let mut all_controls = String::new();
    for code in 0u32..0x20 {
        all_controls.push(char::from_u32(code).unwrap());
    }
    let value = json!({"s": format!("{all_controls}\"\\/\u{7f}\u{80}é€😀")});
    assert_eq!(
        to_string(&value).unwrap(),
        "{\"s\":\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\
         \\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\
         \\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\\\"\\\\/\u{7f}\u{80}é€😀\"}"
    );
}

#[test]
fn empty_containers_and_literals() {
    assert_eq!(
        canon(r#"{"b":[],"a":{},"c":[null,true,false]}"#),
        r#"{"a":{},"b":[],"c":[null,true,false]}"#
    );
    assert_eq!(canon("[]"), "[]");
    assert_eq!(canon("{}"), "{}");
    assert_eq!(canon("\"\""), "\"\"");
}
