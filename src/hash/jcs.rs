//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Every airlock hash that a third party must recompute (`prompt_payload_hash`,
//! `request_payload_hash`, the provenance, policy and manifest hashes) is
//! `blake3(JCS(value))`, so an auditor can reproduce it with any conforming JCS library.
//!
//! The rules, all from RFC 8785 section 3.2:
//!
//! * no insignificant whitespace;
//! * object members sorted recursively by their names as arrays of UTF-16 code units, which
//!   differs from sorting by UTF-8 bytes or code points once a name contains a character
//!   above U+FFFF next to one in U+E000..=U+FFFF;
//! * strings escape only `"`, `\`, and U+0000..=U+001F (`\b \t \n \f \r` for the five that
//!   have short forms, lowercase `\u00xx` for the rest); every other character, including
//!   U+007F, is written as is;
//! * numbers use the ECMAScript `Number::toString` form of their IEEE 754 double value
//!   (shortest round-trip digits, no exponent between 1e-6 and 1e21, `-0` written `0`);
//! * the output is UTF-8.
//!
//! # Integers outside ±2^53
//!
//! RFC 8785 serializes every number as a double, so two integers beyond 2^53 can collapse to
//! one canonical form, and an implementation that reads JSON numbers as doubles cannot
//! reproduce an exact 64-bit integer. RFC 8785 Appendix D says such numbers must be wrapped in
//! JSON strings. [`canonicalize`] therefore refuses them with a [`JcsError`] naming the
//! offending JSON Pointer, rather than emitting bytes a standard library would not reproduce.
//! [`canonicalize_exact_integers`] is the total variant for internal data that is not claimed
//! to be recomputable by a third party: it writes such integers as exact decimal digits, which
//! keeps distinct values distinct but is not RFC 8785.
//!
//! # What this module does not cover
//!
//! Parsing is serde_json's job. Lone surrogates (`"\ud800"`) are rejected by its parser, as
//! RFC 8785 requires, and `Cargo.toml` enables serde_json's `float_roundtrip` feature because
//! its default float parser is off by one ULP for roughly a third of full-precision doubles,
//! which would make a hash differ from every correct JCS implementation.

use std::fmt;

use serde_json::{Map, Number, Value};

/// The largest integer magnitude (2^53) that every double-based implementation reads back
/// exactly. Integers beyond it are refused by [`canonicalize`].
pub const MAX_INTERCHANGE_INTEGER: u64 = 1 << 53;

/// A value that RFC 8785 cannot canonicalize interoperably.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JcsError {
    /// RFC 6901 JSON Pointer to the offending number (`""` for the document root).
    pub pointer: String,
    /// The number as it appears in the value.
    pub number: String,
}

impl JcsError {
    /// The error as the `detail` object of a refusal envelope.
    pub fn detail(&self) -> Value {
        serde_json::json!({
            "pointer": self.pointer,
            "number": self.number,
            "max_integer_magnitude": MAX_INTERCHANGE_INTEGER,
            "rule": "RFC 8785 Appendix D: a number that is not exactly an IEEE 754 double \
                     must be written as a JSON string",
        })
    }
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "number {} at {} cannot be canonicalized interoperably: RFC 8785 serializes numbers \
             as IEEE 754 doubles, which hold integers exactly only up to {} in magnitude; \
             write the value as a JSON string instead",
            self.number,
            if self.pointer.is_empty() {
                "the document root"
            } else {
                &self.pointer
            },
            MAX_INTERCHANGE_INTEGER
        )
    }
}

impl std::error::Error for JcsError {}

/// Canonicalize `value` as RFC 8785 JSON, refusing integers outside ±2^53.
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    match write_value(&mut out, value, Integers::Interchange) {
        Ok(()) => Ok(out),
        Err(failure) => Err(failure.into_error()),
    }
}

/// Canonicalize `value` like [`canonicalize`], but write integers outside ±2^53 as exact
/// decimal digits instead of refusing them. Not RFC 8785 for those integers; use it only for
/// data that is not claimed to be recomputable by a third party.
pub fn canonicalize_exact_integers(value: &Value) -> String {
    let mut out = String::new();
    // Integers::Exact never fails: the only failure is a refused integer, and a Number
    // cannot hold a non-finite double.
    let _ = write_value(&mut out, value, Integers::Exact);
    out
}

/// Serialize a finite double the way ECMAScript `Number::toString` does (RFC 8785 section
/// 3.2.2.3). Returns `None` for NaN and the infinities, which JSON cannot represent.
pub fn serialize_f64(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    if value == 0.0 {
        // Covers -0.0: ECMAScript writes both zeros as "0".
        return Some("0".to_string());
    }
    let sign = if value < 0.0 { "-" } else { "" };

    // ECMAScript names: value = digits × 10^(n − k) with k = digits.len().
    let (digits, n) = shortest_digits(value.abs())?;
    let k = i32::try_from(digits.len()).ok()?;

    let mut out = String::from(sign);
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.push_str(&"0".repeat(usize::try_from(n - k).ok()?));
    } else if 0 < n && n <= 21 {
        let split = usize::try_from(n).ok()?;
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat(usize::try_from(-n).ok()?));
        out.push_str(&digits);
    } else {
        let e = n - 1;
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if e < 0 { '-' } else { '+' });
        out.push_str(&e.abs().to_string());
    }
    Some(out)
}

/// The shortest decimal digits that round-trip to `value` (a positive finite double), and the
/// exponent `n` such that `value = 0.digits × 10^n`.
///
/// The digits come from serde_json's own `f64` printing, which is Ryu. When two shortest
/// candidates are exactly equidistant from the value, Ryu picks the even one, as ECMAScript
/// requires (RFC 8785 Appendix B, "round to even": 1424953923781206.25 is written
/// 1424953923781206.2). Rust's `{:e}` formatting rounds that tie up, which is why it is not
/// used here. The text's shape (plain or exponent form) is irrelevant: only digits and the
/// decimal point position are read from it.
fn shortest_digits(value: f64) -> Option<(String, i32)> {
    let text = serde_json::to_string(&value).ok()?;
    let (mantissa, exponent) = match text.split_once('e') {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
        None => (text.as_str(), 0),
    };
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{integer}{fraction}");
    let point = i32::try_from(integer.len()).ok()? + exponent;

    let without_leading = all.trim_start_matches('0');
    let leading_zeros = i32::try_from(all.len() - without_leading.len()).ok()?;
    let digits = without_leading.trim_end_matches('0');
    if digits.is_empty() {
        return None;
    }
    Some((digits.to_string(), point - leading_zeros))
}

#[derive(Clone, Copy)]
enum Integers {
    /// Refuse integers outside ±2^53 (RFC 8785 interchange).
    Interchange,
    /// Write them as exact decimal digits.
    Exact,
}

enum Segment {
    Key(String),
    Index(usize),
}

/// A refused number plus the path to it, collected innermost segment first while unwinding.
struct Failure {
    number: String,
    segments: Vec<Segment>,
}

impl Failure {
    fn at(number: String) -> Self {
        Self {
            number,
            segments: Vec::new(),
        }
    }

    fn under(mut self, segment: Segment) -> Self {
        self.segments.push(segment);
        self
    }

    fn into_error(self) -> JcsError {
        let mut pointer = String::new();
        for segment in self.segments.iter().rev() {
            pointer.push('/');
            match segment {
                Segment::Key(key) => pointer.push_str(&key.replace('~', "~0").replace('/', "~1")),
                Segment::Index(index) => pointer.push_str(&index.to_string()),
            }
        }
        JcsError {
            pointer,
            number: self.number,
        }
    }
}

fn write_value(out: &mut String, value: &Value, integers: Integers) -> Result<(), Failure> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(out, number, integers)?,
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item, integers).map_err(|f| f.under(Segment::Index(index)))?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(out, map, integers)?,
    }
    Ok(())
}

fn write_object(
    out: &mut String,
    map: &Map<String, Value>,
    integers: Integers,
) -> Result<(), Failure> {
    let mut members: Vec<(&String, &Value)> = map.iter().collect();
    // RFC 8785 section 3.2.3: compare member names as arrays of UTF-16 code units. Slice
    // comparison is lexicographic with a shorter prefix first, as the RFC specifies.
    members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));

    out.push('{');
    for (index, (name, member)) in members.into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(out, name);
        out.push(':');
        write_value(out, member, integers).map_err(|f| f.under(Segment::Key(name.clone())))?;
    }
    out.push('}');
    Ok(())
}

fn write_number(out: &mut String, number: &Number, integers: Integers) -> Result<(), Failure> {
    if let Some(unsigned) = number.as_u64() {
        return write_integer(out, number, unsigned, false, integers);
    }
    if let Some(signed) = number.as_i64() {
        return write_integer(out, number, signed.unsigned_abs(), true, integers);
    }
    match number.as_f64().and_then(serialize_f64) {
        Some(text) => {
            out.push_str(&text);
            Ok(())
        }
        // Unreachable for a serde_json Number (it rejects NaN and infinities), but a typed
        // failure beats a panic in a hashing path.
        None => Err(Failure::at(number.to_string())),
    }
}

fn write_integer(
    out: &mut String,
    number: &Number,
    magnitude: u64,
    negative: bool,
    integers: Integers,
) -> Result<(), Failure> {
    if magnitude > MAX_INTERCHANGE_INTEGER && matches!(integers, Integers::Interchange) {
        return Err(Failure::at(number.to_string()));
    }
    // Within ±2^53 every integer is an exact double and ECMAScript writes its digits as is
    // (it only switches to exponent form at 1e21).
    if negative && magnitude != 0 {
        out.push('-');
    }
    out.push_str(&magnitude.to_string());
    Ok(())
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn canon(text: &str) -> String {
        let value: Value = serde_json::from_str(text).unwrap();
        canonicalize(&value).unwrap()
    }

    #[test]
    fn numbers_follow_ecmascript_formatting() {
        // value, expected: boundaries of every branch in serialize_f64.
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
            assert_eq!(serialize_f64(value).as_deref(), Some(expected), "{value:e}");
        }
        assert_eq!(serialize_f64(f64::NAN), None);
        assert_eq!(serialize_f64(f64::INFINITY), None);
        assert_eq!(serialize_f64(f64::NEG_INFINITY), None);
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
            canonicalize(&ok).unwrap(),
            r#"{"edge":9007199254740992,"neg":-9007199254740992}"#
        );

        let too_big = json!({"a": [1, {"b/c~d": 9_007_199_254_740_993_u64}]});
        let error = canonicalize(&too_big).unwrap_err();
        assert_eq!(error.pointer, "/a/1/b~1c~0d");
        assert_eq!(error.number, "9007199254740993");
        assert!(
            error
                .to_string()
                .contains("write the value as a JSON string")
        );

        let max = json!(u64::MAX);
        assert_eq!(canonicalize(&max).unwrap_err().pointer, "");
        let min = json!(i64::MIN);
        assert_eq!(
            canonicalize(&min).unwrap_err().number,
            "-9223372036854775808"
        );
    }

    #[test]
    fn exact_integer_mode_keeps_distinct_integers_distinct() {
        let a = json!([9_007_199_254_740_993_u64]);
        let b = json!([9_007_199_254_740_992_u64]);
        assert_eq!(canonicalize_exact_integers(&a), "[9007199254740993]");
        assert_ne!(
            canonicalize_exact_integers(&a),
            canonicalize_exact_integers(&b)
        );
        assert_eq!(
            canonicalize_exact_integers(&json!([u64::MAX, i64::MIN])),
            "[18446744073709551615,-9223372036854775808]"
        );
        // Identical to the strict form wherever the strict form succeeds.
        let ordinary = json!({"b": [1, 2.5, "x"], "a": null});
        assert_eq!(
            canonicalize_exact_integers(&ordinary),
            canonicalize(&ordinary).unwrap()
        );
    }

    #[test]
    fn keys_sort_by_utf16_code_units_not_utf8_bytes() {
        // U+1F600 is the surrogate pair D83D DE00; U+FB33 is the single unit FB33. UTF-16 order
        // puts the emoji first, UTF-8 / code point order puts it last.
        let value = json!({"\u{fb33}": 1, "\u{1f600}": 2, "\u{20ac}": 3, "a": 4, "\u{80}": 5});
        assert_eq!(
            canonicalize(&value).unwrap(),
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
            canonicalize(&value).unwrap(),
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
}
