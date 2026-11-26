//! RFC 8785 (JCS) conformance against published vectors.
//!
//! Sources, all recorded with pinned hashes in `fixtures/jcs/SOURCES.json`:
//! * RFC 8785 itself: the section 3.2.2 to 3.2.4 example with its byte dump, the section 3.2.3
//!   sorting sample, and the Appendix B number table (inline below);
//! * the reference repository's `testdata` input/output pairs (cyberphone/json-canonicalization);
//! * a sample of the reference repository's 100-million-line ES6 number file, with the full
//!   file runnable through `es6_published_file_matches_in_full` (ignored by default);
//! * hash-stability goldens computed with PyPI `jcs` and `blake3`, not with airlock code.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use airlock::hash::{blake3_hash, jcs_blake3_hash};
use airlock::output::{canonical_json, canonical_json_bytes, sort_value};
// al-9ir: the canonicalizer is cmdrvl-core's; the local names are kept so the vectors and
// expected values below are untouched.
use cmdrvl_core::jcs::{
    MAX_INTERCHANGE_INTEGER, format_f64 as serialize_f64, to_string as canonicalize,
    to_string_exact_integers as canonicalize_exact_integers,
};
use serde_json::{Number, Value, json};

fn fixture(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/jcs")
        .join(path)
}

fn read(path: &str) -> Vec<u8> {
    fs::read(fixture(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&read(path)).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn decode_hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

// -------------------------------------------------------------------------------------------
// Vector files are exactly what was published
// -------------------------------------------------------------------------------------------

#[test]
fn vector_files_match_their_pinned_hashes() {
    let sources = read_json("SOURCES.json");
    let files = sources["cyberphone"]["files"].as_object().unwrap();
    assert!(files.len() >= 13, "expected every vector file to be pinned");
    for (path, pinned) in files {
        assert_eq!(
            blake3_hash(&read(path)),
            pinned.as_str().unwrap(),
            "{path} no longer matches the published vector it pins"
        );
    }
    assert_eq!(
        blake3_hash(&read("es6_numbers_sample.txt")),
        sources["es6_numbers"]["sample_file_hash"].as_str().unwrap()
    );
}

// -------------------------------------------------------------------------------------------
// Reference repository input/output pairs
// -------------------------------------------------------------------------------------------

#[test]
fn reference_repository_pairs_canonicalize_to_the_published_bytes() {
    for name in [
        "arrays",
        "french",
        "structures",
        "unicode",
        "values",
        "weird",
    ] {
        let input = read_json(&format!("cyberphone/input/{name}.json"));
        let published = read(&format!("cyberphone/output/{name}.json"));

        assert_eq!(
            canonicalize(&input).unwrap().into_bytes(),
            published,
            "{name}: strict canonicalization differs from the published output"
        );
        assert_eq!(
            canonical_json_bytes(&input),
            published,
            "{name}: output::canonical_json_bytes differs from the published output"
        );
        assert_eq!(
            jcs_blake3_hash(&input).unwrap(),
            blake3_hash(&published),
            "{name}"
        );
    }
}

// -------------------------------------------------------------------------------------------
// RFC 8785 text
// -------------------------------------------------------------------------------------------

#[test]
fn rfc_section_3_2_example_matches_the_published_byte_dump() {
    // Section 3.2.2 input: the reference repository's `values.json` is this document (pinned by
    // hash in `vector_files_match_their_pinned_hashes`), so the escapes are read from the file
    // rather than retyped here.
    let value = read_json("cyberphone/input/values.json");
    // Section 3.2.4 byte dump of the canonical form.
    let expected = decode_hex(
        "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72
         75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
         5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31
         65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
         5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30
         30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d",
    );
    assert_eq!(canonicalize(&value).unwrap().into_bytes(), expected);
}

#[test]
fn rfc_section_3_2_3_sorting_sample_orders_members_as_published() {
    // The sample object, section 3.2.3, in the RFC's input order. The keys are JSON escapes
    // (doubled backslashes here), so the parser's escape handling is part of the test.
    let input_members = [
        ("\\u20ac", "Euro Sign"),
        ("\\r", "Carriage Return"),
        ("\\ufb33", "Hebrew Letter Dalet With Dagesh"),
        ("1", "One"),
        ("\\ud83d\\ude00", "Emoji: Grinning Face"),
        ("\\u0080", "Control"),
        ("\\u00f6", "Latin Small Letter O With Diaeresis"),
    ];
    let input = format!(
        "{{{}}}",
        input_members
            .iter()
            .map(|(key, value)| format!("\"{key}\": \"{value}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    // Section 3.2.3 "Expected argument order after sorting property strings", with the key
    // that carried each value.
    let published_order = [
        ("\\r", "Carriage Return"),
        ("1", "One"),
        ("\u{80}", "Control"),
        ("\u{f6}", "Latin Small Letter O With Diaeresis"),
        ("\u{20ac}", "Euro Sign"),
        ("\u{1f600}", "Emoji: Grinning Face"),
        ("\u{fb33}", "Hebrew Letter Dalet With Dagesh"),
    ];
    let expected = format!(
        "{{{}}}",
        published_order
            .iter()
            .map(|(key, value)| format!("\"{key}\":\"{value}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    let value: Value = serde_json::from_str(&input).unwrap();
    assert_eq!(canonicalize(&value).unwrap(), expected);
}

#[test]
fn utf16_order_differs_from_the_utf8_order_airlock_used_before() {
    // The emoji (surrogate pair D83D DE00) sorts before U+FB33 in UTF-16 and after it in
    // UTF-8 / code point order. This is the one place the previous canonical form and RFC 8785
    // disagree for strings, so pin that the new form follows the RFC.
    let value = json!({"\u{fb33}": 1, "\u{1f600}": 2});
    let utf8_order = serde_json::to_string(&sort_value(value.clone())).unwrap();
    assert_eq!(utf8_order, "{\"\u{fb33}\":1,\"\u{1f600}\":2}");
    assert_eq!(canonical_json(&value), "{\"\u{1f600}\":2,\"\u{fb33}\":1}");
}

/// RFC 8785 Appendix B, Table 1: IEEE 754 bits and the published serialization.
const APPENDIX_B: [(&str, &str); 24] = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
];

fn double_from_hex(bits: &str) -> f64 {
    f64::from_bits(u64::from_str_radix(bits, 16).unwrap())
}

#[test]
fn rfc_appendix_b_number_table() {
    for (bits, expected) in APPENDIX_B {
        assert_eq!(
            serialize_f64(double_from_hex(bits)).as_deref(),
            Some(expected),
            "IEEE 754 {bits}"
        );
    }
    // Rows the RFC marks as not permitted: NaN and Infinity.
    for bits in ["7fffffffffffffff", "7ff0000000000000", "fff0000000000000"] {
        assert_eq!(serialize_f64(double_from_hex(bits)), None, "{bits}");
    }
    assert!(Number::from_f64(f64::NAN).is_none());
    assert!(Number::from_f64(f64::INFINITY).is_none());
}

#[test]
fn appendix_b_numbers_survive_a_full_canonicalization() {
    // Same rows, but through a JSON document so number parsing is part of the path.
    for (bits, expected) in APPENDIX_B {
        let number = Number::from_f64(double_from_hex(bits)).unwrap();
        let document = json!({ "n": number });
        assert_eq!(
            canonicalize(&document).unwrap(),
            format!("{{\"n\":{expected}}}"),
            "IEEE 754 {bits}"
        );
    }
}

// -------------------------------------------------------------------------------------------
// ES6 number file published by the reference repository
// -------------------------------------------------------------------------------------------

fn check_es6_lines(reader: impl BufRead, label: &str) -> usize {
    let mut checked = 0usize;
    let mut mismatch_count = 0usize;
    let mut first_mismatches = Vec::new();
    for line in reader.lines() {
        let line = line.unwrap();
        let (bits, expected) = line
            .split_once(',')
            .unwrap_or_else(|| panic!("{label}: malformed line {line:?}"));
        let got = serialize_f64(double_from_hex(bits));
        if got.as_deref() != Some(expected) {
            mismatch_count += 1;
            if first_mismatches.len() < 10 {
                first_mismatches.push(format!("{bits}: got {got:?}, published {expected}"));
            }
        }
        checked += 1;
    }
    assert_eq!(
        mismatch_count, 0,
        "{label}: {mismatch_count} of {checked} lines differ from the published serialization, \
         first: {first_mismatches:#?}"
    );
    checked
}

#[test]
fn es6_published_sample_matches() {
    let file = fs::File::open(fixture("es6_numbers_sample.txt")).unwrap();
    let checked = check_es6_lines(BufReader::new(file), "es6_numbers_sample.txt");
    assert_eq!(checked, 140);
}

/// Runs every line of the published 100-million-line file (2 GB gzipped) through the
/// serializer. Stream it through a named pipe so the decompressed file is never stored:
///
/// ```text
/// mkfifo /tmp/es6.fifo
/// gzip -dc es6testfile100m.txt.gz > /tmp/es6.fifo &
/// AIRLOCK_JCS_ES6_FILE=/tmp/es6.fifo cargo test --release --test jcs_conformance \
///     es6_published_file_matches_in_full -- --ignored --nocapture
/// ```
#[test]
#[ignore = "needs the 2 GB gzipped published file; see the doc comment for how to stream it"]
fn es6_published_file_matches_in_full() {
    let path = std::env::var("AIRLOCK_JCS_ES6_FILE")
        .expect("set AIRLOCK_JCS_ES6_FILE to the decompressed published file or a pipe");
    let file = fs::File::open(&path).unwrap();
    let checked = check_es6_lines(BufReader::with_capacity(1 << 20, file), &path);
    eprintln!("es6 published file: {checked} lines matched");
    assert!(checked >= 100_000_000, "only {checked} lines were read");
}

// -------------------------------------------------------------------------------------------
// Number edge cases
// -------------------------------------------------------------------------------------------

fn canon_text(text: &str) -> String {
    let value: Value = serde_json::from_str(text).unwrap();
    canonicalize(&value).unwrap()
}

#[test]
fn one_point_zero_and_one_are_the_same_number() {
    assert_eq!(
        canon_text("[1, 1.0, 1.00, 1e0, 0.1e1, 10e-1]"),
        "[1,1,1,1,1,1]"
    );
    assert_eq!(canon_text(r#"{"t": 1.0}"#), r#"{"t":1}"#);
    assert_eq!(canon_text("[100, 100.0, 1e2, 1E+2]"), "[100,100,100,100]");
}

#[test]
fn negative_zero_is_zero() {
    assert_eq!(canon_text("[-0, -0.0, -0e0, 0, 0.0]"), "[0,0,0,0,0]");
}

#[test]
fn exponent_boundaries() {
    assert_eq!(
        canon_text("[1e20, 1e21, 1e22, 1e-6, 1e-7, 123e18, 1.5e-6, 12345678901234567890e0]"),
        "[100000000000000000000,1e+21,1e+22,0.000001,1e-7,123000000000000000000,0.0000015,\
         12345678901234567000]"
    );
}

#[test]
fn integers_up_to_two_to_the_53_are_exact_and_beyond_are_refused() {
    assert_eq!(MAX_INTERCHANGE_INTEGER, 9_007_199_254_740_992);
    assert_eq!(
        canon_text("[9007199254740991, 9007199254740992, -9007199254740992]"),
        "[9007199254740991,9007199254740992,-9007199254740992]"
    );
    for refused in [
        "9007199254740993",
        "-9007199254740993",
        "9223372036854775807",
        "-9223372036854775808",
        "18446744073709551615",
    ] {
        let value: Value = serde_json::from_str(&format!(r#"{{"id": [{refused}]}}"#)).unwrap();
        let error = canonicalize(&value).unwrap_err();
        assert_eq!(error.pointer, "/id/0", "{refused}");
        assert_eq!(error.number, refused);
        assert!(jcs_blake3_hash(&value).is_err(), "{refused} must not hash");
        // The total variant keeps the digits and stays injective for these values.
        assert!(canonicalize_exact_integers(&value).contains(refused));
    }
}

#[test]
fn integer_literals_beyond_u64_follow_double_semantics() {
    // serde_json holds an integer literal larger than u64::MAX as a double, exactly as an
    // implementation that reads every JSON number as a double does, and RFC 8785 serializes
    // that double. The two literals below are different integers and the same double.
    assert_eq!(
        canon_text("[18446744073709551616, 18446744073709551617]"),
        "[18446744073709552000,18446744073709552000]"
    );
}

#[test]
fn json_that_cannot_hold_nan_or_infinity_is_rejected_by_the_parser() {
    for text in ["NaN", "Infinity", "-Infinity", "1e400", "-1e400"] {
        assert!(
            serde_json::from_str::<Value>(text).is_err(),
            "{text} must not parse"
        );
    }
}

#[test]
fn lone_surrogates_are_rejected_by_the_parser() {
    // RFC 8785 section 3.2.2.2: lone surrogates MUST cause an error.
    for text in [
        r#""\ud800""#,
        r#""\udc00""#,
        r#""\ud83d x""#,
        r#"{"\ud800": 1}"#,
    ] {
        assert!(
            serde_json::from_str::<Value>(text).is_err(),
            "{text} must not parse"
        );
    }
}

#[test]
fn full_precision_floats_parse_correctly_rounded() {
    // serde_json's default float parser is one ULP off for these strings (picked from a
    // comparison with `str::parse::<f64>` on pseudo-random inputs, see
    // docs/canonicalization.md); `float_roundtrip` in Cargo.toml fixes it. If this test fails,
    // the feature was removed and airlock hashes would disagree with every correct JCS
    // implementation for payloads containing such numbers.
    for text in [
        "-1.638344060600543e-227",
        "2.6104882325689648e-130",
        "9.335744933994957e-17",
        "-1.6990709035471285e-94",
        "5.084767197776064e190",
        "6.32034819298954389e-285",
        "3.2152770018161699021e104",
        "9.6263127533920758e-281",
        "2.454613369214613474e-294",
        "1.215251705755784437869484e-216",
    ] {
        let correct: f64 = text.parse().unwrap();
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            value.as_f64().unwrap().to_bits(),
            correct.to_bits(),
            "{text} parsed one ULP away from the correctly rounded value"
        );
    }
}

// -------------------------------------------------------------------------------------------
// Hash-stability goldens (computed with PyPI jcs and blake3, not with airlock)
// -------------------------------------------------------------------------------------------

#[test]
fn hash_stability_goldens() {
    let goldens = read_json("golden_hashes.json");
    let cases = goldens["goldens"].as_array().unwrap();
    assert!(cases.len() >= 4);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let input: Value = serde_json::from_str(case["input_json"].as_str().unwrap()).unwrap();
        let canonical = case["canonical"].as_str().unwrap();
        let hash = case["blake3"].as_str().unwrap();

        assert_eq!(canonicalize(&input).unwrap(), canonical, "{name}");
        assert_eq!(
            canonical_json(&input),
            canonical,
            "{name}: output::canonical_json"
        );
        assert_eq!(jcs_blake3_hash(&input).unwrap(), hash, "{name}");
        assert_eq!(blake3_hash(&canonical_json_bytes(&input)), hash, "{name}");
        assert_eq!(
            blake3_hash(canonical.as_bytes()),
            hash,
            "{name}: golden is self-consistent"
        );
    }
}
