//! Cross-implementation check: airlock's RFC 8785 canonicalizer against an independent Python
//! implementation (`tests/jcs_reference.py`) on random doubles and random documents.
//!
//! Two independent implementations agreeing on hundreds of thousands of random inputs is not by
//! itself proof of correctness, so the test first checks that the Python reference reproduces
//! the published RFC and reference-repository vectors; agreement is then meaningful.
//!
//! Needs `python3` (standard library only). When it is missing the tests are skipped with a
//! message locally and FAIL when the `CI` environment variable is set.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use airlock::hash::jcs::{canonicalize, serialize_f64};
use serde_json::{Map, Number, Value};

fn python() -> Option<String> {
    let python = std::env::var("AIRLOCK_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let works = Command::new(&python)
        .args(["-I", "-c", "pass"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if works {
        return Some(python);
    }
    assert!(
        std::env::var("CI").is_err(),
        "python3 is required for the JCS cross-check in CI (set AIRLOCK_PYTHON to override)"
    );
    eprintln!("SKIPPED: python3 is not available, so the JCS cross-check did not run");
    None
}

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/jcs_reference.py")
}

/// Run the Python reference over `lines` and return one output line per input line.
fn reference(python: &str, mode: &str, lines: &[String]) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.txt");
    fs::write(&input, lines.join("\n") + "\n").unwrap();
    let output = Command::new(python)
        .arg("-I")
        .arg(script())
        .arg(mode)
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "jcs_reference.py {mode} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let mut results: Vec<String> = text.split('\n').map(str::to_string).collect();
    assert_eq!(
        results.pop().as_deref(),
        Some(""),
        "output must end in a newline"
    );
    assert_eq!(results.len(), lines.len(), "one output line per input line");
    results
}

/// Deterministic xorshift64* generator, so a failure reproduces exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

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

fn fixture(path: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/jcs")
            .join(path),
    )
    .unwrap()
}

#[test]
fn the_python_reference_reproduces_the_published_vectors() {
    let Some(python) = python() else { return };

    // RFC 8785 Appendix B.
    let lines: Vec<String> = APPENDIX_B
        .iter()
        .map(|(bits, _)| bits.to_string())
        .collect();
    let expected: Vec<&str> = APPENDIX_B.iter().map(|(_, text)| *text).collect();
    assert_eq!(reference(&python, "numbers", &lines), expected);

    // Reference-repository input/output pairs, one compact document per line.
    for name in [
        "arrays",
        "french",
        "structures",
        "unicode",
        "values",
        "weird",
    ] {
        let input: Value =
            serde_json::from_slice(&fixture(&format!("cyberphone/input/{name}.json"))).unwrap();
        let published =
            String::from_utf8(fixture(&format!("cyberphone/output/{name}.json"))).unwrap();
        let line = serde_json::to_string(&input).unwrap();
        assert_eq!(reference(&python, "canon", &[line]), [published], "{name}");
    }
}

/// A finite double drawn from every binade, plus integral values, short decimals and powers of
/// two and ten, where shortest-digit algorithms differ most.
fn random_double(rng: &mut Rng) -> f64 {
    loop {
        let value = match rng.below(8) {
            0 => f64::from_bits(rng.next()),
            1 => rng.below(1 << 20) as f64,
            2 => (rng.below(2_000_001) as f64 - 1_000_000.0) / 1000.0,
            3 => {
                let text = format!(
                    "{}.{}e{}",
                    rng.below(10),
                    rng.below(1_000_000_000_000),
                    rng.below(61) as i64 - 30
                );
                text.parse().unwrap()
            }
            4 => 2f64.powi(rng.below(2098) as i32 - 1074),
            5 => 10f64.powi(rng.below(631) as i32 - 323),
            6 => f64::from_bits(rng.next() & 0x800F_FFFF_FFFF_FFFF), // subnormals
            _ => rng.below(1 << 53) as f64 + 0.5,
        };
        if value.is_finite() {
            return value;
        }
    }
}

#[test]
fn doubles_serialize_like_the_python_reference() {
    let Some(python) = python() else { return };

    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let doubles: Vec<f64> = (0..200_000).map(|_| random_double(&mut rng)).collect();
    let lines: Vec<String> = doubles
        .iter()
        .map(|value| format!("{:x}", value.to_bits()))
        .collect();
    let python_says = reference(&python, "numbers", &lines);

    for ((value, line), expected) in doubles.iter().zip(&lines).zip(&python_says) {
        assert_eq!(
            serialize_f64(*value).as_deref(),
            Some(expected.as_str()),
            "IEEE 754 {line} ({value:e})"
        );
    }
}

fn random_char(rng: &mut Rng) -> char {
    loop {
        let code = match rng.below(8) {
            0 => rng.below(0x20) as u32,                // control characters
            1 => 0x20 + rng.below(0x5F) as u32,         // printable ASCII, incl. " and \
            2 => 0x7F + rng.below(0x81) as u32,         // DEL and Latin-1
            3 => 0x100 + rng.below(0xF00) as u32,       // Latin Extended .. Devanagari
            4 => 0xE000 + rng.below(0x2000) as u32,     // U+E000..=U+FFFF: above the surrogates
            5 => 0x1_0000 + rng.below(0x1_0000) as u32, // supplementary: surrogate pairs
            6 => 0x2028 + rng.below(2) as u32,          // line and paragraph separators
            _ => 0x1F300 + rng.below(0x300) as u32,     // emoji
        };
        if let Some(c) = char::from_u32(code) {
            return c;
        }
    }
}

fn random_string(rng: &mut Rng) -> String {
    (0..rng.below(8)).map(|_| random_char(rng)).collect()
}

fn random_value(rng: &mut Rng, depth: u32) -> Value {
    let kinds = if depth == 0 { 6 } else { 8 };
    match rng.below(kinds) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 0),
        2 => Value::from(rng.below(2 * (1 << 53) + 1) as i64 - (1 << 53)),
        3 => Value::Number(Number::from_f64(random_double(rng)).unwrap()),
        4 | 5 => Value::String(random_string(rng)),
        6 => Value::Array(
            (0..rng.below(5))
                .map(|_| random_value(rng, depth - 1))
                .collect(),
        ),
        _ => {
            let mut map = Map::new();
            for _ in 0..rng.below(6) {
                map.insert(random_string(rng), random_value(rng, depth - 1));
            }
            Value::Object(map)
        }
    }
}

#[test]
fn documents_canonicalize_like_the_python_reference() {
    let Some(python) = python() else { return };

    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    // serde_json's own compact output is the input text: it is not canonical (ryu number forms,
    // UTF-8 key order), and parsing it back exercises the correctly rounded float parser.
    let lines: Vec<String> = (0..20_000)
        .map(|_| serde_json::to_string(&random_value(&mut rng, 4)).unwrap())
        .collect();
    let python_says = reference(&python, "canon", &lines);

    for (line, expected) in lines.iter().zip(&python_says) {
        let value: Value = serde_json::from_str(line).unwrap();
        assert_eq!(&canonicalize(&value).unwrap(), expected, "input: {line}");
    }
}

#[test]
fn integers_beyond_two_to_the_53_are_refused_by_both() {
    let Some(python) = python() else { return };

    let lines: Vec<String> = [
        r#"{"id": 9007199254740993}"#,
        r#"[1, -9007199254740993]"#,
        r#"{"a": {"b": [18446744073709551615]}}"#,
        r#"[-9223372036854775808]"#,
        // Exactly 2^53 is representable and accepted by both.
        r#"[9007199254740992, -9007199254740992]"#,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let python_says = reference(&python, "canon", &lines);

    for (line, expected) in lines.iter().zip(&python_says) {
        let value: Value = serde_json::from_str(line).unwrap();
        match canonicalize(&value) {
            Ok(text) => assert_eq!(&text, expected, "input: {line}"),
            Err(_) => assert!(
                expected.starts_with("ERROR:"),
                "input: {line} -> {expected}"
            ),
        }
    }
    assert!(python_says[0].starts_with("ERROR:"));
    assert!(python_says[4].starts_with('['));
}
