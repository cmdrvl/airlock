//! The `transmission` member `airlock send` adds to a v0.3 manifest, and the rules that tie it
//! to `attestation`. Valid shapes validate; every illegal combination is rejected on its own.

use std::path::PathBuf;

use airlock::manifest::{Transmission, TransmissionError};
use serde_json::{Value, json};

const HASH: &str = "blake3:1111111111111111111111111111111111111111111111111111111111111111";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(repo_root().join(path)).unwrap()).unwrap()
}

/// Format checks are on: `format: date-time` is only an annotation to the crate's default
/// validator, and `sent_at` is declared as a date-time.
fn schema() -> jsonschema::Validator {
    jsonschema::options()
        .should_validate_formats(true)
        .build(&read_json("schemas/airlock.v0.schema.json"))
        .unwrap()
}

/// A golden v0.3 manifest with the given attestation and transmission.
fn manifest_with(attestation: &str, transmission: Value) -> Value {
    let mut manifest = read_json("fixtures/clean_telemetry_only/expected_manifest_v0_3.json");
    manifest["attestation"] = json!(attestation);
    manifest["transmission"] = transmission;
    manifest
}

fn clean_exchange() -> Value {
    json!({
        "sent": true,
        "endpoint_host": "api.example.com",
        "request_bytes": 632,
        "request_hash": HASH,
        "sent_at": "2026-11-25T12:00:00Z",
        "latency_ms": 412,
        "response_status": 200,
        "response_hash": HASH,
        "response_bytes": 2048
    })
}

fn not_sent(error: &str) -> Value {
    json!({
        "sent": false,
        "endpoint_host": "api.example.com",
        "request_bytes": 632,
        "request_hash": HASH,
        "error": error
    })
}

fn accepted(manifest: &Value) -> bool {
    schema().is_valid(manifest)
}

fn with(mut value: Value, key: &str, member: Value) -> Value {
    value[key] = member;
    value
}

fn without(mut value: Value, key: &str) -> Value {
    value.as_object_mut().unwrap().remove(key);
    value
}

#[test]
fn every_legal_shape_of_a_transmission_validates() {
    let legal = [
        ("transmitted", clean_exchange()),
        // An HTTP error status is still a completed exchange.
        (
            "transmitted",
            with(clean_exchange(), "response_status", json!(500)),
        ),
        (
            "transmitted",
            with(
                with(clean_exchange(), "error", json!("RESPONSE_TOO_LARGE")),
                "response_bytes",
                json!(33_554_432),
            ),
        ),
        (
            "transmitted",
            with(
                without(
                    without(
                        without(clean_exchange(), "response_status"),
                        "response_hash",
                    ),
                    "response_bytes",
                ),
                "error",
                json!("RESPONSE_TIMEOUT"),
            ),
        ),
        (
            "transmitted",
            with(
                without(
                    without(
                        without(clean_exchange(), "response_status"),
                        "response_hash",
                    ),
                    "response_bytes",
                ),
                "error",
                json!("TRANSPORT_ERROR"),
            ),
        ),
        ("self_attested", not_sent("CLAIM_BELOW_REQUIRED")),
        ("self_attested", not_sent("CONNECT_FAILED")),
    ];

    for (attestation, transmission) in legal {
        let manifest = manifest_with(attestation, transmission.clone());
        assert!(
            accepted(&manifest),
            "{transmission} with {attestation} should validate: {:?}",
            schema().validate(&manifest).err().map(|e| e.to_string())
        );
    }
}

#[test]
fn a_manifest_without_a_transmission_still_validates_with_any_attestation() {
    // verify never writes a transmission, and absent says nothing about sending.
    for attestation in ["self_attested", "gated"] {
        let mut manifest = read_json("fixtures/clean_telemetry_only/expected_manifest_v0_3.json");
        manifest["attestation"] = json!(attestation);
        assert!(accepted(&manifest), "{attestation}");
    }
}

#[test]
fn attestation_and_sent_must_agree() {
    let transmitted_without_transmission = {
        let mut manifest = read_json("fixtures/clean_telemetry_only/expected_manifest_v0_3.json");
        manifest["attestation"] = json!("transmitted");
        manifest
    };
    let rejected = [
        (
            "transmitted but no transmission",
            transmitted_without_transmission,
        ),
        (
            "transmitted but sent false",
            manifest_with("transmitted", not_sent("CLAIM_BELOW_REQUIRED")),
        ),
        (
            "sent true but self_attested",
            manifest_with("self_attested", clean_exchange()),
        ),
        (
            "sent true but gated",
            manifest_with("gated", clean_exchange()),
        ),
        (
            "sent false but gated",
            manifest_with("gated", not_sent("CONNECT_FAILED")),
        ),
    ];
    for (why, manifest) in rejected {
        assert!(!accepted(&manifest), "{why} must not validate");
    }
}

#[test]
fn a_sent_request_records_when_and_how_long() {
    for member in ["sent_at", "latency_ms"] {
        let manifest = manifest_with("transmitted", without(clean_exchange(), member));
        assert!(!accepted(&manifest), "sent true without {member}");
    }
}

#[test]
fn a_sent_request_has_a_response_or_an_error_never_both_never_neither() {
    let no_response = |value: Value| {
        without(
            without(without(value, "response_status"), "response_hash"),
            "response_bytes",
        )
    };
    let rejected = [
        (
            "neither a response nor an error",
            no_response(clean_exchange()),
        ),
        (
            "a clean response that also carries an error",
            with(clean_exchange(), "error", json!("TRANSPORT_ERROR")),
        ),
        (
            "a response and a timeout",
            with(clean_exchange(), "error", json!("RESPONSE_TIMEOUT")),
        ),
        (
            "an error that cannot follow a sent request",
            with(
                no_response(clean_exchange()),
                "error",
                json!("CONNECT_FAILED"),
            ),
        ),
        (
            "an error that cannot follow a sent request (claim)",
            with(
                no_response(clean_exchange()),
                "error",
                json!("CLAIM_BELOW_REQUIRED"),
            ),
        ),
        (
            "too large with no response to show for it",
            with(
                no_response(clean_exchange()),
                "error",
                json!("RESPONSE_TOO_LARGE"),
            ),
        ),
    ];
    for (why, transmission) in rejected {
        let manifest = manifest_with("transmitted", transmission);
        assert!(!accepted(&manifest), "{why} must not validate");
    }
}

#[test]
fn a_request_that_was_not_sent_has_a_reason_and_nothing_that_implies_it_was() {
    let rejected = [
        ("no reason", without(not_sent("CONNECT_FAILED"), "error")),
        (
            "a reason that implies it was sent",
            not_sent("RESPONSE_TIMEOUT"),
        ),
        (
            "a transport error that implies it was sent",
            not_sent("TRANSPORT_ERROR"),
        ),
        (
            "a send time",
            with(
                not_sent("CONNECT_FAILED"),
                "sent_at",
                json!("2026-11-25T12:00:00Z"),
            ),
        ),
        (
            "a latency",
            with(not_sent("CONNECT_FAILED"), "latency_ms", json!(5)),
        ),
        (
            "a response status",
            with(not_sent("CONNECT_FAILED"), "response_status", json!(200)),
        ),
    ];
    for (why, transmission) in rejected {
        let manifest = manifest_with("self_attested", transmission);
        assert!(
            !accepted(&manifest),
            "not sent with {why} must not validate"
        );
    }
}

#[test]
fn the_three_response_members_come_together_or_not_at_all() {
    let members = ["response_status", "response_hash", "response_bytes"];

    // Any one of the three missing.
    for missing in members {
        let manifest = manifest_with("transmitted", without(clean_exchange(), missing));
        assert!(
            !accepted(&manifest),
            "a response without {missing} must not validate"
        );
    }

    // Any one of the three alone. Each member must name the other two on its own: with only
    // the one-missing cases above, dropping a single member's dependency goes unnoticed.
    // Each case is otherwise legal for a sent request (a status with no error, or a response
    // member with a TRANSPORT_ERROR and no status), so only that member's own dependency can
    // reject it. An error beside a status would be rejected by the response-or-error rule
    // instead and prove nothing about the dependency.
    let alone = |keep: &str, error: Option<&str>| {
        let mut transmission = clean_exchange();
        for other in members.into_iter().filter(|member| *member != keep) {
            transmission = without(transmission, other);
        }
        match error {
            Some(code) => with(transmission, "error", json!(code)),
            None => transmission,
        }
    };
    for (keep, transmission) in [
        ("response_status", alone("response_status", None)),
        (
            "response_hash",
            alone("response_hash", Some("TRANSPORT_ERROR")),
        ),
        (
            "response_bytes",
            alone("response_bytes", Some("TRANSPORT_ERROR")),
        ),
    ] {
        let manifest = manifest_with("transmitted", transmission);
        assert!(
            !accepted(&manifest),
            "{keep} without the other two response members must not validate"
        );
    }
}

#[test]
fn malformed_members_and_unknown_members_are_rejected() {
    let rejected = [
        (
            "unknown member",
            with(clean_exchange(), "headers", json!({})),
        ),
        (
            "a host that is empty",
            with(clean_exchange(), "endpoint_host", json!("")),
        ),
        (
            "a hash that is not blake3",
            with(clean_exchange(), "request_hash", json!("sha256:abc")),
        ),
        (
            "a response hash that is not blake3",
            with(clean_exchange(), "response_hash", json!("abc")),
        ),
        (
            "a status below 100",
            with(clean_exchange(), "response_status", json!(99)),
        ),
        (
            "a status above 599",
            with(clean_exchange(), "response_status", json!(600)),
        ),
        (
            "a negative byte count",
            with(clean_exchange(), "request_bytes", json!(-1)),
        ),
        (
            "an error code that is not defined",
            with(
                without(
                    without(
                        without(clean_exchange(), "response_status"),
                        "response_hash",
                    ),
                    "response_bytes",
                ),
                "error",
                json!("SOMETHING_ELSE"),
            ),
        ),
        (
            "a send time that is not a date-time",
            with(clean_exchange(), "sent_at", json!("yesterday")),
        ),
    ];
    for (why, transmission) in rejected {
        let manifest = manifest_with("transmitted", transmission);
        assert!(!accepted(&manifest), "{why} must not validate");
    }
}

#[test]
fn an_airlock_v0_2_manifest_may_not_carry_a_transmission() {
    // Two rules reject this today: the v0.2 branch forbids `transmission`, and the
    // attestation/sent rules need an `attestation` that v0.2 forbids. Dropping the first
    // changes no verdict, so this test cannot tell the rules apart; it pins the verdict.
    let mut manifest = read_json("fixtures/clean_telemetry_only/expected_manifest.json");
    assert_eq!(manifest["manifest_version"], "airlock.v0.2");
    manifest["transmission"] = not_sent("CONNECT_FAILED");

    assert!(!accepted(&manifest));
}

#[test]
fn the_rust_and_schema_error_codes_are_the_same_set() {
    // A new variant makes this match non-exhaustive, so the list below cannot quietly fall
    // behind the enum.
    fn covered(error: TransmissionError) {
        match error {
            TransmissionError::ClaimBelowRequired
            | TransmissionError::ConnectFailed
            | TransmissionError::ResponseTimeout
            | TransmissionError::ResponseTooLarge
            | TransmissionError::TransportError => {}
        }
    }
    let all = [
        TransmissionError::ClaimBelowRequired,
        TransmissionError::ConnectFailed,
        TransmissionError::ResponseTimeout,
        TransmissionError::ResponseTooLarge,
        TransmissionError::TransportError,
    ];
    all.into_iter().for_each(covered);

    let schema_value = read_json("schemas/airlock.v0.schema.json");
    let mut in_schema: Vec<String> =
        schema_value["$defs"]["transmission"]["properties"]["error"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap().to_owned())
            .collect();
    let mut in_rust: Vec<String> = all.iter().map(|error| error.as_str().to_owned()).collect();
    in_schema.sort();
    in_rust.sort();

    assert_eq!(in_rust, in_schema);
    for error in all {
        // The serde name is the same string as as_str, so a manifest round-trips.
        assert_eq!(serde_json::to_value(error).unwrap(), json!(error.as_str()));
    }
}

#[test]
fn a_transmission_round_trips_without_inventing_members() {
    for value in [
        clean_exchange(),
        not_sent("CONNECT_FAILED"),
        not_sent("CLAIM_BELOW_REQUIRED"),
    ] {
        let parsed: Transmission = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
    }

    let unknown = with(clean_exchange(), "headers", json!({}));
    assert!(serde_json::from_value::<Transmission>(unknown).is_err());
}
