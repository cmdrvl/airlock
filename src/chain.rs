//! Conversation chains: tying an earlier turn's response to the gate receipt that recorded it.
//!
//! A manifest is written by `verify` before the request is sent, so it cannot hold the response
//! hash. The gate receipt (`airlock.gate.v1`) is the artifact that does: it records the hash of
//! the upstream response body and, in strict-manifest mode, `matched_manifest_hash` naming the
//! manifest the forwarded request matched. A receipt is plain unsigned JSON, so the link from a
//! manifest to its response is only as strong as the receipt file's custody.

use serde_json::{Value, json};

use crate::hash::{blake3_hash, is_canonical_blake3_hash};
use crate::refusal::RefusalEnvelope;

/// The only receipt version this module reads.
pub const GATE_RECEIPT_VERSION: &str = "airlock.gate.v1";

/// What a receipt vouches for once its response hash matched the bytes in hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedReceipt {
    /// `blake3:` hash of the response bytes; equal to the receipt's `response_hash`.
    pub response_hash: String,
    /// The manifest the gate matched the forwarded request to.
    pub matched_manifest_hash: String,
}

fn bad_receipt(message: &str, field: &str) -> RefusalEnvelope {
    RefusalEnvelope::bad_input(
        message.to_string(),
        json!({ "field": format!("prior_receipt.{field}") }),
    )
}

/// Check that `receipt` records exactly the response `response_bytes`, for a request the gate
/// admitted and the upstream answered successfully.
///
/// Refuses, with `E_BAD_INPUT` and the failing field, when the receipt is not an
/// `airlock.gate.v1` object, was a blocked request, has no 2xx upstream status, has no
/// `response_hash`, records a different hash than the bytes hash to, or names no
/// `matched_manifest_hash` (a policy-proxy receipt has none, so it cannot anchor a chain).
pub fn check_receipt(
    receipt: &Value,
    response_bytes: &[u8],
) -> Result<CheckedReceipt, RefusalEnvelope> {
    let object = receipt
        .as_object()
        .ok_or_else(|| bad_receipt("prior receipt must be a JSON object", ""))?;

    if object.get("gate_version").and_then(Value::as_str) != Some(GATE_RECEIPT_VERSION) {
        return Err(bad_receipt(
            "prior receipt is not an airlock.gate.v1 receipt",
            "gate_version",
        ));
    }
    if object.get("blocked").and_then(Value::as_bool) != Some(false) {
        return Err(bad_receipt(
            "prior receipt records a blocked request, so no response was forwarded",
            "blocked",
        ));
    }
    let status = object.get("upstream_status").and_then(Value::as_u64);
    if !status.is_some_and(|status| (200..300).contains(&status)) {
        return Err(bad_receipt(
            "prior receipt has no successful (2xx) upstream status; an error body is not model output",
            "upstream_status",
        ));
    }
    let recorded = object
        .get("response_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| bad_receipt("prior receipt records no response_hash", "response_hash"))?;

    let actual = blake3_hash(response_bytes);
    if recorded != actual {
        return Err(RefusalEnvelope::bad_input(
            "response does not match the response_hash in the prior receipt",
            json!({
                "field": "prior_receipt.response_hash",
                "receipt_response_hash": recorded,
                "response_hash": actual,
            }),
        ));
    }

    let matched_manifest_hash = object
        .get("matched_manifest_hash")
        .and_then(Value::as_str)
        .filter(|hash| is_canonical_blake3_hash(hash))
        .ok_or_else(|| {
            bad_receipt(
                "prior receipt names no matched manifest; only a strict-manifest receipt can anchor a chain",
                "matched_manifest_hash",
            )
        })?;

    Ok(CheckedReceipt {
        response_hash: actual,
        matched_manifest_hash: matched_manifest_hash.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE: &[u8] = br#"{"object":"response"}"#;

    fn manifest_hash() -> String {
        blake3_hash(b"the prior manifest")
    }

    fn good_receipt() -> Value {
        json!({
            "gate_version": GATE_RECEIPT_VERSION,
            "mode": "strict-manifest",
            "achieved_claim": "STRICT_TELEMETRY_ONLY",
            "request_hash": blake3_hash(b"the request"),
            "response_hash": blake3_hash(RESPONSE),
            "upstream_status": 200,
            "blocked": false,
            "findings": [],
            "timestamp": "2026-11-25T00:00:00Z",
            "matched_manifest_hash": manifest_hash(),
        })
    }

    fn refused_field(receipt: &Value, response: &[u8]) -> String {
        let refusal = check_receipt(receipt, response).expect_err("must refuse");
        refusal.refusal.detail["field"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn a_receipt_that_records_this_response_is_accepted() {
        let checked = check_receipt(&good_receipt(), RESPONSE).expect("accepted");
        assert_eq!(checked.response_hash, blake3_hash(RESPONSE));
        assert_eq!(checked.matched_manifest_hash, manifest_hash());
    }

    #[test]
    fn a_response_that_differs_by_one_byte_is_refused_with_both_hashes() {
        let mut altered = RESPONSE.to_vec();
        *altered.last_mut().unwrap() = b' ';
        let refusal = check_receipt(&good_receipt(), &altered).expect_err("must refuse");
        let detail = &refusal.refusal.detail;
        assert_eq!(detail["field"], "prior_receipt.response_hash");
        assert_eq!(detail["receipt_response_hash"], blake3_hash(RESPONSE));
        assert_eq!(detail["response_hash"], blake3_hash(&altered));
    }

    #[test]
    fn each_missing_or_wrong_receipt_field_is_refused_by_name() {
        type Edit = fn(&mut Value);
        let cases: [(&str, Edit); 7] = [
            ("prior_receipt.gate_version", |r| {
                r["gate_version"] = json!("airlock.gate.v0");
            }),
            ("prior_receipt.blocked", |r| r["blocked"] = json!(true)),
            ("prior_receipt.blocked", |r| {
                r.as_object_mut().unwrap().remove("blocked");
            }),
            ("prior_receipt.upstream_status", |r| {
                r["upstream_status"] = json!(500);
            }),
            ("prior_receipt.upstream_status", |r| {
                r.as_object_mut().unwrap().remove("upstream_status");
            }),
            ("prior_receipt.response_hash", |r| {
                r.as_object_mut().unwrap().remove("response_hash");
            }),
            ("prior_receipt.matched_manifest_hash", |r| {
                r.as_object_mut().unwrap().remove("matched_manifest_hash");
            }),
        ];
        for (expected_field, edit) in cases {
            let mut receipt = good_receipt();
            edit(&mut receipt);
            assert_eq!(refused_field(&receipt, RESPONSE), expected_field);
        }
    }

    #[test]
    fn a_malformed_matched_manifest_hash_is_refused() {
        let uppercase_hex = format!("blake3:{}", "A".repeat(64));
        for bad in [
            "",
            "blake3:abc",
            "sha256:",
            "BLAKE3:00",
            uppercase_hex.as_str(),
        ] {
            let mut receipt = good_receipt();
            receipt["matched_manifest_hash"] = json!(bad);
            assert_eq!(
                refused_field(&receipt, RESPONSE),
                "prior_receipt.matched_manifest_hash",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_receipt_that_is_not_an_object_is_refused() {
        assert_eq!(refused_field(&json!([1, 2]), RESPONSE), "prior_receipt.");
    }

    #[test]
    fn the_2xx_range_is_inclusive_of_200_and_299_and_excludes_199_and_300() {
        for (status, accepted) in [(199, false), (200, true), (299, true), (300, false)] {
            let mut receipt = good_receipt();
            receipt["upstream_status"] = json!(status);
            assert_eq!(
                check_receipt(&receipt, RESPONSE).is_ok(),
                accepted,
                "status {status}"
            );
        }
    }
}
