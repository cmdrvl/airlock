//! Conversation chains: tying an earlier turn's response to the gate receipt that recorded it.
//!
//! A manifest is written by `verify` before the request is sent, so it cannot hold the response
//! hash. The gate receipt (`airlock.gate.v1`) is the artifact that does: it records the hash of
//! the upstream response body and, in strict-manifest mode, `matched_manifest_hash` naming the
//! manifest the forwarded request matched. A receipt is plain unsigned JSON, so the link from a
//! manifest to its response is only as strong as the receipt file's custody.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::hash::{blake3_hash, is_canonical_blake3_hash};
use crate::manifest::{AirlockManifest, is_supported_manifest_version};
use crate::refusal::RefusalEnvelope;

/// The only receipt version this module reads.
pub const GATE_RECEIPT_VERSION: &str = "airlock.gate.v1";

/// The link from a chained turn to the turn before it. `assemble` writes it into the prompt
/// provenance, `verify` and `send` copy it into the manifest (which makes that manifest
/// `airlock.v0.4`), and `airlock chain verify` walks it. A manifest with no link is turn 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainLink {
    /// `blake3:` hash of the prior turn's manifest, as [`AirlockManifest::hash`] computes it:
    /// the same value the gate stamps into a receipt as `matched_manifest_hash`.
    pub prior_manifest_hash: String,
    /// 1 for the first turn after a manifest that has no link, then one more than the prior
    /// manifest's index. Never 0: turn 0 is the absence of a link.
    pub turn_index: u64,
}

impl ChainLink {
    /// Why this link cannot be valid, or `None`.
    pub fn invalid_reason(&self) -> Option<&'static str> {
        if !is_canonical_blake3_hash(&self.prior_manifest_hash) {
            return Some("prior_manifest_hash must be blake3: followed by 64 lowercase hex digits");
        }
        if self.turn_index == 0 {
            return Some("turn_index must be at least 1; turn 0 is a manifest with no chain link");
        }
        None
    }
}

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

fn bad_prior_manifest(message: &str, field: &str, extra: Value) -> RefusalEnvelope {
    let field = if field.is_empty() {
        "prior_manifest".to_string()
    } else {
        format!("prior_manifest.{field}")
    };
    let mut detail = json!({ "field": field });
    if let (Some(detail), Some(extra)) = (detail.as_object_mut(), extra.as_object()) {
        detail.extend(extra.clone());
    }
    RefusalEnvelope::bad_input(message.to_string(), detail)
}

/// The link a turn that follows `manifest_bytes` carries, given the receipt's
/// `matched_manifest_hash`.
///
/// The receipt names the prior manifest by hash and cannot carry an index, so the manifest
/// itself is needed. This refuses, with `E_BAD_INPUT` and the failing field, when the bytes are
/// not an airlock manifest, are a version this binary does not read, break the chain-member
/// rule for their version, or hash to something other than `matched_manifest_hash` (the receipt
/// belongs to a different manifest). The hash is the one the gate computes: the canonical JSON of
/// the parsed manifest, signature included.
pub fn link_to_prior_manifest(
    matched_manifest_hash: &str,
    manifest_bytes: &[u8],
) -> Result<ChainLink, RefusalEnvelope> {
    let manifest: AirlockManifest = serde_json::from_slice(manifest_bytes).map_err(|error| {
        bad_prior_manifest(
            "prior manifest is not an airlock manifest",
            "",
            json!({ "error": error.to_string() }),
        )
    })?;
    if !is_supported_manifest_version(&manifest.manifest_version) {
        return Err(bad_prior_manifest(
            "prior manifest is a version this airlock does not read",
            "manifest_version",
            json!({ "manifest_version": manifest.manifest_version }),
        ));
    }
    if let Some(reason) = manifest.chain_shape_error() {
        return Err(bad_prior_manifest(
            &format!("prior manifest is malformed: {reason}"),
            "chain",
            json!({ "manifest_version": manifest.manifest_version }),
        ));
    }
    let manifest_hash = manifest.hash();
    if manifest_hash != matched_manifest_hash {
        return Err(bad_prior_manifest(
            "prior manifest is not the manifest the receipt matched",
            "hash",
            json!({
                "receipt_matched_manifest_hash": matched_manifest_hash,
                "manifest_hash": manifest_hash,
            }),
        ));
    }
    let turn_index = match &manifest.chain {
        None => 1,
        Some(link) => link.turn_index.checked_add(1).ok_or_else(|| {
            bad_prior_manifest(
                "prior manifest's turn_index cannot be incremented",
                "chain",
                json!({ "turn_index": link.turn_index }),
            )
        })?,
    };
    Ok(ChainLink {
        prior_manifest_hash: manifest_hash,
        turn_index,
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

    // --- chain links (al-210 D-c) ---------------------------------------------------------

    /// A real airlock.v0.3 manifest and a real airlock.v0.2 one: the goldens `verify` wrote.
    const V0_3: &str = include_str!("../fixtures/clean_telemetry_only/expected_manifest_v0_3.json");
    const V0_2: &str = include_str!("../fixtures/clean_telemetry_only/expected_manifest.json");

    fn gate_hash(manifest_text: &str) -> String {
        serde_json::from_str::<AirlockManifest>(manifest_text)
            .expect("a manifest")
            .hash()
    }

    /// `V0_3` turned into a v0.4 manifest whose own link is `turn_index`.
    fn v0_4_at(turn_index: u64) -> String {
        let mut value: Value = serde_json::from_str(V0_3).expect("json");
        value["manifest_version"] = json!("airlock.v0.4");
        value["chain"] = json!({
            "prior_manifest_hash": blake3_hash(b"an earlier manifest"),
            "turn_index": turn_index,
        });
        serde_json::to_string(&value).expect("serialize")
    }

    fn manifest_refusal_field(matched: &str, manifest_text: &str) -> String {
        let refusal =
            link_to_prior_manifest(matched, manifest_text.as_bytes()).expect_err("must refuse");
        assert_eq!(refusal.refusal.code.as_str(), "E_BAD_INPUT");
        refusal.refusal.detail["field"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn a_link_is_valid_only_with_a_canonical_hash_and_an_index_of_at_least_one() {
        let good = ChainLink {
            prior_manifest_hash: blake3_hash(b"m"),
            turn_index: 1,
        };
        assert_eq!(good.invalid_reason(), None);
        for bad_hash in [
            "".to_string(),
            "blake3:abc".to_string(),
            blake3_hash(b"m").to_uppercase(),
            blake3_hash(b"m").replace("blake3:", "sha256:"),
            format!("{} ", blake3_hash(b"m")),
        ] {
            let link = ChainLink {
                prior_manifest_hash: bad_hash.clone(),
                turn_index: 1,
            };
            assert!(link.invalid_reason().is_some(), "{bad_hash:?}");
        }
        let turn_zero = ChainLink {
            turn_index: 0,
            ..good.clone()
        };
        assert!(turn_zero.invalid_reason().unwrap().contains("turn_index"));
        assert_eq!(
            ChainLink {
                turn_index: u64::MAX,
                ..good
            }
            .invalid_reason(),
            None
        );
    }

    #[test]
    fn a_link_deserializes_only_from_exactly_its_two_members() {
        let hash = blake3_hash(b"m");
        assert!(
            serde_json::from_value::<ChainLink>(
                json!({"prior_manifest_hash": hash, "turn_index": 1})
            )
            .is_ok()
        );
        for bad in [
            json!({"prior_manifest_hash": hash}),
            json!({"turn_index": 1}),
            json!({"prior_manifest_hash": hash, "turn_index": 1, "response_hash": hash}),
            json!({"prior_manifest_hash": hash, "turn_index": -1}),
            json!({"prior_manifest_hash": hash, "turn_index": "1"}),
        ] {
            assert!(
                serde_json::from_value::<ChainLink>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_first_turn_after_a_manifest_with_no_link_is_turn_one_and_names_the_gate_hash() {
        for (label, text) in [("v0.3", V0_3), ("v0.2", V0_2)] {
            let hash = gate_hash(text);
            let link = link_to_prior_manifest(&hash, text.as_bytes()).expect("linked");
            assert_eq!(link.prior_manifest_hash, hash, "{label}");
            assert_eq!(link.turn_index, 1, "{label}");
        }
    }

    #[test]
    fn a_turn_after_a_chained_manifest_is_one_more_than_its_index() {
        for index in [1, 2, 41] {
            let text = v0_4_at(index);
            let link = link_to_prior_manifest(&gate_hash(&text), text.as_bytes()).expect("linked");
            assert_eq!(link.turn_index, index + 1);
            assert_eq!(
                link.prior_manifest_hash,
                gate_hash(&text),
                "the hash of the v0.4 manifest, chain member included"
            );
        }
    }

    #[test]
    fn the_hash_covers_the_chain_member_so_changing_the_link_changes_the_hash() {
        assert_ne!(gate_hash(&v0_4_at(1)), gate_hash(&v0_4_at(2)));
    }

    #[test]
    fn a_receipt_naming_a_different_manifest_is_refused_with_both_hashes() {
        let refusal = link_to_prior_manifest(&blake3_hash(b"someone else's"), V0_3.as_bytes())
            .expect_err("must refuse");
        let detail = &refusal.refusal.detail;
        assert_eq!(detail["field"], "prior_manifest.hash");
        assert_eq!(
            detail["receipt_matched_manifest_hash"],
            blake3_hash(b"someone else's")
        );
        assert_eq!(detail["manifest_hash"], gate_hash(V0_3));
    }

    #[test]
    fn a_manifest_that_cannot_anchor_a_chain_is_refused_by_field() {
        let hash = gate_hash(V0_3);

        assert_eq!(manifest_refusal_field(&hash, "not json"), "prior_manifest");
        assert_eq!(manifest_refusal_field(&hash, "{}"), "prior_manifest");

        let mut unsupported: Value = serde_json::from_str(V0_3).unwrap();
        unsupported["manifest_version"] = json!("airlock.v0.5");
        assert_eq!(
            manifest_refusal_field(&hash, &unsupported.to_string()),
            "prior_manifest.manifest_version"
        );

        // v0.4 without its chain member, and a chain member on a version that may not have one.
        let mut v0_4_without = unsupported.clone();
        v0_4_without["manifest_version"] = json!("airlock.v0.4");
        assert_eq!(
            manifest_refusal_field(&hash, &v0_4_without.to_string()),
            "prior_manifest.chain"
        );
        let mut v0_3_with: Value = serde_json::from_str(V0_3).unwrap();
        v0_3_with["chain"] = json!({
            "prior_manifest_hash": blake3_hash(b"x"),
            "turn_index": 1,
        });
        assert_eq!(
            manifest_refusal_field(&hash, &v0_3_with.to_string()),
            "prior_manifest.chain"
        );
        let mut index_zero: Value = serde_json::from_str(&v0_4_at(1)).unwrap();
        index_zero["chain"]["turn_index"] = json!(0);
        assert_eq!(
            manifest_refusal_field(&hash, &index_zero.to_string()),
            "prior_manifest.chain"
        );
    }

    #[test]
    fn an_index_that_cannot_be_incremented_is_refused_not_wrapped() {
        let text = v0_4_at(u64::MAX);
        assert_eq!(
            manifest_refusal_field(&gate_hash(&text), &text),
            "prior_manifest.chain"
        );
    }
}
