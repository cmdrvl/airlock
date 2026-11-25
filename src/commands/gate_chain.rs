//! The strict-manifest gate's check of a chained turn (al-3pz G11).
//!
//! A manifest that carries a chain link says: this request was built from the response the
//! model gave to the turn before it. Nothing in the manifest proves that response ever came
//! through this gate. This module is how the gate finds out. It keeps the exchanges the gate
//! forwarded (the manifest a request matched, and the hash of the 2xx response streamed back)
//! and walks a chained manifest back to the start of its conversation, asking at every link
//! whether the gate forwarded the exchange that link relies on.
//!
//! The rules follow `airlock chain verify` link by link, in the same order, and report its
//! reason strings, so a directory one of them refuses the other refuses for the same reason
//! (`tests/gate_strict.rs` runs both over the same tampered directories).
//!
//! What this does not prove: a gate receipt is unsigned, and the exchanges a restarted gate
//! knows about are read back from the receipts in `--out-dir`. Whoever can write that
//! directory can add an exchange to it.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use serde_json::Value;

use crate::assembler::{MODEL_OUTPUT_RULE_ID, PromptProvenance};
use crate::chain::{ChainLink, receipt_hashes};

/// What the walk needs to know about one manifest.
struct ManifestNode {
    chain: Option<ChainLink>,
    prompt_provenance_hash: String,
}

/// What the walk needs to know about one prompt provenance file.
struct ProvenanceNode {
    chain: Option<ChainLink>,
    /// The distinct `source_artifact_hash` values of its `chain.model_output` records: the
    /// responses the turn admitted.
    model_output_hashes: BTreeSet<String>,
}

/// Every manifest and prompt provenance file in the strict-manifest directory, found by
/// content: the hash of a manifest as the gate computes it, and the hash of a provenance file,
/// are the only keys. A file name or a `prompt_provenance_ref` is whatever its author typed.
#[derive(Default)]
pub struct ChainIndex {
    manifests: BTreeMap<String, ManifestNode>,
    provenances: BTreeMap<String, ProvenanceNode>,
}

/// Why a chained request is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainFault {
    /// A link cannot be followed: a file that should describe it is missing or disagrees with
    /// another. `reason` is `airlock chain verify`'s name for the same fault.
    Unresolved {
        reason: &'static str,
        manifest_hash: String,
    },
    /// Every link resolves, but the gate did not forward the exchange one of them relies on.
    NotForwarded {
        prior_manifest_hash: String,
        response_hash: String,
    },
}

impl ChainFault {
    /// The finding rule the gate records for this refusal.
    pub fn rule_id(&self) -> &'static str {
        match self {
            ChainFault::Unresolved { .. } => "REQUEST_CHAIN_UNRESOLVED",
            ChainFault::NotForwarded { .. } => "REQUEST_CHAIN_RESPONSE_NOT_FORWARDED",
        }
    }
}

impl fmt::Display for ChainFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainFault::Unresolved {
                reason,
                manifest_hash,
            } => write!(formatter, "{reason} (at manifest {manifest_hash})"),
            ChainFault::NotForwarded {
                prior_manifest_hash,
                response_hash,
            } => write!(
                formatter,
                "this gate has not forwarded the response {response_hash} to a request that matched manifest {prior_manifest_hash}"
            ),
        }
    }
}

impl ChainIndex {
    /// Index a manifest under `hash`, the hash the gate computes and stamps into receipts.
    pub fn add_manifest(
        &mut self,
        hash: String,
        chain: Option<ChainLink>,
        prompt_provenance_hash: String,
    ) {
        self.manifests.entry(hash).or_insert(ManifestNode {
            chain,
            prompt_provenance_hash,
        });
    }

    pub fn add_provenance(&mut self, provenance: &PromptProvenance) {
        let model_output_hashes = provenance
            .records
            .iter()
            .filter(|record| record.policy_rule_id == MODEL_OUTPUT_RULE_ID)
            .map(|record| record.source_artifact_hash.clone())
            .collect();
        self.provenances
            .entry(provenance.hash())
            .or_insert(ProvenanceNode {
                chain: provenance.chain.clone(),
                model_output_hashes,
            });
    }

    /// Walk from the manifest a request matched back to the start of its conversation. A
    /// manifest with no chain link (a conversation's first turn, or any v0.2 or v0.3 manifest)
    /// has nothing before it and is admitted.
    pub fn check(
        &self,
        matched_manifest_hash: &str,
        forwarded: &ForwardedExchanges,
    ) -> Result<(), ChainFault> {
        let mut hash = matched_manifest_hash;
        loop {
            let unresolved = |reason: &'static str| ChainFault::Unresolved {
                reason,
                manifest_hash: hash.to_owned(),
            };
            // The matched manifest was indexed when the directory was loaded, so a miss is a
            // gate bug. It is refused, not waved through.
            let Some(current) = self.manifests.get(hash) else {
                return Err(unresolved("manifest_not_indexed"));
            };
            let Some(link) = &current.chain else {
                return Ok(());
            };
            let Some(prior) = self.manifests.get(&link.prior_manifest_hash) else {
                return Err(unresolved("prior_manifest_not_found"));
            };
            let expected_index = match &prior.chain {
                None => Some(1),
                Some(prior_link) => prior_link.turn_index.checked_add(1),
            };
            if expected_index != Some(link.turn_index) {
                return Err(unresolved("turn_index_mismatch"));
            }
            let Some(provenance) = self.provenances.get(&current.prompt_provenance_hash) else {
                return Err(unresolved("provenance_not_found"));
            };
            if provenance.chain.as_ref() != Some(link) {
                return Err(unresolved("provenance_chain_mismatch"));
            }
            let mut admitted = provenance.model_output_hashes.iter();
            let response_hash = match (admitted.next(), admitted.next()) {
                (Some(only), None) => only,
                (None, _) => return Err(unresolved("model_output_hash_missing")),
                (Some(_), Some(_)) => return Err(unresolved("model_output_hash_ambiguous")),
            };
            if !forwarded.contains(&link.prior_manifest_hash, response_hash) {
                return Err(ChainFault::NotForwarded {
                    prior_manifest_hash: link.prior_manifest_hash.clone(),
                    response_hash: response_hash.clone(),
                });
            }
            // Each step lowers turn_index by one (checked above), so the walk ends at a root.
            hash = &link.prior_manifest_hash;
        }
    }
}

/// The exchanges this gate has forwarded: `(matched manifest hash, response hash)` for each 2xx
/// upstream response it streamed back to a request that matched a manifest.
#[derive(Default)]
pub struct ForwardedExchanges {
    exchanges: Mutex<HashSet<(String, String)>>,
}

impl ForwardedExchanges {
    /// Remember an exchange. A poisoned lock records nothing, which can only make the gate
    /// refuse more.
    pub fn record(&self, matched_manifest_hash: &str, response_hash: &str) {
        if let Ok(mut exchanges) = self.exchanges.lock() {
            exchanges.insert((matched_manifest_hash.to_owned(), response_hash.to_owned()));
        }
    }

    pub fn contains(&self, matched_manifest_hash: &str, response_hash: &str) -> bool {
        self.exchanges.lock().is_ok_and(|exchanges| {
            exchanges.contains(&(matched_manifest_hash.to_owned(), response_hash.to_owned()))
        })
    }

    /// Read back the exchanges earlier runs of this gate recorded: every receipt in `directory`
    /// that `airlock chain verify` would also accept as one (a forwarded request, a 2xx status,
    /// a response hash and a matched manifest). Returns how many it found. A file that is not
    /// JSON, or a receipt that fails those rules, is skipped; one that cannot be read stops the
    /// gate, since a silent skip could hide the very receipt a link needs.
    pub fn seed_from_receipts(&self, directory: &Path) -> Result<usize, String> {
        let entries = fs::read_dir(directory)
            .map_err(|error| format!("receipt directory is unreadable: {error}"))?;
        let mut found = 0;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("receipt directory could not be read: {error}"))?
                .path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") || !path.is_file() {
                continue;
            }
            let bytes = fs::read(&path)
                .map_err(|error| format!("receipt {} is unreadable: {error}", path.display()))?;
            let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if let Ok((response_hash, matched_manifest_hash)) = receipt_hashes(&value) {
                self.record(&matched_manifest_hash, &response_hash);
                found += 1;
            }
        }
        Ok(found)
    }
}
