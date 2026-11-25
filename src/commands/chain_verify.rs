use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};

use crate::assembler::{MODEL_OUTPUT_RULE_ID, PromptProvenance};
use crate::chain::receipt_hashes;
use crate::cli::{ChainCommands, ChainVerifyArgs, VERIFY_PASS};
use crate::manifest::{AirlockManifest, is_supported_manifest_version};
use crate::output::canonical_json;
use crate::refusal::RefusalEnvelope;
use crate::signing;

/// What this command does and does not establish, said on every successful report.
const UNSIGNED_RECEIPT_NOTE: &str = "a gate receipt is unsigned: this checks that the hashes of the manifests, provenance files and receipts agree with each other, not who produced any of them";

/// `airlock chain verify`: walk a manifest's chain back to turn 0 and check every link.
///
/// Exit 0 and a report when every link holds; otherwise a refusal (exit 2, `E_BAD_MANIFEST`)
/// whose detail has a stable `reason`, the `turn_index` and `manifest_hash` of the manifest
/// whose link failed, and what was expected. Read-only: nothing is written and nothing is
/// recorded in the witness ledger, and nothing is fetched; everything read is in the two
/// directories and the manifest given.
pub fn run(command: ChainCommands) -> u8 {
    match command {
        ChainCommands::Verify(args) => run_with_writer(args, &mut io::stdout()),
    }
}

fn run_with_writer(args: ChainVerifyArgs, stdout: &mut impl Write) -> u8 {
    match verify_chain(&args) {
        Ok(report) => {
            let _ = writeln!(stdout, "{}", canonical_json(&report));
            VERIFY_PASS
        }
        Err(refusal) => refusal.write_to(stdout),
    }
}

/// One manifest read from disk: what its signature covers (`value`), what the gate hashes
/// (`manifest`, parsed), and that hash.
struct Turn {
    path: PathBuf,
    value: Value,
    manifest: AirlockManifest,
    hash: String,
}

impl Turn {
    /// The index of the turn this manifest is: its link's, or 0 for a manifest with no link.
    fn index(&self) -> u64 {
        self.manifest
            .chain
            .as_ref()
            .map_or(0, |link| link.turn_index)
    }

    fn file(&self) -> String {
        file_name(&self.path)
    }
}

struct Receipt {
    file: String,
    response_hash: String,
    matched_manifest_hash: String,
}

/// Every manifest and provenance file in the manifest directory, found by content: the gate
/// hash of a manifest and the hash of a provenance are the only keys. A file name or a
/// `prompt_provenance_ref` is whatever its author typed and is never trusted.
struct Library {
    manifests: BTreeMap<String, Turn>,
    provenances: BTreeMap<String, PromptProvenance>,
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn read_error(path: &Path, error: io::Error) -> RefusalEnvelope {
    if error.kind() == io::ErrorKind::NotFound {
        return RefusalEnvelope::missing_file(path.display().to_string());
    }
    RefusalEnvelope::bad_input(
        "failed to read",
        json!({ "path": path.display().to_string(), "error": error.to_string() }),
    )
}

/// The `*.json` files directly in `dir`, sorted, so the same directory always gives the same
/// answer. A file that cannot be read refuses: a silent skip could hide the very file a link
/// needs.
fn json_files(dir: &Path) -> Result<Vec<PathBuf>, RefusalEnvelope> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|error| read_error(dir, error))? {
        let path = entry.map_err(|error| read_error(dir, error))?.path();
        if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn turn_from_value(path: PathBuf, value: Value) -> Option<Turn> {
    let manifest: AirlockManifest = serde_json::from_value(value.clone()).ok()?;
    if !is_supported_manifest_version(&manifest.manifest_version) {
        return None;
    }
    let hash = manifest.hash();
    Some(Turn {
        path,
        value,
        manifest,
        hash,
    })
}

fn load_library(dir: &Path) -> Result<Library, RefusalEnvelope> {
    let mut library = Library {
        manifests: BTreeMap::new(),
        provenances: BTreeMap::new(),
    };
    for path in json_files(dir)? {
        let bytes = std::fs::read(&path).map_err(|error| read_error(&path, error))?;
        // Anything else that lives in the directory is not this command's business.
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if value.get("manifest_version").is_some() {
            if let Some(turn) = turn_from_value(path, value) {
                library.manifests.entry(turn.hash.clone()).or_insert(turn);
            }
        } else if let Ok(provenance) = serde_json::from_value::<PromptProvenance>(value) {
            library
                .provenances
                .entry(provenance.hash())
                .or_insert(provenance);
        }
    }
    Ok(library)
}

/// Every receipt in `dir` that meets the rules `assemble` applies to a prior receipt other
/// than the comparison with response bytes.
fn load_receipts(dir: &Path) -> Result<Vec<Receipt>, RefusalEnvelope> {
    let mut receipts = Vec::new();
    for path in json_files(dir)? {
        let bytes = std::fs::read(&path).map_err(|error| read_error(&path, error))?;
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if let Ok((response_hash, matched_manifest_hash)) = receipt_hashes(&value) {
            receipts.push(Receipt {
                file: file_name(&path),
                response_hash,
                matched_manifest_hash,
            });
        }
    }
    Ok(receipts)
}

fn load_entry(path: &Path) -> Result<Turn, RefusalEnvelope> {
    let bytes = std::fs::read(path).map_err(|error| read_error(path, error))?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        RefusalEnvelope::bad_manifest(
            "manifest is not valid JSON",
            json!({ "path": path.display().to_string(), "error": error.to_string() }),
        )
    })?;
    let manifest: AirlockManifest = serde_json::from_value(value.clone()).map_err(|error| {
        RefusalEnvelope::bad_manifest(
            "file is not an airlock manifest",
            json!({
                "reason": "not_a_manifest",
                "path": path.display().to_string(),
                "error": error.to_string(),
            }),
        )
    })?;
    if !is_supported_manifest_version(&manifest.manifest_version) {
        return Err(RefusalEnvelope::bad_manifest(
            "manifest is a version this airlock does not read",
            json!({
                "reason": "unsupported_manifest_version",
                "path": path.display().to_string(),
                "manifest_version": manifest.manifest_version,
            }),
        ));
    }
    let hash = manifest.hash();
    Ok(Turn {
        path: path.to_path_buf(),
        value,
        manifest,
        hash,
    })
}

/// A refusal about `turn`'s link, with the fields every one of them carries.
fn broken(
    reason: &'static str,
    message: impl Into<String>,
    turn: &Turn,
    extra: Value,
) -> RefusalEnvelope {
    let mut detail = json!({
        "reason": reason,
        "turn_index": turn.index(),
        "manifest_hash": turn.hash,
        "path": turn.path.display().to_string(),
    });
    if let (Some(detail), Some(extra)) = (detail.as_object_mut(), extra.as_object()) {
        detail.extend(extra.clone());
    }
    RefusalEnvelope::bad_manifest(message, detail)
}

/// The one response hash the turn's `chain.model_output` records name: the response the turn
/// admitted. None, or two different ones, leaves nothing to tie a receipt to.
fn admitted_response_hash(
    provenance: &PromptProvenance,
    turn: &Turn,
) -> Result<String, RefusalEnvelope> {
    let hashes: BTreeSet<&str> = provenance
        .records
        .iter()
        .filter(|record| record.policy_rule_id == MODEL_OUTPUT_RULE_ID)
        .map(|record| record.source_artifact_hash.as_str())
        .collect();
    let mut hashes = hashes.into_iter();
    match (hashes.next(), hashes.next()) {
        (Some(only), None) => Ok(only.to_string()),
        (None, _) => Err(broken(
            "model_output_hash_missing",
            "the turn's provenance has no model output record, so no response hash to match a receipt to",
            turn,
            json!({ "prompt_provenance_hash": turn.manifest.prompt_provenance_hash }),
        )),
        (Some(first), Some(second)) => {
            let mut all = vec![first, second];
            all.extend(hashes);
            Err(broken(
                "model_output_hash_ambiguous",
                "the turn's model output records name more than one response hash",
                turn,
                json!({ "response_hashes": all }),
            ))
        }
    }
}

/// The receipt that vouches for the response `turn` admitted: it names the prior manifest
/// and records that response's hash. Returns its file name.
fn matching_receipt(
    receipts: &[Receipt],
    prior_manifest_hash: &str,
    response_hash: &str,
    turn: &Turn,
) -> Result<String, RefusalEnvelope> {
    let naming_prior: Vec<&Receipt> = receipts
        .iter()
        .filter(|receipt| receipt.matched_manifest_hash == prior_manifest_hash)
        .collect();
    if let Some(found) = naming_prior
        .iter()
        .find(|receipt| receipt.response_hash == response_hash)
    {
        return Ok(found.file.clone());
    }
    if naming_prior.is_empty() {
        return Err(broken(
            "receipt_not_found",
            "no gate receipt names the prior manifest",
            turn,
            json!({
                "prior_manifest_hash": prior_manifest_hash,
                "response_hash": response_hash,
            }),
        ));
    }
    let recorded: BTreeSet<&str> = naming_prior
        .iter()
        .map(|receipt| receipt.response_hash.as_str())
        .collect();
    Err(broken(
        "receipt_response_mismatch",
        "a gate receipt names the prior manifest but none records the response this turn admitted",
        turn,
        json!({
            "prior_manifest_hash": prior_manifest_hash,
            "response_hash": response_hash,
            "receipt_response_hashes": recorded,
        }),
    ))
}

/// `"ok"`, `"unsigned"` (not refused: a signature is never required) or `"not_checked"`.
fn signature_status(
    turn: &Turn,
    key: Option<&VerifyingKey>,
) -> Result<&'static str, RefusalEnvelope> {
    let Some(key) = key else {
        return Ok("not_checked");
    };
    if turn.manifest.signature.is_none() {
        return Ok("unsigned");
    }
    match signing::verify_value(&turn.value, key) {
        Ok(_) => Ok("ok"),
        Err(failure) => Err(broken(
            "signature_invalid",
            failure.to_string(),
            turn,
            json!({ "signature_reason": failure.reason() }),
        )),
    }
}

fn verify_chain(args: &ChainVerifyArgs) -> Result<Value, RefusalEnvelope> {
    let entry = load_entry(&args.manifest)?;
    let library = load_library(&args.manifest_dir)?;
    let receipts = match &args.receipt_dir {
        Some(dir) => Some(load_receipts(dir)?),
        None => None,
    };
    let key = match &args.pubkey {
        Some(path) => Some(signing::load_verifying_key(path).map_err(|error| error.refusal())?),
        None => None,
    };

    let mut links = Vec::new();
    let mut current = &entry;
    let root = loop {
        if let Some(reason) = current.manifest.chain_shape_error() {
            return Err(broken(
                "chain_shape",
                format!("manifest breaks the chain member rule for its version: {reason}"),
                current,
                json!({ "manifest_version": current.manifest.manifest_version }),
            ));
        }
        let signature = signature_status(current, key.as_ref())?;
        let Some(link) = &current.manifest.chain else {
            break json!({
                "manifest_hash": current.hash,
                "manifest_version": current.manifest.manifest_version,
                "file": current.file(),
                "signature": signature,
            });
        };

        let prior = library
            .manifests
            .get(&link.prior_manifest_hash)
            .ok_or_else(|| {
                broken(
                    "prior_manifest_not_found",
                    "no manifest in the manifest directory has the hash this link names",
                    current,
                    json!({ "prior_manifest_hash": link.prior_manifest_hash }),
                )
            })?;

        let expected_index = match &prior.manifest.chain {
            None => Some(1),
            Some(prior_link) => prior_link.turn_index.checked_add(1),
        };
        if expected_index != Some(link.turn_index) {
            return Err(broken(
                "turn_index_mismatch",
                "the link's turn_index is not one more than the prior manifest's",
                current,
                json!({
                    "turn_index": link.turn_index,
                    "expected_turn_index": expected_index,
                    "prior_manifest_hash": link.prior_manifest_hash,
                }),
            ));
        }

        let provenance = library
            .provenances
            .get(&current.manifest.prompt_provenance_hash)
            .ok_or_else(|| {
                broken(
                    "provenance_not_found",
                    "no prompt provenance in the manifest directory has the hash this manifest names",
                    current,
                    json!({
                        "prompt_provenance_hash": current.manifest.prompt_provenance_hash,
                        "prompt_provenance_ref": current.manifest.prompt_provenance_ref,
                    }),
                )
            })?;
        if provenance.chain.as_ref() != Some(link) {
            return Err(broken(
                "provenance_chain_mismatch",
                "the prompt provenance this manifest names carries a different chain link than the manifest",
                current,
                json!({
                    "manifest_chain": link,
                    "provenance_chain": provenance.chain,
                }),
            ));
        }
        let response_hash = admitted_response_hash(provenance, current)?;

        let (receipt_status, receipt_file) = match &receipts {
            None => ("not_checked", Value::Null),
            Some(receipts) => (
                "ok",
                json!(matching_receipt(
                    receipts,
                    &link.prior_manifest_hash,
                    &response_hash,
                    current
                )?),
            ),
        };

        links.push(json!({
            "turn_index": link.turn_index,
            "manifest_hash": current.hash,
            "file": current.file(),
            "prior_manifest_hash": link.prior_manifest_hash,
            "response_hash": response_hash,
            "receipt_file": receipt_file,
            "checks": {
                "prior_manifest": "ok",
                "turn_index": "ok",
                "provenance": "ok",
                "receipt": receipt_status,
                "signature": signature,
            },
        }));
        current = prior;
    };

    let mut notes = vec![UNSIGNED_RECEIPT_NOTE.to_string()];
    if receipts.is_none() {
        notes.push("receipts were not checked: pass --receipt-dir to check each link against a gate receipt".to_string());
    }
    if key.is_none() {
        notes.push(
            "signatures were not checked: pass --pubkey to check the signed manifests".to_string(),
        );
    }
    Ok(json!({
        "command": "chain verify",
        "verified": true,
        "manifest": args.manifest.display().to_string(),
        "turn_index": entry.index(),
        "links": links,
        "root": root,
        "receipts_checked": receipts.is_some(),
        "signatures_checked": key.is_some(),
        "notes": notes,
    }))
}
