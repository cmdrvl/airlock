use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};

use serde_json::{Value, json};

use crate::assembler::NotCrossedReason;
use crate::cli::ExplainArgs;
use crate::hash::blake3_hash;
use crate::manifest::gate::GateReceipt;
use crate::manifest::{AirlockManifest, Attestation};
use crate::output::canonical_json;
use crate::refusal::RefusalEnvelope;
use crate::types::{BlockedReason, ClaimLevel, Finding};

pub fn run(args: ExplainArgs) -> u8 {
    let mut stdout = io::stdout();
    run_with_writer(args, &mut stdout)
}

fn run_with_writer(args: ExplainArgs, stdout: &mut impl Write) -> u8 {
    let manifest_bytes = match std::fs::read(&args.manifest) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return RefusalEnvelope::missing_file(args.manifest.display().to_string())
                .write_to(stdout);
        }
        Err(err) => {
            return RefusalEnvelope::bad_manifest(
                "failed to read manifest file",
                json!({
                    "path": args.manifest.display().to_string(),
                    "error": err.to_string(),
                }),
            )
            .write_to(stdout);
        }
    };

    if is_gate_receipt(&manifest_bytes) {
        return explain_gate_receipt(&args, &manifest_bytes, stdout);
    }

    let manifest: AirlockManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(err) => {
            return RefusalEnvelope::bad_manifest(
                "manifest file is not valid airlock JSON",
                json!({
                    "path": args.manifest.display().to_string(),
                    "error": err.to_string(),
                }),
            )
            .write_to(stdout);
        }
    };

    let rendered = if args.json {
        canonical_json(&json_explanation(
            &manifest,
            &args.manifest.display().to_string(),
        ))
    } else {
        render_manifest(&manifest)
    };
    let _ = stdout.write_all(rendered.as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    0
}

const GATE_RECEIPT_VERSION: &str = "airlock.gate.v1";

/// Gate receipts carry `gate_version`, which no Airlock manifest does.
fn is_gate_receipt(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes).is_ok_and(|value| value.get("gate_version").is_some())
}

fn explain_gate_receipt(args: &ExplainArgs, bytes: &[u8], stdout: &mut impl Write) -> u8 {
    let receipt_ref = args.manifest.display().to_string();
    let receipt: GateReceipt = match serde_json::from_slice(bytes) {
        Ok(receipt) => receipt,
        Err(err) => {
            return RefusalEnvelope::bad_manifest(
                "gate receipt file is not valid airlock.gate.v1 JSON",
                json!({ "path": receipt_ref, "error": err.to_string() }),
            )
            .write_to(stdout);
        }
    };
    if receipt.gate_version != GATE_RECEIPT_VERSION {
        return RefusalEnvelope::bad_manifest(
            "unsupported gate receipt version",
            json!({ "path": receipt_ref, "gate_version": receipt.gate_version }),
        )
        .write_to(stdout);
    }

    let rendered = if args.json {
        canonical_json(&json_gate_explanation(&receipt, &receipt_ref))
    } else {
        render_gate_receipt(&receipt)
    };
    let _ = stdout.write_all(rendered.as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    0
}

/// What the gate did with the request, read from the receipt alone.
fn gate_decision(receipt: &GateReceipt) -> &'static str {
    if receipt.blocked {
        "denied"
    } else if receipt
        .findings
        .iter()
        .any(|finding| finding.rule_id == "GATE_STREAM_INTERRUPTED")
    {
        "forwarded_interrupted"
    } else if receipt.upstream_status.is_some() {
        "forwarded"
    } else {
        "authorized_upstream_failed"
    }
}

fn gate_decision_sentence(decision: &str) -> &'static str {
    match decision {
        "denied" => "DENIED. The gate did not forward this request.",
        "forwarded" => "FORWARDED. The gate sent this request upstream and returned the response.",
        "forwarded_interrupted" => {
            "FORWARDED, RESPONSE INCOMPLETE. The request went upstream but the response stream ended early."
        }
        _ => {
            "AUTHORIZED, NOT DELIVERED. The gate admitted this request but the upstream gave no response."
        }
    }
}

/// Why the gate recorded a finding, for the rules the gate itself raises. Detector rules from
/// a policy-proxy scan carry their own ids and get no sentence here.
fn gate_rule_explanation(rule_id: &str) -> Option<&'static str> {
    Some(match rule_id {
        "REQUEST_MANIFEST_NOT_FOUND" => {
            "no verified manifest is bound to this request's canonical hash"
        }
        "REQUEST_CLAIM_BELOW_REQUIRED" => {
            "the manifest bound to this request claims less than --require-claim asks for"
        }
        "REQUEST_SCAN_REFUSED" => {
            "the request body could not be read, parsed or screened, or was over the size limit"
        }
        "INVALID_REQUEST_TARGET" => {
            "the request target was not a plain path starting with a single /"
        }
        "MULTIMODAL_ATTACHMENT_BLOCKED" => {
            "the request carries a media attachment or remote reference the policy does not allow"
        }
        "GATE_BUSY" => "the gate was at its concurrent request limit",
        "UPSTREAM_TIMEOUT" => "the upstream did not answer within --timeout-seconds",
        "UPSTREAM_UNAVAILABLE" => "the upstream could not be reached",
        "GATE_STREAM_INTERRUPTED" => "the response stream ended before it completed",
        _ => return None,
    })
}

/// The request hash recorded when the gate refused before it had one.
fn request_hash_if_computed(receipt: &GateReceipt) -> Option<&str> {
    (receipt.request_hash != blake3_hash(b"unavailable")).then_some(receipt.request_hash.as_str())
}

fn json_gate_explanation(receipt: &GateReceipt, receipt_ref: &str) -> Value {
    let reasons: Vec<Value> = receipt
        .findings
        .iter()
        .map(|finding| {
            json!({
                "rule_id": finding.rule_id,
                "artifact_class": finding.artifact_class,
                "key_path": finding.key_path,
                "explanation": gate_rule_explanation(&finding.rule_id),
            })
        })
        .collect();
    json!({
        "schema": "airlock.explain_gate.v1",
        "tool": "airlock",
        "receipt_ref": receipt_ref,
        "decision": gate_decision(receipt),
        "mode": receipt.mode,
        "claim": { "achieved": receipt.achieved_claim },
        "request": {
            "hash": request_hash_if_computed(receipt),
            "bytes": receipt.request_bytes
        },
        "matched_manifest_hash": receipt.matched_manifest_hash,
        "upstream": {
            "status": receipt.upstream_status,
            "response_hash": receipt.response_hash,
            "response_bytes": receipt.response_bytes
        },
        "limit": receipt.limit,
        "policy": { "id": receipt.policy_id, "hash": receipt.policy_hash },
        "reasons": reasons,
        "recorded_at": receipt.timestamp,
        "next_commands": {
            "human_explain": format!("airlock explain --manifest {receipt_ref}")
        }
    })
}

fn render_gate_receipt(receipt: &GateReceipt) -> String {
    let mut output = String::new();

    writeln!(&mut output, "AIRLOCK GATE").unwrap();
    writeln!(&mut output).unwrap();
    writeln!(
        &mut output,
        "Decision: {}",
        gate_decision_sentence(gate_decision(receipt))
    )
    .unwrap();
    writeln!(&mut output, "Mode: {}", receipt.mode).unwrap();
    writeln!(&mut output, "Claim: {}", receipt.achieved_claim).unwrap();
    writeln!(&mut output).unwrap();

    match (request_hash_if_computed(receipt), receipt.request_bytes) {
        (Some(hash), Some(bytes)) => {
            writeln!(&mut output, "Request: {hash} ({bytes} bytes received)").unwrap()
        }
        (Some(hash), None) => writeln!(&mut output, "Request: {hash}").unwrap(),
        (None, _) => writeln!(
            &mut output,
            "Request: no hash (the gate refused before it had one)"
        )
        .unwrap(),
    }
    if let Some(hash) = &receipt.matched_manifest_hash {
        writeln!(&mut output, "Matched manifest: {hash}").unwrap();
    }
    if let Some(status) = receipt.upstream_status {
        writeln!(&mut output, "Upstream response: HTTP {status}").unwrap();
    }
    if let (Some(bytes), Some(hash)) = (receipt.response_bytes, &receipt.response_hash) {
        writeln!(&mut output, "Response body: {bytes} bytes, {hash}").unwrap();
    }
    if let Some(limit) = &receipt.limit {
        match limit.observed {
            Some(observed) => writeln!(
                &mut output,
                "Limit hit: {} {} (observed {observed})",
                limit.kind, limit.limit
            )
            .unwrap(),
            None => writeln!(&mut output, "Limit hit: {} {}", limit.kind, limit.limit).unwrap(),
        }
    }

    if !receipt.findings.is_empty() {
        writeln!(&mut output).unwrap();
        writeln!(&mut output, "Findings:").unwrap();
        for finding in &receipt.findings {
            match &finding.key_path {
                Some(path) => writeln!(
                    &mut output,
                    "  - {} [{}] at {path}",
                    finding.rule_id, finding.artifact_class
                )
                .unwrap(),
                None => writeln!(
                    &mut output,
                    "  - {} [{}]",
                    finding.rule_id, finding.artifact_class
                )
                .unwrap(),
            }
            if let Some(explanation) = gate_rule_explanation(&finding.rule_id) {
                writeln!(&mut output, "    {explanation}").unwrap();
            }
        }
    }

    writeln!(&mut output).unwrap();
    if let Some(policy_id) = &receipt.policy_id {
        match &receipt.policy_hash {
            Some(hash) => writeln!(&mut output, "Policy: {policy_id} ({hash})").unwrap(),
            None => writeln!(&mut output, "Policy: {policy_id}").unwrap(),
        }
    }
    writeln!(&mut output, "Recorded: {}", receipt.timestamp).unwrap();

    output
}

fn json_explanation(manifest: &AirlockManifest, manifest_ref: &str) -> Value {
    let mut explanation = json!({
        "schema": "airlock.explain.v1",
        "tool": "airlock",
        "manifest_ref": manifest_ref,
        "manifest_hash": manifest.hash(),
        "claim": {
            "achieved": manifest.achieved_claim,
            "boundary_mode": manifest.boundary_mode,
            "raw_document_present": manifest.raw_document_present,
            "filing_derived_text_present": manifest.filing_derived_text_present
        },
        "proof": {
            "policy_id": manifest.policy_id,
            "policy_hash": manifest.policy_hash,
            "prompt_payload_hash": manifest.prompt_payload_hash,
            "prompt_provenance_hash": manifest.prompt_provenance_hash,
            "prompt_provenance_ref": manifest.prompt_provenance_ref,
            "request_payload_hash": manifest.request_payload_hash,
            "replay_ref": manifest.replay_ref,
            "model_id": manifest.model_id,
            "adapter": manifest.adapter
        },
        "provenance_summary": manifest.provenance_summary,
        "blocked_paths": blocked_paths(&manifest.blocked_reasons),
        "blocked_reasons": manifest.blocked_reasons,
        "findings": manifest.findings,
        "next_commands": {
            "human_explain": format!("airlock explain --manifest {manifest_ref}"),
            "verify_again": "airlock verify --policy <POLICY> --prompt <PROMPT> --provenance <PROVENANCE> --request <REQUEST> --out airlock_manifest.json"
        }
    });

    if has_v0_3_fields(manifest) {
        // Mirrors the manifest's own member names. null means the manifest does not carry
        // the member: `signature` null is an unsigned manifest, `not_crossed` null is a
        // verify run that was not given the inventory (an empty array means nothing was
        // left out). The signature value itself is not repeated here and `checked: false`
        // says explain did not verify it.
        explanation["bytes_crossed"] = json!(manifest.bytes_crossed);
        explanation["attestation"] = json!(manifest.attestation.map(Attestation::as_str));
        explanation["not_crossed"] = json!(manifest.not_crossed);
        explanation["signature"] = match &manifest.signature {
            Some(signature) => json!({
                "algorithm": signature.algorithm,
                "public_key_fingerprint": signature.public_key_fingerprint,
                "checked": false
            }),
            None => Value::Null,
        };
    }

    explanation
}

fn render_manifest(manifest: &AirlockManifest) -> String {
    let mut output = String::new();

    writeln!(&mut output, "AIRLOCK").unwrap();
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "Claim achieved: {}", manifest.achieved_claim).unwrap();
    writeln!(&mut output, "Boundary mode: {}", manifest.boundary_mode).unwrap();
    writeln!(&mut output).unwrap();
    writeln!(
        &mut output,
        "Raw document artifacts: {}",
        presence_word(manifest.raw_document_present)
    )
    .unwrap();
    writeln!(
        &mut output,
        "Derived filing text: {}",
        presence_word(manifest.filing_derived_text_present)
    )
    .unwrap();

    if has_v0_3_fields(manifest) {
        render_v0_3_fields(&mut output, manifest);
    }

    if manifest.achieved_claim == ClaimLevel::BoundaryFailed {
        writeln!(&mut output).unwrap();
        writeln!(&mut output, "Boundary violation detected:").unwrap();
        if manifest.findings.is_empty() {
            writeln!(&mut output, "  - no findings recorded").unwrap();
        } else {
            for finding in &manifest.findings {
                writeln!(&mut output, "  - {}", format_finding(finding)).unwrap();
            }
        }
    }

    if manifest.achieved_claim < ClaimLevel::StrictTelemetryOnly {
        writeln!(&mut output).unwrap();
        writeln!(&mut output, "Why strict telemetry-only was not earned:").unwrap();
        let blocked_paths = blocked_paths(&manifest.blocked_reasons);
        if blocked_paths.is_empty() {
            writeln!(&mut output, "  - no blocked reasons recorded").unwrap();
        } else {
            for path in blocked_paths {
                writeln!(&mut output, "  - {path}").unwrap();
            }
        }
    }

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "Prompt provenance:").unwrap();
    writeln!(
        &mut output,
        "  - {} prompt fragments emitted",
        manifest.provenance_summary.total_fragments
    )
    .unwrap();
    for (boundary_class, count) in &manifest.provenance_summary.by_boundary_class {
        writeln!(&mut output, "  - {count} {boundary_class}").unwrap();
    }

    writeln!(&mut output).unwrap();
    writeln!(
        &mut output,
        "Policy: {} ({})",
        manifest.policy_id, manifest.policy_hash
    )
    .unwrap();
    writeln!(&mut output, "Manifest hash: {}", manifest.hash()).unwrap();

    output
}

fn presence_word(is_present: bool) -> &'static str {
    if is_present { "present" } else { "absent" }
}

/// True for a manifest that carries any airlock.v0.3 member. An airlock.v0.2 manifest has
/// none, and its explanation stays exactly as it was before those members existed.
fn has_v0_3_fields(manifest: &AirlockManifest) -> bool {
    manifest.bytes_crossed.is_some()
        || manifest.attestation.is_some()
        || manifest.not_crossed.is_some()
        || manifest.signature.is_some()
}

fn attestation_sentence(attestation: Attestation) -> String {
    match attestation {
        Attestation::SelfAttested => {
            "self_attested (written by airlock verify, not by a send or gate receipt)".to_string()
        }
        other => other.as_str().to_string(),
    }
}

/// The reason as it is written in the manifest. Exhaustive on purpose: a new reason must be
/// named here, and a unit test holds these to the serialized names.
fn not_crossed_reason_word(reason: NotCrossedReason) -> &'static str {
    match reason {
        NotCrossedReason::NotAllowed => "NOT_ALLOWED",
        NotCrossedReason::ForbiddenKey => "FORBIDDEN_KEY",
        NotCrossedReason::DerivedTextExcluded => "DERIVED_TEXT_EXCLUDED",
        NotCrossedReason::ShadowedByEarlierInput => "SHADOWED_BY_EARLIER_INPUT",
    }
}

/// What the manifest says about the request's size, who attested it, who signed it and what
/// was left out. Values that were left out are never in the manifest, so they cannot appear
/// here; only their paths, reasons and hashes do.
fn render_v0_3_fields(output: &mut String, manifest: &AirlockManifest) {
    writeln!(output).unwrap();
    if let Some(bytes) = manifest.bytes_crossed {
        writeln!(output, "Bytes crossed: {bytes}").unwrap();
    }
    if let Some(attestation) = manifest.attestation {
        writeln!(output, "Attestation: {}", attestation_sentence(attestation)).unwrap();
    }
    match &manifest.signature {
        Some(signature) => writeln!(
            output,
            "Signature: {} by {} (explain does not check it; run airlock verify-manifest)",
            signature.algorithm, signature.public_key_fingerprint
        )
        .unwrap(),
        None => writeln!(output, "Signature: none (unsigned manifest)").unwrap(),
    }

    match &manifest.not_crossed {
        None => writeln!(
            output,
            "Left out of the request: not recorded (verify was not given a not-crossed inventory)"
        )
        .unwrap(),
        Some(entries) if entries.is_empty() => writeln!(
            output,
            "Left out of the request: nothing (the not-crossed inventory is empty)"
        )
        .unwrap(),
        Some(entries) => {
            let noun = if entries.len() == 1 {
                "field"
            } else {
                "fields"
            };
            writeln!(
                output,
                "Left out of the request: {} {noun} (values are never stored):",
                entries.len()
            )
            .unwrap();
            for entry in entries {
                writeln!(
                    output,
                    "  - {} [{}] {}",
                    entry.path,
                    not_crossed_reason_word(entry.reason),
                    entry.value_hash
                )
                .unwrap();
            }
        }
    }
}

fn blocked_paths(blocked_reasons: &[BlockedReason]) -> Vec<String> {
    let mut unique = BTreeMap::new();

    for reason in blocked_reasons {
        if reason.offending_paths.is_empty() {
            unique
                .entry(reason.reason.clone())
                .or_insert_with(|| reason.reason.clone());
            continue;
        }

        for path in &reason.offending_paths {
            unique.entry(path.clone()).or_insert_with(|| path.clone());
        }
    }

    unique.into_values().collect()
}

fn format_finding(finding: &Finding) -> String {
    match &finding.sample_value {
        Some(sample) => format!(
            "{} [{} via {}] sample={}",
            finding.key_path, finding.artifact_class, finding.matched_rule, sample
        ),
        None => format!(
            "{} [{} via {}]",
            finding.key_path, finding.artifact_class, finding.matched_rule
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::assembler::NotCrossedEntry;
    use crate::manifest::{
        AIRLOCK_MANIFEST_VERSION, Attestation, ManifestSignature, ProvenanceSummary,
    };
    use crate::refusal::REFUSAL_OUTCOME;
    use crate::types::{BindingStatus, BoundaryMode, UpstreamArtifact};

    fn sample_manifest(
        achieved_claim: ClaimLevel,
        raw_document_present: bool,
        filing_derived_text_present: bool,
        findings: Vec<Finding>,
        blocked_reasons: Vec<BlockedReason>,
    ) -> AirlockManifest {
        let mut by_boundary_class = BTreeMap::new();
        by_boundary_class.insert("DERIVED_TEXT".to_string(), 2);
        by_boundary_class.insert("TELEMETRY".to_string(), 25);

        AirlockManifest {
            manifest_version: AIRLOCK_MANIFEST_VERSION.to_string(),
            binding_status: BindingStatus::Bound,
            boundary_mode: BoundaryMode::Annotated,
            policy_id: "tournament_baseline".to_string(),
            policy_hash: "blake3:1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            claim_levels_evaluated: vec![
                ClaimLevel::BoundaryFailed,
                ClaimLevel::RawDocumentAbsent,
                ClaimLevel::StrictTelemetryOnly,
            ],
            achieved_claim,
            upstream_artifact_inventory: vec![UpstreamArtifact {
                path: "strategy_space.json".to_string(),
                content_hash:
                    "blake3:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                artifact_class: "strategy_space".to_string(),
                extends: None,
            }],
            system_prompt_hash:
                "blake3:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            prompt_payload_hash:
                "blake3:4444444444444444444444444444444444444444444444444444444444444444"
                    .to_string(),
            prompt_provenance_hash:
                "blake3:5555555555555555555555555555555555555555555555555555555555555555"
                    .to_string(),
            prompt_provenance_ref: "prompt_provenance.json".to_string(),
            request_payload_hash:
                "blake3:6666666666666666666666666666666666666666666666666666666666666666"
                    .to_string(),
            replay_ref: "request.json".to_string(),
            model_id: "gpt-5".to_string(),
            adapter: "openai".to_string(),
            raw_document_present,
            filing_derived_text_present,
            findings,
            blocked_reasons,
            provenance_summary: ProvenanceSummary {
                total_fragments: 27,
                by_boundary_class,
            },
            timestamp: "2026-03-26T14:00:00Z".to_string(),
            bytes_crossed: Some(1234),
            attestation: Some(Attestation::SelfAttested),
            not_crossed: None,
            signature: None,
        }
    }

    fn write_manifest_file(tempdir: &tempfile::TempDir, manifest: &AirlockManifest) -> PathBuf {
        let path = tempdir.path().join("airlock_manifest.json");
        std::fs::write(&path, manifest.to_canonical_json()).unwrap();
        path
    }

    #[test]
    fn explain_renders_raw_document_absent_summary() {
        let manifest = sample_manifest(
            ClaimLevel::RawDocumentAbsent,
            false,
            true,
            vec![],
            vec![BlockedReason {
                claim_attempted: ClaimLevel::StrictTelemetryOnly,
                reason: "derived text present".to_string(),
                offending_paths: vec![
                    "mutator_context.challenge_observation".to_string(),
                    "mutator_context.challenge_profile.layout_notes[0]".to_string(),
                ],
            }],
        );
        let tempdir = tempfile::tempdir().unwrap();
        let path = write_manifest_file(&tempdir, &manifest);
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            ExplainArgs {
                manifest: path,
                json: false,
            },
            &mut stdout,
        );

        assert_eq!(exit_code, 0);
        let rendered = String::from_utf8(stdout).unwrap();
        assert!(rendered.contains("AIRLOCK"));
        assert!(rendered.contains("Claim achieved: RAW_DOCUMENT_ABSENT"));
        assert!(rendered.contains("Boundary mode: ANNOTATED"));
        assert!(rendered.contains("Raw document artifacts: absent"));
        assert!(rendered.contains("Derived filing text: present"));
        assert!(rendered.contains("Why strict telemetry-only was not earned:"));
        assert!(rendered.contains("mutator_context.challenge_observation"));
        assert!(rendered.contains("27 prompt fragments emitted"));
        assert!(rendered.contains("25 TELEMETRY"));
        assert!(rendered.contains("2 DERIVED_TEXT"));
        assert!(rendered.contains("Policy: tournament_baseline"));
        assert!(rendered.contains("Manifest hash: blake3:"));
    }

    #[test]
    fn explain_renders_boundary_failed_findings() {
        let manifest = sample_manifest(
            ClaimLevel::BoundaryFailed,
            true,
            true,
            vec![Finding {
                key_path: "request.messages[1].content".to_string(),
                sample_value: Some("https://www.sec.gov/Archives/example".to_string()),
                artifact_class: "forbidden_pattern".to_string(),
                matched_rule: "deny_rules[0]".to_string(),
                span_hash: None,
            }],
            vec![BlockedReason {
                claim_attempted: ClaimLevel::StrictTelemetryOnly,
                reason: "forbidden content present".to_string(),
                offending_paths: vec!["request.messages[1].content".to_string()],
            }],
        );
        let tempdir = tempfile::tempdir().unwrap();
        let path = write_manifest_file(&tempdir, &manifest);
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            ExplainArgs {
                manifest: path,
                json: false,
            },
            &mut stdout,
        );

        assert_eq!(exit_code, 0);
        let rendered = String::from_utf8(stdout).unwrap();
        assert!(rendered.contains("Claim achieved: BOUNDARY_FAILED"));
        assert!(rendered.contains("Boundary violation detected:"));
        assert!(rendered.contains("request.messages[1].content"));
        assert!(rendered.contains("forbidden_pattern"));
    }

    #[test]
    fn explain_renders_strict_telemetry_only_without_blocked_reasons() {
        let manifest = sample_manifest(
            ClaimLevel::StrictTelemetryOnly,
            false,
            false,
            vec![],
            vec![],
        );
        let tempdir = tempfile::tempdir().unwrap();
        let path = write_manifest_file(&tempdir, &manifest);
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            ExplainArgs {
                manifest: path,
                json: false,
            },
            &mut stdout,
        );

        assert_eq!(exit_code, 0);
        let rendered = String::from_utf8(stdout).unwrap();
        assert!(rendered.contains("Claim achieved: STRICT_TELEMETRY_ONLY"));
        assert!(!rendered.contains("Why strict telemetry-only was not earned:"));
        assert!(!rendered.contains("Boundary violation detected:"));
    }

    #[test]
    fn missing_manifest_emits_structured_refusal() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("missing.json");
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            ExplainArgs {
                manifest: path,
                json: false,
            },
            &mut stdout,
        );

        assert_eq!(exit_code, 2);
        let refusal: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(refusal["outcome"], REFUSAL_OUTCOME);
        assert_eq!(refusal["refusal"]["code"], "E_MISSING_FILE");
    }

    #[test]
    fn invalid_manifest_json_emits_structured_refusal() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("bad.json");
        std::fs::write(&path, b"{not valid json").unwrap();
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            ExplainArgs {
                manifest: path,
                json: false,
            },
            &mut stdout,
        );

        assert_eq!(exit_code, 2);
        let refusal: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(refusal["outcome"], REFUSAL_OUTCOME);
        assert_eq!(refusal["refusal"]["code"], "E_BAD_MANIFEST");
    }

    #[test]
    fn explain_json_is_machine_readable() {
        let manifest = sample_manifest(
            ClaimLevel::RawDocumentAbsent,
            false,
            true,
            vec![],
            vec![BlockedReason {
                claim_attempted: ClaimLevel::StrictTelemetryOnly,
                reason: "derived text present".to_string(),
                offending_paths: vec!["mutator_context.challenge_observation".to_string()],
            }],
        );
        let tempdir = tempfile::tempdir().unwrap();
        let path = write_manifest_file(&tempdir, &manifest);
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            ExplainArgs {
                manifest: path,
                json: true,
            },
            &mut stdout,
        );

        assert_eq!(exit_code, 0);
        let explanation: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(explanation["schema"], "airlock.explain.v1");
        assert_eq!(explanation["claim"]["achieved"], "RAW_DOCUMENT_ABSENT");
        assert_eq!(
            explanation["blocked_paths"][0],
            "mutator_context.challenge_observation"
        );
        assert_eq!(explanation["proof"]["policy_id"], "tournament_baseline");
        assert!(
            explanation["next_commands"]["human_explain"]
                .as_str()
                .unwrap()
                .starts_with("airlock explain --manifest ")
        );
    }

    fn hash_of(digit: char) -> String {
        format!("blake3:{}", digit.to_string().repeat(64))
    }

    fn left_out(path: &str, reason: NotCrossedReason, value_digit: char) -> NotCrossedEntry {
        NotCrossedEntry {
            path: path.to_string(),
            source_artifact_hash: hash_of('7'),
            value_hash: hash_of(value_digit),
            reason,
        }
    }

    fn two_left_out() -> Vec<NotCrossedEntry> {
        vec![
            left_out("html_path", NotCrossedReason::ForbiddenKey, '9'),
            left_out("operator_note", NotCrossedReason::NotAllowed, 'e'),
        ]
    }

    /// An airlock.v0.3 manifest as `verify` writes it, with the signature optional.
    fn v0_3_manifest(not_crossed: Option<Vec<NotCrossedEntry>>, signed: bool) -> AirlockManifest {
        let mut manifest =
            sample_manifest(ClaimLevel::RawDocumentAbsent, false, true, vec![], vec![]);
        manifest.not_crossed = not_crossed;
        manifest.signature = signed.then(|| ManifestSignature {
            algorithm: "ed25519".to_string(),
            public_key_fingerprint: hash_of('a'),
            value: "b".repeat(128),
        });
        manifest
    }

    /// An airlock.v0.2 manifest: none of the v0.3 members.
    fn v0_2_manifest() -> AirlockManifest {
        let mut manifest =
            sample_manifest(ClaimLevel::RawDocumentAbsent, false, true, vec![], vec![]);
        manifest.manifest_version = "airlock.v0.2".to_string();
        manifest.bytes_crossed = None;
        manifest.attestation = None;
        manifest
    }

    #[test]
    fn explain_lists_what_was_left_out_by_path_reason_and_hash() {
        let manifest = v0_3_manifest(Some(two_left_out()), true);

        let rendered = render_manifest(&manifest);

        let expected = format!(
            "Derived filing text: present\n\
             \n\
             Bytes crossed: 1234\n\
             Attestation: self_attested (written by airlock verify, not by a send or gate receipt)\n\
             Signature: ed25519 by {} (explain does not check it; run airlock verify-manifest)\n\
             Left out of the request: 2 fields (values are never stored):\n\
             \x20 - html_path [FORBIDDEN_KEY] {}\n\
             \x20 - operator_note [NOT_ALLOWED] {}\n",
            hash_of('a'),
            hash_of('9'),
            hash_of('e'),
        );
        assert!(rendered.contains(&expected), "{rendered}");
        // The input artifact's hash is in the manifest but is not part of this summary.
        assert!(!rendered.contains(&hash_of('7')), "{rendered}");
    }

    #[test]
    fn explain_says_when_the_manifest_is_unsigned_and_carries_no_inventory() {
        let manifest = v0_3_manifest(None, false);

        let rendered = render_manifest(&manifest);

        assert!(rendered.contains("Signature: none (unsigned manifest)\n"));
        assert!(rendered.contains(
            "Left out of the request: not recorded (verify was not given a not-crossed inventory)\n"
        ));
    }

    #[test]
    fn explain_says_nothing_was_left_out_for_an_empty_inventory() {
        let manifest = v0_3_manifest(Some(vec![]), true);

        let rendered = render_manifest(&manifest);

        assert!(
            rendered.contains(
                "Left out of the request: nothing (the not-crossed inventory is empty)\n"
            )
        );
        assert!(!rendered.contains("not recorded"));
    }

    #[test]
    fn explain_uses_the_singular_for_one_left_out_field() {
        let one = vec![left_out("operator_note", NotCrossedReason::NotAllowed, 'e')];
        let manifest = v0_3_manifest(Some(one), false);

        let rendered = render_manifest(&manifest);

        assert!(rendered.contains("Left out of the request: 1 field (values are never stored):\n"));
    }

    #[test]
    fn explain_names_the_other_attestations_plainly() {
        assert_eq!(
            attestation_sentence(Attestation::Transmitted),
            "transmitted"
        );
        assert_eq!(attestation_sentence(Attestation::Gated), "gated");
        assert!(attestation_sentence(Attestation::SelfAttested).starts_with("self_attested ("));
    }

    #[test]
    fn explain_json_carries_the_v0_3_members_and_never_the_signature_bytes() {
        let manifest = v0_3_manifest(Some(two_left_out()), true);

        let explanation = json_explanation(&manifest, "manifest.json");

        assert_eq!(explanation["bytes_crossed"], 1234);
        assert_eq!(explanation["attestation"], "self_attested");
        assert_eq!(
            explanation["not_crossed"],
            json!([
                {
                    "path": "html_path",
                    "source_artifact_hash": hash_of('7'),
                    "value_hash": hash_of('9'),
                    "reason": "FORBIDDEN_KEY"
                },
                {
                    "path": "operator_note",
                    "source_artifact_hash": hash_of('7'),
                    "value_hash": hash_of('e'),
                    "reason": "NOT_ALLOWED"
                }
            ])
        );
        assert_eq!(
            explanation["signature"],
            json!({
                "algorithm": "ed25519",
                "public_key_fingerprint": hash_of('a'),
                "checked": false
            })
        );
        assert!(!explanation.to_string().contains(&"b".repeat(128)));
    }

    #[test]
    fn explain_json_says_null_for_v0_3_members_the_manifest_lacks() {
        let manifest = v0_3_manifest(None, false);

        let explanation = json_explanation(&manifest, "manifest.json");

        let members = explanation.as_object().unwrap();
        assert_eq!(members["signature"], Value::Null);
        assert_eq!(members["not_crossed"], Value::Null);
        assert_eq!(members["bytes_crossed"], 1234);
        // An empty inventory is not the same thing as a missing one.
        let empty = json_explanation(&v0_3_manifest(Some(vec![]), false), "manifest.json");
        assert_eq!(empty["not_crossed"], json!([]));
    }

    #[test]
    fn a_v0_2_manifest_explains_without_any_v0_3_member() {
        let manifest = v0_2_manifest();

        let rendered = render_manifest(&manifest);
        let explanation = json_explanation(&manifest, "manifest.json");

        for label in ["Bytes crossed", "Attestation", "Signature", "Left out"] {
            assert!(!rendered.contains(label), "{label} in:\n{rendered}");
        }
        let members = explanation.as_object().unwrap();
        for member in ["bytes_crossed", "attestation", "not_crossed", "signature"] {
            assert!(!members.contains_key(member), "{member} in {explanation}");
        }
    }

    #[test]
    fn not_crossed_reason_words_are_the_serialized_names() {
        for reason in [
            NotCrossedReason::NotAllowed,
            NotCrossedReason::ForbiddenKey,
            NotCrossedReason::DerivedTextExcluded,
            NotCrossedReason::ShadowedByEarlierInput,
        ] {
            assert_eq!(json!(reason), json!(not_crossed_reason_word(reason)));
        }
    }

    fn gate_finding(artifact_class: &str, rule_id: &str) -> crate::scanner::egress::EgressFinding {
        crate::scanner::egress::EgressFinding {
            artifact_class: artifact_class.to_owned(),
            rule_id: rule_id.to_owned(),
            key_path: None,
            span_hash: None,
        }
    }

    const SAMPLE_HASH: &str =
        "blake3:7777777777777777777777777777777777777777777777777777777777777777";

    fn explain_gate(receipt: &GateReceipt, json: bool) -> (u8, String) {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("gate-receipt.json");
        std::fs::write(&path, serde_json::to_vec(receipt).unwrap()).unwrap();
        let mut stdout = Vec::new();
        let exit_code = run_with_writer(
            ExplainArgs {
                manifest: path,
                json,
            },
            &mut stdout,
        );
        (exit_code, String::from_utf8(stdout).unwrap())
    }

    #[test]
    fn gate_receipt_decision_follows_blocked_status_and_findings() {
        let mut receipt = GateReceipt::new(
            "strict-manifest",
            "STRICT_TELEMETRY_ONLY",
            SAMPLE_HASH,
            false,
            vec![],
        );
        assert_eq!(gate_decision(&receipt), "authorized_upstream_failed");

        receipt.upstream_status = Some(200);
        assert_eq!(gate_decision(&receipt), "forwarded");

        receipt
            .findings
            .push(gate_finding("UPSTREAM_ERROR", "GATE_STREAM_INTERRUPTED"));
        assert_eq!(gate_decision(&receipt), "forwarded_interrupted");

        receipt.blocked = true;
        assert_eq!(gate_decision(&receipt), "denied");
    }

    #[test]
    fn explain_renders_a_denied_gate_receipt_with_the_reason_and_the_limit() {
        let mut receipt = GateReceipt::new(
            "strict-manifest",
            "BOUNDARY_FAILED",
            SAMPLE_HASH,
            true,
            vec![gate_finding(
                "STRICT_MANIFEST_REQUIRED",
                "REQUEST_MANIFEST_NOT_FOUND",
            )],
        )
        .with_request_bytes(Some(2048))
        .with_limit(crate::manifest::gate::GateLimit::max_request_bytes(
            1024,
            Some(2048),
        ));
        receipt.timestamp = "2026-11-25T12:00:00Z".to_owned();

        let (exit_code, rendered) = explain_gate(&receipt, false);

        assert_eq!(exit_code, 0);
        assert!(rendered.starts_with("AIRLOCK GATE\n"));
        assert!(rendered.contains("Decision: DENIED. The gate did not forward this request."));
        assert!(rendered.contains("Mode: strict-manifest"));
        assert!(rendered.contains(&format!("Request: {SAMPLE_HASH} (2048 bytes received)")));
        assert!(rendered.contains("Limit hit: max_request_bytes 1024 (observed 2048)"));
        assert!(rendered.contains("  - REQUEST_MANIFEST_NOT_FOUND [STRICT_MANIFEST_REQUIRED]"));
        assert!(
            rendered.contains("no verified manifest is bound to this request's canonical hash")
        );
        assert!(rendered.contains("Recorded: 2026-11-25T12:00:00Z"));
        assert!(!rendered.contains("Upstream response:"));
    }

    #[test]
    fn explain_does_not_present_the_no_hash_placeholder_as_a_request_hash() {
        let receipt = GateReceipt::new(
            "strict-manifest",
            "BOUNDARY_FAILED",
            blake3_hash(b"unavailable"),
            true,
            vec![gate_finding("REQUEST_SCAN_REFUSED", "REQUEST_SCAN_REFUSED")],
        );

        let (_, rendered) = explain_gate(&receipt, false);
        assert!(rendered.contains("Request: no hash (the gate refused before it had one)"));
        assert!(!rendered.contains(&blake3_hash(b"unavailable")));

        let (_, json) = explain_gate(&receipt, true);
        let explanation: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(explanation["schema"], "airlock.explain_gate.v1");
        assert!(explanation["request"]["hash"].is_null());
    }

    #[test]
    fn explain_gate_receipt_with_an_unsupported_version_emits_a_structured_refusal() {
        let mut receipt = GateReceipt::new(
            "strict-manifest",
            "BOUNDARY_FAILED",
            SAMPLE_HASH,
            true,
            vec![],
        );
        receipt.gate_version = "airlock.gate.v9".to_owned();

        let (exit_code, output) = explain_gate(&receipt, false);

        assert_eq!(exit_code, 2);
        let refusal: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(refusal["refusal"]["code"], "E_BAD_MANIFEST");
        assert_eq!(
            refusal["refusal"]["detail"]["gate_version"],
            "airlock.gate.v9"
        );
    }
}
