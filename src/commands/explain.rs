use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};

use serde_json::json;

use crate::cli::ExplainArgs;
use crate::manifest::AirlockManifest;
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
                .write_to(stdout)
        }
        Err(err) => {
            return RefusalEnvelope::bad_manifest(
                "failed to read manifest file",
                json!({
                    "path": args.manifest.display().to_string(),
                    "error": err.to_string(),
                }),
            )
            .write_to(stdout)
        }
    };

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
            .write_to(stdout)
        }
    };

    let rendered = render_manifest(&manifest);
    let _ = stdout.write_all(rendered.as_bytes());
    let _ = stdout.flush();
    0
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
    if is_present {
        "present"
    } else {
        "absent"
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
    use crate::manifest::{ProvenanceSummary, AIRLOCK_MANIFEST_VERSION};
    use crate::refusal::REFUSAL_OUTCOME;
    use crate::types::{BoundaryMode, UpstreamArtifact};

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

        let exit_code = run_with_writer(ExplainArgs { manifest: path }, &mut stdout);

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

        let exit_code = run_with_writer(ExplainArgs { manifest: path }, &mut stdout);

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

        let exit_code = run_with_writer(ExplainArgs { manifest: path }, &mut stdout);

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

        let exit_code = run_with_writer(ExplainArgs { manifest: path }, &mut stdout);

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

        let exit_code = run_with_writer(ExplainArgs { manifest: path }, &mut stdout);

        assert_eq!(exit_code, 2);
        let refusal: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(refusal["outcome"], REFUSAL_OUTCOME);
        assert_eq!(refusal["refusal"]["code"], "E_BAD_MANIFEST");
    }
}
