use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::assembler::{self, InputArtifact, PromptProvenance};
use crate::cli::{AssembleArgs, VERIFY_PASS};
use crate::hash::blake3_hash;
use crate::output::canonical_json;
use crate::policy::{hash_policy, load_policy};
use crate::refusal::{RefusalCode, RefusalEnvelope};
use crate::witness::{self, WitnessInput, WitnessRecord};

pub fn run(args: AssembleArgs) -> u8 {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let witness_path = witness::default_witness_path();
    run_with_writers(args, &witness_path, &mut stdout, &mut stderr)
}

fn run_with_writers(
    args: AssembleArgs,
    witness_path: &Path,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    let (policy, policy_hash) = match load_policy_artifact(&args.policy) {
        Ok(result) => result,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let mut witness_inputs = vec![WitnessRecord::input(
        args.policy.display().to_string(),
        policy_hash.clone(),
    )];

    let input_artifacts = match load_input_artifacts(&args.input, &mut witness_inputs) {
        Ok(artifacts) => artifacts,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let system_prompt = match load_system_prompt(args.system_prompt.as_deref(), &mut witness_inputs)
    {
        Ok(system_prompt) => system_prompt,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let assembly = match assembler::assemble(
        &policy,
        &input_artifacts,
        &system_prompt,
        args.boundary_mode,
    ) {
        Ok(assembly) => assembly,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let prompt_bytes = canonical_json(&assembly.prompt_payload).into_bytes();
    let provenance_bytes = assemble_provenance_bytes(assembly.prompt_provenance);

    if let Err(refusal) = write_output_file(&args.out, &prompt_bytes) {
        return refusal.write_to(stdout);
    }
    if let Err(refusal) = write_output_file(&args.provenance_out, &provenance_bytes) {
        return refusal.write_to(stdout);
    }

    let _ = stdout.write_all(&prompt_bytes);
    let _ = stdout.flush();

    let witness_record = WitnessRecord::new(
        "assemble",
        "ASSEMBLED",
        VERIFY_PASS,
        witness_inputs,
        json!({
            "boundary_mode": args.boundary_mode.to_string(),
        }),
        blake3_hash(&prompt_bytes),
        prompt_bytes.len(),
    );

    witness::maybe_append_witness_at(
        witness_path,
        &witness_record,
        !args.no_witness,
        VERIFY_PASS,
        stderr,
    )
}

fn load_policy_artifact(
    path: &Path,
) -> Result<(crate::policy::AirlockPolicy, String), RefusalEnvelope> {
    if !path.exists() {
        return Err(RefusalEnvelope::bad_policy(
            "policy file does not exist",
            json!({ "path": path.display().to_string() }),
        ));
    }

    let policy = load_policy(path)?;
    let policy_hash = hash_policy(path).map_err(map_missing_policy_refusal)?;
    Ok((policy, policy_hash))
}

fn map_missing_policy_refusal(refusal: RefusalEnvelope) -> RefusalEnvelope {
    if refusal.refusal.code == RefusalCode::EMissingFile {
        RefusalEnvelope::bad_policy(
            "policy file does not exist",
            json!({ "path": refusal.refusal.detail["path"].clone() }),
        )
    } else {
        refusal
    }
}

fn load_input_artifacts(
    paths: &[PathBuf],
    witness_inputs: &mut Vec<WitnessInput>,
) -> Result<Vec<InputArtifact>, RefusalEnvelope> {
    let mut artifacts = Vec::with_capacity(paths.len());

    for path in paths {
        let raw = std::fs::read(path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => {
                RefusalEnvelope::missing_file(path.display().to_string())
            }
            _ => RefusalEnvelope::bad_input(
                "failed to read input file",
                json!({
                    "path": path.display().to_string(),
                    "error": error.to_string(),
                }),
            ),
        })?;

        let content_hash = blake3_hash(&raw);
        let data: Value = serde_json::from_slice(&raw).map_err(|error| {
            RefusalEnvelope::bad_input(
                "input file is not valid JSON",
                json!({
                    "path": path.display().to_string(),
                    "error": error.to_string(),
                }),
            )
        })?;

        witness_inputs.push(WitnessRecord::input(
            path.display().to_string(),
            content_hash.clone(),
        ));
        artifacts.push(InputArtifact {
            path: path.clone(),
            content_hash,
            data,
        });
    }

    Ok(artifacts)
}

fn load_system_prompt(
    path: Option<&Path>,
    witness_inputs: &mut Vec<WitnessInput>,
) -> Result<String, RefusalEnvelope> {
    let Some(path) = path else {
        return Ok(String::new());
    };

    let raw = std::fs::read(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => RefusalEnvelope::missing_file(path.display().to_string()),
        _ => RefusalEnvelope::bad_input(
            "failed to read system prompt file",
            json!({
                "path": path.display().to_string(),
                "error": error.to_string(),
            }),
        ),
    })?;
    let content_hash = blake3_hash(&raw);
    let system_prompt = String::from_utf8(raw).map_err(|error| {
        RefusalEnvelope::bad_input(
            "system prompt file must be valid UTF-8 text",
            json!({
                "path": path.display().to_string(),
                "error": error.to_string(),
            }),
        )
    })?;

    witness_inputs.push(WitnessRecord::input(
        path.display().to_string(),
        content_hash,
    ));

    Ok(system_prompt)
}

fn assemble_provenance_bytes(provenance: PromptProvenance) -> Vec<u8> {
    provenance.to_canonical_json().into_bytes()
}

fn write_output_file(path: &Path, bytes: &[u8]) -> Result<(), RefusalEnvelope> {
    std::fs::write(path, bytes).map_err(|error| {
        RefusalEnvelope::bad_input(
            "failed to write output file",
            json!({
                "path": path.display().to_string(),
                "error": error.to_string(),
            }),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;
    use crate::cli::REFUSAL;
    use crate::types::BoundaryMode;
    use crate::witness::WITNESS_VERSION;

    fn write_file(path: &Path, contents: &[u8]) {
        fs::write(path, contents).unwrap();
    }

    fn sample_policy_yaml() -> &'static str {
        r#"policy_id: tournament_baseline
version: airlock.v0
allowed_keys:
  - key_path: family_id
  - key_path: benchmark_summary.score
  - key_path: mutator_context.challenge_observation
forbidden_keys:
  - html_path
forbidden_patterns:
  - pattern: sec\.gov/Archives
derived_text_paths:
  - mutator_context.challenge_observation
claim_levels:
  - BOUNDARY_FAILED
  - RAW_DOCUMENT_ABSENT
  - STRICT_TELEMETRY_ONLY
"#
    }

    fn sample_assemble_args(tempdir: &Path) -> AssembleArgs {
        AssembleArgs {
            policy: tempdir.join("policy.yaml"),
            input: vec![
                tempdir.join("strategy.json"),
                tempdir.join("heuristic.json"),
            ],
            system_prompt: Some(tempdir.join("system_prompt.txt")),
            boundary_mode: BoundaryMode::Annotated,
            out: tempdir.join("prompt_payload.json"),
            provenance_out: tempdir.join("prompt_provenance.json"),
            no_witness: false,
        }
    }

    fn write_success_fixture_files(tempdir: &Path) -> (String, String) {
        let policy = sample_policy_yaml().to_string();
        let strategy = r#"{"family_id":"family-001","benchmark_summary":{"score":97}}"#.to_string();
        let heuristic = r#"{"mutator_context":{"challenge_observation":"Dense footnotes in note disclosures."}}"#.to_string();
        let system_prompt = "You are a careful boundary verifier.".to_string();

        write_file(&tempdir.join("policy.yaml"), policy.as_bytes());
        write_file(&tempdir.join("strategy.json"), strategy.as_bytes());
        write_file(&tempdir.join("heuristic.json"), heuristic.as_bytes());
        write_file(&tempdir.join("system_prompt.txt"), system_prompt.as_bytes());

        (strategy, heuristic)
    }

    #[test]
    fn assemble_writes_outputs_prints_prompt_and_records_witness() {
        let tempdir = tempdir().unwrap();
        let (strategy_raw, heuristic_raw) = write_success_fixture_files(tempdir.path());
        let witness_path = tempdir.path().join("witness.jsonl");
        let args = sample_assemble_args(tempdir.path());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args.clone(), &witness_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PASS);
        assert!(stderr.is_empty());

        let prompt_bytes = fs::read(&args.out).unwrap();
        let provenance_bytes = fs::read(&args.provenance_out).unwrap();
        assert_eq!(stdout, prompt_bytes);

        let prompt: Value = serde_json::from_slice(&prompt_bytes).unwrap();
        assert_eq!(
            prompt["messages"][1]["content"]["family_id"],
            json!("family-001")
        );
        assert_eq!(
            prompt["messages"][1]["content"]["benchmark_summary"]["score"],
            json!(97)
        );
        assert_eq!(
            prompt["messages"][1]["content"]["mutator_context"]["challenge_observation"],
            json!("Dense footnotes in note disclosures.")
        );

        let provenance: PromptProvenance = serde_json::from_slice(&provenance_bytes).unwrap();
        let strategy_hash = blake3_hash(strategy_raw.as_bytes());
        let heuristic_hash = blake3_hash(heuristic_raw.as_bytes());
        assert!(provenance
            .records
            .iter()
            .any(|record| record.source_artifact_hash == strategy_hash));
        assert!(provenance
            .records
            .iter()
            .any(|record| record.source_artifact_hash == heuristic_hash));

        let witness_line = fs::read_to_string(&witness_path).unwrap();
        let witness: Value = serde_json::from_str(witness_line.trim()).unwrap();
        assert_eq!(witness["witness_version"], WITNESS_VERSION);
        assert_eq!(witness["command"], "assemble");
        assert_eq!(witness["outcome"], "ASSEMBLED");
        assert_eq!(witness["exit_code"], VERIFY_PASS);
    }

    #[test]
    fn assemble_is_deterministic_across_repeated_runs() {
        let tempdir = tempdir().unwrap();
        write_success_fixture_files(tempdir.path());

        let mut first = sample_assemble_args(tempdir.path());
        first.out = tempdir.path().join("prompt_a.json");
        first.provenance_out = tempdir.path().join("provenance_a.json");
        first.no_witness = true;

        let mut second = sample_assemble_args(tempdir.path());
        second.out = tempdir.path().join("prompt_b.json");
        second.provenance_out = tempdir.path().join("provenance_b.json");
        second.no_witness = true;

        let witness_path = tempdir.path().join("witness.jsonl");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run_with_writers(first.clone(), &witness_path, &mut stdout, &mut stderr),
            VERIFY_PASS
        );
        stdout.clear();
        stderr.clear();
        assert_eq!(
            run_with_writers(second.clone(), &witness_path, &mut stdout, &mut stderr),
            VERIFY_PASS
        );

        assert_eq!(fs::read(first.out).unwrap(), fs::read(second.out).unwrap());
        assert_eq!(
            fs::read(first.provenance_out).unwrap(),
            fs::read(second.provenance_out).unwrap()
        );
        assert!(!witness_path.exists());
    }

    #[test]
    fn missing_policy_returns_bad_policy_refusal() {
        let tempdir = tempdir().unwrap();
        let args = sample_assemble_args(tempdir.path());
        let witness_path = tempdir.path().join("witness.jsonl");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args, &witness_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, REFUSAL);
        assert!(stderr.is_empty());
        let refusal: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(refusal["refusal"]["code"], "E_BAD_POLICY");
    }

    #[test]
    fn missing_input_returns_missing_file_refusal() {
        let tempdir = tempdir().unwrap();
        write_file(
            tempdir.path().join("policy.yaml").as_path(),
            sample_policy_yaml().as_bytes(),
        );
        write_file(
            tempdir.path().join("system_prompt.txt").as_path(),
            b"You are a careful boundary verifier.",
        );
        write_file(
            tempdir.path().join("strategy.json").as_path(),
            br#"{"family_id":"family-001"}"#,
        );
        let args = sample_assemble_args(tempdir.path());
        let witness_path = tempdir.path().join("witness.jsonl");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args, &witness_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, REFUSAL);
        let refusal: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(refusal["refusal"]["code"], "E_MISSING_FILE");
    }

    #[test]
    fn no_witness_skips_ledger_append() {
        let tempdir = tempdir().unwrap();
        write_success_fixture_files(tempdir.path());
        let witness_path = tempdir.path().join("witness.jsonl");
        let mut args = sample_assemble_args(tempdir.path());
        args.no_witness = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args, &witness_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PASS);
        assert!(!witness_path.exists());
        assert!(stderr.is_empty());
    }

    #[test]
    fn telemetry_only_strips_derived_text_from_output() {
        let tempdir = tempdir().unwrap();
        write_success_fixture_files(tempdir.path());
        let witness_path = tempdir.path().join("witness.jsonl");
        let mut args = sample_assemble_args(tempdir.path());
        args.boundary_mode = BoundaryMode::TelemetryOnly;
        args.no_witness = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args.clone(), &witness_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PASS);
        let prompt: Value = serde_json::from_slice(&fs::read(args.out).unwrap()).unwrap();
        assert!(
            prompt["messages"][1]["content"]["mutator_context"]["challenge_observation"].is_null()
        );
    }

    #[test]
    fn witness_append_failure_preserves_success_exit() {
        let tempdir = tempdir().unwrap();
        write_success_fixture_files(tempdir.path());
        let mut args = sample_assemble_args(tempdir.path());
        args.no_witness = false;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args, tempdir.path(), &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PASS);
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("witness append failed"));
    }
}
