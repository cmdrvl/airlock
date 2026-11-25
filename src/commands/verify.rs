use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

use serde_json::{Value, json};

use crate::adapter::{self, TransportDeclaration};
use crate::assembler::PromptProvenance;
use crate::cli::{VERIFY_PARTIAL, VERIFY_PASS, VerifyArgs};
use crate::hash::{blake3_hash, jcs_blake3_hash};
use crate::manifest::ManifestBuilder;
use crate::output::{SOURCE_DATE_EPOCH_ENV, now_utc};
use crate::policy::{self, AirlockPolicy};
use crate::refusal::RefusalEnvelope;
use crate::scanner;
use crate::types::UpstreamArtifact;
use crate::witness::{self, WitnessRecord};

pub fn run(args: VerifyArgs) -> u8 {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    run_with_writers(
        args,
        &witness::default_witness_path(),
        &mut stdout,
        &mut stderr,
    )
}

fn run_with_writers(
    args: VerifyArgs,
    witness_path: &Path,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    // Resolve the manifest instant first: SOURCE_DATE_EPOCH pins it for reproducible
    // output, and a malformed value refuses before any input is read.
    let manifest_instant = match now_utc() {
        Ok(instant) => instant,
        Err(invalid) => {
            return RefusalEnvelope::bad_input_with_next_command(
                format!("invalid {SOURCE_DATE_EPOCH_ENV}: {}", invalid.reason),
                json!({
                    "env": SOURCE_DATE_EPOCH_ENV,
                    "value": invalid.value,
                    "expected": "Unix seconds",
                }),
                "airlock verify --help",
            )
            .write_to(stdout);
        }
    };

    let policy = match policy::load_policy(&args.policy) {
        Ok(policy) => policy,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let policy_hash = canonical_policy_hash(&policy);
    let prompt_value = match read_json_value(
        &args.prompt,
        RefusalEnvelope::bad_prompt,
        "failed to read prompt payload",
        "prompt payload is not valid JSON",
    ) {
        Ok(value) => value,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let prompt_provenance = match read_json_typed::<PromptProvenance>(
        &args.provenance,
        RefusalEnvelope::bad_provenance,
        "failed to read prompt provenance",
        "prompt provenance is not valid JSON",
    ) {
        Ok(value) => value,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let request_value = match read_json_value(
        &args.request,
        RefusalEnvelope::bad_request,
        "failed to read request payload",
        "request payload is not valid JSON",
    ) {
        Ok(value) => value,
        Err(refusal) => return refusal.write_to(stdout),
    };

    // Both payload hashes are blake3(RFC 8785 JCS(payload)) so a third party can recompute them
    // with any standard JCS library. A payload JCS cannot represent interoperably (an integer
    // beyond 2^53) is refused here instead of being hashed into something nobody else can
    // reproduce.
    let prompt_payload_hash = match jcs_blake3_hash(&prompt_value) {
        Ok(hash) => hash,
        Err(error) => {
            return RefusalEnvelope::bad_prompt(
                format!("prompt payload cannot be hashed as RFC 8785 canonical JSON: {error}"),
                error.detail(),
            )
            .write_to(stdout);
        }
    };
    let request_payload_hash = match jcs_blake3_hash(&request_value) {
        Ok(hash) => hash,
        Err(error) => {
            return RefusalEnvelope::bad_request(
                format!("request payload cannot be hashed as RFC 8785 canonical JSON: {error}"),
                error.detail(),
            )
            .write_to(stdout);
        }
    };
    if prompt_provenance.prompt_payload_hash != prompt_payload_hash {
        return RefusalEnvelope::bad_provenance(
            "prompt provenance does not match prompt payload hash",
            json!({
                "expected_prompt_payload_hash": prompt_payload_hash,
                "prompt_payload_hash": prompt_provenance.prompt_payload_hash,
                "path": args.provenance.display().to_string(),
            }),
        )
        .write_to(stdout);
    }

    if prompt_provenance.policy_hash != policy_hash {
        return RefusalEnvelope::bad_provenance(
            "prompt provenance does not match policy hash",
            json!({
                "expected_policy_hash": policy_hash,
                "policy_hash": prompt_provenance.policy_hash,
                "path": args.provenance.display().to_string(),
            }),
        )
        .write_to(stdout);
    }

    let boundary_mode = prompt_provenance.boundary_mode;
    let system_prompt_hash = match system_prompt_hash(&prompt_value) {
        Ok(hash) => hash,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let declared_transport = match args.transport.as_deref() {
        Some(path) => match read_json_typed::<TransportDeclaration>(
            path,
            RefusalEnvelope::bad_input,
            "failed to read transport declaration",
            "transport declaration is not a valid transport JSON object",
        ) {
            Ok(declaration) => Some(declaration),
            Err(refusal) => return refusal.write_to(stdout),
        },
        None => None,
    };
    let adapter = match adapter::select(&request_value, declared_transport.as_ref()) {
        Ok(adapter) => adapter,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let model_id = match adapter.model_id(&request_value) {
        Some(model_id) => model_id,
        None => {
            return RefusalEnvelope::bad_request(
                "request payload must contain a non-empty model id",
                json!({ "adapter": adapter.name() }),
            )
            .write_to(stdout);
        }
    };
    let adapter_name = adapter.name().to_string();

    let verify_result = match scanner::verify(
        &policy,
        &prompt_value,
        &prompt_provenance,
        &request_value,
        boundary_mode,
        adapter.as_ref(),
    ) {
        Ok(result) => result,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let manifest = match ManifestBuilder::new()
        .binding_status(verify_result.binding_status)
        .boundary_mode(boundary_mode)
        .policy_id(policy.policy_id.clone())
        .policy_hash(policy_hash.clone())
        .claim_levels_evaluated(policy.claim_levels.clone())
        .achieved_claim(verify_result.achieved_claim)
        .upstream_artifact_inventory(upstream_inventory(&prompt_provenance, &policy))
        .system_prompt_hash(system_prompt_hash)
        .prompt_payload_hash(prompt_payload_hash)
        .prompt_provenance(args.provenance.display().to_string(), &prompt_provenance)
        .request_payload_hash(request_payload_hash)
        .replay_ref(args.request.display().to_string())
        .model_id(model_id)
        .adapter(adapter_name)
        .raw_document_present(verify_result.raw_document_present)
        .filing_derived_text_present(verify_result.filing_derived_text_present)
        .findings(verify_result.findings)
        .blocked_reasons(verify_result.blocked_reasons)
        .timestamp(manifest_instant.to_rfc3339())
        .build()
    {
        Ok(manifest) => manifest,
        Err(error) => {
            return RefusalEnvelope::internal(
                "failed to build airlock manifest",
                json!({ "error": error.to_string() }),
            )
            .write_to(stdout);
        }
    };

    if let Err(error) = manifest.write_to(&args.out) {
        return RefusalEnvelope::bad_input(
            "failed to write manifest output",
            json!({
                "error": error.to_string(),
                "path": args.out.display().to_string(),
            }),
        )
        .write_to(stdout);
    }

    let manifest_json = manifest.to_canonical_json();
    let _ = stdout.write_all(manifest_json.as_bytes());
    let _ = stdout.flush();

    let exit_code = if args
        .require_claim
        .is_some_and(|required| manifest.achieved_claim < required)
    {
        VERIFY_PARTIAL
    } else {
        VERIFY_PASS
    };

    let witness_outcome = if exit_code == VERIFY_PARTIAL {
        "VERIFY_PARTIAL"
    } else {
        "VERIFIED"
    };
    let witness_record = WitnessRecord::new(
        "verify",
        witness_outcome,
        exit_code,
        vec![
            WitnessRecord::input(args.policy.display().to_string(), policy_hash),
            WitnessRecord::input(
                args.prompt.display().to_string(),
                manifest.prompt_payload_hash.clone(),
            ),
            WitnessRecord::input(
                args.provenance.display().to_string(),
                manifest.prompt_provenance_hash.clone(),
            ),
            WitnessRecord::input(
                args.request.display().to_string(),
                manifest.request_payload_hash.clone(),
            ),
        ],
        json!({
            "boundary_mode": boundary_mode,
            "require_claim": args.require_claim,
            "achieved_claim": manifest.achieved_claim,
        }),
        blake3_hash(manifest_json.as_bytes()),
        manifest_json.len(),
    );

    witness::maybe_append_witness_at(
        witness_path,
        &witness_record,
        !args.no_witness,
        exit_code,
        stderr,
    )
}

fn read_json_value(
    path: &Path,
    constructor: fn(String, Value) -> RefusalEnvelope,
    read_message: &str,
    parse_message: &str,
) -> Result<Value, RefusalEnvelope> {
    read_json_bytes(path, constructor, read_message, parse_message).and_then(|bytes| {
        serde_json::from_slice(&bytes).map_err(|error| {
            constructor(
                parse_message.to_string(),
                json!({
                    "path": path.display().to_string(),
                    "error": error.to_string(),
                }),
            )
        })
    })
}

fn read_json_typed<T>(
    path: &Path,
    constructor: fn(String, Value) -> RefusalEnvelope,
    read_message: &str,
    parse_message: &str,
) -> Result<T, RefusalEnvelope>
where
    T: serde::de::DeserializeOwned,
{
    read_json_bytes(path, constructor, read_message, parse_message).and_then(|bytes| {
        serde_json::from_slice(&bytes).map_err(|error| {
            constructor(
                parse_message.to_string(),
                json!({
                    "path": path.display().to_string(),
                    "error": error.to_string(),
                }),
            )
        })
    })
}

fn read_json_bytes(
    path: &Path,
    constructor: fn(String, Value) -> RefusalEnvelope,
    read_message: &str,
    _parse_message: &str,
) -> Result<Vec<u8>, RefusalEnvelope> {
    std::fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RefusalEnvelope::missing_file(path.display().to_string())
        } else {
            constructor(
                read_message.to_string(),
                json!({
                    "path": path.display().to_string(),
                    "error": error.to_string(),
                }),
            )
        }
    })
}

fn canonical_policy_hash(policy: &AirlockPolicy) -> String {
    policy::resolved_policy_hash(policy)
}

fn system_prompt_hash(prompt_payload: &Value) -> Result<String, RefusalEnvelope> {
    let system_prompt = prompt_payload
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| messages.first())
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RefusalEnvelope::bad_prompt(
                "prompt payload must contain a system message with string content",
                json!({ "field": "messages[0].content" }),
            )
        })?;

    Ok(blake3_hash(system_prompt.as_bytes()))
}

fn upstream_inventory(
    prompt_provenance: &PromptProvenance,
    policy: &AirlockPolicy,
) -> Vec<UpstreamArtifact> {
    let mut inventory = BTreeMap::<String, UpstreamArtifact>::new();

    for record in &prompt_provenance.records {
        inventory
            .entry(record.source_artifact_hash.clone())
            .or_insert_with(|| UpstreamArtifact {
                path: record.source_path.clone(),
                content_hash: record.source_artifact_hash.clone(),
                artifact_class: boundary_class_label(record),
                extends: None,
            });
    }

    for source in &policy.source_chain {
        inventory
            .entry(format!(
                "policy_source:{}:{}",
                source.source_ref, source.content_hash
            ))
            .or_insert_with(|| UpstreamArtifact {
                path: source.source_ref.clone(),
                content_hash: source.content_hash.clone(),
                artifact_class: "policy_source".to_string(),
                extends: Some(source.extends.clone()),
            });
    }

    inventory.into_values().collect()
}

fn boundary_class_label(record: &crate::assembler::ProvenanceRecord) -> String {
    match record.boundary_class {
        crate::assembler::BoundaryClass::Telemetry => "telemetry".to_string(),
        crate::assembler::BoundaryClass::DerivedText => "derived_text".to_string(),
        crate::assembler::BoundaryClass::Forbidden => "forbidden".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;
    use crate::adapter::{Adapter, OpenAiChatCompletionsAdapter, TransportConfig};
    use crate::assembler::{self, InputArtifact};
    use crate::output::canonical_json;
    use crate::policy::{AllowRule, ForbiddenPattern};
    use crate::types::{BoundaryMode, ClaimLevel};

    fn sample_policy() -> AirlockPolicy {
        AirlockPolicy {
            policy_id: "tournament_baseline".to_string(),
            version: "airlock.v0".to_string(),
            allowed_keys: vec![
                AllowRule {
                    key_path: "family_id".to_string(),
                    description: None,
                    boundary_class: Some(crate::assembler::BoundaryClass::Telemetry),
                },
                AllowRule {
                    key_path: "benchmark_summary.score".to_string(),
                    description: None,
                    boundary_class: Some(crate::assembler::BoundaryClass::Telemetry),
                },
                AllowRule {
                    key_path: "mutator_context.challenge_observation".to_string(),
                    description: None,
                    boundary_class: Some(crate::assembler::BoundaryClass::DerivedText),
                },
            ],
            forbidden_keys: vec!["html_path".to_string()],
            forbidden_patterns: vec![ForbiddenPattern {
                pattern: "<[a-z][^>]*>".to_string(),
                description: Some("Raw HTML".to_string()),
                artifact_class: Some("raw_html".to_string()),
            }],
            derived_text_paths: vec!["mutator_context.challenge_observation".to_string()],
            claim_levels: vec![
                ClaimLevel::BoundaryFailed,
                ClaimLevel::RawDocumentAbsent,
                ClaimLevel::StrictTelemetryOnly,
            ],
            detectors: Vec::new(),
            detectors_warn_only: Vec::new(),
            protected_bloom_min_hits: None,
            tabular_min_rows: None,
            allow_multimodal: None,
            extends: Vec::new(),
            source_chain: Vec::new(),
        }
    }

    fn write_policy(path: &Path, policy: &AirlockPolicy) {
        std::fs::write(path, serde_yaml::to_string(policy).unwrap()).unwrap();
    }

    fn write_json(path: &Path, value: &Value) {
        std::fs::write(path, canonical_json(value)).unwrap();
    }

    fn verify_args(dir: &tempfile::TempDir) -> VerifyArgs {
        VerifyArgs {
            policy: dir.path().join("policy.yaml"),
            prompt: dir.path().join("prompt.json"),
            provenance: dir.path().join("provenance.json"),
            request: dir.path().join("request.json"),
            transport: None,
            out: dir.path().join("manifest.json"),
            require_claim: None,
            no_witness: false,
        }
    }

    fn setup_clean_case(
        dir: &tempfile::TempDir,
        boundary_mode: BoundaryMode,
    ) -> (VerifyArgs, Value) {
        let policy = sample_policy();
        write_policy(&dir.path().join("policy.yaml"), &policy);

        let input = InputArtifact {
            path: PathBuf::from("strategy_space.json"),
            content_hash: blake3_hash(b"strategy-space"),
            data: json!({
                "family_id": "bdc_schedule_of_investments",
                "benchmark_summary": { "score": 0.98 },
                "mutator_context": {
                    "challenge_observation": "Dense layout."
                }
            }),
        };

        let assembled =
            assembler::assemble(&policy, &[input], "System prompt", boundary_mode).unwrap();
        write_json(&dir.path().join("prompt.json"), &assembled.prompt_payload);
        write_json(
            &dir.path().join("provenance.json"),
            &serde_json::to_value(&assembled.prompt_provenance).unwrap(),
        );

        let adapter = OpenAiChatCompletionsAdapter;
        let request = adapter
            .wrap(
                &assembled.prompt_payload,
                &TransportConfig {
                    model_id: "gpt-5".to_string(),
                    temperature: Some(0.0),
                    max_tokens: None,
                    response_format: None,
                    additional_params: None,
                },
            )
            .unwrap();
        write_json(&dir.path().join("request.json"), &request);

        (verify_args(dir), request)
    }

    #[test]
    fn verify_writes_manifest_and_returns_pass_for_clean_telemetry_only() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("witness.jsonl");
        let (args, _) = setup_clean_case(&dir, BoundaryMode::TelemetryOnly);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args.clone(), &ledger_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PASS);
        let manifest: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(manifest["achieved_claim"], "STRICT_TELEMETRY_ONLY");
        assert_eq!(manifest["binding_status"], "BOUND");
        assert!(args.out.exists());
        assert!(ledger_path.exists());
        assert!(stderr.is_empty());
    }

    #[test]
    fn verify_applies_require_claim_gating() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("witness.jsonl");
        let (mut args, _) = setup_clean_case(&dir, BoundaryMode::Annotated);
        args.require_claim = Some(ClaimLevel::StrictTelemetryOnly);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args.clone(), &ledger_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PARTIAL);
        let manifest: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(manifest["achieved_claim"], "RAW_DOCUMENT_ABSENT");
        assert!(args.out.exists());
        assert!(ledger_path.exists());
        assert!(stderr.is_empty());
    }

    #[test]
    fn verify_always_emits_manifest_for_boundary_failed() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("witness.jsonl");
        let (args, mut request) = setup_clean_case(&dir, BoundaryMode::TelemetryOnly);
        request["html_path"] = json!("/tmp/filing.html");
        write_json(&args.request, &request);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args.clone(), &ledger_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PASS);
        let manifest: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(manifest["achieved_claim"], "BOUNDARY_FAILED");
        assert_eq!(manifest["binding_status"], "UNBOUND");
        assert!(args.out.exists());
        assert!(stderr.is_empty());
    }

    #[test]
    fn missing_prompt_file_returns_structured_refusal() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("witness.jsonl");
        let args = verify_args(&dir);
        write_policy(&args.policy, &sample_policy());
        std::fs::write(&args.provenance, "{}").unwrap();
        std::fs::write(&args.request, "{}").unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args, &ledger_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, crate::cli::REFUSAL);
        let refusal: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(refusal["outcome"], "REFUSAL");
        assert_eq!(refusal["refusal"]["code"], "E_MISSING_FILE");
        assert!(!ledger_path.exists());
        assert!(stderr.is_empty());
    }

    #[test]
    fn request_with_integer_beyond_two_to_the_53_is_refused_not_hashed() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("witness.jsonl");
        let (args, mut request) = setup_clean_case(&dir, BoundaryMode::TelemetryOnly);
        // A legitimate OpenAI field whose value a double-based JCS library would round.
        request["seed"] = json!(9_007_199_254_740_993_u64);
        write_json(&args.request, &request);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args.clone(), &ledger_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, crate::cli::REFUSAL);
        let refusal: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(refusal["refusal"]["code"], "E_BAD_REQUEST");
        assert_eq!(refusal["refusal"]["detail"]["pointer"], "/seed");
        assert_eq!(refusal["refusal"]["detail"]["number"], "9007199254740993");
        assert_eq!(
            refusal["refusal"]["detail"]["max_integer_magnitude"],
            9_007_199_254_740_992_u64
        );
        assert!(!args.out.exists(), "no manifest may be written");
        assert!(!ledger_path.exists());
    }

    #[test]
    fn prompt_with_integer_beyond_two_to_the_53_is_refused_not_hashed() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("witness.jsonl");
        let (args, _) = setup_clean_case(&dir, BoundaryMode::TelemetryOnly);
        let mut prompt: Value =
            serde_json::from_slice(&std::fs::read(&args.prompt).unwrap()).unwrap();
        prompt["extra"] = json!({ "ids": [1, 18_446_744_073_709_551_615_u64] });
        write_json(&args.prompt, &prompt);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args.clone(), &ledger_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, crate::cli::REFUSAL);
        let refusal: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(refusal["refusal"]["code"], "E_BAD_PROMPT");
        assert_eq!(refusal["refusal"]["detail"]["pointer"], "/extra/ids/1");
        assert_eq!(
            refusal["refusal"]["detail"]["number"],
            "18446744073709551615"
        );
        assert!(!args.out.exists(), "no manifest may be written");
        assert!(!ledger_path.exists());
    }

    #[test]
    fn request_with_integer_exactly_two_to_the_53_still_verifies() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("witness.jsonl");
        let (args, mut request) = setup_clean_case(&dir, BoundaryMode::TelemetryOnly);
        request["seed"] = json!(9_007_199_254_740_992_u64);
        write_json(&args.request, &request);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args, &ledger_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PASS);
        let manifest: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(
            manifest["request_payload_hash"],
            crate::hash::jcs_blake3_hash(&request).unwrap()
        );
    }

    #[test]
    fn no_witness_skips_ledger_append() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("witness.jsonl");
        let (mut args, _) = setup_clean_case(&dir, BoundaryMode::TelemetryOnly);
        args.no_witness = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args, &ledger_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PASS);
        assert!(!ledger_path.exists());
        assert!(stderr.is_empty());
    }
}
