use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::adapter::{self, Adapter, TransportDeclaration};
use crate::assembler::{
    NOT_CROSSED_VERSION, NotCrossedEntry, NotCrossedInventory, PromptProvenance,
};
use crate::cli::{VERIFY_PARTIAL, VERIFY_PASS, VerifyArgs};
use crate::hash::{blake3_hash, jcs, jcs_blake3_hash};
use crate::manifest::{AirlockManifest, Attestation, ManifestBuilder};
use crate::output::{SOURCE_DATE_EPOCH_ENV, now_utc};
use crate::policy::{self, AirlockPolicy};
use crate::refusal::RefusalEnvelope;
use crate::scanner;
use crate::signing;
use crate::types::{BoundaryMode, UpstreamArtifact};
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
    let manifest_instant = match manifest_instant("verify") {
        Ok(instant) => instant,
        Err(refusal) => return refusal.write_to(stdout),
    };

    // Signing is the default. A missing or unusable key refuses here, before any input is read
    // and before anything is written, so a run never produces a manifest it cannot sign. CI
    // without a key says so with --no-sign.
    let signing_key = match resolve_signing_key(args.no_sign) {
        Ok(key) => key,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let inputs = match load_inputs(&args.policy, &args.prompt, &args.provenance) {
        Ok(inputs) => inputs,
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

    let verified = match verify_request(
        &RequestToVerify {
            inputs: &inputs,
            provenance_path: &args.provenance,
            request_value: &request_value,
            replay_ref: args.request.display().to_string(),
            not_crossed_path: args.not_crossed.as_deref(),
            timestamp: manifest_instant.to_rfc3339(),
        },
        |request| {
            let declared_transport = match args.transport.as_deref() {
                Some(path) => Some(read_json_typed::<TransportDeclaration>(
                    path,
                    RefusalEnvelope::bad_input,
                    "failed to read transport declaration",
                    "transport declaration is not a valid transport JSON object",
                )?),
                None => None,
            };
            adapter::select(request, declared_transport.as_ref())
        },
    ) {
        Ok(verified) => verified,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let Verified {
        mut manifest,
        not_crossed,
        ..
    } = verified;
    let policy_hash = inputs.policy_hash.clone();
    let boundary_mode = manifest.boundary_mode;
    if let Some(key) = &signing_key
        && let Err(error) = signing::sign(&mut manifest, key)
    {
        return error.refusal().write_to(stdout);
    }

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
    let mut witness_inputs = vec![
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
    ];
    if let (Some(path), Some(loaded)) = (args.not_crossed.as_deref(), &not_crossed) {
        witness_inputs.push(WitnessRecord::input(
            path.display().to_string(),
            loaded.content_hash.clone(),
        ));
    }
    let witness_record = WitnessRecord::new(
        "verify",
        witness_outcome,
        exit_code,
        witness_inputs,
        json!({
            "boundary_mode": boundary_mode,
            "require_claim": args.require_claim,
            "achieved_claim": manifest.achieved_claim,
            // Where the manifest and its prompt provenance are, as absolute paths, so that
            // `airlock gate --witness-lookup` can find them. The ledger only says where to look:
            // the gate loads a file only if it still hashes to this record's stdout_hash.
            "manifest_path": absolute_path(&args.out),
            "provenance_path": absolute_path(&args.provenance),
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

/// `path` as an absolute path string, or null when it cannot be made one (it then names nothing
/// a later reader could open). Resolves symlinks, so it is the file itself.
fn absolute_path(path: &Path) -> Value {
    fs::canonicalize(path)
        .ok()
        .and_then(|resolved| resolved.to_str().map(str::to_owned))
        .map_or(Value::Null, Value::String)
}

/// The instant a manifest is stamped with: the fixed one `SOURCE_DATE_EPOCH` names, else now.
/// A malformed value refuses rather than falling back to the clock. `command` names the
/// subcommand in the refusal's next step.
pub(crate) fn manifest_instant(command: &str) -> Result<DateTime<Utc>, RefusalEnvelope> {
    now_utc().map_err(|invalid| {
        RefusalEnvelope::bad_input_with_next_command(
            format!("invalid {SOURCE_DATE_EPOCH_ENV}: {}", invalid.reason),
            json!({
                "env": SOURCE_DATE_EPOCH_ENV,
                "value": invalid.value,
                "expected": "Unix seconds",
            }),
            format!("airlock {command} --help"),
        )
    })
}

/// The key manifests are signed with, or `None` for `--no-sign`. A missing or unusable key is
/// a refusal.
pub(crate) fn resolve_signing_key(no_sign: bool) -> Result<Option<SigningKey>, RefusalEnvelope> {
    if no_sign {
        return Ok(None);
    }
    signing::secrets_dir()
        .and_then(|dir| signing::load_signing_key(&dir))
        .map(Some)
        .map_err(|error| error.refusal())
}

/// What `verify` and `send` both load before a request exists: the policy, the assembled prompt
/// and its provenance, read in that order.
pub(crate) struct LoadedInputs {
    pub(crate) policy: AirlockPolicy,
    pub(crate) policy_hash: String,
    pub(crate) prompt_value: Value,
    pub(crate) prompt_provenance: PromptProvenance,
}

pub(crate) fn load_inputs(
    policy_path: &Path,
    prompt_path: &Path,
    provenance_path: &Path,
) -> Result<LoadedInputs, RefusalEnvelope> {
    let policy = policy::load_policy(policy_path)?;
    let policy_hash = canonical_policy_hash(&policy);
    let prompt_value = read_json_value(
        prompt_path,
        RefusalEnvelope::bad_prompt,
        "failed to read prompt payload",
        "prompt payload is not valid JSON",
    )?;
    let prompt_provenance = read_json_typed::<PromptProvenance>(
        provenance_path,
        RefusalEnvelope::bad_provenance,
        "failed to read prompt provenance",
        "prompt provenance is not valid JSON",
    )?;
    Ok(LoadedInputs {
        policy,
        policy_hash,
        prompt_value,
        prompt_provenance,
    })
}

/// One request to check against the loaded inputs.
pub(crate) struct RequestToVerify<'a> {
    pub(crate) inputs: &'a LoadedInputs,
    pub(crate) provenance_path: &'a Path,
    pub(crate) request_value: &'a Value,
    /// What the manifest's `replay_ref` says the request came from.
    pub(crate) replay_ref: String,
    pub(crate) not_crossed_path: Option<&'a Path>,
    /// The manifest's `timestamp`, already resolved.
    pub(crate) timestamp: String,
}

/// A request that passed every check that can refuse: its manifest, unsigned and
/// `self_attested`, and the not-crossed inventory it carries, if any.
pub(crate) struct Verified {
    pub(crate) manifest: AirlockManifest,
    pub(crate) not_crossed: Option<LoadedNotCrossed>,
    /// The RFC 8785 canonical request: the exact bytes `request_payload_hash` covers and
    /// `bytes_crossed` measures. `send` transmits this buffer and nothing else.
    pub(crate) canonical_request: String,
}

/// The verification `airlock verify` writes a manifest from, shared with `airlock send` so a
/// sent request is judged by exactly the code that judges a verified one. `select_adapter` runs
/// at the point the adapter is chosen, after the payload and provenance checks, so the order
/// in which bad inputs are refused does not depend on the caller.
pub(crate) fn verify_request(
    request: &RequestToVerify<'_>,
    select_adapter: impl FnOnce(&Value) -> Result<Box<dyn Adapter>, RefusalEnvelope>,
) -> Result<Verified, RefusalEnvelope> {
    let policy = &request.inputs.policy;
    let policy_hash = request.inputs.policy_hash.as_str();
    let prompt_value = &request.inputs.prompt_value;
    let prompt_provenance = &request.inputs.prompt_provenance;
    let request_value = request.request_value;

    // Both payload hashes are blake3(RFC 8785 JCS(payload)) so a third party can recompute them
    // with any standard JCS library. A payload JCS cannot represent interoperably (an integer
    // beyond 2^53) is refused here instead of being hashed into something nobody else can
    // reproduce.
    let prompt_payload_hash = jcs_blake3_hash(prompt_value).map_err(|error| {
        RefusalEnvelope::bad_prompt(
            format!("prompt payload cannot be hashed as RFC 8785 canonical JSON: {error}"),
            error.detail(),
        )
    })?;
    // One canonicalization feeds both the hash and bytes_crossed, so the recorded length is by
    // construction the length of the bytes that request_payload_hash covers.
    let canonical_request = jcs::canonicalize(request_value).map_err(|error| {
        RefusalEnvelope::bad_request(
            format!("request payload cannot be hashed as RFC 8785 canonical JSON: {error}"),
            error.detail(),
        )
    })?;
    let request_payload_hash = blake3_hash(canonical_request.as_bytes());
    let bytes_crossed = canonical_request.len() as u64;
    if prompt_provenance.prompt_payload_hash != prompt_payload_hash {
        return Err(RefusalEnvelope::bad_provenance(
            "prompt provenance does not match prompt payload hash",
            json!({
                "expected_prompt_payload_hash": prompt_payload_hash,
                "prompt_payload_hash": prompt_provenance.prompt_payload_hash,
                "path": request.provenance_path.display().to_string(),
            }),
        ));
    }

    if prompt_provenance.policy_hash != policy_hash {
        return Err(RefusalEnvelope::bad_provenance(
            "prompt provenance does not match policy hash",
            json!({
                "expected_policy_hash": policy_hash,
                "policy_hash": prompt_provenance.policy_hash,
                "path": request.provenance_path.display().to_string(),
            }),
        ));
    }

    // A prompt that carries an earlier turn must say which one, and a link must have something to
    // link: otherwise a manifest that took model output from a prior turn could present as turn
    // 0, and `chain verify` ("walk back to turn 0") would stop at it. The claim is derived from
    // the prompt either way; this keeps "no chain member means root" true.
    let carries_prior_turn = scanner::carries_prior_turn(prompt_value);
    match (&prompt_provenance.chain, carries_prior_turn) {
        (Some(link), true) => {
            if let Some(reason) = link.invalid_reason() {
                return Err(RefusalEnvelope::bad_provenance(
                    format!("prompt provenance chain link is invalid: {reason}"),
                    json!({
                        "field": "chain",
                        "path": request.provenance_path.display().to_string(),
                    }),
                ));
            }
        }
        (Some(_), false) => {
            return Err(RefusalEnvelope::bad_provenance(
                "prompt provenance carries a chain link but the prompt has no prior_turn",
                json!({
                    "field": "chain",
                    "path": request.provenance_path.display().to_string(),
                }),
            ));
        }
        (None, true) => {
            return Err(RefusalEnvelope::bad_provenance(
                "the prompt carries a prior_turn but its provenance has no chain link; assemble it with --prior-manifest",
                json!({
                    "field": "chain",
                    "path": request.provenance_path.display().to_string(),
                }),
            ));
        }
        (None, false) => {}
    }

    let boundary_mode = prompt_provenance.boundary_mode;
    let not_crossed = match request.not_crossed_path {
        Some(path) => Some(load_not_crossed(
            path,
            policy_hash,
            &prompt_payload_hash,
            boundary_mode,
        )?),
        None => None,
    };
    let system_prompt_hash = system_prompt_hash(prompt_value)?;
    let adapter = select_adapter(request_value)?;
    let model_id = adapter.model_id(request_value).ok_or_else(|| {
        RefusalEnvelope::bad_request(
            "request payload must contain a non-empty model id",
            json!({ "adapter": adapter.name() }),
        )
    })?;
    let adapter_name = adapter.name().to_string();

    let verify_result = scanner::verify(
        policy,
        prompt_value,
        prompt_provenance,
        request_value,
        boundary_mode,
        adapter.as_ref(),
    )?;

    let builder = ManifestBuilder::new()
        .binding_status(verify_result.binding_status)
        .boundary_mode(boundary_mode)
        .policy_id(policy.policy_id.clone())
        .policy_hash(policy_hash.to_owned())
        .claim_levels_evaluated(policy.claim_levels.clone())
        .achieved_claim(verify_result.achieved_claim)
        .upstream_artifact_inventory(upstream_inventory(prompt_provenance, policy))
        .system_prompt_hash(system_prompt_hash)
        .prompt_payload_hash(prompt_payload_hash)
        .prompt_provenance(
            request.provenance_path.display().to_string(),
            prompt_provenance,
        )
        .request_payload_hash(request_payload_hash)
        .replay_ref(request.replay_ref.clone())
        .model_id(model_id)
        .adapter(adapter_name)
        .raw_document_present(verify_result.raw_document_present)
        .filing_derived_text_present(verify_result.filing_derived_text_present)
        .findings(verify_result.findings)
        .blocked_reasons(verify_result.blocked_reasons)
        .timestamp(request.timestamp.clone())
        .bytes_crossed(bytes_crossed)
        .attestation(Attestation::SelfAttested);
    let builder = match &not_crossed {
        Some(loaded) => builder.not_crossed(loaded.entries.clone()),
        None => builder,
    };
    let builder = match &prompt_provenance.chain {
        Some(link) => builder.chain(link.clone()),
        None => builder,
    };
    let manifest = builder.build().map_err(|error| {
        RefusalEnvelope::internal(
            "failed to build airlock manifest",
            json!({ "error": error.to_string() }),
        )
    })?;
    Ok(Verified {
        manifest,
        not_crossed,
        canonical_request,
    })
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

/// A not-crossed inventory accepted by verify: the entries to copy into the manifest and the
/// hash of the file they came from, for the witness record.
pub(crate) struct LoadedNotCrossed {
    pub(crate) entries: Vec<NotCrossedEntry>,
    pub(crate) content_hash: String,
}

/// Read the inventory `assemble --not-crossed-out` wrote and check it belongs to this run: the
/// same policy, the same prompt payload and the same boundary mode. One from another run, or
/// with unknown fields or malformed entries, is refused rather than copied into the manifest.
fn load_not_crossed(
    path: &Path,
    policy_hash: &str,
    prompt_payload_hash: &str,
    boundary_mode: BoundaryMode,
) -> Result<LoadedNotCrossed, RefusalEnvelope> {
    let bytes = read_json_bytes(
        path,
        RefusalEnvelope::bad_input,
        "failed to read not-crossed inventory",
        "",
    )?;
    let inventory: NotCrossedInventory = serde_json::from_slice(&bytes).map_err(|error| {
        RefusalEnvelope::bad_provenance(
            "not-crossed inventory is not a valid airlock.not_crossed.v1 document",
            json!({
                "path": path.display().to_string(),
                "error": error.to_string(),
            }),
        )
    })?;
    let mismatch = |what: &str, expected: &str, actual: &str| {
        RefusalEnvelope::bad_provenance(
            format!("not-crossed inventory does not match this run: {what}"),
            json!({
                "path": path.display().to_string(),
                "expected": expected,
                "actual": actual,
            }),
        )
    };
    if inventory.version != NOT_CROSSED_VERSION {
        return Err(mismatch(
            "unsupported version",
            NOT_CROSSED_VERSION,
            &inventory.version,
        ));
    }
    if inventory.policy_hash != policy_hash {
        return Err(mismatch("policy_hash", policy_hash, &inventory.policy_hash));
    }
    if inventory.prompt_payload_hash != prompt_payload_hash {
        return Err(mismatch(
            "prompt_payload_hash",
            prompt_payload_hash,
            &inventory.prompt_payload_hash,
        ));
    }
    if inventory.boundary_mode != boundary_mode {
        return Err(mismatch(
            "boundary_mode",
            &boundary_mode.to_string(),
            &inventory.boundary_mode.to_string(),
        ));
    }
    if let Some(entry) = inventory.entries.iter().find(|entry| {
        entry.path.trim().is_empty()
            || !is_blake3_hash(&entry.source_artifact_hash)
            || !is_blake3_hash(&entry.value_hash)
    }) {
        return Err(RefusalEnvelope::bad_provenance(
            "not-crossed inventory has a malformed entry",
            json!({
                "path": path.display().to_string(),
                "entry_path": entry.path,
            }),
        ));
    }
    Ok(LoadedNotCrossed {
        content_hash: blake3_hash(&bytes),
        entries: inventory.entries,
    })
}

fn is_blake3_hash(value: &str) -> bool {
    value
        .strip_prefix("blake3:")
        .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
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
        crate::assembler::BoundaryClass::ModelOutput => "model_output".to_string(),
        crate::assembler::BoundaryClass::ToolResult => "tool_result".to_string(),
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
            declared_tool_results: Vec::new(),
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
            not_crossed: None,
            no_sign: true,
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
    fn verify_records_where_its_manifest_and_provenance_are_for_the_gate_to_find() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("witness.jsonl");
        let (args, _) = setup_clean_case(&dir, BoundaryMode::TelemetryOnly);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with_writers(args.clone(), &ledger_path, &mut stdout, &mut stderr);

        assert_eq!(exit_code, VERIFY_PASS);
        let records = witness::query_at(&ledger_path, &witness::WitnessFilters::default()).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        for (member, written) in [
            ("manifest_path", &args.out),
            ("provenance_path", &args.provenance),
        ] {
            let recorded = record.params[member].as_str().unwrap();
            assert!(Path::new(recorded).is_absolute(), "{member}: {recorded}");
            assert_eq!(
                recorded,
                std::fs::canonicalize(written).unwrap().to_str().unwrap(),
                "{member}"
            );
        }
        // The file the record names holds exactly the bytes its stdout_hash covers: that is what
        // lets a reader of the ledger tell the file is still what verify wrote.
        let manifest_bytes =
            std::fs::read(record.params["manifest_path"].as_str().unwrap()).unwrap();
        assert_eq!(blake3_hash(&manifest_bytes), record.stdout_hash);
        assert_eq!(manifest_bytes, stdout);
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
