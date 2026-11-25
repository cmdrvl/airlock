use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::adapter::{self, PartKind, TransportDeclaration};
use crate::cli::{GateArgs, GateMode, REFUSAL, VERIFY_PASS};
use crate::hash::blake3_hash;
use crate::manifest::AirlockManifest;
use crate::manifest::gate::{GateLimit, GateReceipt, GateRefusal};
use crate::output::canonical_json_bytes;
use crate::policy::{self, AirlockPolicy};
use crate::scanner::egress::{
    DEFAULT_PROTECTED_BLOOM_MIN_HITS, EgressFinding, MAX_GATE_REQUEST_BYTES, egress_scanner,
    load_protected_bloom, scan_policy_proxy_request, scan_policy_proxy_request_with_media,
};
use crate::types::ClaimLevel;
use crate::witness::{self, WitnessInput, WitnessRecord};

const MAX_CONCURRENT_REQUESTS: usize = 32;
/// Strict-manifest mode only canonicalizes and hashes a body, so it takes up to 32 MiB by
/// default. policy-proxy also scans the body and is held to the scanner's own limit.
const DEFAULT_STRICT_MAX_REQUEST_BYTES: u64 = 32 * 1024 * 1024;

/// The request-body cap in force for `mode`. policy-proxy cannot read more than it can scan,
/// so a larger `--max-request-bytes` is refused at startup instead of silently clamped.
fn effective_max_request_bytes(mode: GateMode, requested: Option<u64>) -> Result<u64, String> {
    let scan_limit = MAX_GATE_REQUEST_BYTES as u64;
    match (mode, requested) {
        (GateMode::StrictManifest, None) => Ok(DEFAULT_STRICT_MAX_REQUEST_BYTES),
        (GateMode::StrictManifest, Some(bytes)) => Ok(bytes),
        (GateMode::PolicyProxy, None) => Ok(scan_limit),
        (GateMode::PolicyProxy, Some(bytes)) if bytes <= scan_limit => Ok(bytes),
        (GateMode::PolicyProxy, Some(_)) => Err(format!(
            "--max-request-bytes cannot exceed the policy-proxy scan limit of {scan_limit} bytes"
        )),
    }
}

#[derive(Clone)]
struct StrictManifestEntry {
    achieved_claim: ClaimLevel,
    manifest_hash: String,
}

#[derive(Clone)]
struct GateState {
    mode: GateMode,
    upstream: String,
    agent: ureq::Agent,
    policy: Option<AirlockPolicy>,
    transport: Option<TransportDeclaration>,
    policy_hash: Option<String>,
    scanner: Option<Arc<boundary_detectors::Scanner>>,
    strict_manifests: Arc<BTreeMap<String, StrictManifestEntry>>,
    out_dir: PathBuf,
    no_witness: bool,
    max_request_bytes: u64,
    timeout_seconds: u64,
    required_claim: Option<ClaimLevel>,
}

pub fn run(args: GateArgs) -> u8 {
    let mut stderr = io::stderr();
    let listen = match validate_loopback(&args.listen) {
        Ok(address) => address,
        Err(message) => {
            let _ = writeln!(stderr, "airlock gate: {message}");
            return REFUSAL;
        }
    };
    let upstream = match validate_upstream(&args.upstream) {
        Ok(upstream) => upstream,
        Err(message) => {
            let _ = writeln!(stderr, "airlock gate: {message}");
            return REFUSAL;
        }
    };
    let max_request_bytes = match effective_max_request_bytes(args.mode, args.max_request_bytes) {
        Ok(bytes) => bytes,
        Err(message) => {
            let _ = writeln!(stderr, "airlock gate: {message}");
            return REFUSAL;
        }
    };

    let (policy, transport, policy_hash, scanner, strict_manifests) = match args.mode {
        GateMode::PolicyProxy => {
            if args.manifest_dir.is_some() {
                let _ = writeln!(
                    stderr,
                    "airlock gate: --manifest-dir only applies to strict-manifest mode"
                );
                return REFUSAL;
            }
            if args.require_claim.is_some() {
                let _ = writeln!(
                    stderr,
                    "airlock gate: --require-claim only applies to strict-manifest mode"
                );
                return REFUSAL;
            }
            let Some(policy_path) = args.policy.as_deref() else {
                let _ = writeln!(stderr, "airlock gate: policy-proxy mode requires --policy");
                return REFUSAL;
            };
            let transport = match args.transport.as_deref() {
                Some(path) => match fs::read(path)
                    .map_err(|_| "transport declaration is unreadable")
                    .and_then(|bytes| {
                        serde_json::from_slice::<TransportDeclaration>(&bytes)
                            .map_err(|_| "transport declaration is invalid JSON")
                    }) {
                    Ok(transport) => Some(transport),
                    Err(message) => {
                        let _ = writeln!(stderr, "airlock gate: {message}; refusing to start");
                        return REFUSAL;
                    }
                },
                None => None,
            };
            let policy = match policy::load_policy(policy_path) {
                Ok(policy) => policy,
                Err(refusal) => return refusal.write_to(&mut io::stdout()),
            };
            let policy_hash = policy::resolved_policy_hash(&policy);
            let bloom = if let Some(path) = args.protected_bloom.as_deref() {
                match load_protected_bloom(path) {
                    Ok(bloom) => Some(bloom),
                    Err(message) => {
                        let _ = writeln!(stderr, "airlock gate: {message}; refusing to start");
                        return REFUSAL;
                    }
                }
            } else {
                None
            };
            let min_hits = policy
                .protected_bloom_min_hits
                .unwrap_or(DEFAULT_PROTECTED_BLOOM_MIN_HITS);
            let scanner = Arc::new(egress_scanner(&policy, bloom, min_hits));
            (
                Some(policy),
                transport,
                Some(policy_hash),
                Some(scanner),
                Arc::new(BTreeMap::new()),
            )
        }
        GateMode::StrictManifest => {
            if args.policy.is_some() || args.protected_bloom.is_some() || args.transport.is_some() {
                let _ = writeln!(
                    stderr,
                    "airlock gate: --policy, --transport, and --protected-bloom only apply to policy-proxy mode"
                );
                return REFUSAL;
            }
            let Some(directory) = args.manifest_dir.as_deref() else {
                let _ = writeln!(
                    stderr,
                    "airlock gate: strict-manifest mode requires --manifest-dir"
                );
                return REFUSAL;
            };
            let manifests = match load_strict_manifests(directory) {
                Ok(manifests) => manifests,
                Err(message) => {
                    let _ = writeln!(stderr, "airlock gate: {message}");
                    return REFUSAL;
                }
            };
            (None, None, None, None, Arc::new(manifests))
        }
    };

    if let Err(error) = fs::create_dir_all(&args.out_dir) {
        let _ = writeln!(
            stderr,
            "airlock gate: cannot create receipt directory: {error}"
        );
        return REFUSAL;
    }

    let timeout = Duration::from_secs(args.timeout_seconds);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .timeout_connect(Some(timeout))
        .timeout_recv_response(Some(timeout))
        .timeout_recv_body(Some(timeout))
        .timeout_send_body(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let state = Arc::new(GateState {
        mode: args.mode,
        upstream,
        agent,
        policy,
        transport,
        policy_hash,
        scanner,
        strict_manifests,
        out_dir: args.out_dir,
        no_witness: args.no_witness,
        max_request_bytes,
        timeout_seconds: args.timeout_seconds,
        required_claim: args.require_claim,
    });
    let server = match Server::http(listen) {
        Ok(server) => server,
        Err(error) => {
            let _ = writeln!(
                stderr,
                "airlock gate: failed to bind loopback listener: {error}"
            );
            return REFUSAL;
        }
    };
    let active = Arc::new(AtomicUsize::new(0));
    let bound_address = server.server_addr().to_ip().unwrap_or(listen);
    let _ = writeln!(stderr, "airlock gate listening on {bound_address}");

    loop {
        let request = match server.recv() {
            Ok(request) => request,
            Err(error) => {
                let _ = writeln!(stderr, "airlock gate: listener stopped: {error}");
                return REFUSAL;
            }
        };
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONCURRENT_REQUESTS {
            active.fetch_sub(1, Ordering::AcqRel);
            reject_overloaded(request, &state);
            continue;
        }
        let state = Arc::clone(&state);
        let active = Arc::clone(&active);
        thread::spawn(move || {
            let _active = ActiveRequest(active);
            handle_request(request, &state);
        });
    }
}

struct ActiveRequest(Arc<AtomicUsize>);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn validate_loopback(value: &str) -> Result<SocketAddr, &'static str> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "--listen must be a numeric loopback socket address")?;
    if !address.ip().is_loopback() {
        return Err("--listen must bind to a loopback address");
    }
    Ok(address)
}

fn validate_upstream(value: &str) -> Result<String, &'static str> {
    let (scheme, rest) = value
        .split_once("://")
        .ok_or("--upstream must be an absolute http or https URL")?;
    if !matches!(scheme, "https" | "http") || rest.is_empty() || rest.contains(['?', '#', '@']) {
        return Err("--upstream must be an origin URL without credentials, query, or fragment");
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || rest[authority.len()..].chars().any(|ch| ch != '/') {
        return Err("--upstream must not contain a path");
    }
    if scheme == "http" {
        let host = authority
            .strip_prefix('[')
            .and_then(|host| host.split_once(']'))
            .map(|(host, _)| host)
            .or_else(|| authority.rsplit_once(':').map(|(host, _)| host))
            .unwrap_or(authority);
        let loopback =
            host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !loopback {
            return Err("plain HTTP upstreams are allowed only for loopback hosts");
        }
    }
    Ok(value.trim_end_matches('/').to_owned())
}

fn load_strict_manifests(
    directory: &Path,
) -> Result<BTreeMap<String, StrictManifestEntry>, String> {
    let entries = fs::read_dir(directory).map_err(|_| "strict-manifest directory is unreadable")?;
    let mut manifests = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|_| "strict-manifest directory could not be read")?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "strict-manifest entry is unreadable")?;
        if !metadata.file_type().is_file() {
            return Err("strict-manifest directory contains a non-regular JSON entry".to_owned());
        }
        let bytes = fs::read(&path).map_err(|_| "strict-manifest entry is unreadable")?;
        let manifest: AirlockManifest = serde_json::from_slice(&bytes)
            .map_err(|_| "strict-manifest directory contains an invalid Airlock manifest")?;
        if manifest.manifest_version != crate::manifest::AIRLOCK_MANIFEST_VERSION {
            return Err(
                "strict-manifest directory contains an unsupported manifest version".to_owned(),
            );
        }
        if !matches!(
            manifest.achieved_claim,
            ClaimLevel::RawDocumentAbsent | ClaimLevel::StrictTelemetryOnly
        ) || manifest.binding_status != crate::types::BindingStatus::Bound
        {
            continue;
        }
        let key = manifest.request_payload_hash.clone();
        let value = StrictManifestEntry {
            achieved_claim: manifest.achieved_claim,
            manifest_hash: manifest.hash(),
        };
        manifests
            .entry(key)
            .and_modify(|prior: &mut StrictManifestEntry| {
                if value.achieved_claim == ClaimLevel::StrictTelemetryOnly
                    && prior.achieved_claim == ClaimLevel::RawDocumentAbsent
                {
                    *prior = value.clone();
                }
            })
            .or_insert(value);
    }
    Ok(manifests)
}

fn handle_request(mut request: Request, state: &GateState) {
    if request.method() != &Method::Post {
        return_json(
            request,
            StatusCode(405),
            json!({"error":"airlock gate accepts POST requests only"}),
        );
        return;
    }
    if let Some(declared) = request
        .body_length()
        .filter(|length| *length as u64 > state.max_request_bytes)
    {
        reject_oversized(request, state, Some(declared as u64));
        return;
    }
    let mut body = Vec::new();
    let read_result = request
        .as_reader()
        .take(state.max_request_bytes + 1)
        .read_to_end(&mut body);
    if read_result.is_err() {
        block_request(
            request,
            state,
            "request body could not be read",
            "REQUEST_SCAN_REFUSED",
            None,
            None,
        );
        return;
    }
    if body.len() as u64 > state.max_request_bytes {
        reject_oversized(request, state, None);
        return;
    }
    let received = body.len() as u64;
    let request_value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            block_request(
                request,
                state,
                "request body is not valid JSON",
                "REQUEST_SCAN_REFUSED",
                None,
                Some(received),
            );
            return;
        }
    };
    let canonical_body = canonical_json_bytes(&request_value);
    let canonical_request_hash = blake3_hash(&canonical_body);
    let (request_hash, achieved_claim, findings, matched_manifest_hash) = match state.mode {
        GateMode::PolicyProxy => {
            let policy = state
                .policy
                .as_ref()
                .expect("policy-proxy state has policy");
            let scanner = state
                .scanner
                .as_ref()
                .expect("policy-proxy state has scanner");
            let adapter = match adapter::select(&request_value, state.transport.as_ref()) {
                Ok(adapter) => adapter,
                Err(_) => {
                    block_request(
                        request,
                        state,
                        "request shape is not declared",
                        "ADAPTER_SELECTION_REFUSED",
                        Some(canonical_request_hash.clone()),
                        Some(received),
                    );
                    return;
                }
            };
            let screenable_parts = match adapter.extract_screenable_parts(&request_value) {
                Ok(parts) => parts,
                Err(_) => {
                    block_request(
                        request,
                        state,
                        "request shape could not be screened",
                        "ADAPTER_SCREENING_REFUSED",
                        Some(canonical_request_hash.clone()),
                        Some(received),
                    );
                    return;
                }
            };
            let base64_media_pointers = screenable_parts
                .iter()
                .filter(|part| matches!(&part.kind, PartKind::Base64Media { .. }))
                .map(|part| part.pointer.clone())
                .collect::<HashSet<_>>();
            let mut scan = match scan_policy_proxy_request_with_media(
                policy,
                &canonical_body,
                scanner,
                &base64_media_pointers,
            ) {
                Ok(scan) => scan,
                Err(error) => {
                    block_request(
                        request,
                        state,
                        &error.to_string(),
                        "REQUEST_SCAN_REFUSED",
                        Some(canonical_request_hash.clone()),
                        Some(received),
                    );
                    return;
                }
            };
            let mut should_block = scan.blocking;
            let combined_text = screenable_parts
                .iter()
                .filter(|part| matches!(&part.kind, PartKind::Text))
                .map(|part| part.data.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if !combined_text.is_empty() {
                let combined_body = canonical_json_bytes(&Value::String(combined_text));
                let combined_scan = match scan_policy_proxy_request(policy, &combined_body, scanner)
                {
                    Ok(scan) => scan,
                    Err(error) => {
                        block_request(
                            request,
                            state,
                            &error.to_string(),
                            "REQUEST_SCAN_REFUSED",
                            Some(canonical_request_hash.clone()),
                            Some(received),
                        );
                        return;
                    }
                };
                should_block |= combined_scan.blocking;
                for finding in combined_scan.findings {
                    let already_located = scan.findings.iter().any(|existing| {
                        existing.artifact_class == finding.artifact_class
                            && existing.rule_id == finding.rule_id
                            && existing.span_hash == finding.span_hash
                    });
                    if !already_located {
                        scan.findings.push(finding);
                    }
                }
            }
            if let Some(part) = screenable_parts.iter().find(|part| {
                policy.allow_multimodal != Some(true)
                    && matches!(
                        &part.kind,
                        PartKind::Base64Media { .. } | PartKind::RemoteReference
                    )
            }) {
                should_block = true;
                scan.findings.push(EgressFinding {
                    artifact_class: "MULTIMODAL_ATTACHMENT".to_owned(),
                    rule_id: "MULTIMODAL_ATTACHMENT_BLOCKED".to_owned(),
                    key_path: Some(part.pointer.clone()),
                    span_hash: None,
                });
            }
            scan.findings.sort_by(|left, right| {
                left.artifact_class
                    .cmp(&right.artifact_class)
                    .then_with(|| left.rule_id.cmp(&right.rule_id))
                    .then_with(|| left.key_path.cmp(&right.key_path))
                    .then_with(|| left.span_hash.cmp(&right.span_hash))
            });
            scan.findings.dedup();
            if should_block {
                block_request_with_findings(
                    request,
                    state,
                    &scan.findings,
                    &scan.request_hash,
                    Some(received),
                );
                return;
            }
            (
                scan.request_hash,
                "POLICY_SCREENED".to_owned(),
                scan.findings,
                None,
            )
        }
        GateMode::StrictManifest => {
            let Some(manifest) = state.strict_manifests.get(&canonical_request_hash) else {
                let finding = EgressFinding {
                    artifact_class: "STRICT_MANIFEST_REQUIRED".to_owned(),
                    rule_id: "REQUEST_MANIFEST_NOT_FOUND".to_owned(),
                    key_path: None,
                    span_hash: None,
                };
                deny_request(
                    request,
                    state,
                    &[finding],
                    &canonical_request_hash,
                    Some(received),
                );
                return;
            };
            if state
                .required_claim
                .is_some_and(|required| manifest.achieved_claim < required)
            {
                let finding = EgressFinding {
                    artifact_class: "STRICT_MANIFEST_REQUIRED".to_owned(),
                    rule_id: "REQUEST_CLAIM_BELOW_REQUIRED".to_owned(),
                    key_path: None,
                    span_hash: None,
                };
                deny_request(
                    request,
                    state,
                    &[finding],
                    &canonical_request_hash,
                    Some(received),
                );
                return;
            }
            (
                canonical_request_hash,
                manifest.achieved_claim.to_string(),
                Vec::new(),
                Some(manifest.manifest_hash.clone()),
            )
        }
    };

    forward_request(
        request,
        state,
        &canonical_body,
        Admitted {
            request_hash,
            achieved_claim,
            findings,
            matched_manifest_hash,
            request_bytes: received,
        },
    );
}

/// A request the gate has decided to forward, and what it recorded about it on the way in.
struct Admitted {
    request_hash: String,
    achieved_claim: String,
    findings: Vec<EgressFinding>,
    matched_manifest_hash: Option<String>,
    /// Bytes of request body received from the client (not the canonical bytes forwarded).
    request_bytes: u64,
}

fn block_request(
    request: Request,
    state: &GateState,
    _message: &str,
    rule_id: &str,
    request_hash: Option<String>,
    request_bytes: Option<u64>,
) {
    let findings = [scan_refused_finding(rule_id)];
    let request_hash = request_hash.unwrap_or_else(|| blake3_hash(b"unavailable"));
    let receipt = denial_receipt(state, &findings, &request_hash, request_bytes);
    refuse_request(
        request,
        state,
        receipt,
        refusal_for_mode(state.mode, &findings),
    );
}

/// Refuse a request whose body is over the size cap, recording the cap and, when the client
/// declared a length, the size it declared.
fn reject_oversized(request: Request, state: &GateState, declared: Option<u64>) {
    let findings = [scan_refused_finding("REQUEST_SCAN_REFUSED")];
    let receipt = denial_receipt(state, &findings, &blake3_hash(b"unavailable"), None).with_limit(
        GateLimit::max_request_bytes(state.max_request_bytes, declared),
    );
    refuse_request(
        request,
        state,
        receipt,
        refusal_for_mode(state.mode, &findings),
    );
}

fn scan_refused_finding(rule_id: &str) -> EgressFinding {
    EgressFinding {
        artifact_class: "REQUEST_SCAN_REFUSED".to_owned(),
        rule_id: rule_id.to_owned(),
        key_path: None,
        span_hash: None,
    }
}

/// policy-proxy keeps its published contract (a request it cannot screen is a boundary
/// failure); strict-manifest refusals are gate denials.
fn refusal_for_mode(mode: GateMode, findings: &[EgressFinding]) -> GateRefusal {
    match mode {
        GateMode::StrictManifest => GateRefusal::denied(findings.to_vec()),
        GateMode::PolicyProxy => GateRefusal::blocked(findings.to_vec()),
    }
}

/// Refuse a request because screening found something: HTTP 403, code BOUNDARY_FAILED.
fn block_request_with_findings(
    request: Request,
    state: &GateState,
    findings: &[EgressFinding],
    request_hash: &str,
    request_bytes: Option<u64>,
) {
    let receipt = denial_receipt(state, findings, request_hash, request_bytes);
    refuse_request(
        request,
        state,
        receipt,
        GateRefusal::blocked(findings.to_vec()),
    );
}

/// Refuse a strict-manifest request the gate will not forward (no matching manifest,
/// unreadable, malformed or oversized body, invalid target): HTTP 403, code E_GATE_DENIED.
fn deny_request(
    request: Request,
    state: &GateState,
    findings: &[EgressFinding],
    request_hash: &str,
    request_bytes: Option<u64>,
) {
    let receipt = denial_receipt(state, findings, request_hash, request_bytes);
    refuse_request(
        request,
        state,
        receipt,
        GateRefusal::denied(findings.to_vec()),
    );
}

/// The receipt for a request the gate refused: claim BOUNDARY_FAILED, blocked.
fn denial_receipt(
    state: &GateState,
    findings: &[EgressFinding],
    request_hash: &str,
    request_bytes: Option<u64>,
) -> GateReceipt {
    GateReceipt::new(
        mode_name(state.mode),
        "BOUNDARY_FAILED",
        request_hash,
        true,
        findings.to_vec(),
    )
    .with_policy(
        state.policy.as_ref().map(|policy| policy.policy_id.clone()),
        state.policy_hash.clone(),
    )
    .with_request_bytes(request_bytes)
}

fn refuse_request(
    request: Request,
    state: &GateState,
    mut receipt: GateReceipt,
    refusal: GateRefusal,
) {
    write_receipt_and_witness(state, &mut receipt, "BOUNDARY_FAILED", 1);
    return_json(
        request,
        StatusCode(403),
        serde_json::to_value(refusal).unwrap_or(Value::Null),
    );
}

fn forward_request(request: Request, state: &GateState, body: &[u8], admitted: Admitted) {
    let path = request.url().to_owned();
    if !path.starts_with('/') || path.starts_with("//") || path.contains(['\r', '\n']) {
        block_request(
            request,
            state,
            "request target is invalid",
            "INVALID_REQUEST_TARGET",
            Some(admitted.request_hash.clone()),
            Some(admitted.request_bytes),
        );
        return;
    }
    let upstream_url = format!("{}{}", state.upstream, path);
    let mut upstream_request = state.agent.post(&upstream_url);
    for header in request.headers() {
        let name = header.field.as_str().as_str();
        if is_hop_by_hop_header(name)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        upstream_request = upstream_request.header(name, header.value.as_str());
    }
    let upstream_response = match upstream_request.send(body) {
        Ok(response) => response,
        Err(ureq::Error::Timeout(_)) => {
            let limit = GateLimit::timeout_seconds(state.timeout_seconds);
            gateway_error(request, state, &admitted, "UPSTREAM_TIMEOUT", Some(limit));
            return;
        }
        Err(_) => {
            gateway_error(request, state, &admitted, "UPSTREAM_UNAVAILABLE", None);
            return;
        }
    };
    let status = upstream_response.status().as_u16();
    let mut response_headers = Vec::new();
    for (name, value) in upstream_response.headers() {
        if is_hop_by_hop_header(name.as_str())
            || name.as_str().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(value) = value.to_str()
            && let Ok(header) = Header::from_bytes(name.as_str().as_bytes(), value.as_bytes())
        {
            response_headers.push(header);
        }
    }
    let digest = Arc::new(Mutex::new(ResponseDigest::default()));
    let reader = HashingReader {
        inner: upstream_response.into_body().into_reader(),
        digest: Arc::clone(&digest),
    };
    let proxy_response = Response::new(StatusCode(status), response_headers, reader, None, None);
    let response_result = request.respond(proxy_response);
    let (response_hash, response_bytes) = {
        let digest = digest.lock().expect("response digest poisoned");
        (
            format!("blake3:{}", digest.hasher.finalize().to_hex()),
            digest.bytes,
        )
    };
    let completed = response_result.is_ok();

    let mut receipt = GateReceipt::new(
        mode_name(state.mode),
        &admitted.achieved_claim,
        &admitted.request_hash,
        false,
        admitted.findings,
    )
    .with_policy(
        state.policy.as_ref().map(|policy| policy.policy_id.clone()),
        state.policy_hash.clone(),
    )
    .with_request_bytes(Some(admitted.request_bytes))
    .with_matched_manifest(admitted.matched_manifest_hash);
    receipt.response_hash = Some(response_hash.clone());
    receipt.response_bytes = Some(response_bytes);
    receipt.upstream_status = Some(status);
    write_receipt_and_witness(
        state,
        &mut receipt,
        if completed {
            "GATED"
        } else {
            "GATE_STREAM_INTERRUPTED"
        },
        if completed { VERIFY_PASS } else { REFUSAL },
    );
}

/// The upstream did not give the gate a response: HTTP 502, with the limit recorded when the
/// cause was the configured upstream timeout.
fn gateway_error(
    request: Request,
    state: &GateState,
    admitted: &Admitted,
    rule_id: &str,
    limit: Option<GateLimit>,
) {
    let mut receipt = GateReceipt::new(
        mode_name(state.mode),
        &admitted.achieved_claim,
        &admitted.request_hash,
        false,
        vec![EgressFinding {
            artifact_class: "UPSTREAM_ERROR".to_owned(),
            rule_id: rule_id.to_owned(),
            key_path: None,
            span_hash: None,
        }],
    )
    .with_policy(
        state.policy.as_ref().map(|policy| policy.policy_id.clone()),
        state.policy_hash.clone(),
    )
    .with_request_bytes(Some(admitted.request_bytes))
    .with_matched_manifest(admitted.matched_manifest_hash.clone());
    receipt.limit = limit;
    write_receipt_and_witness(state, &mut receipt, "GATE_UPSTREAM_ERROR", REFUSAL);
    let refusal = GateRefusal::with_code(
        "UPSTREAM_UNAVAILABLE",
        "upstream request failed",
        vec![EgressFinding {
            artifact_class: "UPSTREAM_ERROR".to_owned(),
            rule_id: rule_id.to_owned(),
            key_path: None,
            span_hash: None,
        }],
    );
    return_json(
        request,
        StatusCode(502),
        serde_json::to_value(refusal).unwrap_or(Value::Null),
    );
}

fn write_receipt_and_witness(
    state: &GateState,
    receipt: &mut GateReceipt,
    outcome: &str,
    exit_code: u8,
) {
    if let Err(error) = receipt.write_to(&state.out_dir) {
        let _ = writeln!(io::stderr(), "airlock gate: receipt write failed: {error}");
    }
    let params = json!({
        "mode": receipt.mode,
        "achieved_claim": receipt.achieved_claim,
        "request_hash": receipt.request_hash,
        "response_hash": receipt.response_hash,
        "upstream_status": receipt.upstream_status,
        "request_bytes": receipt.request_bytes,
        "response_bytes": receipt.response_bytes,
        "limit": receipt.limit,
        "blocked": receipt.blocked,
        "finding_rules": receipt.findings.iter().map(|finding| finding.rule_id.as_str()).collect::<Vec<_>>(),
        "matched_manifest_hash": receipt.matched_manifest_hash,
    });
    let record = WitnessRecord::new(
        "gate",
        outcome,
        exit_code,
        vec![WitnessInput {
            path: "outbound_request".to_owned(),
            hash: receipt.request_hash.clone(),
        }],
        params,
        receipt.response_hash.clone().unwrap_or_default(),
        0,
    );
    let mut stderr = io::stderr();
    witness::maybe_append_witness(record, !state.no_witness, exit_code, &mut stderr);
}

fn return_json(request: Request, status: StatusCode, value: Value) {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    let response = Response::from_data(body)
        .with_status_code(status)
        .with_header(content_type);
    let _ = request.respond(response);
}

fn reject_overloaded(request: Request, state: &GateState) {
    let finding = EgressFinding {
        artifact_class: "GATE_BUSY".to_owned(),
        rule_id: "GATE_BUSY".to_owned(),
        key_path: None,
        span_hash: None,
    };
    let mut receipt = GateReceipt::new(
        mode_name(state.mode),
        "BOUNDARY_FAILED",
        blake3_hash(b"unavailable"),
        true,
        vec![finding.clone()],
    )
    .with_policy(
        state.policy.as_ref().map(|policy| policy.policy_id.clone()),
        state.policy_hash.clone(),
    );
    write_receipt_and_witness(state, &mut receipt, "BOUNDARY_FAILED", REFUSAL);
    let refusal = GateRefusal::with_code(
        "GATE_BUSY",
        "airlock gate is at its concurrent request limit",
        vec![finding],
    );
    return_json(
        request,
        StatusCode(503),
        serde_json::to_value(refusal).unwrap_or(Value::Null),
    );
}

fn is_hop_by_hop_header(name: &str) -> bool {
    [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|header| name.eq_ignore_ascii_case(header))
}

fn mode_name(mode: GateMode) -> &'static str {
    match mode {
        GateMode::StrictManifest => "strict-manifest",
        GateMode::PolicyProxy => "policy-proxy",
    }
}

/// Running hash and byte count of a response body as it streams through the gate.
#[derive(Default)]
struct ResponseDigest {
    hasher: blake3::Hasher,
    bytes: u64,
}

struct HashingReader<R> {
    inner: R,
    digest: Arc<Mutex<ResponseDigest>>,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read > 0 {
            let mut digest = self
                .digest
                .lock()
                .map_err(|_| io::Error::other("response digest poisoned"))?;
            digest.hasher.update(&buffer[..read]);
            digest.bytes += read as u64;
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_cap_defaults_and_limits_follow_the_mode() {
        let scan_limit = MAX_GATE_REQUEST_BYTES as u64;
        assert_eq!(
            effective_max_request_bytes(GateMode::StrictManifest, None),
            Ok(32 * 1024 * 1024)
        );
        assert_eq!(
            effective_max_request_bytes(GateMode::StrictManifest, Some(100 * 1024 * 1024)),
            Ok(100 * 1024 * 1024)
        );
        assert_eq!(
            effective_max_request_bytes(GateMode::PolicyProxy, None),
            Ok(scan_limit)
        );
        assert_eq!(
            effective_max_request_bytes(GateMode::PolicyProxy, Some(scan_limit)),
            Ok(scan_limit)
        );
        assert_eq!(
            effective_max_request_bytes(GateMode::PolicyProxy, Some(1024)),
            Ok(1024)
        );
        let refused = effective_max_request_bytes(GateMode::PolicyProxy, Some(scan_limit + 1));
        assert!(refused.is_err_and(|message| message.contains("scan limit")));
    }

    #[test]
    fn listener_and_upstream_must_be_constrained() {
        assert!(validate_loopback("127.0.0.1:8787").is_ok());
        assert!(validate_loopback("0.0.0.0:8787").is_err());
        assert!(validate_upstream("https://api.openai.com").is_ok());
        assert!(validate_upstream("http://127.0.0.1:9000").is_ok());
        assert!(validate_upstream("http://api.openai.com").is_err());
        assert!(validate_upstream("https://user:pass@api.openai.com").is_err());
    }

    #[test]
    fn response_hashing_reader_hashes_and_counts_streamed_bytes_without_buffering() {
        let digest = Arc::new(Mutex::new(ResponseDigest::default()));
        let mut reader = HashingReader {
            inner: &b"event: data\n\n"[..],
            digest: Arc::clone(&digest),
        };
        let mut bytes = [0; 5];
        while reader.read(&mut bytes).unwrap() > 0 {}
        let digest = digest.lock().unwrap();
        let actual = format!("blake3:{}", digest.hasher.finalize().to_hex());
        assert_eq!(actual, blake3_hash(b"event: data\n\n"));
        assert_eq!(digest.bytes, 13);
    }

    #[test]
    fn strict_manifest_index_ignores_unbound_manifests() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/clean_telemetry_only/expected_manifest.json"
        );
        let mut manifest: Value = serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        manifest["binding_status"] = Value::String("UNBOUND".to_owned());
        fs::write(
            directory.path().join("unbound.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        assert!(load_strict_manifests(directory.path()).unwrap().is_empty());
    }
}
