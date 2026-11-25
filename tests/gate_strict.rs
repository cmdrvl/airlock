//! Strict-manifest gate contract, exercised against the real `airlock gate` binary and a
//! local mock origin: what is denied, with which refusal code, and what is recorded.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use jsonschema::validator_for;
use serde_json::{Value, json};
use tiny_http::{Response, Server};

/// One request as the mock origin received it.
struct Received {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct Origin {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<Received>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// A mock provider that counts every request it receives and answers 200.
fn start_origin() -> Origin {
    start_origin_replying(b"{\"ok\":true}".to_vec())
}

/// Like `start_origin`, with a chosen response body.
fn start_origin_replying(reply: Vec<u8>) -> Origin {
    start_origin_after(reply, Duration::ZERO)
}

/// Like `start_origin_replying`, but the origin waits `delay` before it answers. The wait
/// ends early when the origin is dropped, so a slow origin never slows a test down.
fn start_origin_after(reply: Vec<u8>, delay: Duration) -> Origin {
    let server = Server::http("127.0.0.1:0").unwrap();
    let address = server.server_addr().to_ip().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (thread_count, thread_received, thread_stop) =
        (Arc::clone(&count), Arc::clone(&received), Arc::clone(&stop));
    let worker = thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            let mut request = match server.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(request)) => request,
                Ok(None) => continue,
                Err(_) => break,
            };
            let headers = request
                .headers()
                .iter()
                .map(|header| (header.field.to_string(), header.value.to_string()))
                .collect();
            let mut body = Vec::new();
            let _ = request.as_reader().read_to_end(&mut body);
            thread_received
                .lock()
                .unwrap()
                .push(Received { headers, body });
            thread_count.fetch_add(1, Ordering::AcqRel);
            let answer_at = Instant::now() + delay;
            while Instant::now() < answer_at && !thread_stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(20));
            }
            let _ = request.respond(Response::from_data(reply.clone()));
        }
    });
    Origin {
        address,
        count,
        received,
        stop,
        worker: Some(worker),
    }
}

struct GateProcess {
    child: Child,
    address: SocketAddr,
    /// Everything the gate has written to stderr so far, drained by a background thread.
    stderr: Arc<Mutex<String>>,
}

impl GateProcess {
    fn stderr_text(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }
}

impl Drop for GateProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_strict_gate(
    upstream: SocketAddr,
    manifest_dir: &Path,
    out_dir: &Path,
    witness_path: &Path,
    extra: &[&str],
) -> GateProcess {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args(["gate", "--mode", "strict-manifest", "--upstream"])
        .arg(format!("http://{upstream}"))
        .args(["--listen", "127.0.0.1:0", "--manifest-dir"])
        .arg(manifest_dir)
        .arg("--out-dir")
        .arg(out_dir)
        .args(extra);
    launch_gate(command, witness_path)
}

fn start_policy_proxy_gate(
    upstream: SocketAddr,
    policy: &Path,
    out_dir: &Path,
    witness_path: &Path,
) -> GateProcess {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args(["gate", "--mode", "policy-proxy", "--upstream"])
        .arg(format!("http://{upstream}"))
        .args(["--listen", "127.0.0.1:0", "--policy"])
        .arg(policy)
        .arg("--out-dir")
        .arg(out_dir);
    launch_gate(command, witness_path)
}

/// Start the gate that `command` describes and wait for its "listening on" line.
fn launch_gate(mut command: Command, witness_path: &Path) -> GateProcess {
    let mut child = command
        .env("EPISTEMIC_WITNESS", witness_path)
        .env_remove("ALL_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("NO_PROXY")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    let address = line
        .trim()
        .strip_prefix("airlock gate listening on ")
        .unwrap_or_else(|| panic!("gate did not start: {line}"))
        .parse()
        .unwrap();
    let log = Arc::new(Mutex::new(line));
    let drain = Arc::clone(&log);
    thread::spawn(move || {
        for line in stderr.lines().map_while(Result::ok) {
            let mut log = drain.lock().unwrap();
            log.push_str(&line);
            log.push('\n');
        }
    });
    GateProcess {
        child,
        address,
        stderr: log,
    }
}

fn client() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into()
}

fn post(agent: &ureq::Agent, address: SocketAddr, body: &[u8]) -> (u16, Value) {
    post_with(agent, address, body.to_vec())
}

/// POST any kind of body: a byte vector goes out with a Content-Length, a reader goes out
/// chunked with no declared length.
fn post_with(
    agent: &ureq::Agent,
    address: SocketAddr,
    body: impl ureq::AsSendBody,
) -> (u16, Value) {
    let response = agent
        .post(&format!("http://{address}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .send(body)
        .unwrap();
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut bytes)
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn read_receipts(directory: &Path) -> Vec<Value> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .collect()
}

fn assert_valid_gate_document(document: &Value) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas/airlock_gate.v1.schema.json");
    let schema: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let validator = validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(document)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "gate document does not match airlock_gate.v1: {errors:?}\n{document}"
    );
}

/// Run one denied request through an empty-manifest strict gate and return what came back
/// plus everything recorded about it.
fn denied_request(body: &[u8]) -> (u16, Value, Vec<Value>, usize) {
    let temp = tempfile::tempdir().unwrap();
    let manifest_dir = temp.path().join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
    let origin = start_origin();
    let receipts_dir = temp.path().join("receipts");
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &receipts_dir,
        &temp.path().join("witness.jsonl"),
        &[],
    );
    let (status, refusal) = post(&client(), gate.address, body);
    drop(gate);
    let forwarded = origin.count.load(Ordering::Acquire);
    (status, refusal, read_receipts(&receipts_dir), forwarded)
}

#[test]
fn request_with_no_matching_manifest_is_denied_with_e_gate_denied() {
    let (status, refusal, receipts, forwarded) = denied_request(br#"{"messages":[]}"#);

    assert_eq!(status, 403);
    assert_eq!(refusal["schema_version"], "airlock.gate_refusal.v1");
    assert_eq!(refusal["code"], "E_GATE_DENIED");
    assert_eq!(
        refusal["findings"][0]["rule_id"],
        "REQUEST_MANIFEST_NOT_FOUND"
    );
    assert_eq!(forwarded, 0, "a denied request must never reach the origin");
    assert_valid_gate_document(&refusal);

    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["blocked"], true);
    assert_eq!(receipts[0]["mode"], "strict-manifest");
    assert_eq!(receipts[0]["achieved_claim"], "BOUNDARY_FAILED");
    assert_valid_gate_document(&receipts[0]);
}

#[test]
fn malformed_request_body_is_denied_with_e_gate_denied() {
    let (status, refusal, receipts, forwarded) = denied_request(b"{not json");

    assert_eq!(status, 403);
    assert_eq!(refusal["code"], "E_GATE_DENIED");
    assert_eq!(refusal["findings"][0]["rule_id"], "REQUEST_SCAN_REFUSED");
    assert_eq!(forwarded, 0);
    assert_valid_gate_document(&refusal);
    assert_eq!(receipts.len(), 1);
    assert_valid_gate_document(&receipts[0]);
}

/// Run `airlock verify` on the clean fixture and leave the bound manifest in a new
/// directory, so the gate has a manifest whose request hash a request can match.
fn bound_manifest_dir(parent: &Path) -> (PathBuf, Value) {
    let manifest_dir = parent.join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
    let request = add_bound_manifest(&manifest_dir, "clean_telemetry_only");
    (manifest_dir, request)
}

/// Run `airlock verify` on `fixtures/<fixture>` and add the bound manifest to `manifest_dir`
/// as `<fixture>.json`. Returns that fixture's request, which the manifest matches.
fn add_bound_manifest(manifest_dir: &Path, fixture: &str) -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(fixture);
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["verify", "--policy"])
        .arg(root.join("policy.yaml"))
        .arg("--prompt")
        .arg(root.join("expected_prompt_payload.json"))
        .arg("--provenance")
        .arg(root.join("expected_prompt_provenance.json"))
        .arg("--request")
        .arg(root.join("request.json"))
        .arg("--out")
        .arg(manifest_dir.join(format!("{fixture}.json")))
        .arg("--no-witness")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture {fixture} verification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(root.join("request.json")).unwrap()).unwrap()
}

fn read_witness(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The receipts and witness records the gate has written so far, waiting until there are
/// `expected` of each. A forwarded request is recorded after its response has gone out, so
/// a test that reads right after the response can see a receipt that is not there yet or is
/// half written; files and lines that do not parse yet are skipped and retried.
fn wait_for_recorded(
    receipts_dir: &Path,
    witness_path: &Path,
    expected: usize,
) -> (Vec<Value>, Vec<Value>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let receipts: Vec<Value> = std::fs::read_dir(receipts_dir)
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                serde_json::from_slice(&std::fs::read(entry.ok()?.path()).ok()?).ok()
            })
            .collect();
        let witness: Vec<Value> = std::fs::read_to_string(witness_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if receipts.len() >= expected && witness.len() >= expected {
            return (receipts, witness);
        }
        assert!(
            Instant::now() < deadline,
            "gate recorded {} receipts and {} witness records, expected {expected}",
            receipts.len(),
            witness.len()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn forwarded_and_denied_requests_record_byte_counts_in_receipt_and_witness() {
    const REPLY_BYTES: usize = 1234;
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin_replying(vec![b'x'; REPLY_BYTES]);
    let receipts_dir = temp.path().join("receipts");
    let witness_path = temp.path().join("witness.jsonl");
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &receipts_dir,
        &witness_path,
        &[],
    );
    let agent = client();

    // A matched request sent in pretty-printed (non-canonical) form: the byte count must be
    // what the client sent, not the canonical bytes the gate forwards.
    let pretty = serde_json::to_vec_pretty(&request).unwrap();
    let canonical = airlock::hash::jcs::canonicalize(&request).unwrap();
    assert_ne!(pretty.len(), canonical.len(), "test needs distinct sizes");
    let unmatched = br#"{"messages":[]}"#;
    let malformed = b"{not json";

    let response = agent
        .post(&format!("http://{}/v1/chat/completions", gate.address))
        .header("Content-Type", "application/json")
        .send(pretty.clone())
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let mut reply = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut reply)
        .unwrap();
    assert_eq!(reply.len(), REPLY_BYTES);
    assert_eq!(post(&agent, gate.address, unmatched).0, 403);
    assert_eq!(post(&agent, gate.address, malformed).0, 403);
    let (receipts, witness) = wait_for_recorded(&receipts_dir, &witness_path, 3);
    drop(gate);

    assert_eq!(receipts.len(), 3);
    receipts.iter().for_each(assert_valid_gate_document);
    let find = |predicate: &dyn Fn(&Value) -> bool| {
        receipts
            .iter()
            .find(|receipt| predicate(receipt))
            .unwrap_or_else(|| panic!("no matching receipt in {receipts:?}"))
    };
    let forwarded = find(&|receipt| receipt["blocked"] == false);
    assert_eq!(forwarded["request_bytes"], pretty.len());
    assert_eq!(forwarded["response_bytes"], REPLY_BYTES);
    assert_eq!(forwarded["upstream_status"], 200);
    let denied_unmatched = find(&|receipt| receipt["request_bytes"] == unmatched.len());
    assert_eq!(denied_unmatched["blocked"], true);
    assert!(denied_unmatched.get("response_bytes").is_none());
    let denied_malformed = find(&|receipt| receipt["request_bytes"] == malformed.len());
    assert_eq!(denied_malformed["blocked"], true);

    let gated = witness
        .iter()
        .find(|record| record["outcome"] == "GATED")
        .expect("a GATED witness record");
    assert_eq!(gated["params"]["request_bytes"], pretty.len());
    assert_eq!(gated["params"]["response_bytes"], REPLY_BYTES);
    assert_eq!(gated["params"]["upstream_status"], 200);
    let denied: Vec<&Value> = witness
        .iter()
        .filter(|record| record["outcome"] == "BOUNDARY_FAILED")
        .collect();
    assert_eq!(denied.len(), 2);
    assert!(
        denied
            .iter()
            .any(|record| record["params"]["request_bytes"] == unmatched.len())
    );
    assert!(
        denied
            .iter()
            .all(|record| record["params"]["response_bytes"].is_null())
    );
}

/// What one request sent to a strict gate with a request-size cap left behind.
struct CapRun {
    status: u16,
    body: Value,
    receipts: Vec<Value>,
    witness: Vec<Value>,
    forwarded: usize,
    sent_bytes: usize,
}

/// Send the fixture request that a bound manifest matches, pretty-printed, to a strict gate
/// whose `--max-request-bytes` is the request's size plus `cap_delta`. `chunked` sends the
/// body with no declared length.
fn run_with_cap(cap_delta: i64, chunked: bool) -> CapRun {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let pretty = serde_json::to_vec_pretty(&request).unwrap();
    let cap = (pretty.len() as i64 + cap_delta).to_string();
    let origin = start_origin();
    let receipts_dir = temp.path().join("receipts");
    let witness_path = temp.path().join("witness.jsonl");
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &receipts_dir,
        &witness_path,
        &["--max-request-bytes", &cap],
    );
    let agent = client();
    let (status, body) = if chunked {
        post_with(
            &agent,
            gate.address,
            ureq::SendBody::from_owned_reader(std::io::Cursor::new(pretty.clone())),
        )
    } else {
        post(&agent, gate.address, &pretty)
    };
    let (receipts, witness) = wait_for_recorded(&receipts_dir, &witness_path, 1);
    drop(gate);
    CapRun {
        status,
        body,
        receipts,
        witness,
        forwarded: origin.count.load(Ordering::Acquire),
        sent_bytes: pretty.len(),
    }
}

#[test]
fn request_over_the_size_cap_is_denied_and_the_cap_is_recorded() {
    let run = run_with_cap(-1, false);

    assert_eq!(run.status, 403);
    assert_eq!(run.body["code"], "E_GATE_DENIED");
    assert_eq!(
        run.forwarded, 0,
        "an oversized request must never reach the origin"
    );
    assert_eq!(run.receipts.len(), 1);
    let receipt = &run.receipts[0];
    assert_valid_gate_document(receipt);
    assert_eq!(receipt["blocked"], true);
    assert_eq!(receipt["limit"]["kind"], "max_request_bytes");
    assert_eq!(receipt["limit"]["limit"], run.sent_bytes - 1);
    assert_eq!(
        receipt["limit"]["observed"], run.sent_bytes,
        "a declared Content-Length is recorded as the observed size"
    );
    assert!(
        receipt.get("request_bytes").is_none(),
        "the oversized body was never read, so no received size is claimed"
    );
    let witness = run
        .witness
        .iter()
        .find(|record| record["outcome"] == "BOUNDARY_FAILED")
        .expect("a witness record for the denial");
    assert_eq!(witness["params"]["limit"], receipt["limit"]);
}

#[test]
fn chunked_request_over_the_size_cap_is_denied_without_an_observed_size() {
    let run = run_with_cap(-1, true);

    assert_eq!(run.status, 403);
    assert_eq!(run.body["code"], "E_GATE_DENIED");
    assert_eq!(run.forwarded, 0);
    assert_eq!(run.receipts.len(), 1);
    let receipt = &run.receipts[0];
    assert_valid_gate_document(receipt);
    assert_eq!(receipt["limit"]["kind"], "max_request_bytes");
    assert_eq!(receipt["limit"]["limit"], run.sent_bytes - 1);
    assert!(
        receipt["limit"].get("observed").is_none(),
        "a body with no declared length has no observed size to report: {receipt}"
    );
}

#[test]
fn request_exactly_at_the_size_cap_is_forwarded() {
    let run = run_with_cap(0, false);

    assert_eq!(run.status, 200);
    assert_eq!(run.forwarded, 1);
    assert_eq!(run.receipts.len(), 1);
    assert_valid_gate_document(&run.receipts[0]);
    assert_eq!(run.receipts[0]["blocked"], false);
    assert_eq!(run.receipts[0]["request_bytes"], run.sent_bytes);
    assert!(run.receipts[0].get("limit").is_none());
}

#[test]
fn upstream_timeout_is_recorded_with_the_configured_limit_but_other_failures_are_not() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let pretty = serde_json::to_vec_pretty(&request).unwrap();

    // An origin that answers after 3 s, behind a gate that waits 1 s.
    let slow_origin = start_origin_after(b"{}".to_vec(), Duration::from_secs(3));
    let slow_receipts = temp.path().join("slow-receipts");
    let slow_witness = temp.path().join("slow-witness.jsonl");
    let slow_gate = start_strict_gate(
        slow_origin.address,
        &manifest_dir,
        &slow_receipts,
        &slow_witness,
        &["--timeout-seconds", "1"],
    );
    let (status, refusal) = post(&client(), slow_gate.address, &pretty);
    drop(slow_gate);

    assert_eq!(status, 502);
    assert_eq!(refusal["code"], "UPSTREAM_UNAVAILABLE");
    let receipts = read_receipts(&slow_receipts);
    assert_eq!(receipts.len(), 1);
    assert_valid_gate_document(&receipts[0]);
    assert_eq!(receipts[0]["findings"][0]["rule_id"], "UPSTREAM_TIMEOUT");
    assert_eq!(receipts[0]["limit"]["kind"], "timeout_seconds");
    assert_eq!(receipts[0]["limit"]["limit"], 1);
    assert_eq!(receipts[0]["request_bytes"], pretty.len());
    let witness = read_witness(&slow_witness);
    let record = witness
        .iter()
        .find(|record| record["outcome"] == "GATE_UPSTREAM_ERROR")
        .expect("a witness record for the timeout");
    assert_eq!(record["params"]["limit"], receipts[0]["limit"]);

    // An upstream that refuses the connection is an upstream failure, not a timeout.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_address = closed.local_addr().unwrap();
    drop(closed);
    let refused_receipts = temp.path().join("refused-receipts");
    let refused_gate = start_strict_gate(
        closed_address,
        &manifest_dir,
        &refused_receipts,
        &temp.path().join("refused-witness.jsonl"),
        &[],
    );
    let (status, refusal) = post(&client(), refused_gate.address, &pretty);
    drop(refused_gate);

    assert_eq!(status, 502);
    assert_eq!(refusal["code"], "UPSTREAM_UNAVAILABLE");
    let receipts = read_receipts(&refused_receipts);
    assert_eq!(receipts.len(), 1);
    assert_valid_gate_document(&receipts[0]);
    assert_eq!(
        receipts[0]["findings"][0]["rule_id"],
        "UPSTREAM_UNAVAILABLE"
    );
    assert!(receipts[0].get("limit").is_none());
}

#[test]
fn policy_proxy_refuses_a_size_cap_above_its_scan_limit_at_startup() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/clean_telemetry_only");
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args([
            "gate",
            "--mode",
            "policy-proxy",
            "--upstream",
            "https://api.openai.com",
            "--max-request-bytes",
            "4194305",
            "--policy",
        ])
        .arg(root.join("policy.yaml"))
        .arg("--out-dir")
        .arg(temp.path().join("receipts"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--max-request-bytes cannot exceed the policy-proxy scan limit of 4194304"),
        "unexpected stderr: {stderr}"
    );
}

/// What a strict gate did with one request from each of two fixtures whose bound manifests
/// carry different claim levels.
struct ClaimRun {
    /// `annotated_mode`, whose manifest claims RAW_DOCUMENT_ABSENT.
    weaker: (u16, Value),
    /// `clean_telemetry_only`, whose manifest claims STRICT_TELEMETRY_ONLY.
    stronger: (u16, Value),
    forwarded: usize,
    receipts: Vec<Value>,
}

fn run_with_claims(extra: &[&str]) -> ClaimRun {
    let temp = tempfile::tempdir().unwrap();
    let manifest_dir = temp.path().join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
    let weaker_request = add_bound_manifest(&manifest_dir, "annotated_mode");
    let stronger_request = add_bound_manifest(&manifest_dir, "clean_telemetry_only");
    let origin = start_origin();
    let receipts_dir = temp.path().join("receipts");
    let witness_path = temp.path().join("witness.jsonl");
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &receipts_dir,
        &witness_path,
        extra,
    );
    let agent = client();
    let weaker = post(
        &agent,
        gate.address,
        &serde_json::to_vec(&weaker_request).unwrap(),
    );
    let stronger = post(
        &agent,
        gate.address,
        &serde_json::to_vec(&stronger_request).unwrap(),
    );
    let (receipts, _) = wait_for_recorded(&receipts_dir, &witness_path, 2);
    drop(gate);
    ClaimRun {
        weaker,
        stronger,
        forwarded: origin.count.load(Ordering::Acquire),
        receipts,
    }
}

fn claims_of_forwarded(receipts: &[Value]) -> Vec<String> {
    let mut claims: Vec<String> = receipts
        .iter()
        .filter(|receipt| receipt["blocked"] == false)
        .map(|receipt| receipt["achieved_claim"].as_str().unwrap().to_owned())
        .collect();
    claims.sort();
    claims
}

#[test]
fn strict_gate_without_require_claim_forwards_every_bound_manifest_level() {
    let run = run_with_claims(&[]);

    assert_eq!(run.weaker.0, 200);
    assert_eq!(run.stronger.0, 200);
    assert_eq!(run.forwarded, 2);
    run.receipts.iter().for_each(assert_valid_gate_document);
    assert_eq!(
        claims_of_forwarded(&run.receipts),
        ["RAW_DOCUMENT_ABSENT", "STRICT_TELEMETRY_ONLY"]
    );
}

#[test]
fn require_claim_denies_a_request_whose_manifest_claims_less() {
    let run = run_with_claims(&["--require-claim", "STRICT_TELEMETRY_ONLY"]);

    assert_eq!(run.weaker.0, 403);
    assert_eq!(run.weaker.1["code"], "E_GATE_DENIED");
    assert_eq!(
        run.weaker.1["findings"][0]["rule_id"],
        "REQUEST_CLAIM_BELOW_REQUIRED"
    );
    assert_valid_gate_document(&run.weaker.1);
    assert_eq!(run.stronger.0, 200);
    assert_eq!(
        run.forwarded, 1,
        "only the request whose manifest meets the required claim reaches the origin"
    );
    run.receipts.iter().for_each(assert_valid_gate_document);
    assert_eq!(
        claims_of_forwarded(&run.receipts),
        ["STRICT_TELEMETRY_ONLY"]
    );
    let denied: Vec<&Value> = run
        .receipts
        .iter()
        .filter(|receipt| receipt["blocked"] == true)
        .collect();
    assert_eq!(denied.len(), 1);
    assert_eq!(
        denied[0]["findings"][0]["rule_id"],
        "REQUEST_CLAIM_BELOW_REQUIRED"
    );
}

#[test]
fn require_claim_forwards_manifests_at_that_level_and_above() {
    let run = run_with_claims(&["--require-claim", "RAW_DOCUMENT_ABSENT"]);

    assert_eq!(run.weaker.0, 200);
    assert_eq!(run.stronger.0, 200);
    assert_eq!(run.forwarded, 2);
}

#[test]
fn policy_proxy_refuses_require_claim_at_startup() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/clean_telemetry_only");
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args([
            "gate",
            "--mode",
            "policy-proxy",
            "--upstream",
            "https://api.openai.com",
            "--require-claim",
            "RAW_DOCUMENT_ABSENT",
            "--policy",
        ])
        .arg(root.join("policy.yaml"))
        .arg("--out-dir")
        .arg(temp.path().join("receipts"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--require-claim only applies to strict-manifest mode"),
        "unexpected stderr: {stderr}"
    );
}

fn get_health(agent: &ureq::Agent, address: SocketAddr, path: &str) -> (u16, Value) {
    let response = agent
        .get(&format!("http://{address}{path}"))
        .call()
        .unwrap();
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut bytes)
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[test]
fn health_endpoint_reports_the_gate_without_forwarding_or_recording() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin();
    let receipts_dir = temp.path().join("receipts");
    let witness_path = temp.path().join("witness.jsonl");
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &receipts_dir,
        &witness_path,
        &[],
    );
    let agent = client();

    let (status, health) = get_health(&agent, gate.address, "/airlock/health");
    assert_eq!(status, 200);
    assert_eq!(
        health,
        json!({
            "status": "ok",
            "gate_version": "airlock.gate.v1",
            "mode": "strict-manifest",
            "manifest_count": 1
        })
    );
    // A query string does not take a request off the reserved path.
    assert_eq!(
        get_health(&agent, gate.address, "/airlock/health?probe=1").0,
        200
    );

    // The path is reserved for every method: a POST that a manifest matches is answered
    // with 405 and never forwarded.
    let posted = agent
        .post(&format!("http://{}/airlock/health", gate.address))
        .header("Content-Type", "application/json")
        .send(serde_json::to_vec(&request).unwrap())
        .unwrap();
    assert_eq!(posted.status().as_u16(), 405);

    assert_eq!(origin.count.load(Ordering::Acquire), 0);
    assert_eq!(
        std::fs::read_dir(&receipts_dir).unwrap().count(),
        0,
        "health checks write no receipts"
    );
    assert!(
        std::fs::read_to_string(&witness_path)
            .unwrap_or_default()
            .is_empty(),
        "health checks write no witness records"
    );
}

#[test]
fn policy_proxy_health_reports_the_enforced_policy() {
    let temp = tempfile::tempdir().unwrap();
    let origin = start_origin();
    let policy =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/clean_telemetry_only/policy.yaml");
    let gate = start_policy_proxy_gate(
        origin.address,
        &policy,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
    );

    let (status, health) = get_health(&client(), gate.address, "/airlock/health");

    assert_eq!(status, 200);
    assert_eq!(
        health,
        json!({
            "status": "ok",
            "gate_version": "airlock.gate.v1",
            "mode": "policy-proxy",
            "policy_id": "clean_telemetry_only"
        })
    );
    assert_eq!(origin.count.load(Ordering::Acquire), 0);
}

fn receipt_paths(directory: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

/// Run `airlock explain` on a gate receipt; `--json` output is parsed, human output is returned
/// as a string value.
fn explain(receipt: &Path, json: bool) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command.args(["explain", "--manifest"]).arg(receipt);
    if json {
        command.arg("--json");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "explain failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    if json {
        serde_json::from_str(&stdout).unwrap()
    } else {
        Value::String(stdout)
    }
}

#[test]
fn explain_describes_real_gate_receipts() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin();
    let receipts_dir = temp.path().join("receipts");
    let witness_path = temp.path().join("witness.jsonl");
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &receipts_dir,
        &witness_path,
        &[],
    );
    let agent = client();
    let pretty = serde_json::to_vec_pretty(&request).unwrap();
    assert_eq!(post(&agent, gate.address, &pretty).0, 200);
    assert_eq!(post(&agent, gate.address, br#"{"messages":[]}"#).0, 403);
    assert_eq!(post(&agent, gate.address, b"{not json").0, 403);
    wait_for_recorded(&receipts_dir, &witness_path, 3);
    drop(gate);

    let explanations: Vec<Value> = receipt_paths(&receipts_dir)
        .iter()
        .map(|path| explain(path, true))
        .collect();
    assert_eq!(explanations.len(), 3);
    explanations
        .iter()
        .for_each(|explanation| assert_eq!(explanation["schema"], "airlock.explain_gate.v1"));
    let with_decision = |decision: &str| -> Vec<&Value> {
        explanations
            .iter()
            .filter(|explanation| explanation["decision"] == decision)
            .collect()
    };

    let forwarded = with_decision("forwarded");
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0]["claim"]["achieved"], "STRICT_TELEMETRY_ONLY");
    assert_eq!(forwarded[0]["request"]["bytes"], pretty.len());
    assert_eq!(forwarded[0]["upstream"]["status"], 200);
    assert_eq!(forwarded[0]["upstream"]["response_bytes"], 11);
    assert!(forwarded[0]["matched_manifest_hash"].is_string());
    assert_eq!(forwarded[0]["reasons"], json!([]));

    let denied = with_decision("denied");
    assert_eq!(denied.len(), 2);
    let unmatched = denied
        .iter()
        .find(|explanation| explanation["request"]["hash"].is_string())
        .expect("the unmatched request was hashed");
    assert_eq!(
        unmatched["reasons"][0]["rule_id"],
        "REQUEST_MANIFEST_NOT_FOUND"
    );
    assert!(
        unmatched["reasons"][0]["explanation"]
            .as_str()
            .unwrap()
            .contains("no verified manifest")
    );
    let malformed = denied
        .iter()
        .find(|explanation| explanation["request"]["hash"].is_null())
        .expect("the malformed request never got a hash");
    assert_eq!(malformed["request"]["bytes"], b"{not json".len());

    // The human form of the forwarded receipt says so too.
    let forwarded_path = receipt_paths(&receipts_dir)
        .into_iter()
        .find(|path| explain(path, true)["decision"] == "forwarded")
        .unwrap();
    let human = explain(&forwarded_path, false);
    let human = human.as_str().unwrap();
    assert!(human.contains("Decision: FORWARDED."), "{human}");
    assert!(human.contains("Upstream response: HTTP 200"), "{human}");
    assert!(human.contains("Response body: 11 bytes"), "{human}");
}

/// An origin that promises a 1000-byte body, sends ten bytes and hangs up.
fn start_truncating_origin() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; content_length];
        let _ = reader.read_exact(&mut body);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n0123456789",
        );
        let _ = stream.flush();
    });
    address
}

#[test]
fn response_cut_short_is_marked_interrupted_in_receipt_witness_and_explain() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let upstream = start_truncating_origin();
    let receipts_dir = temp.path().join("receipts");
    let witness_path = temp.path().join("witness.jsonl");
    let gate = start_strict_gate(upstream, &manifest_dir, &receipts_dir, &witness_path, &[]);

    // The client's view of the cut-off response does not matter here, only what was recorded.
    // The gate does not end this client's response when the upstream cuts it short: the
    // request stays open until the client gives up (al-3pz G14), so the client runs on its own
    // thread and this test reads what the gate recorded instead of waiting on it.
    let url = format!("http://{}/v1/chat/completions", gate.address);
    let body = serde_json::to_vec(&request).unwrap();
    let client_thread = thread::spawn(move || {
        let _ = client()
            .post(&url)
            .header("Content-Type", "application/json")
            .send(body)
            .map(|response| {
                response
                    .into_body()
                    .into_reader()
                    .read_to_end(&mut Vec::new())
            });
    });
    let (receipts, witness) = wait_for_recorded(&receipts_dir, &witness_path, 1);
    drop(gate);
    client_thread.join().unwrap();

    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_valid_gate_document(receipt);
    assert_eq!(receipt["blocked"], false);
    assert_eq!(receipt["upstream_status"], 200);
    assert!(receipt["response_bytes"].as_u64().unwrap() < 1000);
    assert_eq!(receipt["findings"][0]["rule_id"], "GATE_STREAM_INTERRUPTED");
    assert!(
        witness
            .iter()
            .any(|record| record["outcome"] == "GATE_STREAM_INTERRUPTED")
    );

    let explanation = explain(&receipt_paths(&receipts_dir)[0], true);
    assert_eq!(explanation["decision"], "forwarded_interrupted");
    assert_eq!(
        explanation["reasons"][0]["explanation"],
        "the response stream ended before it completed"
    );
}

#[test]
fn forwarded_request_keeps_end_user_headers_drops_hop_by_hop_and_sends_canonical_bytes() {
    const AUTHORIZATION: &str = "Bearer sk-test-SECRET-AUTH-1234";
    const API_KEY: &str = "SECRET-API-KEY-5678";
    const PROXY_SECRET: &str = "c2VjcmV0LXByb3h5";
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin();
    let receipts_dir = temp.path().join("receipts");
    let witness_path = temp.path().join("witness.jsonl");
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &receipts_dir,
        &witness_path,
        &[],
    );
    let pretty = serde_json::to_vec_pretty(&request).unwrap();
    let canonical = airlock::hash::jcs::canonicalize(&request).unwrap();
    let canonical: &[u8] = canonical.as_ref();
    assert_ne!(pretty, canonical, "test needs a non-canonical client body");

    let response = client()
        .post(&format!("http://{}/v1/chat/completions", gate.address))
        .header("Content-Type", "application/json")
        .header("Authorization", AUTHORIZATION)
        .header("x-api-key", API_KEY)
        .header("X-Trace-Id", "trace-42")
        .header("OpenAI-Organization", "org-demo")
        .header("Keep-Alive", "timeout=5")
        .header("Proxy-Authorization", format!("Basic {PROXY_SECRET}"))
        .header("TE", "trailers")
        .header("Trailer", "Expires")
        .header("Upgrade", "h2c")
        .send(pretty)
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    drop(response);

    {
        let received = origin.received.lock().unwrap();
        assert_eq!(received.len(), 1);
        let upstream = &received[0];
        // End-user headers go through untouched, credentials included.
        assert_eq!(upstream.header("authorization"), Some(AUTHORIZATION));
        assert_eq!(upstream.header("x-api-key"), Some(API_KEY));
        assert_eq!(upstream.header("x-trace-id"), Some("trace-42"));
        assert_eq!(upstream.header("openai-organization"), Some("org-demo"));
        assert_eq!(upstream.header("content-type"), Some("application/json"));
        // Hop-by-hop headers stop at the gate.
        for name in [
            "keep-alive",
            "proxy-authorization",
            "te",
            "trailer",
            "upgrade",
            "transfer-encoding",
        ] {
            assert_eq!(upstream.header(name), None, "{name} must not be forwarded");
        }
        // The gate talks to the upstream as itself, with the length of what it sends.
        assert_eq!(
            upstream.header("host"),
            Some(origin.address.to_string().as_str())
        );
        assert_eq!(
            upstream.header("content-length"),
            Some(canonical.len().to_string().as_str())
        );
        // What the manifest hash covers is what is sent: the canonical bytes, not the
        // client's own formatting.
        assert_eq!(upstream.body, canonical);
    }

    // None of the credentials reach anything the gate writes.
    let (receipts, witness) = wait_for_recorded(&receipts_dir, &witness_path, 1);
    let mut recorded = gate.stderr_text();
    recorded.push_str(&std::fs::read_to_string(&witness_path).unwrap());
    for path in receipt_paths(&receipts_dir) {
        recorded.push_str(&std::fs::read_to_string(path).unwrap());
    }
    assert_eq!((receipts.len(), witness.len()), (1, 1));
    for secret in ["SECRET-AUTH-1234", "SECRET-API-KEY-5678", PROXY_SECRET] {
        assert!(
            !recorded.contains(secret),
            "{secret} leaked into the gate's stderr, receipts or witness"
        );
    }
}

#[test]
fn bodies_the_gate_cannot_canonicalize_are_denied_and_it_keeps_serving() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin();
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );
    let agent = client();
    let deeply_nested = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let bodies: Vec<(&str, Vec<u8>)> = vec![
        ("empty body", Vec::new()),
        ("not json", b"{not json".to_vec()),
        ("invalid utf-8", vec![0xff, 0xfe, 0x7b, 0x7d]),
        ("json null", b"null".to_vec()),
        ("json array", b"[1,2,3]".to_vec()),
        ("json string", br#""a string""#.to_vec()),
        ("deeply nested array", deeply_nested.into_bytes()),
    ];

    for (label, body) in &bodies {
        let (status, refusal) = post(&agent, gate.address, body);
        assert_eq!(status, 403, "{label}");
        assert_eq!(refusal["code"], "E_GATE_DENIED", "{label}");
    }
    assert_eq!(
        origin.count.load(Ordering::Acquire),
        0,
        "no hostile body may reach the origin"
    );

    // The gate is still up and still forwards what a manifest covers.
    let (status, _) = post(&agent, gate.address, &serde_json::to_vec(&request).unwrap());
    assert_eq!(status, 200);
    assert_eq!(origin.count.load(Ordering::Acquire), 1);
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/clean_telemetry_only")
}

/// The gate accepts airlock.v0.2 and airlock.v0.3 during the transition. `verify` now writes
/// v0.3, so this uses the committed v0.2 golden, which was never regenerated.
#[test]
fn gate_still_forwards_against_a_v0_2_manifest_during_the_transition() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_dir = temp.path().join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
    let v0_2 = fixture_root().join("expected_manifest.json");
    let manifest: Value = serde_json::from_slice(&std::fs::read(&v0_2).unwrap()).unwrap();
    assert_eq!(manifest["manifest_version"], "airlock.v0.2");
    assert!(manifest.get("bytes_crossed").is_none());
    std::fs::copy(&v0_2, manifest_dir.join("v0_2.json")).unwrap();
    let request: Value =
        serde_json::from_slice(&std::fs::read(fixture_root().join("request.json")).unwrap())
            .unwrap();
    let origin = start_origin();
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );

    let (status, _) = post(
        &client(),
        gate.address,
        &serde_json::to_vec(&request).unwrap(),
    );

    assert_eq!(
        status, 200,
        "a v0.2 manifest must still authorize its request"
    );
    assert_eq!(origin.count.load(Ordering::Acquire), 1);
}

/// A v0.3 manifest that lists what did not cross still authorizes its request: the gate reads
/// the field (it is part of the manifest type, not an unknown key) and ignores it.
#[test]
fn gate_forwards_against_a_v0_3_manifest_that_carries_a_not_crossed_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let path = manifest_dir.join("clean_telemetry_only.json");
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(manifest["manifest_version"], "airlock.v0.3");
    manifest["not_crossed"] = serde_json::json!([{
        "path": "operator_note",
        "source_artifact_hash":
            "blake3:7f1fda7875ce52060297be56ccde65cf7643d682e9b909d01f54f722da4fa2c9",
        "value_hash": "blake3:e492e079dfe5a48a0b35ecfe64592fdde152b4d1a00f577e649d06a47a80bf24",
        "reason": "NOT_ALLOWED",
    }]);
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let origin = start_origin();
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );

    let (status, _) = post(
        &client(),
        gate.address,
        &serde_json::to_vec(&request).unwrap(),
    );

    assert_eq!(status, 200);
    assert_eq!(origin.count.load(Ordering::Acquire), 1);
}

fn gate_startup_with_manifest(manifest: &Value) -> (Option<i32>, String) {
    let temp = tempfile::tempdir().unwrap();
    let manifest_dir = temp.path().join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
    std::fs::write(
        manifest_dir.join("manifest.json"),
        serde_json::to_vec(manifest).unwrap(),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args([
            "gate",
            "--mode",
            "strict-manifest",
            "--upstream",
            "http://127.0.0.1:9",
            "--manifest-dir",
        ])
        .arg(&manifest_dir)
        .arg("--out-dir")
        .arg(temp.path().join("receipts"))
        .arg("--no-witness")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A gate that accepts the manifest keeps serving and never exits. Bound the wait so that
    // regression fails this test (code None) instead of hanging the suite.
    let deadline = Instant::now() + Duration::from_secs(10);
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut stderr);
    (code, stderr)
}

#[test]
fn gate_refuses_unsupported_versions_and_incomplete_v0_3_manifests_at_startup() {
    let v0_3: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join("expected_manifest_v0_3.json")).unwrap(),
    )
    .unwrap();

    let mut future = v0_3.clone();
    future["manifest_version"] = Value::from("airlock.v0.4");
    let mut without_bytes = v0_3.clone();
    without_bytes
        .as_object_mut()
        .unwrap()
        .remove("bytes_crossed");
    let mut without_attestation = v0_3.clone();
    without_attestation
        .as_object_mut()
        .unwrap()
        .remove("attestation");

    for (label, manifest, expected) in [
        ("airlock.v0.4", &future, "unsupported manifest version"),
        (
            "v0.3 without bytes_crossed",
            &without_bytes,
            "v0.3 manifest without bytes_crossed and attestation",
        ),
        (
            "v0.3 without attestation",
            &without_attestation,
            "v0.3 manifest without bytes_crossed and attestation",
        ),
    ] {
        let (code, stderr) = gate_startup_with_manifest(manifest);
        assert_eq!(code, Some(2), "{label}: {stderr}");
        assert!(
            stderr.contains(expected),
            "{label}: unexpected stderr {stderr}"
        );
    }
}

/// bytes_crossed is the size of the canonical request the manifest hash covers, so it is what
/// the gate puts on the wire. 632 was counted independently of verify, from the fixture's
/// request, with a separate canonicalizer.
#[test]
fn bytes_crossed_is_the_number_of_bytes_the_origin_receives() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(manifest_dir.join("clean_telemetry_only.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["manifest_version"], "airlock.v0.3");
    assert_eq!(manifest["bytes_crossed"], 632);
    assert_eq!(manifest["attestation"], "self_attested");
    let origin = start_origin();
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );

    // Sent pretty-printed: the origin must still receive exactly bytes_crossed bytes.
    let pretty = serde_json::to_vec_pretty(&request).unwrap();
    assert_ne!(
        pretty.len() as u64,
        manifest["bytes_crossed"].as_u64().unwrap()
    );
    let (status, _) = post(&client(), gate.address, &pretty);

    assert_eq!(status, 200);
    let received = origin.received.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].body.len() as u64, manifest["bytes_crossed"]);
}
