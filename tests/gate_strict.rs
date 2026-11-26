//! Strict-manifest gate contract, exercised against the real `airlock gate` binary and a
//! local mock origin: what is denied, with which refusal code, and what is recorded.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
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
    start_origin_answering(vec![(200, reply)], delay)
}

/// A mock provider that answers its n-th request with the n-th `(status, body)` of `answers`
/// (the last one again once they run out), after waiting `delay`.
fn start_origin_answering(answers: Vec<(u16, Vec<u8>)>, delay: Duration) -> Origin {
    assert!(!answers.is_empty(), "an origin needs at least one answer");
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
            let position = thread_count.fetch_add(1, Ordering::AcqRel);
            let answer_at = Instant::now() + delay;
            while Instant::now() < answer_at && !thread_stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(20));
            }
            let (status, body) = &answers[position.min(answers.len() - 1)];
            let _ = request.respond(
                Response::from_data(body.clone()).with_status_code(tiny_http::StatusCode(*status)),
            );
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

/// The command that starts a strict gate. HOME and USERPROFILE are removed so that no default
/// signing key is ever picked up from whoever runs the tests; a test that wants one sets HOME.
fn strict_gate_command(
    upstream: SocketAddr,
    manifest_dir: &Path,
    out_dir: &Path,
    extra: &[&str],
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args(["gate", "--mode", "strict-manifest", "--upstream"])
        .arg(format!("http://{upstream}"))
        .args(["--listen", "127.0.0.1:0", "--manifest-dir"])
        .arg(manifest_dir)
        .arg("--out-dir")
        .arg(out_dir)
        .args(extra)
        .env_remove("HOME")
        .env_remove("USERPROFILE");
    command
}

fn start_strict_gate(
    upstream: SocketAddr,
    manifest_dir: &Path,
    out_dir: &Path,
    witness_path: &Path,
    extra: &[&str],
) -> GateProcess {
    launch_gate(
        strict_gate_command(upstream, manifest_dir, out_dir, extra),
        witness_path,
    )
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

/// Every spelling of the proxy variables an HTTP client library may read.
const PROXY_VARIABLES: [&str; 8] = [
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "no_proxy",
];

/// Start the gate that `command` describes and wait for its "listening on" line. The proxy
/// variables of whoever runs the tests are removed so that no test depends on them; a test
/// that sets one on `command` on purpose keeps it.
fn launch_gate(mut command: Command, witness_path: &Path) -> GateProcess {
    for name in PROXY_VARIABLES {
        let set_by_the_test = command.get_envs().any(|(key, _)| key == name);
        if !set_by_the_test {
            command.env_remove(name);
        }
    }
    let mut child = command
        .env("EPISTEMIC_WITNESS", witness_path)
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
        .args(["verify", "--no-sign", "--policy"])
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
            "manifest_count": 1,
            "signature_key": null
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

    // The client's view of the cut-off response does not matter here, only what was recorded
    // (what the client sees is pinned by the G14 tests below), so the client runs on its own
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

/// With no signing key configured (HOME is removed, so there is no default key either), a
/// signed v0.3 manifest still authorizes its request: the gate reads the `signature` member and
/// does not check it. The tests below cover what happens once a key is configured.
#[test]
fn gate_forwards_against_a_signed_v0_3_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_dir = temp.path().join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
    let signed = fixture_root().join("expected_manifest_v0_3_signed.json");
    let manifest: Value = serde_json::from_slice(&std::fs::read(&signed).unwrap()).unwrap();
    assert!(manifest["signature"]["value"].is_string());
    std::fs::copy(&signed, manifest_dir.join("signed.json")).unwrap();
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

    assert_eq!(status, 200);
    assert_eq!(origin.count.load(Ordering::Acquire), 1);
}

/// The public half of the RFC 8032 section 7.1 test-1 key that signed
/// `expected_manifest_v0_3_signed.json` (see tests/signing.rs), and its fingerprint.
const GOLDEN_PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const GOLDEN_FINGERPRINT: &str =
    "blake3:6c31041268f471609c79f5f2dbcc38e4a4ab2f4d416109a4e09fcf50fd0f0062";

fn write_public_key(path: &Path, hex: &str) {
    std::fs::write(path, format!("{hex}\n")).unwrap();
}

/// A manifest directory holding the signed golden, altered after signing when `tamper` is set.
/// Returns the directory and the request the manifest matches.
fn signed_manifest_dir(parent: &Path, tamper: bool) -> (PathBuf, Value) {
    let manifest_dir = parent.join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
    let signed = fixture_root().join("expected_manifest_v0_3_signed.json");
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(signed).unwrap()).unwrap();
    if tamper {
        manifest["timestamp"] = json!("2030-01-01T00:00:00Z");
    }
    std::fs::write(
        manifest_dir.join("signed.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let request =
        serde_json::from_slice(&std::fs::read(fixture_root().join("request.json")).unwrap())
            .unwrap();
    (manifest_dir, request)
}

/// A public key file for a freshly generated key, made by the real `airlock keygen` in a
/// throwaway HOME. Returns the path of its `ed25519.pub`.
fn fresh_public_key(parent: &Path) -> PathBuf {
    let home = parent.join("other-home");
    std::fs::create_dir(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .arg("keygen")
        .env("HOME", &home)
        .env_remove("USERPROFILE")
        .output()
        .unwrap();
    assert!(output.status.success());
    home.join(".cmdrvl/secrets/airlock/ed25519.pub")
}

/// A HOME whose default signing public key is `hex`.
fn home_with_default_key(parent: &Path, hex: &str) -> PathBuf {
    let home = parent.join("gate-home");
    let directory = home.join(".cmdrvl/secrets/airlock");
    std::fs::create_dir_all(&directory).unwrap();
    write_public_key(&directory.join("ed25519.pub"), hex);
    home
}

/// Run a gate that must refuse to start. Returns its stderr. A gate that starts instead is
/// killed after ten seconds and fails the test.
fn gate_refuses_to_start(mut command: Command) -> String {
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut exited = false;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    if !exited {
        let _ = child.kill();
    }
    // Reaped on every path; once the child has exited this returns its status at once.
    let status = child.wait().unwrap();
    assert!(exited, "the gate started instead of refusing to start");
    assert_eq!(status.code(), Some(2));
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    stderr
}

/// Wait for the gate's stderr to contain `needle`; the gate's own lines arrive on a drain thread.
fn wait_for_stderr(gate: &GateProcess, needle: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if gate.stderr_text().contains(needle) {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn a_manifest_signed_by_the_configured_key_authorizes_its_request() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = signed_manifest_dir(temp.path(), false);
    let key = temp.path().join("key.pub");
    write_public_key(&key, GOLDEN_PUBLIC_HEX);
    let origin = start_origin();
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &["--pubkey", key.to_str().unwrap()],
    );
    let agent = client();

    let (status, _) = post(&agent, gate.address, &serde_json::to_vec(&request).unwrap());
    let (_, health) = get_health(&agent, gate.address, "/airlock/health");

    assert_eq!(status, 200);
    assert_eq!(origin.count.load(Ordering::Acquire), 1);
    assert_eq!(health["signature_key"], GOLDEN_FINGERPRINT);
    assert!(
        wait_for_stderr(
            &gate,
            &format!("signed manifests were checked against {GOLDEN_FINGERPRINT}")
        ),
        "{}",
        gate.stderr_text()
    );
}

#[test]
fn gate_refuses_to_start_on_a_manifest_altered_after_signing() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, _) = signed_manifest_dir(temp.path(), true);
    let key = temp.path().join("key.pub");
    write_public_key(&key, GOLDEN_PUBLIC_HEX);
    let origin = start_origin();

    let stderr = gate_refuses_to_start(strict_gate_command(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &["--pubkey", key.to_str().unwrap()],
    ));

    assert!(stderr.contains("signed.json"), "{stderr}");
    assert!(stderr.contains("does not verify"), "{stderr}");
    assert!(stderr.contains("refusing to start"), "{stderr}");
    assert_eq!(origin.count.load(Ordering::Acquire), 0);
}

#[test]
fn gate_refuses_to_start_on_a_manifest_signed_by_a_different_key() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, _) = signed_manifest_dir(temp.path(), false);
    let other_key = fresh_public_key(temp.path());
    let origin = start_origin();

    let stderr = gate_refuses_to_start(strict_gate_command(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &["--pubkey", other_key.to_str().unwrap()],
    ));

    assert!(stderr.contains("signed.json"), "{stderr}");
    assert!(stderr.contains("does not verify"), "{stderr}");
}

#[test]
fn a_configured_key_never_makes_a_signature_required() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(manifest_dir.join("clean_telemetry_only.json")).unwrap(),
    )
    .unwrap();
    assert!(
        manifest.get("signature").is_none(),
        "the manifest is unsigned"
    );
    let key = temp.path().join("key.pub");
    write_public_key(&key, GOLDEN_PUBLIC_HEX);
    let origin = start_origin();
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &["--pubkey", key.to_str().unwrap()],
    );
    let agent = client();

    let (status, _) = post(&agent, gate.address, &serde_json::to_vec(&request).unwrap());
    let (_, health) = get_health(&agent, gate.address, "/airlock/health");

    assert_eq!(status, 200);
    assert_eq!(origin.count.load(Ordering::Acquire), 1);
    assert_eq!(health["signature_key"], GOLDEN_FINGERPRINT);
}

#[test]
fn without_a_key_signatures_are_not_checked_and_the_gate_says_so() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = signed_manifest_dir(temp.path(), true);
    let origin = start_origin();
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );
    let agent = client();

    let (status, _) = post(&agent, gate.address, &serde_json::to_vec(&request).unwrap());
    let (_, health) = get_health(&agent, gate.address, "/airlock/health");

    assert_eq!(status, 200, "no key is configured, so nothing is checked");
    assert_eq!(health["signature_key"], Value::Null);
    assert!(
        wait_for_stderr(
            &gate,
            "no signing key configured; manifest signatures are not checked"
        ),
        "{}",
        gate.stderr_text()
    );
}

#[test]
fn the_default_public_key_is_used_when_no_pubkey_is_given() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = signed_manifest_dir(temp.path(), false);
    let home = home_with_default_key(temp.path(), GOLDEN_PUBLIC_HEX);
    let origin = start_origin();
    let mut command = strict_gate_command(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &[],
    );
    command.env("HOME", &home);
    let gate = launch_gate(command, &temp.path().join("witness.jsonl"));
    let agent = client();

    let (status, _) = post(&agent, gate.address, &serde_json::to_vec(&request).unwrap());
    let (_, health) = get_health(&agent, gate.address, "/airlock/health");

    assert_eq!(status, 200);
    assert_eq!(health["signature_key"], GOLDEN_FINGERPRINT);
}

#[test]
fn the_default_public_key_refuses_a_manifest_altered_after_signing() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, _) = signed_manifest_dir(temp.path(), true);
    let home = home_with_default_key(temp.path(), GOLDEN_PUBLIC_HEX);
    let origin = start_origin();
    let mut command = strict_gate_command(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &[],
    );
    command.env("HOME", &home);

    let stderr = gate_refuses_to_start(command);

    assert!(stderr.contains("does not verify"), "{stderr}");
}

#[test]
fn an_explicit_pubkey_wins_over_the_default_key() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = signed_manifest_dir(temp.path(), false);
    let other_key = fresh_public_key(temp.path());
    let other_hex = std::fs::read_to_string(other_key).unwrap();
    let home = home_with_default_key(temp.path(), other_hex.trim());
    let key = temp.path().join("key.pub");
    write_public_key(&key, GOLDEN_PUBLIC_HEX);
    let origin = start_origin();
    let mut command = strict_gate_command(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &["--pubkey", key.to_str().unwrap()],
    );
    command.env("HOME", &home);
    let gate = launch_gate(command, &temp.path().join("witness.jsonl"));
    let agent = client();

    let (status, _) = post(&agent, gate.address, &serde_json::to_vec(&request).unwrap());
    let (_, health) = get_health(&agent, gate.address, "/airlock/health");

    assert_eq!(
        status, 200,
        "the default key would have refused this manifest"
    );
    assert_eq!(health["signature_key"], GOLDEN_FINGERPRINT);
}

#[test]
fn a_configured_key_that_cannot_be_loaded_stops_the_gate() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, _) = bound_manifest_dir(temp.path());
    let origin = start_origin();
    let receipts = temp.path().join("receipts");

    // --pubkey names a file that is not there.
    let missing = temp.path().join("no-such-key.pub");
    let stderr = gate_refuses_to_start(strict_gate_command(
        origin.address,
        &manifest_dir,
        &receipts,
        &["--pubkey", missing.to_str().unwrap()],
    ));
    assert!(stderr.contains("refusing to start"), "{stderr}");

    // --pubkey names a file that is not a key.
    let malformed = temp.path().join("malformed.pub");
    std::fs::write(&malformed, "not a key\n").unwrap();
    let stderr = gate_refuses_to_start(strict_gate_command(
        origin.address,
        &manifest_dir,
        &receipts,
        &["--pubkey", malformed.to_str().unwrap()],
    ));
    assert!(stderr.contains("refusing to start"), "{stderr}");

    // No --pubkey, and the default key in HOME is not a key either.
    let home = home_with_default_key(temp.path(), "not a key");
    let mut command = strict_gate_command(origin.address, &manifest_dir, &receipts, &[]);
    command.env("HOME", &home);
    let stderr = gate_refuses_to_start(command);
    assert!(stderr.contains("refusing to start"), "{stderr}");
}

#[test]
fn policy_proxy_refuses_pubkey_at_startup() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/clean_telemetry_only");
    let temp = tempfile::tempdir().unwrap();
    let key = temp.path().join("key.pub");
    write_public_key(&key, GOLDEN_PUBLIC_HEX);
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args([
            "gate",
            "--mode",
            "policy-proxy",
            "--upstream",
            "https://api.openai.com",
            "--policy",
        ])
        .arg(root.join("policy.yaml"))
        .arg("--pubkey")
        .arg(&key)
        .arg("--out-dir")
        .arg(temp.path().join("receipts"));

    let stderr = gate_refuses_to_start(command);

    assert!(
        stderr.contains("--pubkey only applies to strict-manifest mode"),
        "{stderr}"
    );
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
    // v0.4 is a supported version now (al-210 D-c), so the stand-in for a version this binary
    // does not read moves to v0.5. The assertion is unchanged.
    future["manifest_version"] = Value::from("airlock.v0.5");
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

    // The chain member belongs to airlock.v0.4 and only to it (al-210 D-c): a manifest that
    // says v0.4 without it, or says v0.3 with it, is not a manifest the gate will serve.
    let link = serde_json::json!({
        "prior_manifest_hash":
            "blake3:0000000000000000000000000000000000000000000000000000000000000000",
        "turn_index": 1,
    });
    let mut v0_4_without_chain = v0_3.clone();
    v0_4_without_chain["manifest_version"] = Value::from("airlock.v0.4");
    let mut v0_3_with_chain = v0_3.clone();
    v0_3_with_chain["chain"] = link.clone();
    let mut v0_4_index_zero = v0_3.clone();
    v0_4_index_zero["manifest_version"] = Value::from("airlock.v0.4");
    v0_4_index_zero["chain"] = link;
    v0_4_index_zero["chain"]["turn_index"] = Value::from(0);
    let mut v0_4_without_bytes = v0_4_index_zero.clone();
    v0_4_without_bytes["chain"]["turn_index"] = Value::from(1);
    v0_4_without_bytes
        .as_object_mut()
        .unwrap()
        .remove("bytes_crossed");

    for (label, manifest, expected) in [
        ("airlock.v0.5", &future, "unsupported manifest version"),
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
        (
            "v0.4 without its chain member",
            &v0_4_without_chain,
            "must carry a chain member",
        ),
        (
            "v0.3 with a chain member",
            &v0_3_with_chain,
            "only an airlock.v0.4 manifest may carry a chain member",
        ),
        ("v0.4 with turn_index 0", &v0_4_index_zero, "turn_index"),
        (
            "v0.4 without bytes_crossed",
            &v0_4_without_bytes,
            "v0.4 manifest without bytes_crossed and attestation",
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

/// A stand-in HTTP proxy. It records the request line of every request that reaches it and
/// answers each with a fixed JSON body, so a test can tell whether, and where, the gate sent
/// its upstream request.
struct RecordingProxy {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    request_lines: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for RecordingProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

const PROXY_REPLY: &[u8] = br#"{"via":"proxy"}"#;

fn start_recording_proxy() -> RecordingProxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let request_lines = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (thread_connections, thread_lines, thread_stop) = (
        Arc::clone(&connections),
        Arc::clone(&request_lines),
        Arc::clone(&stop),
    );
    let worker = thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            };
            thread_connections.fetch_add(1, Ordering::AcqRel);
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            // One connection can carry a CONNECT and then the request tunnelled through it, which
            // is how an HTTP client library uses a proxy; the proxy answers the second itself.
            loop {
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                    break;
                }
                thread_lines
                    .lock()
                    .unwrap()
                    .push(request_line.trim_end().to_owned());
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; content_length];
                let _ = reader.read_exact(&mut body);
                if request_line.starts_with("CONNECT ") {
                    let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                    let _ = stream.flush();
                    continue;
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    PROXY_REPLY.len()
                );
                let _ = stream.write_all(PROXY_REPLY);
                let _ = stream.flush();
                break;
            }
        }
    });
    RecordingProxy {
        address,
        connections,
        request_lines,
        stop,
        worker: Some(worker),
    }
}

/// Wait for the proxy to have been asked `expected` times; the gate's request arrives on the
/// proxy's own thread, so a read straight after the response can come first.
fn proxy_connections(proxy: &RecordingProxy, expected: usize) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && proxy.connections.load(Ordering::Acquire) < expected {
        thread::sleep(Duration::from_millis(10));
    }
    proxy.connections.load(Ordering::Acquire)
}

#[test]
fn the_gate_ignores_proxy_environment_variables_and_connects_to_the_upstream() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin();
    let proxy = start_recording_proxy();
    let proxy_url = format!("http://{}", proxy.address);
    let mut command = strict_gate_command(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &[],
    );
    // Every spelling points at the proxy, and one carries credentials the gate must never print.
    for name in PROXY_VARIABLES
        .into_iter()
        .filter(|name| !name.eq_ignore_ascii_case("NO_PROXY"))
    {
        command.env(name, &proxy_url);
    }
    command.env(
        "HTTPS_PROXY",
        format!("http://user:s3cr3t-token@{}", proxy.address),
    );
    let gate = launch_gate(command, &temp.path().join("witness.jsonl"));

    let (status, body) = post(
        &client(),
        gate.address,
        &serde_json::to_vec(&request).unwrap(),
    );

    assert_eq!(status, 200);
    assert_eq!(body, json!({"ok": true}), "the reply came from the origin");
    assert_eq!(origin.count.load(Ordering::Acquire), 1);
    assert_eq!(
        proxy_connections(&proxy, 1),
        0,
        "the gate sent upstream traffic to a proxy named only in its environment"
    );
    assert!(wait_for_stderr(&gate, "ALL_PROXY is set and is ignored"));
    assert!(wait_for_stderr(&gate, "HTTPS_PROXY is set and is ignored"));
    assert!(
        !gate.stderr_text().contains("s3cr3t-token"),
        "a proxy variable's value, which can carry credentials, was printed"
    );
}

#[test]
fn upstream_proxy_flag_sends_the_upstream_request_through_that_proxy() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin();
    let proxy = start_recording_proxy();
    let receipts_dir = temp.path().join("receipts");
    let witness_path = temp.path().join("witness.jsonl");
    let proxy_url = format!("http://{}", proxy.address);
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &receipts_dir,
        &witness_path,
        &["--upstream-proxy", &proxy_url],
    );

    let (status, body) = post(
        &client(),
        gate.address,
        &serde_json::to_vec(&request).unwrap(),
    );

    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({"via": "proxy"}),
        "the reply came from the proxy"
    );
    assert_eq!(origin.count.load(Ordering::Acquire), 0);
    assert_eq!(proxy_connections(&proxy, 1), 1);
    let lines = proxy.request_lines.lock().unwrap().clone();
    assert_eq!(
        lines,
        [
            format!("CONNECT {} HTTP/1.1", origin.address),
            "POST /v1/chat/completions HTTP/1.1".to_owned(),
        ],
        "the proxy is asked to connect to the upstream, then the request goes through it"
    );
    assert!(wait_for_stderr(
        &gate,
        &format!("upstream requests go through the proxy {proxy_url}")
    ));
    let (receipts, _) = wait_for_recorded(&receipts_dir, &witness_path, 1);
    assert_eq!(receipts[0]["upstream_status"], 200);
    assert_eq!(receipts[0]["response_bytes"], PROXY_REPLY.len());
}

#[test]
fn upstream_proxy_flag_wins_over_a_proxy_environment() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin();
    let chosen = start_recording_proxy();
    let hostile = start_recording_proxy();
    let chosen_url = format!("http://{}", chosen.address);
    let mut command = strict_gate_command(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &["--upstream-proxy", &chosen_url],
    );
    for name in ["ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"] {
        command.env(name, format!("http://{}", hostile.address));
    }
    let gate = launch_gate(command, &temp.path().join("witness.jsonl"));

    let (status, body) = post(
        &client(),
        gate.address,
        &serde_json::to_vec(&request).unwrap(),
    );

    assert_eq!(status, 200);
    assert_eq!(body, json!({"via": "proxy"}));
    assert_eq!(proxy_connections(&chosen, 1), 1);
    assert_eq!(
        hostile.connections.load(Ordering::Acquire),
        0,
        "the environment was read even though --upstream-proxy was given"
    );
    assert_eq!(origin.count.load(Ordering::Acquire), 0);
}

#[test]
fn the_gate_refuses_to_start_on_an_upstream_proxy_it_cannot_use() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, _) = bound_manifest_dir(temp.path());
    let upstream: SocketAddr = "127.0.0.1:9".parse().unwrap();
    for bad in [
        "socks5://127.0.0.1:1080",
        "http://user:s3cr3t-token@127.0.0.1:3128",
        "127.0.0.1:3128",
        "ftp://127.0.0.1:21",
        "http://127.0.0.1:3128/path",
        "http://127.0.0.1:3128?x=1",
        "http://",
    ] {
        let stderr = gate_refuses_to_start(strict_gate_command(
            upstream,
            &manifest_dir,
            &temp.path().join("receipts"),
            &["--upstream-proxy", bad],
        ));
        // The gate's own refusal, not clap's "unexpected argument" for a flag it does not know.
        assert!(
            stderr.contains("airlock gate: --upstream-proxy "),
            "{bad}: the gate did not refuse the proxy itself: {stderr}"
        );
        assert!(
            !stderr.contains("s3cr3t-token"),
            "{bad}: the refusal printed the credential"
        );
    }
}

// --- chained turns (al-3pz G11) -------------------------------------------------------------
//
// A manifest that carries a chain link says its request was built from the reply the model gave
// to the turn before. The strict gate must find that the reply came through it. Every
// conversation here is built by the real `assemble` and `verify`; the receipts `assemble` is
// given are written by hand, in the world's own directory and never in a gate's `--out-dir`, so
// a gate only knows an exchange if it forwarded it (or was handed a receipt for it on purpose).

const CHAIN_ZERO_HASH: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

fn repo_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_json_file(path: &Path) -> Value {
    serde_json::from_slice(
        &std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn write_json_file(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

/// The hash the gate computes for the manifest at `path`.
fn manifest_gate_hash(path: &Path) -> String {
    serde_json::from_slice::<airlock::manifest::AirlockManifest>(&std::fs::read(path).unwrap())
        .unwrap()
        .hash()
}

fn provenance_gate_hash(value: &Value) -> String {
    serde_json::from_value::<airlock::assembler::PromptProvenance>(value.clone())
        .unwrap()
        .hash()
}

/// The reply the model gave to turn `turn`, as the bytes the gate hashes. Each turn's reply is
/// different, so a receipt for the wrong reply is distinguishable from the right one.
fn chain_reply(turn: usize) -> Vec<u8> {
    let mut reply = read_json_file(&repo_file("fixtures/chain/anthropic_messages_reply.json"));
    reply["content"][1]["text"] = json!(format!("This is the reply to turn {turn}."));
    serde_json::to_vec(&reply).unwrap()
}

/// A receipt in the shape the gate writes for a forwarded 200 exchange that matched a manifest.
fn chain_receipt(response: &[u8], matched_manifest_hash: &str) -> Value {
    json!({
        "gate_version": "airlock.gate.v1",
        "mode": "strict-manifest",
        "achieved_claim": "STRICT_TELEMETRY_ONLY",
        "request_hash": airlock::hash::blake3_hash(b"fixture request"),
        "response_hash": airlock::hash::blake3_hash(response),
        "upstream_status": 200,
        "blocked": false,
        "findings": [],
        "timestamp": "2026-11-25T00:00:00Z",
        "matched_manifest_hash": matched_manifest_hash,
    })
}

struct ChainWorld {
    dir: tempfile::TempDir,
    /// Manifests and prompt provenance files, as `--manifest-dir` wants them.
    lib: PathBuf,
    /// The receipts `assemble` was given: not a gate's `--out-dir`.
    receipts: PathBuf,
    /// When set, `verify` records each manifest it writes in this witness ledger.
    ledger: Option<PathBuf>,
    requests: Vec<Value>,
}

impl ChainWorld {
    /// `turns` turns, numbered from 0. Turn `n` follows turn `n - 1` and its reply.
    fn build(turns: usize) -> ChainWorld {
        ChainWorld::build_recording(turns, false)
    }

    /// As `build`, with `verify` recording in the world's own witness ledger.
    fn build_with_ledger(turns: usize) -> ChainWorld {
        ChainWorld::build_recording(turns, true)
    }

    fn build_recording(turns: usize, record_in_ledger: bool) -> ChainWorld {
        let dir = tempfile::tempdir().unwrap();
        let lib = dir.path().join("lib");
        let receipts = dir.path().join("receipts");
        std::fs::create_dir(&lib).unwrap();
        std::fs::create_dir(&receipts).unwrap();
        let ledger = record_in_ledger.then(|| dir.path().join("ledger.jsonl"));
        let mut world = ChainWorld {
            dir,
            lib,
            receipts,
            ledger,
            requests: Vec::new(),
        };
        for turn in 0..turns {
            let request = world.add_turn(turn);
            world.requests.push(request);
        }
        world
    }

    fn manifest(&self, turn: usize) -> PathBuf {
        self.lib.join(format!("turn{turn}.manifest.json"))
    }

    fn provenance(&self, turn: usize) -> PathBuf {
        self.lib.join(format!("turn{turn}.provenance.json"))
    }

    fn manifest_hash(&self, turn: usize) -> String {
        manifest_gate_hash(&self.manifest(turn))
    }

    /// The request body turn `turn` sends.
    fn body(&self, turn: usize) -> Vec<u8> {
        serde_json::to_vec(&self.requests[turn]).unwrap()
    }

    fn run(&self, what: &str, command: &mut Command) {
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{what}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn add_turn(&self, turn: usize) -> Value {
        let stem = format!("turn{turn}");
        let prompt = self.dir.path().join(format!("{stem}.prompt.json"));
        let mut assemble = Command::new(env!("CARGO_BIN_EXE_airlock"));
        assemble
            .args(["assemble", "--policy"])
            .arg(repo_file("fixtures/chain/policy.yaml"))
            .arg("--input")
            .arg(repo_file("fixtures/annotated_mode/strategy_space.json"))
            .arg("--system-prompt")
            .arg(repo_file("fixtures/annotated_mode/system_prompt.txt"))
            .args(["--boundary-mode", "TELEMETRY_ONLY", "--out"])
            .arg(&prompt)
            .arg("--provenance-out")
            .arg(self.provenance(turn))
            .arg("--no-witness");
        if turn > 0 {
            let reply_path = self.dir.path().join(format!("{stem}.reply.json"));
            std::fs::write(&reply_path, chain_reply(turn - 1)).unwrap();
            let receipt_path = self.receipts.join(format!("{stem}.receipt.json"));
            write_json_file(
                &receipt_path,
                &chain_receipt(&chain_reply(turn - 1), &self.manifest_hash(turn - 1)),
            );
            assemble
                .arg("--prior-receipt")
                .arg(&receipt_path)
                .arg("--response")
                .arg(&reply_path)
                .args(["--response-adapter", "anthropic_messages"])
                .arg("--prior-manifest")
                .arg(self.manifest(turn - 1));
        }
        self.run(&format!("assemble {stem}"), &mut assemble);

        let request = json!({
            "model": "gpt-5",
            "messages": read_json_file(&prompt)["messages"].clone(),
        });
        let request_path = self.dir.path().join(format!("{stem}.request.json"));
        write_json_file(&request_path, &request);
        let mut verify = Command::new(env!("CARGO_BIN_EXE_airlock"));
        verify
            .args(["verify", "--no-sign", "--policy"])
            .arg(repo_file("fixtures/chain/policy.yaml"))
            .arg("--prompt")
            .arg(&prompt)
            .arg("--provenance")
            .arg(self.provenance(turn))
            .arg("--request")
            .arg(&request_path)
            .arg("--out")
            .arg(self.manifest(turn));
        match &self.ledger {
            Some(ledger) => {
                verify.env("EPISTEMIC_WITNESS", ledger);
            }
            None => {
                verify.arg("--no-witness");
            }
        }
        self.run(&format!("verify {stem}"), &mut verify);

        // The gate forwards only a bound manifest; fail here, in the builder, if it is not one.
        let manifest = read_json_file(&self.manifest(turn));
        assert_eq!(manifest["binding_status"], "BOUND", "{stem}: {manifest}");
        assert_eq!(
            manifest["manifest_version"],
            if turn == 0 {
                "airlock.v0.3"
            } else {
                "airlock.v0.4"
            },
            "{stem}"
        );
        request
    }

    /// Replace turn `turn`'s provenance with `edit` of it, and point its manifest at the new one,
    /// so the manifest and its provenance still agree about the hash: only what is inside differs.
    fn edit_provenance(&self, turn: usize, edit: impl FnOnce(&mut Value)) {
        let mut provenance = read_json_file(&self.provenance(turn));
        edit(&mut provenance);
        write_json_file(&self.provenance(turn), &provenance);
        let mut manifest = read_json_file(&self.manifest(turn));
        manifest["prompt_provenance_hash"] = json!(provenance_gate_hash(&provenance));
        write_json_file(&self.manifest(turn), &manifest);
    }

    /// Put into `directory` the receipt a gate would have written had it forwarded turn `turn`.
    fn write_receipt_for(&self, turn: usize, directory: &Path) {
        std::fs::create_dir_all(directory).unwrap();
        write_json_file(
            &directory.join(format!("hand-written-turn{turn}.json")),
            &chain_receipt(&chain_reply(turn), &self.manifest_hash(turn)),
        );
    }

    /// `airlock chain verify` of turn `turn`'s manifest over this world's library.
    fn chain_verify(&self, turn: usize, with_receipts: bool) -> (Option<i32>, Value) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
        command
            .args(["chain", "verify"])
            .arg(self.manifest(turn))
            .arg("--manifest-dir")
            .arg(&self.lib);
        if with_receipts {
            command.arg("--receipt-dir").arg(&self.receipts);
        }
        let output = command.output().unwrap();
        let body = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "stdout is not one JSON document ({error}): {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), body)
    }

    /// A strict gate over this world's library. `name` keeps each gate's witness ledger apart.
    fn gate(&self, upstream: SocketAddr, out_dir: &Path, name: &str) -> GateProcess {
        start_strict_gate(
            upstream,
            &self.lib,
            out_dir,
            &self.dir.path().join(format!("{name}.witness.jsonl")),
            &[],
        )
    }
}

/// An origin that answers the n-th request it gets with the reply to turn n.
fn chain_origin(turns: usize) -> Origin {
    start_origin_answering(
        (0..turns).map(|turn| (200, chain_reply(turn))).collect(),
        Duration::ZERO,
    )
}

fn assert_chain_denied(status: u16, refusal: &Value, rule_id: &str) {
    assert_eq!(status, 403, "{refusal}");
    assert_eq!(refusal["code"], "E_GATE_DENIED", "{refusal}");
    assert_eq!(refusal["findings"][0]["rule_id"], rule_id, "{refusal}");
    assert_valid_gate_document(refusal);
}

#[test]
fn an_honest_chain_is_admitted_turn_after_turn_by_one_gate() {
    let world = ChainWorld::build(3);
    let origin = chain_origin(3);
    let gate = world.gate(origin.address, &world.dir.path().join("out"), "honest");

    // Each reply is relayed to the client in full before the next turn is sent, which is when
    // a client that has the reply can build the next turn: the gate must know the exchange by then.
    for turn in 0..3 {
        let (status, reply) = post(&client(), gate.address, &world.body(turn));
        assert_eq!(status, 200, "turn {turn}: {reply}");
        assert_eq!(
            reply,
            serde_json::from_slice::<Value>(&chain_reply(turn)).unwrap(),
            "turn {turn}: the reply came from the origin"
        );
    }
    assert_eq!(origin.count.load(Ordering::Acquire), 3);
}

#[test]
fn a_chained_turn_whose_prior_reply_the_gate_never_forwarded_is_denied() {
    let world = ChainWorld::build(2);
    // `chain verify` is satisfied by the hand-written receipt: it checks that the files agree.
    let (code, report) = world.chain_verify(1, true);
    assert_eq!(code, Some(0), "{report}");

    let origin = chain_origin(2);
    let out_dir = world.dir.path().join("out");
    let gate = world.gate(origin.address, &out_dir, "unforwarded");
    let (status, refusal) = post(&client(), gate.address, &world.body(1));

    assert_chain_denied(status, &refusal, "REQUEST_CHAIN_RESPONSE_NOT_FORWARDED");
    assert_eq!(
        origin.count.load(Ordering::Acquire),
        0,
        "a denied request must never reach the origin"
    );
    assert!(
        wait_for_stderr(&gate, "this gate has not forwarded the response"),
        "{}",
        gate.stderr_text()
    );
    let receipts = read_receipts(&out_dir);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["blocked"], true);
    assert_valid_gate_document(&receipts[0]);

    // The first turn of the conversation has nothing before it, so the same gate admits it.
    assert_eq!(post(&client(), gate.address, &world.body(0)).0, 200);
}

#[test]
fn a_chained_turn_is_admitted_after_the_gate_forwarded_the_reply_it_followed() {
    let world = ChainWorld::build(2);
    let out_dir = world.dir.path().join("out");

    // One run of the gate forwards the first turn, so its receipt is in the receipt directory.
    {
        let origin = chain_origin(1);
        let gate = world.gate(origin.address, &out_dir, "first-run");
        assert_eq!(post(&client(), gate.address, &world.body(0)).0, 200);
        wait_for_recorded(
            &out_dir,
            &world.dir.path().join("first-run.witness.jsonl"),
            1,
        );
    }

    // A new run in the same receipt directory knows that exchange: it admits the next turn.
    let origin = start_origin_answering(vec![(200, chain_reply(1))], Duration::ZERO);
    let gate = world.gate(origin.address, &out_dir, "second-run");
    assert!(
        wait_for_stderr(
            &gate,
            "1 forwarded exchange(s) read back from the receipts in"
        ),
        "{}",
        gate.stderr_text()
    );
    assert_eq!(post(&client(), gate.address, &world.body(1)).0, 200);

    // A run whose receipt directory is empty does not.
    let origin = chain_origin(2);
    let gate = world.gate(
        origin.address,
        &world.dir.path().join("elsewhere"),
        "empty-run",
    );
    let (status, refusal) = post(&client(), gate.address, &world.body(1));
    assert_chain_denied(status, &refusal, "REQUEST_CHAIN_RESPONSE_NOT_FORWARDED");
}

#[test]
fn a_link_that_cannot_be_resolved_is_denied_for_the_reason_chain_verify_gives() {
    type Tamper = fn(&ChainWorld);
    let cases: [(&str, Tamper); 6] = [
        ("prior_manifest_not_found", |world| {
            std::fs::remove_file(world.manifest(0)).unwrap();
        }),
        ("turn_index_mismatch", |world| {
            let mut manifest = read_json_file(&world.manifest(1));
            manifest["chain"]["turn_index"] = json!(5);
            write_json_file(&world.manifest(1), &manifest);
        }),
        ("provenance_not_found", |world| {
            std::fs::remove_file(world.provenance(1)).unwrap();
        }),
        ("provenance_chain_mismatch", |world| {
            world.edit_provenance(1, |provenance| {
                provenance["chain"]["turn_index"] = json!(9);
            });
        }),
        ("model_output_hash_missing", |world| {
            world.edit_provenance(1, |provenance| {
                provenance["records"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|record| record["policy_rule_id"] != "chain.model_output");
            });
        }),
        ("model_output_hash_ambiguous", |world| {
            world.edit_provenance(1, |provenance| {
                let record = provenance["records"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|record| record["policy_rule_id"] == "chain.model_output")
                    .unwrap();
                record["source_artifact_hash"] = json!(CHAIN_ZERO_HASH);
            });
        }),
    ];
    for (reason, tamper) in cases {
        let world = ChainWorld::build(2);
        tamper(&world);

        // The command that reads the same directory refuses for the same reason.
        let (code, body) = world.chain_verify(1, false);
        assert_eq!(code, Some(2), "{reason}: {body}");
        assert_eq!(body["refusal"]["detail"]["reason"], reason, "{body}");

        let origin = chain_origin(2);
        let gate = world.gate(origin.address, &world.dir.path().join("out"), "tampered");
        let (status, refusal) = post(&client(), gate.address, &world.body(1));
        assert_chain_denied(status, &refusal, "REQUEST_CHAIN_UNRESOLVED");
        assert_eq!(origin.count.load(Ordering::Acquire), 0, "{reason}");
        assert!(
            wait_for_stderr(&gate, &format!("chained request refused: {reason} ")),
            "{reason}: {}",
            gate.stderr_text()
        );
    }
}

#[test]
fn a_receipt_written_by_hand_into_the_gates_out_dir_is_trusted_at_startup() {
    // A limit, pinned so the documentation of it stays true: a gate receipt is unsigned, and the
    // exchanges a gate knows at startup are the receipts in its --out-dir. Whoever can write that
    // directory can add an exchange to it.
    let world = ChainWorld::build(2);
    let out_dir = world.dir.path().join("out");
    world.write_receipt_for(0, &out_dir);
    let origin = start_origin_answering(vec![(200, chain_reply(1))], Duration::ZERO);
    let gate = world.gate(origin.address, &out_dir, "hand-written");

    assert_eq!(post(&client(), gate.address, &world.body(1)).0, 200);
    assert_eq!(origin.count.load(Ordering::Acquire), 1);
}

#[test]
fn the_gate_walks_a_chain_to_its_root_and_checks_every_link() {
    // Turn 2 follows turn 1 follows turn 0. Seeding both earlier exchanges admits turn 2.
    let world = ChainWorld::build(3);
    let both = world.dir.path().join("both");
    world.write_receipt_for(0, &both);
    world.write_receipt_for(1, &both);
    let origin = start_origin_answering(vec![(200, chain_reply(2))], Duration::ZERO);
    let gate = world.gate(origin.address, &both, "both");
    assert_eq!(post(&client(), gate.address, &world.body(2)).0, 200);
    drop(gate);

    // Only turn 1's exchange is known: the first link is fine, the second is not.
    let only_last = world.dir.path().join("only-last");
    world.write_receipt_for(1, &only_last);
    let origin = chain_origin(3);
    let gate = world.gate(origin.address, &only_last, "only-last");
    let (status, refusal) = post(&client(), gate.address, &world.body(2));
    assert_chain_denied(status, &refusal, "REQUEST_CHAIN_RESPONSE_NOT_FORWARDED");
    assert!(
        wait_for_stderr(&gate, &world.manifest_hash(0)),
        "the refusal should name the manifest whose reply was never forwarded: {}",
        gate.stderr_text()
    );
    assert_eq!(origin.count.load(Ordering::Acquire), 0);
    drop(gate);

    // Both exchanges are known but the root manifest is gone: only a walk of two links finds out.
    std::fs::remove_file(world.manifest(0)).unwrap();
    let origin = chain_origin(3);
    let gate = world.gate(origin.address, &both, "no-root");
    let (status, refusal) = post(&client(), gate.address, &world.body(2));
    assert_chain_denied(status, &refusal, "REQUEST_CHAIN_UNRESOLVED");
    assert!(
        wait_for_stderr(&gate, "chained request refused: prior_manifest_not_found "),
        "{}",
        gate.stderr_text()
    );
    assert_eq!(origin.count.load(Ordering::Acquire), 0);
}

#[test]
fn a_reply_that_was_not_a_success_is_not_a_forwarded_response() {
    // The bytes are exactly what turn 1 admitted, but the upstream answered 500: an error body
    // is not model output, so no exchange is recorded and turn 1 is refused.
    let world = ChainWorld::build(2);
    let origin = start_origin_answering(vec![(500, chain_reply(0))], Duration::ZERO);
    let gate = world.gate(origin.address, &world.dir.path().join("out"), "error-reply");

    let (status, _) = post(&client(), gate.address, &world.body(0));
    assert_eq!(status, 500, "the gate relays the upstream's status");
    let (status, refusal) = post(&client(), gate.address, &world.body(1));

    assert_chain_denied(status, &refusal, "REQUEST_CHAIN_RESPONSE_NOT_FORWARDED");
    assert_eq!(origin.count.load(Ordering::Acquire), 1);
}

#[test]
fn gate_refuses_to_start_when_a_file_in_the_manifest_dir_is_neither_manifest_nor_provenance() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, _) = bound_manifest_dir(temp.path());
    std::fs::write(manifest_dir.join("stray.json"), br#"{"hello":1}"#).unwrap();

    let stderr = gate_refuses_to_start(strict_gate_command(
        "127.0.0.1:9".parse().unwrap(),
        &manifest_dir,
        &temp.path().join("receipts"),
        &[],
    ));

    assert!(stderr.contains("invalid Airlock manifest"), "{stderr}");
}

// --- the witness ledger as a place to find manifests (al-3pz G8) -----------------------------
//
// `airlock verify` records where its manifest went. `gate --witness-lookup` reads that ledger as
// a LOCATOR: a file it names is loaded only if it still hashes to the output hash the record
// carries, and the request match is the same exact canonical-hash match as ever. The ledger never
// admits a request by itself.

const NOTHING_LOCATED: &str = "witness lookup: 0 manifest(s) located";

/// `airlock verify` of a fixture with witness recording ON: its manifest goes to `out` and its
/// record to `ledger`. Returns the request body the manifest binds.
fn verify_fixture_into_ledger(fixture: &str, out: &Path, ledger: &Path) -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(fixture);
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["verify", "--no-sign", "--policy"])
        .arg(root.join("policy.yaml"))
        .arg("--prompt")
        .arg(root.join("expected_prompt_payload.json"))
        .arg("--provenance")
        .arg(root.join("expected_prompt_provenance.json"))
        .arg("--request")
        .arg(root.join("request.json"))
        .arg("--out")
        .arg(out)
        .env("EPISTEMIC_WITNESS", ledger)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verify of {fixture}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    read_json_file(&root.join("request.json"))
}

/// A strict gate whose manifest directory is EMPTY, so any manifest it knows came from the ledger
/// (or from nowhere). The ledger is also the gate's own witness file, as `launch_gate` makes it.
fn ledger_gate(
    upstream: SocketAddr,
    work: &Path,
    ledger: &Path,
    out_name: &str,
    lookup: bool,
) -> GateProcess {
    let manifest_dir = work.join("empty-manifest-dir");
    std::fs::create_dir_all(&manifest_dir).unwrap();
    let extra: &[&str] = if lookup { &["--witness-lookup"] } else { &[] };
    start_strict_gate(upstream, &manifest_dir, &work.join(out_name), ledger, extra)
}

fn assert_manifest_not_found(status: u16, refusal: &Value) {
    assert_eq!(status, 403, "{refusal}");
    assert_eq!(refusal["code"], "E_GATE_DENIED", "{refusal}");
    assert_eq!(
        refusal["findings"][0]["rule_id"], "REQUEST_MANIFEST_NOT_FOUND",
        "{refusal}"
    );
}

#[test]
fn a_manifest_outside_the_manifest_dir_is_matched_only_when_the_gate_is_told_to_look() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("ledger.jsonl");
    let elsewhere = temp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let manifest = elsewhere.join("airlock_manifest.json");
    let request = verify_fixture_into_ledger("clean_telemetry_only", &manifest, &ledger);
    let body = serde_json::to_vec(&request).unwrap();

    // Told to look: the request is forwarded, against that manifest.
    let origin = start_origin();
    let gate = ledger_gate(origin.address, temp.path(), &ledger, "out-looking", true);
    assert!(
        wait_for_stderr(&gate, "witness lookup: 1 manifest(s) located"),
        "{}",
        gate.stderr_text()
    );
    let (status, reply) = post(&client(), gate.address, &body);
    assert_eq!(status, 200, "{reply}");
    let (receipts, _) = wait_for_recorded(&temp.path().join("out-looking"), &ledger, 1);
    assert_eq!(
        receipts[0]["matched_manifest_hash"],
        manifest_gate_hash(&manifest)
    );
    drop(gate);

    // Not told to: the same ledger, the same empty directory, and nothing is found.
    let origin = start_origin();
    let gate = ledger_gate(origin.address, temp.path(), &ledger, "out-blind", false);
    let (status, refusal) = post(&client(), gate.address, &body);
    assert_manifest_not_found(status, &refusal);
    assert_eq!(origin.count.load(Ordering::Acquire), 0);
    assert!(
        !gate.stderr_text().contains("witness lookup"),
        "{}",
        gate.stderr_text()
    );
}

#[test]
fn a_file_changed_after_verify_wrote_it_is_not_loaded() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("ledger.jsonl");
    let manifest = temp.path().join("airlock_manifest.json");
    let request = verify_fixture_into_ledger("clean_telemetry_only", &manifest, &ledger);
    // One byte of whitespace: still a manifest that parses and means the same thing, but no longer
    // the bytes verify wrote.
    let mut bytes = std::fs::read(&manifest).unwrap();
    bytes.push(b'\n');
    std::fs::write(&manifest, bytes).unwrap();

    let origin = start_origin();
    let gate = ledger_gate(origin.address, temp.path(), &ledger, "out", true);
    assert!(
        wait_for_stderr(&gate, "witness lookup: 0 manifest(s) located"),
        "{}",
        gate.stderr_text()
    );
    let log = gate.stderr_text();
    assert!(
        log.contains(&format!(
            "witness lookup skipped {}: changed since airlock verify wrote it",
            std::fs::canonicalize(&manifest).unwrap().display()
        )),
        "{log}"
    );
    assert!(log.contains("1 skipped"), "{log}");

    let (status, refusal) = post(
        &client(),
        gate.address,
        &serde_json::to_vec(&request).unwrap(),
    );
    assert_manifest_not_found(status, &refusal);
    assert_eq!(origin.count.load(Ordering::Acquire), 0);
}

#[test]
fn the_ledger_never_loosens_the_match() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("ledger.jsonl");
    let elsewhere = temp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let first = verify_fixture_into_ledger("annotated_mode", &elsewhere.join("a.json"), &ledger);
    let second =
        verify_fixture_into_ledger("clean_telemetry_only", &elsewhere.join("b.json"), &ledger);
    let origin = start_origin();
    let gate = ledger_gate(origin.address, temp.path(), &ledger, "out", true);
    assert!(
        wait_for_stderr(&gate, "witness lookup: 2 manifest(s) located"),
        "{}",
        gate.stderr_text()
    );

    // Both verified requests are forwarded: they were found.
    for request in [&first, &second] {
        let (status, reply) = post(
            &client(),
            gate.address,
            &serde_json::to_vec(request).unwrap(),
        );
        assert_eq!(status, 200, "{reply}");
    }
    // A request that is not exactly one of them is not: one extra member changes its canonical hash.
    for request in [&first, &second] {
        let mut altered = request.clone();
        altered["metadata"] = json!({"one_more_member": true});
        let (status, refusal) = post(
            &client(),
            gate.address,
            &serde_json::to_vec(&altered).unwrap(),
        );
        assert_manifest_not_found(status, &refusal);
    }
    assert_eq!(origin.count.load(Ordering::Acquire), 2);
    drop(gate);

    // A record that names a request's hash among its inputs but no manifest file (the shape of a
    // record from before verify wrote paths) finds nothing: the hash alone admits nothing.
    let old_ledger = temp.path().join("old-ledger.jsonl");
    let old_manifest = temp.path().join("old-manifest.json");
    verify_fixture_into_ledger(
        "clean_telemetry_only",
        &old_manifest,
        &temp.path().join("scratch-ledger.jsonl"),
    );
    let request_hash = read_json_file(&old_manifest)["request_payload_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let record = airlock::witness::WitnessRecord::new(
        "verify",
        "VERIFIED",
        0,
        vec![airlock::witness::WitnessRecord::input(
            "request.json",
            request_hash,
        )],
        json!({"boundary_mode": "TELEMETRY_ONLY"}),
        airlock::hash::blake3_hash(&std::fs::read(&old_manifest).unwrap()),
        1,
    );
    std::fs::write(&old_ledger, record.to_jsonl_line()).unwrap();
    let origin = start_origin();
    let gate = ledger_gate(origin.address, temp.path(), &old_ledger, "out-old", true);
    assert!(
        wait_for_stderr(&gate, NOTHING_LOCATED),
        "{}",
        gate.stderr_text()
    );
    let (status, refusal) = post(
        &client(),
        gate.address,
        &serde_json::to_vec(&second).unwrap(),
    );
    assert_manifest_not_found(status, &refusal);
    assert_eq!(origin.count.load(Ordering::Acquire), 0);
}

#[test]
fn an_overwritten_manifest_is_loaded_when_its_bytes_match_a_record_for_that_path() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("ledger.jsonl");
    let manifest = temp.path().join("airlock_manifest.json");
    // Two verifies to one path: the ledger has a record for each, and only the second describes
    // the file as it is now.
    let older = verify_fixture_into_ledger("annotated_mode", &manifest, &ledger);
    let newer = verify_fixture_into_ledger("clean_telemetry_only", &manifest, &ledger);
    let origin = start_origin();
    let gate = ledger_gate(origin.address, temp.path(), &ledger, "out", true);

    assert!(
        wait_for_stderr(&gate, "witness lookup: 1 manifest(s) located"),
        "{}",
        gate.stderr_text()
    );
    assert!(
        !gate.stderr_text().contains("witness lookup skipped"),
        "an older record for the same path is not a skipped manifest: {}",
        gate.stderr_text()
    );
    let (status, reply) = post(
        &client(),
        gate.address,
        &serde_json::to_vec(&newer).unwrap(),
    );
    assert_eq!(status, 200, "{reply}");
    // What the file held before is gone, and so is the right to send it.
    let (status, refusal) = post(
        &client(),
        gate.address,
        &serde_json::to_vec(&older).unwrap(),
    );
    assert_manifest_not_found(status, &refusal);
}

#[test]
fn gate_refuses_witness_lookup_in_policy_proxy_mode() {
    let temp = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args([
            "gate",
            "--mode",
            "policy-proxy",
            "--upstream",
            "https://api.openai.com",
            "--policy",
        ])
        .arg(fixture_root().join("policy.yaml"))
        .arg("--witness-lookup")
        .arg("--out-dir")
        .arg(temp.path().join("receipts"));

    let stderr = gate_refuses_to_start(command);

    assert!(
        stderr.contains("--witness-lookup only applies to strict-manifest mode"),
        "{stderr}"
    );
}

#[test]
fn an_unreadable_ledger_stops_the_gate_and_a_missing_one_does_not() {
    let temp = tempfile::tempdir().unwrap();
    let empty = temp.path().join("empty-manifest-dir");
    std::fs::create_dir(&empty).unwrap();

    // A ledger line that is not a witness record: the operator asked for the ledger, so a gate that
    // started without it would hide that the lookup found nothing.
    let corrupt = temp.path().join("corrupt.jsonl");
    std::fs::write(&corrupt, "this is not a witness record\n").unwrap();
    let mut command = strict_gate_command(
        "127.0.0.1:9".parse().unwrap(),
        &empty,
        &temp.path().join("out-corrupt"),
        &["--witness-lookup"],
    );
    command.env("EPISTEMIC_WITNESS", &corrupt);
    let stderr = gate_refuses_to_start(command);
    assert!(
        stderr.contains("witness ledger") && stderr.contains("invalid witness record on line 1"),
        "{stderr}"
    );
    assert!(stderr.contains("refusing to start"), "{stderr}");

    // No ledger at all is a ledger with no records.
    let missing = temp.path().join("never-written.jsonl");
    let gate = ledger_gate(
        "127.0.0.1:9".parse().unwrap(),
        temp.path(),
        &missing,
        "out-missing",
        true,
    );
    assert!(
        wait_for_stderr(&gate, NOTHING_LOCATED),
        "{}",
        gate.stderr_text()
    );
}

#[test]
fn a_record_that_names_a_file_that_is_not_a_manifest_is_skipped() {
    let temp = tempfile::tempdir().unwrap();
    let provenance = temp.path().join("prompt_provenance.json");
    std::fs::copy(
        fixture_root().join("expected_prompt_provenance.json"),
        &provenance,
    )
    .unwrap();
    // The bytes match the record, so only what the file IS can turn it away.
    let record = airlock::witness::WitnessRecord::new(
        "verify",
        "VERIFIED",
        0,
        Vec::new(),
        json!({"manifest_path": std::fs::canonicalize(&provenance).unwrap()}),
        airlock::hash::blake3_hash(&std::fs::read(&provenance).unwrap()),
        1,
    );
    let ledger = temp.path().join("ledger.jsonl");
    std::fs::write(&ledger, record.to_jsonl_line()).unwrap();

    let gate = ledger_gate(
        "127.0.0.1:9".parse().unwrap(),
        temp.path(),
        &ledger,
        "out",
        true,
    );

    assert!(
        wait_for_stderr(&gate, NOTHING_LOCATED),
        "{}",
        gate.stderr_text()
    );
    let log = gate.stderr_text();
    assert!(log.contains("not a manifest"), "{log}");
    assert!(log.contains("1 skipped"), "{log}");
}

#[test]
fn chained_turns_found_through_the_ledger_are_still_held_to_what_the_gate_forwarded() {
    // Both turns' manifests and prompt provenance are outside the gate's manifest directory and
    // known to it only through the ledger. The chain check needs the provenance, so this also shows
    // that verify's `provenance_path` is followed.
    let world = ChainWorld::build_with_ledger(2);
    let ledger = world.ledger.clone().unwrap();
    let origin = chain_origin(2);
    let gate = ledger_gate(origin.address, world.dir.path(), &ledger, "out", true);
    assert!(
        wait_for_stderr(&gate, "witness lookup: 2 manifest(s) located"),
        "{}",
        gate.stderr_text()
    );

    // The gate has forwarded nothing yet, so turn 1 is refused, as it is for a manifest in the directory.
    let (status, refusal) = post(&client(), gate.address, &world.body(1));
    assert_chain_denied(status, &refusal, "REQUEST_CHAIN_RESPONSE_NOT_FORWARDED");
    assert_eq!(origin.count.load(Ordering::Acquire), 0);

    // Turn 0 goes through; then turn 1 is admitted by the same gate.
    assert_eq!(post(&client(), gate.address, &world.body(0)).0, 200);
    assert_eq!(post(&client(), gate.address, &world.body(1)).0, 200);
    assert_eq!(origin.count.load(Ordering::Acquire), 2);
}

// --- what a client sees of a response the upstream cuts short (al-3pz G14) ---------------------
//
// The gate relays a response as it arrives. If the upstream ends it early, the client must be told
// now, by a response that cannot be mistaken for a complete one, instead of waiting for its own
// timeout. These tests read the gate's response with a raw socket and a strict chunked parser, and
// with a real client library, so what is pinned is what a client sees and not how the gate wrote it.

/// One response as a raw HTTP client saw it.
struct RawResponse {
    status: u16,
    /// Header names lower-cased.
    headers: Vec<(String, String)>,
    /// The body bytes that arrived before the body ended or failed to parse.
    body: Vec<u8>,
    /// Why the body could not be read to its proper end, if it could not.
    body_error: Option<String>,
    /// When the response head had been read, from the start of the request.
    head_at: Duration,
    /// When the first piece of the body arrived, from the start of the request.
    first_body_byte_at: Option<Duration>,
    finished_at: Duration,
}

impl RawResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }
}

/// POST `body` to the gate over a raw socket, speaking `version` ("HTTP/1.1" or "HTTP/1.0"), and
/// read the response strictly: a chunked body must be well formed to count as ended. `patience`
/// bounds every read, so a gate that never answers makes this return an error and not hang.
fn raw_post(
    address: SocketAddr,
    version: &str,
    body: &[u8],
    patience: Duration,
) -> Result<RawResponse, String> {
    raw_post_with(address, version, "", body, patience)
}

/// [`raw_post`] with `extra_headers` (each line ending in CRLF) added to the request.
fn raw_post_with(
    address: SocketAddr,
    version: &str,
    extra_headers: &str,
    body: &[u8],
    patience: Duration,
) -> Result<RawResponse, String> {
    let started = Instant::now();
    let mut stream =
        std::net::TcpStream::connect(address).map_err(|error| format!("connect: {error}"))?;
    stream.set_read_timeout(Some(patience)).unwrap();
    let head = format!(
        "POST /v1/chat/completions {version}\r\nHost: gate\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|error| format!("send: {error}"))?;
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| format!("no response head within {patience:?}: {error}"))?;
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("bad status line {line:?}"))?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader
            .read_line(&mut line)
            .map_err(|error| format!("reading headers: {error}"))?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let (name, value) = trimmed
            .split_once(':')
            .ok_or_else(|| format!("bad header line {trimmed:?}"))?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    let chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.contains("chunked"));

    let mut response = RawResponse {
        status,
        headers,
        body: Vec::new(),
        body_error: None,
        head_at: started.elapsed(),
        first_body_byte_at: None,
        finished_at: Duration::ZERO,
    };
    if chunked {
        read_chunked_strictly(&mut reader, started, &mut response);
    } else if let Err(error) = reader.read_to_end(&mut response.body) {
        response.body_error = Some(format!("reading an unframed body: {error}"));
    }
    response.finished_at = started.elapsed();
    Ok(response)
}

fn read_chunked_strictly(
    reader: &mut BufReader<std::net::TcpStream>,
    started: Instant,
    response: &mut RawResponse,
) {
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                response.body_error = Some("the connection ended inside a chunked body".to_owned());
                return;
            }
            Ok(_) => {}
            Err(error) => {
                response.body_error = Some(format!("timed out or failed reading a chunk: {error}"));
                return;
            }
        }
        let size_text = line
            .trim_end_matches("\r\n")
            .split(';')
            .next()
            .unwrap_or("");
        let valid = !size_text.is_empty()
            && size_text.chars().all(|c| c.is_ascii_hexdigit())
            && line.ends_with("\r\n");
        let Some(size) = valid
            .then(|| usize::from_str_radix(size_text, 16).ok())
            .flatten()
        else {
            response.body_error = Some(format!("invalid chunk size line {line:?}"));
            return;
        };
        if size == 0 {
            // The trailer: nothing, then a blank line.
            let mut trailer = String::new();
            if reader.read_line(&mut trailer).is_err() || trailer != "\r\n" {
                response.body_error = Some(format!("bad chunked trailer {trailer:?}"));
            }
            return;
        }
        let mut chunk = vec![0; size];
        if let Err(error) = reader.read_exact(&mut chunk) {
            response.body_error = Some(format!("a chunk ended early: {error}"));
            return;
        }
        response.first_body_byte_at.get_or_insert(started.elapsed());
        response.body.extend_from_slice(&chunk);
        let mut end = [0u8; 2];
        if reader.read_exact(&mut end).is_err() || &end != b"\r\n" {
            response.body_error = Some("a chunk was not followed by CRLF".to_owned());
            return;
        }
    }
}

/// An origin that sends its response head, waits `lead`, sends `first`, waits `pause`, then sends
/// `second`, as a chunked body.
fn start_slow_chunked_origin(
    lead: Duration,
    first: &'static [u8],
    pause: Duration,
    second: &'static [u8],
) -> SocketAddr {
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
        let chunk = |bytes: &[u8]| {
            let mut framed = format!("{:x}\r\n", bytes.len()).into_bytes();
            framed.extend_from_slice(bytes);
            framed.extend_from_slice(b"\r\n");
            framed
        };
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        );
        let _ = stream.flush();
        thread::sleep(lead);
        let _ = stream.write_all(&chunk(first));
        let _ = stream.flush();
        thread::sleep(pause);
        let _ = stream.write_all(&chunk(second));
        let _ = stream.write_all(b"0\r\n\r\n");
        let _ = stream.flush();
    });
    address
}

#[test]
fn a_client_sees_a_protocol_error_at_once_when_the_upstream_cuts_a_response_short() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let upstream = start_truncating_origin();
    let gate = start_strict_gate(
        upstream,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );

    let response = raw_post(
        gate.address,
        "HTTP/1.1",
        &serde_json::to_vec(&request).unwrap(),
        Duration::from_secs(4),
    )
    .expect("the client should get the response head");

    assert_eq!(response.status, 200);
    // What the upstream sent before it stopped reaches the client...
    assert_eq!(response.body, b"0123456789");
    // ...and the client is told, by a body that cannot be read as complete, not left to wait.
    let error = response
        .body_error
        .as_deref()
        .expect("a cut-off body must not look complete");
    assert!(error.contains("invalid chunk size"), "{error}");
    assert!(
        response.finished_at < Duration::from_secs(3),
        "the client waited {:?}",
        response.finished_at
    );
}

#[test]
fn a_client_library_fails_at_once_when_the_upstream_cuts_a_response_short() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let upstream = start_truncating_origin();
    let gate = start_strict_gate(
        upstream,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );
    let url = format!("http://{}/v1/chat/completions", gate.address);

    let started = Instant::now();
    let outcome = client()
        .post(&url)
        .header("Content-Type", "application/json")
        .send(serde_json::to_vec(&request).unwrap())
        .map_err(|error| error.to_string())
        .and_then(|response| {
            let mut body = Vec::new();
            response
                .into_body()
                .into_reader()
                .read_to_end(&mut body)
                .map(|_| body)
                .map_err(|error| error.to_string())
        });

    assert!(
        outcome.is_err(),
        "a cut-off response was handed to the client as a complete body: {outcome:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the client waited {:?} before it was told",
        started.elapsed()
    );
}

#[test]
fn a_complete_response_is_relayed_as_a_well_formed_chunked_body() {
    // Larger than one read of the upstream body, so it crosses several chunks.
    let reply: Vec<u8> = (0..150_000u32).map(|n| b'a' + (n % 26) as u8).collect();
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin_replying(reply.clone());
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );

    let response = raw_post(
        gate.address,
        "HTTP/1.1",
        &serde_json::to_vec(&request).unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body_error, None);
    assert_eq!(response.body, reply);
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert_eq!(response.header("content-length"), None);
}

#[test]
fn a_response_with_no_body_is_relayed_without_chunked_framing() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin_answering(vec![(204, Vec::new())], Duration::ZERO);
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );

    // `Connection: close` makes the gate end the connection after the response, so whatever
    // follows the head is read to its end: a 204 must have nothing after it.
    let response = raw_post_with(
        gate.address,
        "HTTP/1.1",
        "Connection: close\r\n",
        &serde_json::to_vec(&request).unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();

    assert_eq!(response.status, 204);
    assert_eq!(response.header("transfer-encoding"), None);
    assert_eq!(response.body_error, None);
    assert_eq!(response.body, b"");
}

#[test]
fn an_http_1_0_client_still_gets_its_whole_response() {
    let reply = b"{\"ok\":true,\"for\":\"an old client\"}".to_vec();
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let origin = start_origin_replying(reply.clone());
    let gate = start_strict_gate(
        origin.address,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );

    let response = raw_post(
        gate.address,
        "HTTP/1.0",
        &serde_json::to_vec(&request).unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body_error, None);
    assert_eq!(response.body, reply);
    assert_eq!(response.header("transfer-encoding"), None);
}

#[test]
fn a_response_head_reaches_the_client_before_the_first_body_byte() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let lead = Duration::from_millis(1500);
    // The upstream answers at once and then takes a long time to produce anything.
    let upstream =
        start_slow_chunked_origin(lead, b"data: late\n\n", Duration::ZERO, b"data: later\n\n");
    let gate = start_strict_gate(
        upstream,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );

    let response = raw_post(
        gate.address,
        "HTTP/1.1",
        &serde_json::to_vec(&request).unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();

    assert_eq!(response.body_error, None);
    assert!(
        response.head_at < lead / 2,
        "the response head arrived after {:?}: the gate held it until the first body byte",
        response.head_at
    );
    assert!(
        response.first_body_byte_at.unwrap() >= lead,
        "the first body byte arrived after {:?}",
        response.first_body_byte_at
    );
}

#[test]
fn a_streamed_body_reaches_the_client_as_it_arrives_and_not_when_it_ends() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest_dir, request) = bound_manifest_dir(temp.path());
    let pause = Duration::from_millis(1500);
    let upstream = start_slow_chunked_origin(
        Duration::ZERO,
        b"data: first\n\n",
        pause,
        b"data: second\n\n",
    );
    let gate = start_strict_gate(
        upstream,
        &manifest_dir,
        &temp.path().join("receipts"),
        &temp.path().join("witness.jsonl"),
        &[],
    );

    let response = raw_post(
        gate.address,
        "HTTP/1.1",
        &serde_json::to_vec(&request).unwrap(),
        Duration::from_secs(10),
    )
    .unwrap();

    assert_eq!(response.body_error, None);
    assert_eq!(response.body, b"data: first\n\ndata: second\n\n");
    let first = response.first_body_byte_at.expect("a first chunk");
    assert!(
        first < pause / 2,
        "the first event arrived after {first:?}: the gate held it until the stream ended"
    );
    assert!(
        response.finished_at >= pause,
        "the whole stream finished after {:?}",
        response.finished_at
    );
}
