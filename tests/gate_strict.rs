//! Strict-manifest gate contract, exercised against the real `airlock gate` binary and a
//! local mock origin: what is denied, with which refusal code, and what is recorded.

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use jsonschema::validator_for;
use serde_json::Value;
use tiny_http::{Response, Server};

struct Origin {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
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
    let server = Server::http("127.0.0.1:0").unwrap();
    let address = server.server_addr().to_ip().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (thread_count, thread_stop) = (Arc::clone(&count), Arc::clone(&stop));
    let worker = thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            let request = match server.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(request)) => request,
                Ok(None) => continue,
                Err(_) => break,
            };
            thread_count.fetch_add(1, Ordering::AcqRel);
            let _ = request.respond(Response::from_data(reply.clone()));
        }
    });
    Origin {
        address,
        count,
        stop,
        worker: Some(worker),
    }
}

struct GateProcess {
    child: Child,
    address: SocketAddr,
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["gate", "--mode", "strict-manifest", "--upstream"])
        .arg(format!("http://{upstream}"))
        .args(["--listen", "127.0.0.1:0", "--manifest-dir"])
        .arg(manifest_dir)
        .arg("--out-dir")
        .arg(out_dir)
        .args(extra)
        .env("EPISTEMIC_WITNESS", witness_path)
        .env_remove("ALL_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("NO_PROXY")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut line = String::new();
    BufReader::new(stderr).read_line(&mut line).unwrap();
    let address = line
        .trim()
        .strip_prefix("airlock gate listening on ")
        .unwrap_or_else(|| panic!("gate did not start: {line}"))
        .parse()
        .unwrap();
    GateProcess { child, address }
}

fn client() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into()
}

fn post(agent: &ureq::Agent, address: SocketAddr, body: &[u8]) -> (u16, Value) {
    let response = agent
        .post(&format!("http://{address}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .send(body.to_vec())
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
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/clean_telemetry_only");
    let manifest_dir = parent.join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
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
        .arg(manifest_dir.join("verified.json"))
        .arg("--no-witness")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture verification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request =
        serde_json::from_slice(&std::fs::read(root.join("request.json")).unwrap()).unwrap();
    (manifest_dir, request)
}

fn read_witness(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
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
    drop(gate);

    let receipts = read_receipts(&receipts_dir);
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

    let witness = read_witness(&witness_path);
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
