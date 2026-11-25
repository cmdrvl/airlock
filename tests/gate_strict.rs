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
            let _ = request.respond(Response::from_string("{\"ok\":true}"));
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
