use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use boundary_detectors::shingle_bloom::{BloomConfig, ShingleBloom};
use serde_json::{Value, json};
use tiny_http::{Header, Response, Server, StatusCode};

struct Origin {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    received: Receiver<(Vec<u8>, Option<String>)>,
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

fn start_origin() -> Origin {
    let server = Server::http("127.0.0.1:0").unwrap();
    let address = server.server_addr().to_ip().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let thread_count = Arc::clone(&count);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let (sender, received) = mpsc::channel();
    let worker = thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            let mut request = match server.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(request)) => request,
                Ok(None) => continue,
                Err(_) => break,
            };
            thread_count.fetch_add(1, Ordering::AcqRel);
            let auth = request
                .headers()
                .iter()
                .find(|header| {
                    header
                        .field
                        .as_str()
                        .as_str()
                        .eq_ignore_ascii_case("authorization")
                })
                .map(|header| header.value.as_str().to_owned());
            let mut body = Vec::new();
            request.as_reader().read_to_end(&mut body).unwrap();
            let _ = sender.send((body, auth));
            let header =
                Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap();
            let response = Response::new(
                StatusCode(200),
                vec![header],
                ChunkReader::new(b"event: message\n\ndata: {\"ok\":true}\n\n".to_vec()),
                None,
                None,
            );
            let _ = request.respond(response);
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

struct ChunkReader {
    bytes: Vec<u8>,
    offset: usize,
}

impl ChunkReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl Read for ChunkReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.offset == self.bytes.len() {
            return Ok(0);
        }
        let length = buffer.len().min(7).min(self.bytes.len() - self.offset);
        buffer[..length].copy_from_slice(&self.bytes[self.offset..self.offset + length]);
        self.offset += length;
        thread::sleep(Duration::from_millis(1));
        Ok(length)
    }
}

fn start_gate(
    mode: &str,
    upstream: SocketAddr,
    out_dir: &Path,
    witness_path: &Path,
    extra: &[&str],
) -> GateProcess {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args([
            "gate",
            "--mode",
            mode,
            "--upstream",
            &format!("http://{upstream}"),
            "--listen",
            "127.0.0.1:0",
            "--out-dir",
        ])
        .arg(out_dir)
        .args(extra)
        .env("EPISTEMIC_WITNESS", witness_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut line = String::new();
    BufReader::new(stderr).read_line(&mut line).unwrap();
    let address = line
        .trim()
        .strip_prefix("airlock gate listening on ")
        .unwrap_or_else(|| {
            assert!(false, "gate did not start: {line}");
            ""
        })
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

fn post_json(agent: &ureq::Agent, address: SocketAddr, value: &Value) -> (u16, Vec<u8>) {
    let body = serde_json::to_vec(value).unwrap();
    post_body(agent, address, &body)
}

fn post_body(agent: &ureq::Agent, address: SocketAddr, body: &[u8]) -> (u16, Vec<u8>) {
    let response = agent
        .post(&format!("http://{address}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer test-token-never-record")
        .send(body.to_vec())
        .unwrap();
    let status = response.status().as_u16();
    let mut body = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut body)
        .unwrap();
    (status, body)
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(a >> 2) as usize] as char);
        output.push(TABLE[(((a & 0b11) << 4) | (b >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[(((b & 0b1111) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(c & 0b0011_1111) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn read_receipts(directory: &Path) -> Vec<Value> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .collect()
}

#[test]
fn live_policy_proxy_streams_clean_turns_and_blocks_sensitive_multimodal_and_bloom_leaks() {
    let temp = tempfile::tempdir().unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        "policy_id: egress-test\nversion: airlock.v0\nallowed_keys:\n  - key_path: messages\nforbidden_keys: [blocked_field]\nforbidden_patterns:\n  - pattern: 'client-[0-9]+'\nderived_text_paths: []\nclaim_levels: [BOUNDARY_FAILED, RAW_DOCUMENT_ABSENT, STRICT_TELEMETRY_ONLY]\nprotected_bloom_min_hits: 3\n",
    )
    .unwrap();
    let protected = "private northstar transaction rationale includes exact protected phrasing for confidential acquisition targeting on the western industrial portfolio and its upcoming refinancing plan";
    let mut bloom = ShingleBloom::new(BloomConfig::default());
    bloom.insert_text(protected);
    let bloom_dir = temp.path().join("bloom");
    std::fs::create_dir(&bloom_dir).unwrap();
    let bloom_path = bloom_dir.join("protected-corpus.bdbl");
    std::fs::write(&bloom_path, bloom.to_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bloom_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&bloom_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let origin = start_origin();
    let out_dir = temp.path().join("receipts");
    let witness_path = temp.path().join("witness.jsonl");
    let gate = start_gate(
        "policy-proxy",
        origin.address,
        &out_dir,
        &witness_path,
        &[
            "--policy",
            policy.to_str().unwrap(),
            "--protected-bloom",
            bloom_path.to_str().unwrap(),
        ],
    );
    let agent = client();
    let clean_one = json!({"model":"model-a","messages":[{"role":"user","content":"Summarize this plain status update."}],"stream":true});
    let clean_two = json!({"model":"model-a","messages":[{"role":"user","content":"Continue with the second turn."}],"stream":true});
    for clean in [&clean_one, &clean_two] {
        let (status, body) = post_json(&agent, gate.address, clean);
        assert_eq!(status, 200);
        assert_eq!(body, b"event: message\n\ndata: {\"ok\":true}\n\n");
    }

    let csv =
        "name,account,amount\nAlice,001,10\nBob,002,11\nCarol,003,12\nDave,004,13\nEve,005,14\n";
    let blocked_values = [
        json!({"messages":[{"role":"user","content":"AWS key AKIAIOSFODNN7EXAMPLE"}]}),
        json!({"messages":[{"role":"user","content":"SSN 123-45-6789"}]}),
        json!({"messages":[{"role":"user","content":base64_encode(csv.as_bytes())}]}),
        json!({"messages":[{"role":"user","content":base64_encode(b"prefix client-123 private suffix")}]}),
        json!({"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}}]}]}),
        json!({"messages":[{"role":"user","content":protected}]}),
        json!({"contents":[{"parts":[{"text":"private northstar transaction rationale includes exact protected phrasing for confidential"},{"text":"acquisition targeting on the western industrial portfolio and its upcoming refinancing plan"}]}]}),
        json!({"blocked_field":"secret"}),
        json!({"model":"gpt-5","input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,aGVsbG8="}]}]}),
        json!({"model":"claude-sonnet-4-5","max_tokens":256,"system":"Inspect this document","messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"aGVsbG8="}}]}]}),
        json!({"model":"gemini-2.5-pro","contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"aGVsbG8="}}]}]}),
    ];
    let schema: Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/airlock_gate.v1.schema.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut refusal_codes = Vec::new();
    let mut refusals = Vec::new();
    for (index, request) in blocked_values.into_iter().enumerate() {
        let (status, body) = post_json(&agent, gate.address, &request);
        assert_eq!(status, 403, "blocked request index {index} passed");
        let refusal: Value = serde_json::from_slice(&body).unwrap();
        validator.validate(&refusal).unwrap();
        assert_eq!(refusal["code"], "BOUNDARY_FAILED");
        refusals.push(refusal.clone());
        refusal_codes.extend(
            refusal["findings"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|finding| finding["rule_id"].as_str().map(str::to_owned)),
        );
    }
    assert!(
        refusal_codes
            .iter()
            .any(|rule| rule == "PROTECTED_CORPUS_MATCH")
    );
    assert!(
        refusal_codes
            .iter()
            .any(|rule| rule == "MULTIMODAL_ATTACHMENT_BLOCKED")
    );
    assert!(
        refusal_codes
            .iter()
            .any(|rule| rule.starts_with("TABULAR_"))
    );
    assert!(
        refusal_codes
            .iter()
            .any(|rule| rule == "POLICY_FORBIDDEN_PATTERN")
    );
    assert_eq!(
        origin.count.load(Ordering::Acquire),
        2,
        "blocked payloads reached the origin"
    );
    for _ in 0..2 {
        let (_, auth) = origin
            .received
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(auth.as_deref(), Some("Bearer test-token-never-record"));
    }

    drop(gate);
    drop(origin);
    let receipts = read_receipts(&out_dir);
    assert_eq!(receipts.len(), 13);
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt["achieved_claim"] == "POLICY_SCREENED")
            .count(),
        2
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt["achieved_claim"] == "BOUNDARY_FAILED")
            .count(),
        11
    );
    let serialized = serde_json::to_string(&receipts).unwrap();
    assert!(!serialized.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!serialized.contains("123-45-6789"));
    assert!(!serialized.contains("private northstar"));
    assert!(!serialized.contains("test-token-never-record"));
    let refusal_text = serde_json::to_string(&refusals).unwrap();
    assert!(!refusal_text.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!refusal_text.contains("123-45-6789"));
    assert!(!refusal_text.contains("private northstar"));
    let expected_response_hash = format!(
        "blake3:{}",
        blake3::hash(b"event: message\n\ndata: {\"ok\":true}\n\n").to_hex()
    );
    assert!(
        receipts
            .iter()
            .any(|receipt| receipt["response_hash"] == expected_response_hash)
    );
    for receipt in receipts {
        validator.validate(&receipt).unwrap();
    }
    let witness_lines = std::fs::read_to_string(&witness_path).unwrap();
    let witness_records = witness_lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(witness_records.len(), 13);
    assert!(
        witness_records.iter().any(|record| {
            record["params"]["mode"] == "policy-proxy"
                && record["params"]["achieved_claim"] == "POLICY_SCREENED"
                && record["params"]["response_hash"].as_str().is_some()
        }),
        "witness records: {witness_lines}"
    );
    let witness_text = serde_json::to_string(&witness_records).unwrap();
    assert!(!witness_text.contains("test-token-never-record"));
}

#[test]
fn strict_manifest_mode_forwards_only_a_preverified_canonical_request_hash() {
    let temp = tempfile::tempdir().unwrap();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let request_bytes =
        std::fs::read(root.join("fixtures/clean_telemetry_only/request.json")).unwrap();
    let request: Value = serde_json::from_slice(&request_bytes).unwrap();
    let manifest_dir = temp.path().join("manifests");
    std::fs::create_dir(&manifest_dir).unwrap();
    std::fs::copy(
        root.join("fixtures/clean_telemetry_only/expected_manifest.json"),
        manifest_dir.join("verified.json"),
    )
    .unwrap();
    let origin = start_origin();
    let witness_path = temp.path().join("witness.jsonl");
    let gate = start_gate(
        "strict-manifest",
        origin.address,
        &temp.path().join("receipts"),
        &witness_path,
        &["--manifest-dir", manifest_dir.to_str().unwrap()],
    );
    let agent = client();
    let (status, _) = post_json(&agent, gate.address, &request);
    assert_eq!(status, 200);
    let serialized_request = serde_json::to_string(&request).unwrap();
    let duplicate_key_request = format!(
        r#"{{"messages":[{{"role":"user","content":"AWS key AKIAIOSFODNN7EXAMPLE"}}],{}"#,
        &serialized_request[1..]
    );
    let (status, _) = post_body(&agent, gate.address, duplicate_key_request.as_bytes());
    assert_eq!(status, 200);
    let altered = json!({"messages":request["messages"],"model":"gpt-5","extra":"unverified"});
    let (status, refusal_body) = post_json(&agent, gate.address, &altered);
    assert_eq!(status, 403);
    let refusal: Value = serde_json::from_slice(&refusal_body).unwrap();
    assert_eq!(
        refusal["findings"][0]["rule_id"],
        "REQUEST_MANIFEST_NOT_FOUND"
    );
    assert_eq!(origin.count.load(Ordering::Acquire), 2);
    drop(gate);
    for _ in 0..2 {
        let (forwarded, auth) = origin
            .received
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&forwarded).unwrap(),
            request
        );
        assert_eq!(auth.as_deref(), Some("Bearer test-token-never-record"));
        assert!(!String::from_utf8_lossy(&forwarded).contains("AKIAIOSFODNN7EXAMPLE"));
    }
    drop(origin);

    let receipts = read_receipts(&temp.path().join("receipts"));
    assert_eq!(receipts.len(), 3);
    assert!(receipts.iter().any(|receipt| {
        receipt["mode"] == "strict-manifest"
            && receipt["achieved_claim"] == "STRICT_TELEMETRY_ONLY"
            && receipt["matched_manifest_hash"].as_str().is_some()
    }));
    let witness_lines = std::fs::read_to_string(witness_path).unwrap();
    assert!(!witness_lines.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(
        witness_lines.lines().any(|line| {
            let record: Value = serde_json::from_str(line).unwrap();
            record["params"]["mode"] == "strict-manifest"
                && record["params"]["achieved_claim"] == "STRICT_TELEMETRY_ONLY"
        }),
        "witness records: {witness_lines}"
    );
}
