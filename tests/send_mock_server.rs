//! `airlock send` end to end through the real binary, against a mock HTTP server that records
//! exactly what it receives. Nothing here is mocked on the airlock side: the request is built,
//! verified, written, sent over a socket and recorded by the shipped code.
//!
//! The mock is a `std::net` listener, so the bytes the server sees are the bytes on the wire.
//! Proxy variables are removed from every child process: `ureq` honours them, and a developer's
//! `HTTPS_PROXY` would otherwise route the test traffic elsewhere.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};

/// Distinctive enough that finding it anywhere it should not be is unambiguous.
const SECRET: &str = "sk-test-SENTINEL-4f9c1e7a2b";
const KEY_ENV: &str = "AIRLOCK_TEST_API_KEY";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn blake3_of(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

// ---------------------------------------------------------------------------------------
// The mock server
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Received {
    request_line: String,
    /// Header names are lower-cased.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone)]
enum Behavior {
    Respond {
        status: u16,
        body: Vec<u8>,
    },
    Redirect {
        status: u16,
        location: String,
    },
    /// Read the whole request and never answer.
    Hang,
}

struct MockServer {
    port: u16,
    received: Arc<Mutex<Vec<Received>>>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl MockServer {
    fn start(behavior: Behavior) -> Self {
        Self::start_with_hook(behavior, |_| {})
    }

    /// `hook` runs on the server thread after the request is read and before it is answered.
    fn start_with_hook(
        behavior: Behavior,
        hook: impl Fn(&Received) + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let hook = Arc::new(hook);

        let accept = {
            let received = Arc::clone(&received);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut workers = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let received = Arc::clone(&received);
                            let stop = Arc::clone(&stop);
                            let behavior = behavior.clone();
                            let hook = Arc::clone(&hook);
                            workers.push(thread::spawn(move || {
                                stream.set_nonblocking(false).unwrap();
                                stream
                                    .set_read_timeout(Some(Duration::from_secs(10)))
                                    .unwrap();
                                let Some(request) = read_request(&mut stream) else {
                                    return;
                                };
                                received.lock().unwrap().push(request.clone());
                                hook(&request);
                                match behavior {
                                    Behavior::Respond { status, body } => {
                                        let head = format!(
                                            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                            body.len()
                                        );
                                        let _ = stream.write_all(head.as_bytes());
                                        let _ = stream.write_all(&body);
                                    }
                                    Behavior::Redirect { status, location } => {
                                        let head = format!(
                                            "HTTP/1.1 {status} Redirect\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                                        );
                                        let _ = stream.write_all(head.as_bytes());
                                    }
                                    Behavior::Hang => {
                                        while !stop.load(Ordering::SeqCst) {
                                            thread::sleep(Duration::from_millis(20));
                                        }
                                    }
                                }
                            }));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
                for worker in workers {
                    let _ = worker.join();
                }
            })
        };
        Self {
            port,
            received,
            stop,
            accept: Some(accept),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

fn read_request(stream: &mut impl Read) -> Option<Received> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    while !buffer.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => buffer.push(byte[0]),
            _ => return None,
        }
    }
    let head = String::from_utf8_lossy(&buffer).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).ok()?;
    Some(Received {
        request_line,
        headers,
        body,
    })
}

/// A local port nothing is listening on.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

// ---------------------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------------------

struct Inputs {
    policy: PathBuf,
    prompt: PathBuf,
    provenance: PathBuf,
}

fn fixture_inputs(name: &str) -> Inputs {
    let dir = root().join("fixtures").join(name);
    Inputs {
        policy: dir.join("policy.yaml"),
        prompt: dir.join("expected_prompt_payload.json"),
        provenance: dir.join("expected_prompt_provenance.json"),
    }
}

struct Harness {
    dir: tempfile::TempDir,
    inputs: Inputs,
    transport: Value,
    /// Where `--out` points. A test that needs the manifest elsewhere sets it.
    out: PathBuf,
}

impl Harness {
    fn new(inputs: Inputs, url: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            out: dir.path().join("airlock_manifest.json"),
            dir,
            inputs,
            transport: json!({
                "adapter": "openai_chat_completions",
                "model": "gpt-5",
                "url": url,
                "api_key_env": KEY_ENV,
            }),
        }
    }

    fn clean(url: &str) -> Self {
        Self::new(fixture_inputs("clean_telemetry_only"), url)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn out(&self) -> PathBuf {
        self.out.clone()
    }

    fn request_out(&self) -> PathBuf {
        self.path("sent_request.json")
    }

    fn response_out(&self) -> PathBuf {
        self.path("response.json")
    }

    fn witness(&self) -> PathBuf {
        self.path("witness.jsonl")
    }

    fn transport_path(&self) -> PathBuf {
        self.path("send_transport.json")
    }

    /// Run `airlock send` with the key set and proxies removed.
    fn run(&self, extra: &[&str]) -> Output {
        self.run_with(extra, |_| {})
    }

    fn run_with(&self, extra: &[&str], adjust: impl FnOnce(&mut Command)) -> Output {
        std::fs::write(
            self.transport_path(),
            serde_json::to_vec(&self.transport).unwrap(),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
        command
            .arg("send")
            .arg("--policy")
            .arg(&self.inputs.policy)
            .arg("--prompt")
            .arg(&self.inputs.prompt)
            .arg("--provenance")
            .arg(&self.inputs.provenance)
            .arg("--transport")
            .arg(self.transport_path())
            .arg("--out")
            .arg(self.out())
            .arg("--request-out")
            .arg(self.request_out())
            .args(extra);
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "HOME",
            "USERPROFILE",
            "SOURCE_DATE_EPOCH",
        ] {
            command.env_remove(name);
        }
        command
            .env(KEY_ENV, SECRET)
            .env("EPISTEMIC_WITNESS", self.witness());
        adjust(&mut command);
        command.output().unwrap()
    }

    fn manifest(&self) -> Value {
        read_json(&self.out())
    }

    /// The witness records `send` appended, oldest first.
    fn witness_records(&self) -> Vec<Value> {
        match std::fs::read_to_string(self.witness()) {
            Ok(text) => text
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .filter(|record| record["command"] == "send")
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn witness_outcomes(&self) -> Vec<String> {
        self.witness_records()
            .iter()
            .map(|record| record["outcome"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Every byte this run printed or left on disk, for scanning. The transport file is the
    /// input that names the URL, so it is not part of what the run produced.
    fn everything_written(&self, output: &Output) -> String {
        let mut all = String::from_utf8_lossy(&output.stdout).into_owned();
        all.push_str(&String::from_utf8_lossy(&output.stderr));
        let transport = self.transport_path();
        let mut stack = vec![self.dir.path().to_path_buf()];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path != transport {
                    all.push_str(&String::from_utf8_lossy(&std::fs::read(&path).unwrap()));
                }
            }
        }
        all
    }
}

fn stdout_json(output: &Output) -> Value {
    let parsed = serde_json::from_slice::<Value>(&output.stdout);
    assert!(
        parsed.is_ok(),
        "stdout is not JSON ({:?}): {}\nstderr: {}",
        parsed.as_ref().err(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parsed.unwrap_or(Value::Null)
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn manifest_schema() -> jsonschema::Validator {
    // Format checks on: date-time is only an annotation to the default validator.
    jsonschema::options()
        .should_validate_formats(true)
        .build(&read_json(&root().join("schemas/airlock.v0.schema.json")))
        .unwrap()
}

fn assert_valid_manifest(manifest: &Value) {
    let schema = manifest_schema();
    assert!(
        schema.is_valid(manifest),
        "manifest does not validate: {:?}\n{manifest}",
        schema
            .validate(manifest)
            .err()
            .map(|error| error.to_string())
    );
}

fn ok_response() -> Behavior {
    Behavior::Respond {
        status: 200,
        body: br#"{"id":"resp-1","choices":[]}"#.to_vec(),
    }
}

// ---------------------------------------------------------------------------------------
// What was sent
// ---------------------------------------------------------------------------------------

#[test]
fn the_server_receives_exactly_the_bytes_the_manifest_hashes() {
    let server = MockServer::start(ok_response());
    let harness = Harness::clean(&server.url("/v1/chat/completions"));

    let output = harness.run(&[
        "--no-sign",
        "--response-out",
        harness.response_out().to_str().unwrap(),
    ]);

    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let received = server.received();
    assert_eq!(received.len(), 1, "exactly one request");
    let request = &received[0];
    assert_eq!(request.request_line, "POST /v1/chat/completions HTTP/1.1");
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {SECRET}").as_str())
    );

    let manifest = harness.manifest();
    let transmission = &manifest["transmission"];
    // The wire bytes, the file, the hash and the length are one thing.
    assert_eq!(request.body, std::fs::read(harness.request_out()).unwrap());
    assert_eq!(manifest["request_payload_hash"], blake3_of(&request.body));
    assert_eq!(transmission["request_hash"], blake3_of(&request.body));
    assert_eq!(manifest["bytes_crossed"], request.body.len());
    assert_eq!(transmission["request_bytes"], request.body.len());
    // They are the RFC 8785 canonical form of a request for the declared model.
    let parsed: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(parsed["model"], "gpt-5");
    assert_eq!(
        cmdrvl_core::jcs::to_string(&parsed).unwrap().as_bytes(),
        request.body.as_slice()
    );

    assert_eq!(manifest["manifest_version"], "airlock.v0.3");
    assert_eq!(manifest["attestation"], "transmitted");
    assert_eq!(
        manifest["replay_ref"],
        harness.request_out().display().to_string()
    );
    assert_eq!(transmission["sent"], true);
    assert_eq!(
        transmission["endpoint_host"],
        format!("127.0.0.1:{}", server.port)
    );
    assert_eq!(transmission["response_status"], 200);
    let response_body = br#"{"id":"resp-1","choices":[]}"#;
    assert_eq!(transmission["response_hash"], blake3_of(response_body));
    assert_eq!(transmission["response_bytes"], response_body.len());
    assert!(transmission.get("error").is_none());
    assert!(transmission["sent_at"].is_string());
    assert!(transmission["latency_ms"].is_u64());
    assert_valid_manifest(&manifest);

    // stdout is the manifest that is on disk.
    assert_eq!(output.stdout, std::fs::read(harness.out()).unwrap());
    assert_eq!(
        std::fs::read(harness.response_out()).unwrap(),
        response_body.as_slice()
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_request_sent_passes_airlock_verify_with_the_same_verdict() {
    // send judges its request with verify's own code, so verify on the saved request agrees.
    let server = MockServer::start(ok_response());
    let harness = Harness::clean(&server.url("/v1/chat/completions"));
    assert_eq!(code(&harness.run(&["--no-sign"])), 0);
    let sent = harness.manifest();

    let verified_out = harness.path("verify_manifest.json");
    let verify = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .arg("verify")
        .arg("--policy")
        .arg(&harness.inputs.policy)
        .arg("--prompt")
        .arg(&harness.inputs.prompt)
        .arg("--provenance")
        .arg(&harness.inputs.provenance)
        .arg("--request")
        .arg(harness.request_out())
        .arg("--out")
        .arg(&verified_out)
        .args(["--no-sign", "--no-witness"])
        .output()
        .unwrap();

    assert_eq!(
        code(&verify),
        0,
        "{}",
        String::from_utf8_lossy(&verify.stdout)
    );
    let verified = read_json(&verified_out);
    for field in [
        "achieved_claim",
        "request_payload_hash",
        "bytes_crossed",
        "system_prompt_hash",
        "prompt_payload_hash",
        "policy_hash",
        "adapter",
        "model_id",
        "findings",
        "blocked_reasons",
    ] {
        assert_eq!(sent[field], verified[field], "{field}");
    }
    assert_eq!(verified["attestation"], "self_attested");
    assert!(verified.get("transmission").is_none());
}

#[cfg(unix)]
#[test]
fn the_request_and_response_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let server = MockServer::start(ok_response());
    let harness = Harness::clean(&server.url("/v1/chat/completions"));
    let output = harness.run(&[
        "--no-sign",
        "--response-out",
        harness.response_out().to_str().unwrap(),
    ]);
    assert_eq!(code(&output), 0);

    for path in [harness.request_out(), harness.response_out()] {
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", path.display());
    }
}

#[test]
fn an_http_error_status_is_a_completed_exchange() {
    let server = MockServer::start(Behavior::Respond {
        status: 500,
        body: br#"{"error":"upstream"}"#.to_vec(),
    });
    let harness = Harness::clean(&server.url("/v1/chat/completions"));

    let output = harness.run(&[
        "--no-sign",
        "--response-out",
        harness.response_out().to_str().unwrap(),
    ]);

    assert_eq!(code(&output), 0);
    let manifest = harness.manifest();
    assert_eq!(manifest["attestation"], "transmitted");
    assert_eq!(manifest["transmission"]["response_status"], 500);
    assert!(manifest["transmission"].get("error").is_none());
    assert_eq!(
        std::fs::read(harness.response_out()).unwrap(),
        br#"{"error":"upstream"}"#.as_slice()
    );
    assert_valid_manifest(&manifest);
}

#[test]
fn a_redirect_is_recorded_and_never_followed() {
    let elsewhere = MockServer::start(ok_response());
    let server = MockServer::start(Behavior::Redirect {
        status: 307,
        location: elsewhere.url("/elsewhere"),
    });
    let harness = Harness::clean(&server.url("/v1/chat/completions"));

    let output = harness.run(&["--no-sign"]);

    assert_eq!(code(&output), 0);
    assert_eq!(server.received().len(), 1);
    assert!(
        elsewhere.received().is_empty(),
        "the body must not be re-sent to a host the transport file did not name"
    );
    let manifest = harness.manifest();
    assert_eq!(manifest["transmission"]["response_status"], 307);
    assert_eq!(manifest["attestation"], "transmitted");
    assert_valid_manifest(&manifest);
}

#[test]
fn the_anthropic_adapter_authenticates_and_versions_its_request() {
    let server = MockServer::start(ok_response());
    let mut harness = Harness::clean(&server.url("/v1/messages"));
    harness.transport = json!({
        "adapter": "anthropic_messages",
        "model": "claude-test",
        "url": server.url("/v1/messages"),
        "api_key_env": KEY_ENV,
        "params": {"max_tokens": 64},
    });

    let output = harness.run(&["--no-sign"]);

    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let received = server.received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].header("x-api-key"), Some(SECRET));
    assert_eq!(received[0].header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(received[0].header("authorization"), None);
    let manifest = harness.manifest();
    assert_eq!(manifest["adapter"], "anthropic_messages");
    assert_eq!(manifest["model_id"], "claude-test");
    assert_eq!(
        manifest["request_payload_hash"],
        blake3_of(&received[0].body)
    );
}

// ---------------------------------------------------------------------------------------
// What is not sent
// ---------------------------------------------------------------------------------------

#[test]
fn a_claim_below_the_requirement_sends_nothing() {
    // The annotated prompt carries derived text, so it reaches RAW_DOCUMENT_ABSENT and no more.
    let server = MockServer::start(ok_response());
    let harness = Harness::new(
        fixture_inputs("annotated_mode"),
        &server.url("/v1/chat/completions"),
    );

    let output = harness.run(&["--no-sign", "--require-claim", "STRICT_TELEMETRY_ONLY"]);

    assert_eq!(
        code(&output),
        1,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(server.received().is_empty(), "nothing may reach the server");
    let manifest = harness.manifest();
    assert_eq!(manifest["achieved_claim"], "RAW_DOCUMENT_ABSENT");
    assert_eq!(manifest["attestation"], "self_attested");
    let transmission = &manifest["transmission"];
    assert_eq!(transmission["sent"], false);
    assert_eq!(transmission["error"], "CLAIM_BELOW_REQUIRED");
    assert_eq!(
        transmission["request_hash"],
        manifest["request_payload_hash"]
    );
    assert!(transmission.get("sent_at").is_none());
    assert!(transmission.get("response_status").is_none());
    assert_valid_manifest(&manifest);
    assert_eq!(output.stdout, std::fs::read(harness.out()).unwrap());
    // The request that was judged is still saved, so a caller can see what fell short.
    assert!(harness.request_out().exists());
    assert_eq!(harness.witness_outcomes(), ["NOT_SENT"]);
    assert_eq!(harness.witness_records()[0]["exit_code"], 1);
}

/// The clean fixture's prompt with raw HTML in an allowed field, and a provenance that names
/// the edited prompt's hash so it still binds: a prompt that fails the boundary check itself,
/// not merely a request that disagrees with it.
fn boundary_failing_inputs(dir: &Path) -> Inputs {
    let clean = fixture_inputs("clean_telemetry_only");
    let mut prompt = read_json(&clean.prompt);
    prompt["messages"][1]["content"]["current_strategy"] =
        json!("<table><tr><td>raw filing html</td></tr></table>");
    let mut provenance = read_json(&clean.provenance);
    provenance["prompt_payload_hash"] = json!(airlock::hash::jcs_blake3_hash(&prompt).unwrap());

    let inputs = Inputs {
        policy: clean.policy,
        prompt: dir.join("edited_prompt.json"),
        provenance: dir.join("edited_provenance.json"),
    };
    std::fs::write(&inputs.prompt, serde_json::to_vec(&prompt).unwrap()).unwrap();
    std::fs::write(&inputs.provenance, serde_json::to_vec(&provenance).unwrap()).unwrap();
    inputs
}

#[test]
fn a_request_that_failed_the_boundary_is_not_sent_unless_asked() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start(ok_response());
    let harness = Harness::new(
        boundary_failing_inputs(dir.path()),
        &server.url("/v1/chat/completions"),
    );

    // No --require-claim: the default refuses to send a failed boundary.
    let output = harness.run(&["--no-sign"]);

    assert_eq!(
        code(&output),
        1,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(server.received().is_empty());
    let manifest = harness.manifest();
    assert_eq!(manifest["achieved_claim"], "BOUNDARY_FAILED");
    assert_eq!(manifest["transmission"]["sent"], false);
    assert_eq!(manifest["transmission"]["error"], "CLAIM_BELOW_REQUIRED");
    assert_eq!(manifest["attestation"], "self_attested");

    // Asking for BOUNDARY_FAILED is the explicit opt-in, and then it is sent.
    let forced = harness.run(&["--no-sign", "--require-claim", "BOUNDARY_FAILED"]);
    assert_eq!(
        code(&forced),
        0,
        "{}",
        String::from_utf8_lossy(&forced.stdout)
    );
    assert_eq!(server.received().len(), 1);
    let manifest = harness.manifest();
    assert_eq!(manifest["achieved_claim"], "BOUNDARY_FAILED");
    assert_eq!(manifest["attestation"], "transmitted");
}

#[test]
fn an_unset_key_refuses_before_anything_is_written_or_sent() {
    let server = MockServer::start(ok_response());
    let harness = Harness::clean(&server.url("/v1/chat/completions"));

    let output = harness.run_with(&["--no-sign"], |command| {
        command.env_remove(KEY_ENV);
    });

    assert_eq!(code(&output), 2);
    let refusal = stdout_json(&output);
    assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT");
    assert_eq!(refusal["refusal"]["detail"]["env"], KEY_ENV);
    assert!(server.received().is_empty());
    assert!(!harness.out().exists(), "no manifest");
    assert!(!harness.request_out().exists(), "no request file");
    assert!(!harness.witness().exists(), "no witness record");
}

#[test]
fn a_transport_file_that_could_leak_or_redirect_is_refused_without_quoting_it() {
    // A remote plain-http URL, credentials in the URL, and a query string: each refused
    // before any connection, and none of them is echoed back.
    for (url, leaked) in [
        ("http://203.0.113.9/v1/chat", "203.0.113.9"),
        ("https://user:hunter2-pw@api.example.com/v1", "hunter2-pw"),
        (
            "https://api.example.com/v1?key=query-secret-9",
            "query-secret-9",
        ),
    ] {
        let harness = Harness::clean(url);

        let output = harness.run(&["--no-sign"]);

        assert_eq!(code(&output), 2, "{url}");
        let refusal = stdout_json(&output);
        assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT", "{url}");
        assert_eq!(refusal["refusal"]["detail"]["field"], "url", "{url}");
        assert!(
            !harness.everything_written(&output).contains(leaked),
            "{url} must not be quoted"
        );
        assert!(!harness.out().exists(), "{url}");
        assert!(!harness.witness().exists(), "{url}");
    }
}

#[test]
fn outputs_may_not_overwrite_inputs_or_each_other() {
    let server = MockServer::start(ok_response());
    let harness = Harness::clean(&server.url("/v1/chat/completions"));

    let same_as_each_other = harness.run(&[
        "--no-sign",
        "--response-out",
        harness.request_out().to_str().unwrap(),
    ]);
    assert_eq!(code(&same_as_each_other), 2);
    assert_eq!(
        stdout_json(&same_as_each_other)["refusal"]["code"],
        "E_BAD_INPUT"
    );

    let over_the_prompt = harness.run(&[
        "--no-sign",
        "--response-out",
        harness.inputs.prompt.to_str().unwrap(),
    ]);
    assert_eq!(code(&over_the_prompt), 2);
    assert!(server.received().is_empty());
}

// ---------------------------------------------------------------------------------------
// What goes wrong on the wire
// ---------------------------------------------------------------------------------------

#[test]
fn a_connection_that_cannot_be_made_is_recorded_as_not_sent() {
    let harness = Harness::clean(&format!(
        "http://127.0.0.1:{}/v1/chat/completions",
        closed_port()
    ));

    let output = harness.run(&["--no-sign"]);

    assert_eq!(code(&output), 2);
    let refusal = stdout_json(&output);
    assert_eq!(refusal["refusal"]["code"], "E_TRANSPORT");
    assert_eq!(refusal["refusal"]["detail"]["sent"], false);
    assert_eq!(refusal["refusal"]["detail"]["error"], "CONNECT_FAILED");

    let manifest = harness.manifest();
    assert_eq!(manifest["attestation"], "self_attested");
    assert_eq!(manifest["transmission"]["sent"], false);
    assert_eq!(manifest["transmission"]["error"], "CONNECT_FAILED");
    assert!(manifest["transmission"].get("sent_at").is_none());
    assert_valid_manifest(&manifest);
    assert_eq!(harness.witness_outcomes(), ["SENDING", "NOT_SENT"]);
}

#[test]
fn a_missing_response_is_recorded_as_sent_with_no_response() {
    let server = MockServer::start(Behavior::Hang);
    let mut harness = Harness::clean(&server.url("/v1/chat/completions"));
    harness.transport["timeout_seconds"] = json!(1);

    let output = harness.run(&[
        "--no-sign",
        "--response-out",
        harness.response_out().to_str().unwrap(),
    ]);

    assert_eq!(code(&output), 2);
    let refusal = stdout_json(&output);
    assert_eq!(refusal["refusal"]["code"], "E_TRANSPORT");
    assert_eq!(refusal["refusal"]["detail"]["sent"], true);
    assert_eq!(refusal["refusal"]["detail"]["error"], "RESPONSE_TIMEOUT");

    // The server did get the whole body: sent is true because it was.
    let received = server.received();
    assert_eq!(received.len(), 1);
    let manifest = harness.manifest();
    assert_eq!(
        manifest["request_payload_hash"],
        blake3_of(&received[0].body)
    );
    assert_eq!(manifest["attestation"], "transmitted");
    let transmission = &manifest["transmission"];
    assert_eq!(transmission["sent"], true);
    assert_eq!(transmission["error"], "RESPONSE_TIMEOUT");
    for member in ["response_status", "response_hash", "response_bytes"] {
        assert!(transmission.get(member).is_none(), "{member}");
    }
    assert!(
        transmission["latency_ms"].as_u64().unwrap() >= 900,
        "waited for the timeout: {transmission}"
    );
    assert_valid_manifest(&manifest);
    assert!(
        !harness.response_out().exists(),
        "no complete response, no file"
    );
    assert_eq!(harness.witness_outcomes(), ["SENDING", "SEND_FAILED"]);
}

#[test]
fn an_oversized_response_is_cut_off_and_recorded() {
    let server = MockServer::start(Behavior::Respond {
        status: 200,
        body: vec![b'x'; 5000],
    });
    let mut harness = Harness::clean(&server.url("/v1/chat/completions"));
    harness.transport["max_response_bytes"] = json!(1024);

    let output = harness.run(&[
        "--no-sign",
        "--response-out",
        harness.response_out().to_str().unwrap(),
    ]);

    assert_eq!(code(&output), 2);
    assert_eq!(
        stdout_json(&output)["refusal"]["detail"]["error"],
        "RESPONSE_TOO_LARGE"
    );
    let transmission = &harness.manifest()["transmission"];
    assert_eq!(transmission["sent"], true);
    assert_eq!(transmission["error"], "RESPONSE_TOO_LARGE");
    assert_eq!(transmission["response_status"], 200);
    assert_eq!(transmission["response_bytes"], 1024);
    assert_eq!(transmission["response_hash"], blake3_of(&[b'x'; 1024]));
    assert_valid_manifest(&harness.manifest());
    assert!(!harness.response_out().exists());
    assert_eq!(harness.witness_outcomes(), ["SENDING", "SEND_FAILED"]);
}

#[test]
fn a_record_of_the_attempt_exists_before_the_request_goes_out() {
    // A model call can take minutes. A process killed in the middle must not leave a manifest
    // that says nothing happened, so at the moment the server has the request, the manifest,
    // the request file and a SENDING witness record are already on disk.
    #[derive(Clone, Default)]
    struct Snapshot {
        manifest: Option<Value>,
        request_file_exists: bool,
        witness: String,
    }
    let snapshot = Arc::new(Mutex::new(Snapshot::default()));

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("airlock_manifest.json");
    let request_out = dir.path().join("sent_request.json");
    let witness = dir.path().join("witness.jsonl");
    let server = {
        let snapshot = Arc::clone(&snapshot);
        let (out, request_out, witness) = (out.clone(), request_out.clone(), witness.clone());
        MockServer::start_with_hook(ok_response(), move |_| {
            *snapshot.lock().unwrap() = Snapshot {
                manifest: std::fs::read(&out)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok()),
                request_file_exists: request_out.exists(),
                witness: std::fs::read_to_string(&witness).unwrap_or_default(),
            };
        })
    };
    let mut harness = Harness::clean(&server.url("/v1/chat/completions"));
    harness.dir = dir;
    harness.out = out;

    let output = harness.run(&["--no-sign"]);
    assert_eq!(code(&output), 0);

    let snapshot = snapshot.lock().unwrap().clone();
    let before = snapshot
        .manifest
        .expect("a manifest exists before the send");
    assert_eq!(before["attestation"], "self_attested");
    assert!(
        before.get("transmission").is_none(),
        "absent says nothing about whether it was sent"
    );
    assert!(snapshot.request_file_exists);
    assert!(
        snapshot.witness.contains("\"SENDING\""),
        "witness: {}",
        snapshot.witness
    );
    assert!(!snapshot.witness.contains("\"SENT\""));
    // And afterwards the same file says what happened.
    assert_eq!(harness.manifest()["attestation"], "transmitted");
    assert_eq!(harness.witness_outcomes(), ["SENDING", "SENT"]);
}

#[cfg(unix)]
#[test]
fn a_failure_to_record_a_completed_exchange_says_it_was_sent() {
    use std::os::unix::fs::PermissionsExt;
    if Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|id| id.stdout == b"0\n")
    {
        return; // root ignores directory permissions, so the failure cannot be provoked
    }
    let manifest_dir = tempfile::tempdir().unwrap();
    let locked = manifest_dir.path().to_path_buf();
    // While the server holds the request, the directory the manifest lives in becomes
    // read-only: the pre-send manifest is already written, the final one cannot be.
    let server = MockServer::start_with_hook(ok_response(), move |_| {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
    });
    let mut harness = Harness::clean(&server.url("/v1/chat/completions"));
    let out = manifest_dir.path().join("airlock_manifest.json");
    harness.out = out.clone();

    let output = harness.run(&["--no-sign"]);
    std::fs::set_permissions(manifest_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(
        code(&output),
        2,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let refusal = stdout_json(&output);
    assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT");
    assert_eq!(refusal["refusal"]["detail"]["sent"], true);
    assert_eq!(
        refusal["refusal"]["detail"]["transmission"]["response_status"],
        200
    );
    // The record that did get written is the pre-send one, which claims nothing.
    let on_disk = read_json(&out);
    assert_eq!(on_disk["attestation"], "self_attested");
    assert!(on_disk.get("transmission").is_none());
    assert_eq!(harness.witness_outcomes(), ["SENDING", "SENT"]);
    assert_eq!(harness.witness_records()[1]["exit_code"], 2);
}

// ---------------------------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------------------------

#[test]
fn the_key_reaches_the_server_and_nowhere_else() {
    // Success, a refused connection, a timeout and a claim shortfall: whichever way it ends,
    // the key is in no output, manifest, request file, response file or ledger.
    let ok = MockServer::start(ok_response());
    let hang = MockServer::start(Behavior::Hang);
    let mut cases: Vec<(&str, Harness, Vec<&str>)> = Vec::new();
    cases.push(("success", Harness::clean(&ok.url("/v1/c")), vec![]));
    cases.push((
        "refused",
        Harness::clean(&format!("http://127.0.0.1:{}/v1/c", closed_port())),
        vec![],
    ));
    let mut timeout = Harness::clean(&hang.url("/v1/c"));
    timeout.transport["timeout_seconds"] = json!(1);
    cases.push(("timeout", timeout, vec![]));
    cases.push((
        "shortfall",
        Harness::new(fixture_inputs("annotated_mode"), &ok.url("/v1/c")),
        vec!["--require-claim", "STRICT_TELEMETRY_ONLY"],
    ));

    for (name, harness, extra) in cases {
        let mut args = vec!["--no-sign"];
        args.extend(extra);
        let response_out = harness.response_out();
        args.extend(["--response-out", response_out.to_str().unwrap()]);

        let output = harness.run(&args);

        let everything = harness.everything_written(&output);
        assert!(
            !everything.contains(SECRET),
            "{name}: the key appears in output or on disk"
        );
        assert!(!everything.contains("SENTINEL"), "{name}");
    }
    for request in ok.received().iter().chain(hang.received().iter()) {
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {SECRET}").as_str())
        );
        // Not in the body either: the key goes only in a header.
        assert!(!String::from_utf8_lossy(&request.body).contains(SECRET));
    }
}

// ---------------------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------------------

#[test]
fn the_signature_covers_the_transmission() {
    let home = tempfile::tempdir().unwrap();
    let keygen = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .arg("keygen")
        .env("HOME", home.path())
        .env_remove("USERPROFILE")
        .output()
        .unwrap();
    assert_eq!(
        code(&keygen),
        0,
        "{}",
        String::from_utf8_lossy(&keygen.stdout)
    );
    let pubkey = home.path().join(".cmdrvl/secrets/airlock/ed25519.pub");
    assert!(pubkey.exists());

    let server = MockServer::start(ok_response());
    let harness = Harness::clean(&server.url("/v1/chat/completions"));
    // Signing is the default: no --no-sign.
    let output = harness.run_with(&[], |command| {
        command.env("HOME", home.path());
    });
    assert_eq!(
        code(&output),
        0,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let manifest = harness.manifest();
    assert!(manifest["signature"].is_object());
    assert_valid_manifest(&manifest);

    let verify = |path: &Path| {
        Command::new(env!("CARGO_BIN_EXE_airlock"))
            .arg("verify-manifest")
            .arg(path)
            .arg("--pubkey")
            .arg(&pubkey)
            .output()
            .unwrap()
    };
    assert_eq!(code(&verify(&harness.out())), 0);

    // Change what the manifest says about the exchange: the signature no longer holds.
    for (member, value) in [
        ("response_status", json!(404)),
        ("endpoint_host", json!("api.somewhere-else.example")),
    ] {
        let mut tampered = manifest.clone();
        assert_ne!(
            tampered["transmission"][member], value,
            "pick a different value"
        );
        tampered["transmission"][member] = value;
        let path = harness.path("tampered.json");
        std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert_ne!(
            code(&verify(&path)),
            0,
            "tampering with {member} must break the signature"
        );
    }
    let mut flipped = manifest.clone();
    flipped["attestation"] = json!("self_attested");
    let path = harness.path("flipped.json");
    std::fs::write(&path, serde_json::to_vec(&flipped).unwrap()).unwrap();
    assert_ne!(code(&verify(&path)), 0);
}

#[test]
fn two_sends_differ_only_in_what_happened_on_the_wire() {
    let server = MockServer::start(ok_response());
    let run = || {
        let harness = Harness::clean(&server.url("/v1/chat/completions"));
        let output = harness.run_with(&["--no-sign"], |command| {
            command.env("SOURCE_DATE_EPOCH", "1700000000");
        });
        assert_eq!(code(&output), 0);
        harness.manifest()
    };
    let mut first = run();
    let mut second = run();

    // The wall-clock time of the send and how long it took are the only members that vary.
    for manifest in [&mut first, &mut second] {
        let transmission = manifest["transmission"].as_object_mut().unwrap();
        assert!(transmission.remove("sent_at").is_some());
        assert!(transmission.remove("latency_ms").is_some());
        // The replay path is per-run (a fresh temp directory).
        manifest.as_object_mut().unwrap().remove("replay_ref");
    }
    assert_eq!(first, second);
    assert_eq!(first["timestamp"], "2023-11-14T22:13:20+00:00");
}
