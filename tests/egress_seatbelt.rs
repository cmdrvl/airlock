//! al-28e: the macOS Seatbelt egress recipe in docs/deploy/egress-firewall.md, run for real.
//!
//! The profile is not copied here. The test extracts the fenced `seatbelt` block from the doc
//! and runs `/usr/bin/sandbox-exec` with it, so the doc cannot drift from what is proven. The
//! gate is the real `airlock gate` binary; the clients are the system `curl` and `nc`. The
//! origin counts the connections it receives, so a blocked attempt is shown by the server not
//! seeing it, not only by the client's error.
//!
//! This proves one platform: macOS, network egress only, for processes started under the
//! profile. It says nothing about Linux, about processes not launched under the profile, or
//! about files. If `sandbox-exec` cannot apply a profile here the tests FAIL, because a skip
//! would read as a pass.
#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const CURL: &str = "/usr/bin/curl";
const NC: &str = "/usr/bin/nc";
const ORIGIN_BODY: &str = "origin-reached";
const CLEAN_REQUEST: &str =
    r#"{"model":"m","messages":[{"role":"user","content":"hello through the gate"}]}"#;
// RFC 5737 TEST-NET-1: never routable, so even a profile that failed open could not reach a host.
const EXTERNAL_ADDRESS: &str = "192.0.2.1";

// ---------------------------------------------------------------- the profile, from the doc

/// The one fenced `seatbelt` block in the deploy doc, exactly as written.
fn profile_from_the_doc() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/deploy/egress-firewall.md");
    let text = std::fs::read_to_string(&path).expect("the deploy doc must be readable");
    let mut profiles = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        match (&mut current, line.strip_prefix("```")) {
            (None, Some(tag)) => current = Some((tag.trim().to_owned(), String::new())),
            (Some(_), Some(_)) => {
                if let Some((tag, body)) = current.take()
                    && tag == "seatbelt"
                {
                    profiles.push(body);
                }
            }
            (Some((_, body)), None) => {
                body.push_str(line);
                body.push('\n');
            }
            (None, None) => {}
        }
    }
    assert!(current.is_none(), "unterminated code fence in the doc");
    assert_eq!(
        profiles.len(),
        1,
        "the doc must hold exactly one `seatbelt` block, found {}",
        profiles.len()
    );
    profiles.remove(0)
}

fn assert_sandbox_exec_can_apply_a_profile() {
    let output = Command::new(SANDBOX_EXEC)
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .output()
        .expect("/usr/bin/sandbox-exec must exist on macOS");
    assert!(
        output.status.success(),
        "sandbox-exec cannot apply a profile here (stderr: {}). The egress proof did not run, \
         so this test fails instead of skipping.",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ------------------------------------------------------------------------- the origin

/// A bare HTTP origin that counts TCP connections and parsed requests, and forwards each request
/// body to the test. It stands in for the model provider the gate forwards to, and is also the
/// "non-gate host and port" a sandboxed client must not be able to reach.
struct Origin {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    bodies: Receiver<Vec<u8>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Origin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the origin");
        listener.set_nonblocking(true).expect("nonblocking origin");
        let address = listener.local_addr().expect("origin address");
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, bodies) = mpsc::channel();
        let worker = {
            let (connections, requests, stop) = (
                Arc::clone(&connections),
                Arc::clone(&requests),
                Arc::clone(&stop),
            );
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            connections.fetch_add(1, Ordering::AcqRel);
                            let (requests, sender) = (Arc::clone(&requests), sender.clone());
                            thread::spawn(move || answer(stream, &requests, &sender));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            })
        };
        Self {
            address,
            connections,
            requests,
            bodies,
            stop,
            worker: Some(worker),
        }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.address)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Read one HTTP request (headers, then `Content-Length` bytes), record it, answer 200.
fn answer(mut stream: std::net::TcpStream, requests: &AtomicUsize, bodies: &Sender<Vec<u8>>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
        }
    }
    let _ = bodies.send(buffer[header_end..].to_vec());
    requests.fetch_add(1, Ordering::AcqRel);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ORIGIN_BODY}",
        ORIGIN_BODY.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

// --------------------------------------------------------------------------- the gate

struct Gate {
    child: Child,
    address: SocketAddr,
}

impl Drop for Gate {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const PROXY_VARIABLES: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

/// The real gate, started outside any sandbox (it must reach its upstream), on an ephemeral
/// loopback port. Proxy variables are removed so it connects to the origin itself.
fn start_gate(origin: SocketAddr, directory: &Path) -> Gate {
    let policy = directory.join("policy.yaml");
    std::fs::write(
        &policy,
        "policy_id: egress-test\nversion: airlock.v0\nallowed_keys:\n  - key_path: messages\n\
         forbidden_keys: [blocked_field]\nforbidden_patterns:\n  - pattern: 'client-[0-9]+'\n\
         derived_text_paths: []\nclaim_levels: [BOUNDARY_FAILED, RAW_DOCUMENT_ABSENT, STRICT_TELEMETRY_ONLY]\n\
         detectors: [secrets, pii, tabular, blobs, paths]\nprotected_bloom_min_hits: 3\n",
    )
    .expect("write the gate policy");
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock"));
    command
        .args(["gate", "--mode", "policy-proxy", "--upstream"])
        .arg(format!("http://{origin}"))
        .args(["--listen", "127.0.0.1:0", "--no-witness", "--policy"])
        .arg(&policy)
        .arg("--out-dir")
        .arg(directory.join("receipts"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for variable in PROXY_VARIABLES {
        command.env_remove(variable);
    }
    let mut child = command.spawn().expect("start airlock gate");
    let stderr = child.stderr.take().expect("gate stderr");
    let mut line = String::new();
    BufReader::new(stderr)
        .read_line(&mut line)
        .expect("read the gate's listening line");
    let address = line
        .trim()
        .strip_prefix("airlock gate listening on ")
        .unwrap_or_default()
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    assert_ne!(address.port(), 0, "the gate did not start: {line:?}");
    Gate { child, address }
}

// ------------------------------------------------------------------------ the fixture

struct Fixture {
    origin: Origin,
    gate: Gate,
    profile: PathBuf,
    // Held so the profile, policy and receipts outlive the test body.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn start() -> Self {
        assert_sandbox_exec_can_apply_a_profile();
        let directory = tempfile::tempdir().expect("tempdir");
        let origin = Origin::start();
        let gate = start_gate(origin.address, directory.path());
        let profile = directory.path().join("egress.sb");
        std::fs::write(&profile, profile_from_the_doc()).expect("write the profile");
        Self {
            origin,
            gate,
            profile,
            _directory: directory,
        }
    }

    /// `sandbox-exec -f <the doc's profile> -D GATE_PORT=<gate port> <program>`.
    fn sandboxed(&self, program: &str) -> Command {
        let mut command = Command::new(SANDBOX_EXEC);
        command
            .arg("-f")
            .arg(&self.profile)
            .arg("-D")
            .arg(format!("GATE_PORT={}", self.gate.address.port()))
            .arg(program);
        command
    }

    fn gate_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.gate.address)
    }
}

// ------------------------------------------------------------------------- clients

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

impl Ran {
    /// The HTTP status curl printed after the body, `000` when it never connected.
    fn http_status(&self) -> &str {
        self.stdout.rsplit('\n').next().unwrap_or("")
    }
}

fn run(mut command: Command, stdin: Option<&str>) -> Ran {
    for variable in PROXY_VARIABLES {
        command.env_remove(variable);
    }
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = command.spawn().expect("spawn the client");
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(text.as_bytes());
    }
    let output = child.wait_with_output().expect("wait for the client");
    Ran {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        elapsed: started.elapsed(),
    }
}

/// curl: verbose (so the connect errno is on stderr), no proxy, body then the HTTP status.
fn curl_args(command: &mut Command, extra: &[&str], url: &str) {
    command
        .args(["-sSv", "--noproxy", "*", "-m", "5", "-w", "\n%{http_code}"])
        .args(extra)
        .arg(url);
}

fn curl(url: &str) -> Command {
    let mut command = Command::new(CURL);
    curl_args(&mut command, &[], url);
    command
}

fn sandboxed_curl(fixture: &Fixture, extra: &[&str], url: &str) -> Command {
    let mut command = fixture.sandboxed(CURL);
    curl_args(&mut command, extra, url);
    command
}

const POST_REQUEST: [&str; 5] = ["-X", "POST", "-H", "content-type: application/json", "-d"];

fn assert_blocked_by_the_sandbox(ran: &Ran, what: &str) {
    assert_eq!(
        ran.code,
        Some(7),
        "{what}: curl should fail to connect (exit 7)\nstdout: {}\nstderr: {}",
        ran.stdout,
        ran.stderr
    );
    assert!(
        ran.stderr.contains("Operation not permitted"),
        "{what}: the connect must fail with the sandbox's EPERM, not a refusal or a timeout\n\
         stderr: {}",
        ran.stderr
    );
    assert_eq!(
        ran.http_status(),
        "000",
        "{what}: no HTTP response expected"
    );
}

// ----------------------------------------------------------------------------- tests

#[test]
fn an_unsandboxed_client_reaches_the_origin_directly() {
    let fixture = Fixture::start();

    let ran = run(curl(&fixture.origin.url()), None);

    assert_eq!(ran.code, Some(0), "stderr: {}", ran.stderr);
    assert_eq!(ran.http_status(), "200");
    assert!(ran.stdout.contains(ORIGIN_BODY), "{}", ran.stdout);
    assert_eq!(fixture.origin.requests(), 1);
}

#[test]
fn a_sandboxed_client_reaches_the_gate_and_the_gate_reaches_the_origin() {
    let fixture = Fixture::start();

    let health = run(
        sandboxed_curl(&fixture, &[], &fixture.gate_url("/airlock/health")),
        None,
    );
    assert_eq!(health.code, Some(0), "stderr: {}", health.stderr);
    assert_eq!(health.http_status(), "200");
    assert!(
        health.stdout.contains("policy-proxy"),
        "health should name the gate's mode: {}",
        health.stdout
    );
    assert_eq!(
        fixture.origin.connections(),
        0,
        "the health endpoint is answered by the gate and must not touch the origin"
    );

    let mut extra = POST_REQUEST.to_vec();
    extra.push(CLEAN_REQUEST);
    let forwarded = run(
        sandboxed_curl(&fixture, &extra, &fixture.gate_url("/v1/chat/completions")),
        None,
    );
    assert_eq!(forwarded.code, Some(0), "stderr: {}", forwarded.stderr);
    assert_eq!(forwarded.http_status(), "200");
    assert!(
        forwarded.stdout.contains(ORIGIN_BODY),
        "{}",
        forwarded.stdout
    );
    assert_eq!(
        fixture.origin.requests(),
        1,
        "the origin must see exactly the one request the gate forwarded"
    );
    let body = fixture
        .origin
        .bodies
        .recv_timeout(Duration::from_secs(2))
        .expect("the origin received the forwarded body");
    assert!(
        String::from_utf8_lossy(&body).contains("hello through the gate"),
        "the body the origin got is not the one the client sent"
    );
}

#[test]
fn a_sandboxed_client_cannot_reach_the_origin_directly() {
    let fixture = Fixture::start();
    assert_ne!(
        fixture.origin.address.port(),
        fixture.gate.address.port(),
        "the origin must be a different port from the gate"
    );

    let ran = run(sandboxed_curl(&fixture, &[], &fixture.origin.url()), None);

    assert_blocked_by_the_sandbox(&ran, "direct connect to a non-gate loopback port");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        fixture.origin.connections(),
        0,
        "the origin must not have seen a connection from the sandboxed client"
    );
}

#[test]
fn a_sandboxed_client_cannot_reach_an_address_outside_the_machine() {
    let fixture = Fixture::start();

    let ran = run(
        sandboxed_curl(&fixture, &[], &format!("http://{EXTERNAL_ADDRESS}:443/")),
        None,
    );

    assert_blocked_by_the_sandbox(&ran, "connect to an external address");
    assert!(
        ran.elapsed < Duration::from_secs(3),
        "the block should be immediate, not a timeout: {:?}",
        ran.elapsed
    );
}

#[test]
fn a_udp_datagram_from_the_sandbox_is_not_delivered() {
    let fixture = Fixture::start();
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind a UDP receiver");
    receiver
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("read timeout");
    let port = receiver
        .local_addr()
        .expect("udp address")
        .port()
        .to_string();

    let mut sandboxed = fixture.sandboxed(NC);
    sandboxed.args(["-u", "-w", "1", "127.0.0.1", &port]);
    run(sandboxed, Some("udp-from-sandbox\n"));
    let mut buffer = [0u8; 64];
    assert!(
        receiver.recv_from(&mut buffer).is_err(),
        "a datagram from the sandbox was delivered"
    );

    // Control: the same attempt without the sandbox is delivered, so the silence above is the
    // sandbox's doing.
    let mut control = Command::new(NC);
    control.args(["-u", "-w", "1", "127.0.0.1", &port]);
    run(control, Some("udp-from-control\n"));
    let (count, _) = receiver
        .recv_from(&mut buffer)
        .expect("the unsandboxed control datagram should arrive");
    assert!(String::from_utf8_lossy(&buffer[..count]).contains("udp-from-control"));
}

#[test]
fn a_unix_socket_connection_from_the_sandbox_is_not_delivered() {
    let fixture = Fixture::start();
    let directory = tempfile::tempdir().expect("tempdir");
    let socket = directory.path().join("u.sock");
    let listener = UnixListener::bind(&socket).expect("bind a unix socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");

    let mut sandboxed = fixture.sandboxed(NC);
    sandboxed.arg("-U").args(["-w", "1"]).arg(&socket);
    run(sandboxed, Some("unix-from-sandbox\n"));
    assert!(
        listener.accept().is_err(),
        "a unix-socket connection from the sandbox was accepted"
    );

    let mut control = Command::new(NC);
    control.arg("-U").args(["-w", "1"]).arg(&socket);
    run(control, Some("unix-from-control\n"));
    let (mut stream, _) = listener
        .accept()
        .expect("the unsandboxed control connection should arrive");
    stream.set_nonblocking(false).expect("blocking stream");
    // macOS refuses SO_RCVTIMEO (EINVAL) once the peer has closed, and `nc` has already exited
    // here, so the read below ends at EOF. The timeout is only a guard, so ignore that refusal.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut received = String::new();
    let _ = stream.read_to_string(&mut received);
    assert!(received.contains("unix-from-control"), "{received:?}");
}

#[test]
fn a_process_inside_the_sandbox_cannot_apply_a_looser_profile() {
    let fixture = Fixture::start();

    // Inside the sandbox, start another sandbox-exec with a permissive profile and ask it to
    // run curl against the origin. If the inner profile could replace the outer one, curl
    // would connect.
    let mut inner = fixture.sandboxed(SANDBOX_EXEC);
    inner
        .args(["-p", "(version 1)(allow default)", CURL])
        .args(["-sSv", "--noproxy", "*", "-m", "5"])
        .arg(fixture.origin.url());
    let ran = run(inner, None);

    assert_ne!(ran.code, Some(0), "the looser profile took effect");
    assert!(
        ran.stderr
            .contains("sandbox_apply: Operation not permitted"),
        "expected the nested profile to be refused, stderr: {}",
        ran.stderr
    );
    thread::sleep(Duration::from_millis(200));
    assert_eq!(fixture.origin.connections(), 0);
}
