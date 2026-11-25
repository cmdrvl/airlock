//! `airlock send`: verify an assembled prompt, then transmit exactly the bytes the manifest
//! hashes and record what crossed.
//!
//! The request is built from the prompt by the declared adapter, verified by the same code
//! `airlock verify` runs, and POSTed as the RFC 8785 canonical buffer that
//! `request_payload_hash` covers and `bytes_crossed` measures. The manifest therefore describes
//! what was written to the connection rather than what a caller said it would write.
//!
//! Only the request body is attested. Headers, including the credential, are not hashed or
//! recorded.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::adapter::{
    self, ANTHROPIC_MESSAGES_ADAPTER_NAME, GEMINI_GENERATE_CONTENT_ADAPTER_NAME,
    GENERIC_JSON_ADAPTER_NAME, OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME, OPENAI_RESPONSES_ADAPTER_NAME,
    TransportConfig, TransportDeclaration,
};
use crate::cli::{REFUSAL, SendArgs, VERIFY_PARTIAL, VERIFY_PASS};
use crate::commands::verify::{self, RequestToVerify, Verified};
use crate::hash::blake3_hash;
use crate::manifest::{AirlockManifest, Attestation, Transmission, TransmissionError};
use crate::refusal::RefusalEnvelope;
use crate::signing;
use crate::types::ClaimLevel;
use crate::witness::{self, WitnessInput, WitnessRecord};

const DEFAULT_TIMEOUT_SECONDS: u64 = 120;
const MAX_TIMEOUT_SECONDS: u64 = 900;
const DEFAULT_MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Header names a transport file may not set. Credentials come from the environment, never
/// from a file that gets committed; the rest are framing headers the client owns.
const RESERVED_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-goog-api-key",
    "api-key",
    "cookie",
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
];

pub fn run(args: SendArgs) -> u8 {
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
    args: SendArgs,
    witness_path: &Path,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> u8 {
    // Everything that can refuse runs before anything is written or sent, in the order a
    // caller can fix it: instant, signing key, paths, transport and credential, then inputs.
    let manifest_instant = match verify::manifest_instant("send") {
        Ok(instant) => instant,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let signing_key = match verify::resolve_signing_key(args.no_sign) {
        Ok(key) => key,
        Err(refusal) => return refusal.write_to(stdout),
    };
    if let Err(refusal) = check_distinct_paths(&args) {
        return refusal.write_to(stdout);
    }
    let (transport, transport_hash) = match load_transport(&args.transport) {
        Ok(loaded) => loaded,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let endpoint = match parse_endpoint(&transport.url) {
        Ok(endpoint) => endpoint,
        Err(reason) => {
            return invalid_transport(&args.transport, "url", reason).write_to(stdout);
        }
    };
    let api_key = match load_api_key(&transport.api_key_env) {
        Ok(key) => key,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let headers = match request_headers(&transport, &api_key, &args.transport) {
        Ok(headers) => headers,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let timeout = match bounded(
        transport.timeout_seconds,
        DEFAULT_TIMEOUT_SECONDS,
        MAX_TIMEOUT_SECONDS,
        "timeout_seconds",
        &args.transport,
    ) {
        Ok(seconds) => Duration::from_secs(seconds),
        Err(refusal) => return refusal.write_to(stdout),
    };
    let max_response_bytes = match bounded(
        transport.max_response_bytes,
        DEFAULT_MAX_RESPONSE_BYTES,
        MAX_MAX_RESPONSE_BYTES,
        "max_response_bytes",
        &args.transport,
    ) {
        Ok(bytes) => bytes,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let config = match transport.transport_config(&args.transport) {
        Ok(config) => config,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let inputs = match verify::load_inputs(&args.policy, &args.prompt, &args.provenance) {
        Ok(inputs) => inputs,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let declaration = transport.declaration();
    // An explicitly named adapter ignores the request it is handed, so it can be chosen before
    // the request exists; `wrap` then builds the request the same adapter will verify.
    let request_value = match adapter::select(&Value::Null, Some(&declaration))
        .and_then(|adapter| adapter.wrap(&inputs.prompt_value, &config))
    {
        Ok(request) => request,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let verified = match verify::verify_request(
        &RequestToVerify {
            inputs: &inputs,
            provenance_path: &args.provenance,
            request_value: &request_value,
            replay_ref: args.request_out.display().to_string(),
            not_crossed_path: args.not_crossed.as_deref(),
            timestamp: manifest_instant.to_rfc3339(),
        },
        |request| adapter::select(request, Some(&declaration)),
    ) {
        Ok(verified) => verified,
        Err(refusal) => return refusal.write_to(stdout),
    };
    let Verified {
        mut manifest,
        not_crossed,
        canonical_request,
    } = verified;

    let witness_inputs = {
        let mut witness_inputs = vec![
            WitnessRecord::input(
                args.policy.display().to_string(),
                inputs.policy_hash.clone(),
            ),
            WitnessRecord::input(
                args.prompt.display().to_string(),
                manifest.prompt_payload_hash.clone(),
            ),
            WitnessRecord::input(
                args.provenance.display().to_string(),
                manifest.prompt_provenance_hash.clone(),
            ),
            WitnessRecord::input(args.transport.display().to_string(), transport_hash.clone()),
            WitnessRecord::input(
                args.request_out.display().to_string(),
                manifest.request_payload_hash.clone(),
            ),
        ];
        if let (Some(path), Some(loaded)) = (args.not_crossed.as_deref(), &not_crossed) {
            witness_inputs.push(WitnessRecord::input(
                path.display().to_string(),
                loaded.content_hash.clone(),
            ));
        }
        witness_inputs
    };

    // The bytes that will be sent are written down before anything else happens, so a
    // manifest's replay_ref names a real file whatever follows.
    if let Err(error) = write_private(&args.request_out, canonical_request.as_bytes()) {
        return output_failed("request", &args.request_out, &error).write_to(stdout);
    }

    let required = args.require_claim.unwrap_or(ClaimLevel::RawDocumentAbsent);
    let request_bytes = canonical_request.len() as u64;
    let unsent = Transmission {
        sent: false,
        endpoint_host: endpoint.host.clone(),
        request_bytes,
        request_hash: manifest.request_payload_hash.clone(),
        sent_at: None,
        latency_ms: None,
        response_status: None,
        response_hash: None,
        response_bytes: None,
        error: None,
    };
    let achieved_claim = manifest.achieved_claim;
    let context = Context {
        adapter: manifest.adapter.clone(),
        endpoint_host: endpoint.host.clone(),
        required,
        achieved_claim,
        witness_inputs,
        witness_path,
        enabled: !args.no_witness,
    };

    // A request that does not reach the required claim is recorded and not sent.
    if achieved_claim < required {
        let transmission = Transmission {
            error: Some(TransmissionError::ClaimBelowRequired),
            ..unsent
        };
        if let Err(refusal) = record_manifest(
            &mut manifest,
            transmission.clone(),
            signing_key.as_ref(),
            &args.out,
        ) {
            return refusal.write_to(stdout);
        }
        let manifest_json = manifest.to_canonical_json();
        let _ = stdout.write_all(manifest_json.as_bytes());
        let _ = stdout.flush();
        return context.append(
            "NOT_SENT",
            VERIFY_PARTIAL,
            &transmission,
            blake3_hash(manifest_json.as_bytes()),
            manifest_json.len(),
            stderr,
        );
    }

    // Leave a record that the request is about to go, so a process killed during a model call
    // that takes tens of seconds does not leave a manifest that says nothing happened. The
    // pre-send manifest carries no transmission: absent says nothing about whether it was sent.
    if let Some(key) = &signing_key
        && let Err(error) = signing::sign(&mut manifest, key)
    {
        return error.refusal().write_to(stdout);
    }
    if let Err(error) = manifest.write_to(&args.out) {
        return output_failed("manifest", &args.out, &error).write_to(stdout);
    }
    let pre_send_json = manifest.to_canonical_json();
    context.append(
        "SENDING",
        VERIFY_PASS,
        &unsent,
        blake3_hash(pre_send_json.as_bytes()),
        pre_send_json.len(),
        stderr,
    );

    let delivered = deliver(
        &Delivery {
            url: &endpoint.url,
            headers: &headers,
            timeout,
            max_response_bytes,
            secret: api_key.expose(),
        },
        canonical_request.as_bytes(),
        unsent,
    );
    let Delivered {
        transmission,
        response_body,
        reason,
    } = delivered;

    // What came back, then the record of it. The record is written even if the response file
    // cannot be: the exchange happened either way.
    let response_written = match (&args.response_out, &response_body) {
        (Some(path), Some(body)) => {
            Some(write_private(path, body).map_err(|error| output_failed("response", path, &error)))
        }
        _ => None,
    };
    let manifest_written = record_manifest(
        &mut manifest,
        transmission.clone(),
        signing_key.as_ref(),
        &args.out,
    );

    let (exit_code, outcome, printed) = match (&manifest_written, &response_written) {
        (Err(refusal), _) | (_, Some(Err(refusal))) => {
            let mut refusal = refusal.clone();
            // The exchange happened and the caller needs to know what it was. The ledger says
            // SENT when it completed: the exit code, not the outcome, carries the failure to
            // write the record of it.
            refusal.refusal.detail["sent"] = json!(transmission.sent);
            refusal.refusal.detail["transmission"] = transmission_value(&transmission);
            (
                REFUSAL,
                exchange_outcome(&transmission),
                refusal.to_canonical_json(),
            )
        }
        _ if transmission.error.is_some() => {
            let refusal = transport_refusal(
                &transmission,
                reason.as_deref().unwrap_or("no further detail"),
                &args.out,
            );
            (
                REFUSAL,
                exchange_outcome(&transmission),
                refusal.to_canonical_json(),
            )
        }
        _ => (VERIFY_PASS, "SENT", manifest.to_canonical_json()),
    };
    let _ = stdout.write_all(printed.as_bytes());
    let _ = stdout.flush();
    context.append(
        outcome,
        exit_code,
        &transmission,
        blake3_hash(printed.as_bytes()),
        printed.len(),
        stderr,
    )
}

/// What the witness records for every stage of one send.
struct Context<'a> {
    adapter: String,
    endpoint_host: String,
    required: ClaimLevel,
    achieved_claim: ClaimLevel,
    witness_inputs: Vec<WitnessInput>,
    witness_path: &'a Path,
    enabled: bool,
}

impl Context<'_> {
    /// Append one witness record and return `exit_code` unchanged: a ledger problem is a
    /// warning and never changes the outcome of a send.
    fn append(
        &self,
        outcome: &str,
        exit_code: u8,
        transmission: &Transmission,
        stdout_hash: String,
        stdout_bytes: usize,
        stderr: &mut impl Write,
    ) -> u8 {
        let record = WitnessRecord::new(
            "send",
            outcome,
            exit_code,
            self.witness_inputs.clone(),
            json!({
                "adapter": self.adapter,
                "endpoint_host": self.endpoint_host,
                "require_claim": self.required,
                "achieved_claim": self.achieved_claim,
                "transmission": transmission_value(transmission),
            }),
            stdout_hash,
            stdout_bytes,
        );
        witness::maybe_append_witness_at(
            self.witness_path,
            &record,
            self.enabled,
            exit_code,
            stderr,
        )
    }
}

fn transmission_value(transmission: &Transmission) -> Value {
    serde_json::to_value(transmission).expect("a transmission always serializes")
}

/// The witness outcome for what the exchange itself did: `SENT` for a complete response,
/// `SEND_FAILED` for a request that may have been sent and got none, `NOT_SENT` for one that
/// was not sent.
fn exchange_outcome(transmission: &Transmission) -> &'static str {
    match (transmission.sent, transmission.error) {
        (true, None) => "SENT",
        (true, Some(_)) => "SEND_FAILED",
        (false, _) => "NOT_SENT",
    }
}

/// Stamp the manifest with what `send` did and write it, replacing the pre-send manifest.
/// `attestation` is `transmitted` exactly when the request was sent.
fn record_manifest(
    manifest: &mut AirlockManifest,
    transmission: Transmission,
    key: Option<&ed25519_dalek::SigningKey>,
    out: &Path,
) -> Result<(), RefusalEnvelope> {
    manifest.attestation = Some(if transmission.sent {
        Attestation::Transmitted
    } else {
        Attestation::SelfAttested
    });
    manifest.transmission = Some(transmission);
    if let Some(key) = key {
        signing::sign(manifest, key).map_err(|error| error.refusal())?;
    }
    manifest
        .write_to(out)
        .map_err(|error| output_failed("manifest", out, &error))
}

fn output_failed(what: &str, path: &Path, error: &io::Error) -> RefusalEnvelope {
    RefusalEnvelope::bad_input(
        format!("failed to write {what} output"),
        json!({
            "error": error.to_string(),
            "path": path.display().to_string(),
        }),
    )
}

fn transport_refusal(
    transmission: &Transmission,
    reason: &str,
    manifest: &Path,
) -> RefusalEnvelope {
    let error = transmission.error.map(TransmissionError::as_str);
    let message = if transmission.sent {
        "the request may have reached the endpoint and no complete response was received"
    } else {
        "the request was not sent"
    };
    RefusalEnvelope::transport(
        message,
        json!({
            "sent": transmission.sent,
            "error": error,
            "reason": reason,
            "endpoint_host": transmission.endpoint_host,
            "request_hash": transmission.request_hash,
            "response_status": transmission.response_status,
            "manifest": manifest.display().to_string(),
        }),
    )
}

// ---------------------------------------------------------------------------------------
// Transport declaration
// ---------------------------------------------------------------------------------------

/// The `--transport` file of `send`. Unlike the declaration `verify` reads, this one says where
/// to send the request and which environment variable holds the credential.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendTransport {
    adapter: String,
    model: String,
    /// The full endpoint URL, path included.
    url: String,
    /// Name of the environment variable that holds the API key.
    api_key_env: String,
    /// `temperature`, `max_tokens` and `response_format` are typed; every other member is
    /// passed to the adapter as an additional vendor parameter.
    #[serde(default)]
    params: Map<String, Value>,
    /// Extra non-secret request headers.
    #[serde(default)]
    headers: BTreeMap<String, String>,
    /// Header that carries the key, overriding the adapter's default. The value is
    /// `Bearer <key>` for `authorization` and the bare key for any other name.
    auth_header: Option<String>,
    timeout_seconds: Option<u64>,
    max_response_bytes: Option<u64>,
    // `generic_json` only, as in the declaration `verify` reads.
    messages_pointer: Option<String>,
    system_pointer: Option<String>,
    model_pointer: Option<String>,
    transport_keys: Option<Vec<String>>,
}

impl SendTransport {
    fn declaration(&self) -> TransportDeclaration {
        TransportDeclaration {
            adapter: Some(self.adapter.clone()),
            messages_pointer: self.messages_pointer.clone(),
            system_pointer: self.system_pointer.clone(),
            model_pointer: self.model_pointer.clone(),
            transport_keys: self.transport_keys.clone(),
        }
    }

    fn transport_config(&self, path: &Path) -> Result<TransportConfig, RefusalEnvelope> {
        let mut params = self.params.clone();
        let temperature = match params.remove("temperature") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_f64().ok_or_else(|| {
                invalid_transport(path, "params.temperature", "must be a number".to_owned())
            })?),
        };
        let max_tokens = match params.remove("max_tokens") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .and_then(|number| u32::try_from(number).ok())
                    .ok_or_else(|| {
                        invalid_transport(
                            path,
                            "params.max_tokens",
                            "must be a non-negative integer".to_owned(),
                        )
                    })?,
            ),
        };
        let response_format = match params.remove("response_format") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value),
        };
        let mut config = TransportConfig::new(self.model.clone());
        config.temperature = temperature;
        config.max_tokens = max_tokens;
        config.response_format = response_format;
        config.additional_params = if params.is_empty() {
            None
        } else {
            Some(params)
        };
        Ok(config)
    }
}

fn invalid_transport(path: &Path, field: &str, reason: String) -> RefusalEnvelope {
    // The reason never quotes the value: a URL with credentials in it is exactly what this
    // refusal exists to turn away, and a refusal is printed.
    RefusalEnvelope::bad_input(
        "send transport declaration is invalid",
        json!({
            "path": path.display().to_string(),
            "field": field,
            "reason": reason,
        }),
    )
}

fn load_transport(path: &Path) -> Result<(SendTransport, String), RefusalEnvelope> {
    let bytes = std::fs::read(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            RefusalEnvelope::missing_file(path.display().to_string())
        } else {
            RefusalEnvelope::bad_input(
                "failed to read send transport declaration",
                json!({"error": error.to_string(), "path": path.display().to_string()}),
            )
        }
    })?;
    let transport = serde_json::from_slice::<SendTransport>(&bytes).map_err(|error| {
        RefusalEnvelope::bad_input(
            "send transport declaration is not a valid send transport JSON object",
            json!({"error": error.to_string(), "path": path.display().to_string()}),
        )
    })?;
    let hash = blake3_hash(&bytes);
    Ok((transport, hash))
}

fn bounded(
    value: Option<u64>,
    default: u64,
    max: u64,
    field: &str,
    path: &Path,
) -> Result<u64, RefusalEnvelope> {
    match value {
        None => Ok(default),
        Some(value) if (1..=max).contains(&value) => Ok(value),
        Some(_) => Err(invalid_transport(
            path,
            field,
            format!("must be between 1 and {max}"),
        )),
    }
}

// ---------------------------------------------------------------------------------------
// Endpoint, credential and headers
// ---------------------------------------------------------------------------------------

struct Endpoint {
    url: String,
    /// Host, and port when it is not the scheme's default. Never the path, query or
    /// credentials: this is what the manifest records.
    host: String,
}

/// A usable endpoint, or why not. The reason never quotes the URL.
fn parse_endpoint(raw: &str) -> Result<Endpoint, String> {
    // `Uri` rejects most malformed input, but it accepts a query and a trailing `?`, so those
    // are checked on the raw text.
    if raw.contains('?') || raw.contains('#') {
        return Err("must not contain a query string or fragment".to_owned());
    }
    let uri: ureq::http::Uri = raw
        .parse()
        .map_err(|_| "is not a valid absolute URL".to_owned())?;
    let scheme = uri.scheme_str().unwrap_or_default().to_ascii_lowercase();
    let authority = uri
        .authority()
        .ok_or_else(|| "must be an absolute URL with a host".to_owned())?;
    if authority.as_str().contains('@') {
        return Err("must not contain credentials: the key comes from api_key_env".to_owned());
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return Err("must be an absolute URL with a host".to_owned());
    }
    match scheme.as_str() {
        "https" => {}
        "http" if is_loopback(&host) => {}
        "http" => {
            return Err(
                "plain http is allowed only to a loopback host: the request would cross the network unencrypted"
                    .to_owned(),
            );
        }
        _ => return Err("scheme must be https".to_owned()),
    }
    let default_port = if scheme == "https" { 443 } else { 80 };
    let label = match authority.port_u16() {
        Some(port) if port != default_port => format!("{host}:{port}"),
        _ => host,
    };
    Ok(Endpoint {
        url: raw.to_owned(),
        host: label,
    })
}

fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare == "localhost"
        || bare
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// The credential. It is only ever put in a request header: `Debug` hides it, and the text of
/// every error that leaves this module passes through [`redact`].
struct ApiKey(String);

impl ApiKey {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

fn load_api_key(env_name: &str) -> Result<ApiKey, RefusalEnvelope> {
    let valid_name = !env_name.is_empty()
        && env_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_');
    if !valid_name {
        return Err(RefusalEnvelope::bad_input(
            "api_key_env must name an environment variable (letters, digits and underscores)",
            json!({"field": "api_key_env"}),
        ));
    }
    let detail = json!({"env": env_name});
    let value = std::env::var_os(env_name).ok_or_else(|| {
        RefusalEnvelope::bad_input(
            "the environment variable named by api_key_env is not set",
            detail.clone(),
        )
    })?;
    let value = value.into_string().map_err(|_| {
        RefusalEnvelope::bad_input(
            "the environment variable named by api_key_env is not valid UTF-8",
            detail.clone(),
        )
    })?;
    if value.is_empty() {
        return Err(RefusalEnvelope::bad_input(
            "the environment variable named by api_key_env is empty",
            detail,
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(RefusalEnvelope::bad_input(
            "the environment variable named by api_key_env contains characters not allowed in an HTTP header",
            detail,
        ));
    }
    Ok(ApiKey(value))
}

/// The headers sent besides `content-type`: the adapter's authentication, its fixed version
/// header where it has one, and whatever non-secret headers the transport file adds.
fn request_headers(
    transport: &SendTransport,
    key: &ApiKey,
    path: &Path,
) -> Result<Vec<(String, String)>, RefusalEnvelope> {
    let auth_name = match (transport.auth_header.as_deref(), transport.adapter.as_str()) {
        (Some(name), _) => name.to_owned(),
        (None, OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME | OPENAI_RESPONSES_ADAPTER_NAME) => {
            "authorization".to_owned()
        }
        (None, ANTHROPIC_MESSAGES_ADAPTER_NAME) => "x-api-key".to_owned(),
        (None, GEMINI_GENERATE_CONTENT_ADAPTER_NAME) => "x-goog-api-key".to_owned(),
        (None, GENERIC_JSON_ADAPTER_NAME) => {
            return Err(invalid_transport(
                path,
                "auth_header",
                "the generic_json adapter has no default authentication header: name one"
                    .to_owned(),
            ));
        }
        // An unknown adapter is refused by adapter::select with the list of valid names.
        (None, _) => "authorization".to_owned(),
    };
    check_header_name(&auth_name)
        .map_err(|reason| invalid_transport(path, "auth_header", reason))?;
    let auth_value = if auth_name.eq_ignore_ascii_case("authorization") {
        format!("Bearer {}", key.expose())
    } else {
        key.expose().to_owned()
    };

    let mut headers = vec![(auth_name.clone(), auth_value)];
    let mut names = vec![auth_name.to_ascii_lowercase()];
    for (name, value) in &transport.headers {
        let lower = name.to_ascii_lowercase();
        check_header_name(name).map_err(|reason| invalid_transport(path, "headers", reason))?;
        if RESERVED_HEADERS.contains(&lower.as_str()) {
            return Err(invalid_transport(
                path,
                "headers",
                format!("{lower} may not be set here: credentials come from api_key_env"),
            ));
        }
        if names.contains(&lower) {
            return Err(invalid_transport(
                path,
                "headers",
                format!("{lower} is set twice"),
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(invalid_transport(
                path,
                "headers",
                format!("the value of {lower} contains control characters"),
            ));
        }
        names.push(lower);
        headers.push((name.clone(), value.clone()));
    }
    if transport.adapter == ANTHROPIC_MESSAGES_ADAPTER_NAME
        && !names.iter().any(|name| name == "anthropic-version")
    {
        headers.push(("anthropic-version".to_owned(), ANTHROPIC_VERSION.to_owned()));
    }
    Ok(headers)
}

fn check_header_name(name: &str) -> Result<(), String> {
    ureq::http::HeaderName::from_bytes(name.as_bytes())
        .map(|_| ())
        .map_err(|_| "is not a valid HTTP header name".to_owned())
}

/// Refuse output paths that would overwrite an input or each other.
fn check_distinct_paths(args: &SendArgs) -> Result<(), RefusalEnvelope> {
    let mut outputs: Vec<(&str, &Path)> = vec![
        ("--out", args.out.as_path()),
        ("--request-out", args.request_out.as_path()),
    ];
    if let Some(path) = args.response_out.as_deref() {
        outputs.push(("--response-out", path));
    }
    let mut inputs: Vec<(&str, &Path)> = vec![
        ("--policy", args.policy.as_path()),
        ("--prompt", args.prompt.as_path()),
        ("--provenance", args.provenance.as_path()),
        ("--transport", args.transport.as_path()),
    ];
    if let Some(path) = args.not_crossed.as_deref() {
        inputs.push(("--not-crossed", path));
    }
    for (index, (name, path)) in outputs.iter().enumerate() {
        let identity = path_identity(path);
        let clash = outputs[index + 1..]
            .iter()
            .chain(inputs.iter())
            .find(|(_, other)| path_identity(other) == identity);
        if let Some((other_name, _)) = clash {
            return Err(RefusalEnvelope::bad_input(
                format!("{name} and {other_name} name the same file"),
                json!({"path": path.display().to_string()}),
            ));
        }
    }
    Ok(())
}

fn path_identity(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    // Not created yet: resolve the directory it will be created in.
    match (std::path::absolute(path), path.file_name()) {
        (Ok(absolute), Some(name)) => absolute
            .parent()
            .and_then(|parent| std::fs::canonicalize(parent).ok())
            .map(|parent| parent.join(name))
            .unwrap_or(absolute),
        (Ok(absolute), None) => absolute,
        (Err(_), _) => path.to_path_buf(),
    }
}

/// Write `bytes` to `path` through a temporary file in the same directory, owner-only, so a
/// reader never sees a partial file and the request and response bodies are not world-readable.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("airlock_output");
    for attempt in 0..16 {
        let temp = parent.join(format!(".{name}.{}.{attempt}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp) {
            Ok(mut file) => {
                let written = file.write_all(bytes).and_then(|()| file.sync_all());
                drop(file);
                if let Err(error) = written {
                    let _ = std::fs::remove_file(&temp);
                    return Err(error);
                }
                return std::fs::rename(&temp, path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a temporary file",
    ))
}

// ---------------------------------------------------------------------------------------
// The exchange
// ---------------------------------------------------------------------------------------

struct Delivery<'a> {
    url: &'a str,
    headers: &'a [(String, String)],
    timeout: Duration,
    max_response_bytes: u64,
    /// Scrubbed from any error text before it leaves this function.
    secret: &'a str,
}

struct Delivered {
    transmission: Transmission,
    /// The response body, only when a complete response was received.
    response_body: Option<Vec<u8>>,
    /// Redacted error text, when there is no complete response.
    reason: Option<String>,
}

/// POST `body` and read the response. `unsent` is the transmission as it stands before
/// anything is attempted; the returned transmission is `unsent` with the outcome filled in.
///
/// Redirects are not followed: following one would send the body to a host the transport file
/// did not name. A 3xx is recorded as the response it is.
fn deliver(delivery: &Delivery<'_>, body: &[u8], unsent: Transmission) -> Delivered {
    let timeout = delivery.timeout;
    // No global timeout: when it expires during a connect it is indistinguishable from a
    // stall after the body was written, and the first means nothing was sent. Each phase has
    // its own bound instead.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_resolve(Some(timeout))
        .timeout_connect(Some(timeout))
        .timeout_send_request(Some(timeout))
        .timeout_send_body(Some(timeout))
        .timeout_recv_response(Some(timeout))
        .timeout_recv_body(Some(timeout))
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .build()
        .into();
    let mut request = agent
        .post(delivery.url)
        .header("content-type", "application/json");
    for (name, value) in delivery.headers {
        request = request.header(name.as_str(), value.as_str());
    }

    let sent_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let started = Instant::now();
    let response = match request.send(body) {
        Ok(response) => response,
        Err(error) => {
            let (sent, code) = classify(&error);
            return failed(
                unsent,
                sent,
                code,
                Some(sent_at),
                started,
                redact(&error.to_string(), delivery.secret),
            );
        }
    };

    let status = response.status().as_u16();
    if !(100..=599).contains(&status) {
        return failed(
            unsent,
            true,
            TransmissionError::TransportError,
            Some(sent_at),
            started,
            "the response status is outside 100-599".to_owned(),
        );
    }
    let mut reader = response.into_body().into_reader();
    let mut hasher = blake3::Hasher::new();
    let mut received: Vec<u8> = Vec::new();
    let mut too_large = false;
    let mut buffer = vec![0u8; 64 * 1024];
    let read_error = loop {
        match reader.read(&mut buffer) {
            Ok(0) => break None,
            Ok(count) => {
                let room = (delivery.max_response_bytes - received.len() as u64) as usize;
                let take = count.min(room);
                received.extend_from_slice(&buffer[..take]);
                hasher.update(&buffer[..take]);
                if count > room {
                    too_large = true;
                    break None;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => break Some(error),
        }
    };

    if let Some(error) = read_error {
        let code = if is_timeout(&error) {
            TransmissionError::ResponseTimeout
        } else {
            TransmissionError::TransportError
        };
        return failed(
            unsent,
            true,
            code,
            Some(sent_at),
            started,
            redact(
                &format!("reading the response body failed: {error}"),
                delivery.secret,
            ),
        );
    }

    let latency_ms = elapsed_ms(started);
    let transmission = Transmission {
        sent: true,
        sent_at: Some(sent_at),
        latency_ms: Some(latency_ms),
        response_status: Some(status),
        response_hash: Some(format!("blake3:{}", hasher.finalize().to_hex())),
        response_bytes: Some(received.len() as u64),
        error: too_large.then_some(TransmissionError::ResponseTooLarge),
        ..unsent
    };
    if too_large {
        return Delivered {
            transmission,
            response_body: None,
            reason: Some(format!(
                "the response is larger than max_response_bytes ({}); it was not read to the end",
                delivery.max_response_bytes
            )),
        };
    }
    Delivered {
        transmission,
        response_body: Some(received),
        reason: None,
    }
}

fn failed(
    unsent: Transmission,
    sent: bool,
    code: TransmissionError,
    sent_at: Option<String>,
    started: Instant,
    reason: String,
) -> Delivered {
    let transmission = Transmission {
        sent,
        sent_at: sent.then_some(sent_at).flatten(),
        latency_ms: sent.then(|| elapsed_ms(started)),
        error: Some(code),
        ..unsent
    };
    Delivered {
        transmission,
        response_body: None,
        reason: Some(reason),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) || error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ureq::Error>())
        .is_some_and(|inner| matches!(inner, ureq::Error::Timeout(_)))
}

/// Whether the request body may have been written, and the code that says why the exchange
/// failed. `false` only where the connection was never established or the request could not
/// even be formed; anything after that point cannot rule the write out, so it reports `true`:
/// the manifest over-reports what may have crossed rather than under-reports it.
fn classify(error: &ureq::Error) -> (bool, TransmissionError) {
    use ureq::Error as E;
    match error {
        E::BadUri(_)
        | E::Http(_)
        | E::InvalidProxyUrl
        | E::HostNotFound
        | E::ConnectionFailed
        | E::RequireHttpsOnly(_)
        | E::TlsRequired
        | E::ConnectProxyFailed(_)
        | E::Timeout(ureq::Timeout::Resolve | ureq::Timeout::Connect) => {
            (false, TransmissionError::ConnectFailed)
        }
        // The connector returns these only when the connect itself failed.
        E::Io(io_error)
            if matches!(
                io_error.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::HostUnreachable
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::NetworkDown
                    | io::ErrorKind::AddrNotAvailable
            ) =>
        {
            (false, TransmissionError::ConnectFailed)
        }
        E::Timeout(_) => (true, TransmissionError::ResponseTimeout),
        E::Io(io_error) if is_timeout(io_error) => (true, TransmissionError::ResponseTimeout),
        _ => (true, TransmissionError::TransportError),
    }
}

/// `text` with every occurrence of `secret` replaced.
fn redact(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_owned();
    }
    text.replace(secret, "[redacted]")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(raw: &str) -> Result<(String, String), String> {
        parse_endpoint(raw).map(|endpoint| (endpoint.url, endpoint.host))
    }

    #[test]
    fn https_endpoints_are_accepted_and_the_host_label_drops_the_path_and_default_port() {
        for (raw, host) in [
            (
                "https://api.openai.com/v1/chat/completions",
                "api.openai.com",
            ),
            ("https://API.Example.com:443/x", "api.example.com"),
            ("https://example.com:8443/x", "example.com:8443"),
            ("https://example.com", "example.com"),
        ] {
            assert_eq!(endpoint(raw).unwrap().1, host, "{raw}");
        }
    }

    #[test]
    fn plain_http_is_accepted_only_to_a_loopback_host() {
        for raw in [
            "http://127.0.0.1:8080/v1",
            "http://localhost/v1",
            "http://LOCALHOST:9/v1",
            "http://[::1]:8080/v1",
            "http://127.1.2.3/v1",
        ] {
            assert!(endpoint(raw).is_ok(), "{raw} should be accepted");
        }
        for raw in [
            "http://example.com/v1",
            "http://10.0.0.5/v1",
            "http://localhost.example.com/v1",
            "http://192.168.1.1:8080/v1",
        ] {
            let reason = endpoint(raw).unwrap_err();
            assert!(reason.contains("loopback"), "{raw}: {reason}");
        }
    }

    #[test]
    fn urls_that_could_carry_a_secret_or_redirect_the_body_are_refused() {
        for raw in [
            "https://user:pass@example.com/v1",
            "https://user@example.com/v1",
            "https://example.com/v1?key=abc",
            "https://example.com/v1?",
            "https://example.com/v1#frag",
            "ftp://example.com/v1",
            "file:///etc/passwd",
            "example.com/v1",
            "/v1/chat",
            "",
            "https://exa mple.com/",
        ] {
            assert!(endpoint(raw).is_err(), "{raw:?} should be refused");
        }
    }

    #[test]
    fn a_refused_url_is_never_quoted_in_the_reason() {
        for raw in [
            "https://user:sekrit-pass@example.com/v1",
            "https://example.com/v1?key=sekrit-key",
            "http://sekrit-host.example.com/v1",
        ] {
            let reason = endpoint(raw).unwrap_err();
            assert!(!reason.contains("sekrit"), "{reason}");
        }
    }

    fn io_error(kind: io::ErrorKind) -> ureq::Error {
        ureq::Error::Io(io::Error::new(kind, "x"))
    }

    #[test]
    fn errors_before_a_connection_exists_are_not_sent() {
        let not_sent = [
            ureq::Error::BadUri("x".to_owned()),
            ureq::Error::HostNotFound,
            ureq::Error::ConnectionFailed,
            ureq::Error::InvalidProxyUrl,
            ureq::Error::TlsRequired,
            ureq::Error::RequireHttpsOnly("x".to_owned()),
            ureq::Error::ConnectProxyFailed("x".to_owned()),
            ureq::Error::Timeout(ureq::Timeout::Resolve),
            ureq::Error::Timeout(ureq::Timeout::Connect),
            io_error(io::ErrorKind::ConnectionRefused),
            io_error(io::ErrorKind::HostUnreachable),
            io_error(io::ErrorKind::NetworkUnreachable),
            io_error(io::ErrorKind::NetworkDown),
            io_error(io::ErrorKind::AddrNotAvailable),
        ];
        for error in not_sent {
            assert_eq!(
                classify(&error),
                (false, TransmissionError::ConnectFailed),
                "{error:?}"
            );
        }
    }

    #[test]
    fn errors_that_cannot_rule_the_write_out_are_sent() {
        let timeouts = [
            ureq::Error::Timeout(ureq::Timeout::Global),
            ureq::Error::Timeout(ureq::Timeout::PerCall),
            ureq::Error::Timeout(ureq::Timeout::SendBody),
            ureq::Error::Timeout(ureq::Timeout::RecvResponse),
            ureq::Error::Timeout(ureq::Timeout::RecvBody),
            io_error(io::ErrorKind::TimedOut),
        ];
        for error in timeouts {
            assert_eq!(
                classify(&error),
                (true, TransmissionError::ResponseTimeout),
                "{error:?}"
            );
        }
        let others = [
            io_error(io::ErrorKind::ConnectionReset),
            io_error(io::ErrorKind::BrokenPipe),
            io_error(io::ErrorKind::UnexpectedEof),
            // A permission error can come from a connect or from a write: it cannot rule the
            // write out.
            io_error(io::ErrorKind::PermissionDenied),
            ureq::Error::Tls("x"),
            ureq::Error::BodyStalled,
            ureq::Error::LargeResponseHeader(1, 2),
        ];
        for error in others {
            assert_eq!(
                classify(&error),
                (true, TransmissionError::TransportError),
                "{error:?}"
            );
        }
    }

    #[test]
    fn the_key_is_hidden_from_debug_and_scrubbed_from_error_text() {
        let key = ApiKey("sk-sekrit-123".to_owned());
        assert!(!format!("{key:?}").contains("sekrit"));
        assert_eq!(
            redact(
                "connect to sk-sekrit-123 failed: sk-sekrit-123",
                key.expose()
            ),
            "connect to [redacted] failed: [redacted]"
        );
        assert_eq!(redact("unchanged", ""), "unchanged");
    }

    fn transport(adapter: &str) -> SendTransport {
        SendTransport {
            adapter: adapter.to_owned(),
            model: "m".to_owned(),
            url: "https://example.com/v1".to_owned(),
            api_key_env: "K".to_owned(),
            params: Map::new(),
            headers: BTreeMap::new(),
            auth_header: None,
            timeout_seconds: None,
            max_response_bytes: None,
            messages_pointer: None,
            system_pointer: None,
            model_pointer: None,
            transport_keys: None,
        }
    }

    fn headers_for(transport: &SendTransport) -> Result<Vec<(String, String)>, RefusalEnvelope> {
        request_headers(transport, &ApiKey("KEY".to_owned()), Path::new("t.json"))
    }

    #[test]
    fn each_adapter_authenticates_the_way_its_vendor_expects() {
        assert_eq!(
            headers_for(&transport(OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME)).unwrap(),
            vec![("authorization".to_owned(), "Bearer KEY".to_owned())]
        );
        assert_eq!(
            headers_for(&transport(OPENAI_RESPONSES_ADAPTER_NAME)).unwrap(),
            vec![("authorization".to_owned(), "Bearer KEY".to_owned())]
        );
        assert_eq!(
            headers_for(&transport(ANTHROPIC_MESSAGES_ADAPTER_NAME)).unwrap(),
            vec![
                ("x-api-key".to_owned(), "KEY".to_owned()),
                ("anthropic-version".to_owned(), ANTHROPIC_VERSION.to_owned()),
            ]
        );
        assert_eq!(
            headers_for(&transport(GEMINI_GENERATE_CONTENT_ADAPTER_NAME)).unwrap(),
            vec![("x-goog-api-key".to_owned(), "KEY".to_owned())]
        );
    }

    #[test]
    fn an_explicit_anthropic_version_replaces_the_default() {
        let mut declared = transport(ANTHROPIC_MESSAGES_ADAPTER_NAME);
        declared
            .headers
            .insert("Anthropic-Version".to_owned(), "2099-01-01".to_owned());
        let headers = headers_for(&declared).unwrap();
        assert_eq!(
            headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("anthropic-version"))
                .collect::<Vec<_>>(),
            vec![&("Anthropic-Version".to_owned(), "2099-01-01".to_owned())]
        );
    }

    #[test]
    fn generic_json_needs_an_explicit_auth_header_and_the_value_follows_its_name() {
        assert!(headers_for(&transport(GENERIC_JSON_ADAPTER_NAME)).is_err());

        let mut custom = transport(GENERIC_JSON_ADAPTER_NAME);
        custom.auth_header = Some("x-custom-key".to_owned());
        assert_eq!(
            headers_for(&custom).unwrap(),
            vec![("x-custom-key".to_owned(), "KEY".to_owned())]
        );

        let mut bearer = transport(GENERIC_JSON_ADAPTER_NAME);
        bearer.auth_header = Some("Authorization".to_owned());
        assert_eq!(
            headers_for(&bearer).unwrap(),
            vec![("Authorization".to_owned(), "Bearer KEY".to_owned())]
        );
    }

    #[test]
    fn a_transport_file_cannot_carry_credentials_or_framing_headers() {
        for name in [
            "Authorization",
            "x-api-key",
            "X-Goog-Api-Key",
            "api-key",
            "Cookie",
            "proxy-authorization",
            "Host",
            "Content-Length",
            "content-type",
            "Transfer-Encoding",
            "Connection",
        ] {
            let mut declared = transport(OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME);
            declared.headers.insert(name.to_owned(), "v".to_owned());
            assert!(headers_for(&declared).is_err(), "{name} should be refused");
        }

        let mut duplicate = transport(OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME);
        duplicate.auth_header = Some("x-custom".to_owned());
        duplicate
            .headers
            .insert("X-Custom".to_owned(), "v".to_owned());
        assert!(headers_for(&duplicate).is_err());

        let mut bad_name = transport(OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME);
        bad_name
            .headers
            .insert("bad name".to_owned(), "v".to_owned());
        assert!(headers_for(&bad_name).is_err());

        let mut bad_value = transport(OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME);
        bad_value
            .headers
            .insert("x-ok".to_owned(), "a\r\nb: c".to_owned());
        assert!(headers_for(&bad_value).is_err());
    }

    #[test]
    fn params_are_typed_for_three_keys_and_the_rest_pass_through() {
        let mut declared = transport(OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME);
        declared.params = serde_json::from_value(json!({
            "temperature": 0.25,
            "max_tokens": 512,
            "response_format": {"type": "json_object"},
            "logprobs": true,
        }))
        .unwrap();
        let config = declared.transport_config(Path::new("t.json")).unwrap();
        assert_eq!(config.model_id, "m");
        assert_eq!(config.temperature, Some(0.25));
        assert_eq!(config.max_tokens, Some(512));
        assert_eq!(config.response_format, Some(json!({"type": "json_object"})));
        assert_eq!(
            config.additional_params,
            Some(Map::from_iter([("logprobs".to_owned(), json!(true))]))
        );

        for bad in [
            json!({"temperature": "hot"}),
            json!({"max_tokens": -1}),
            json!({"max_tokens": 1.5}),
            json!({"max_tokens": 99_999_999_999u64}),
        ] {
            let mut declared = transport(OPENAI_CHAT_COMPLETIONS_ADAPTER_NAME);
            declared.params = serde_json::from_value(bad.clone()).unwrap();
            assert!(
                declared.transport_config(Path::new("t.json")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_transport_file_rejects_unknown_members_and_out_of_range_limits() {
        let parsed = |value: Value| serde_json::from_value::<SendTransport>(value);
        let base = json!({
            "adapter": "openai_chat_completions",
            "model": "m",
            "url": "https://example.com/v1",
            "api_key_env": "K",
        });
        assert!(parsed(base.clone()).is_ok());

        let mut with_secret = base.clone();
        with_secret["api_key"] = json!("sk-should-not-be-here");
        assert!(parsed(with_secret).is_err());

        for missing in ["adapter", "model", "url", "api_key_env"] {
            let mut incomplete = base.clone();
            incomplete.as_object_mut().unwrap().remove(missing);
            assert!(parsed(incomplete).is_err(), "{missing} is required");
        }

        let path = Path::new("t.json");
        assert!(bounded(None, 120, 900, "f", path).is_ok());
        assert_eq!(bounded(Some(1), 120, 900, "f", path).unwrap(), 1);
        assert_eq!(bounded(Some(900), 120, 900, "f", path).unwrap(), 900);
        assert!(bounded(Some(0), 120, 900, "f", path).is_err());
        assert!(bounded(Some(901), 120, 900, "f", path).is_err());
    }
}
