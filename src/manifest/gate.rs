use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::scanner::egress::EgressFinding;

static GATE_RECEIPT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A configured limit that tripped, recorded on the receipt of the request it stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateLimit {
    /// Which limit: `max_request_bytes` or `timeout_seconds`.
    pub kind: String,
    /// The configured value, in bytes or seconds.
    pub limit: u64,
    /// What was observed when it is known, for example the declared request size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<u64>,
}

impl GateLimit {
    pub fn max_request_bytes(limit: u64, observed: Option<u64>) -> Self {
        Self {
            kind: "max_request_bytes".to_owned(),
            limit,
            observed,
        }
    }

    pub fn timeout_seconds(limit: u64) -> Self {
        Self {
            kind: "timeout_seconds".to_owned(),
            limit,
            observed: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReceipt {
    pub gate_version: String,
    pub mode: String,
    pub achieved_claim: String,
    pub request_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    /// Request-body bytes the gate received from the client, when it had read the body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u64>,
    /// Response-body bytes the gate read from the upstream and handed to the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    /// The limit that tripped, when the request was stopped by one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<GateLimit>,
    pub blocked: bool,
    pub findings: Vec<EgressFinding>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_manifest_hash: Option<String>,
}

impl GateReceipt {
    pub fn new(
        mode: impl Into<String>,
        achieved_claim: impl Into<String>,
        request_hash: impl Into<String>,
        blocked: bool,
        findings: Vec<EgressFinding>,
    ) -> Self {
        Self {
            gate_version: "airlock.gate.v1".to_owned(),
            mode: mode.into(),
            achieved_claim: achieved_claim.into(),
            request_hash: request_hash.into(),
            response_hash: None,
            upstream_status: None,
            request_bytes: None,
            response_bytes: None,
            limit: None,
            blocked,
            findings,
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            policy_id: None,
            policy_hash: None,
            matched_manifest_hash: None,
        }
    }

    /// Record which policy the gate was enforcing when it produced this receipt.
    pub fn with_policy(mut self, policy_id: Option<String>, policy_hash: Option<String>) -> Self {
        self.policy_id = policy_id;
        self.policy_hash = policy_hash;
        self
    }

    /// Record how many request-body bytes the gate received, if it had read the body.
    pub fn with_request_bytes(mut self, request_bytes: Option<u64>) -> Self {
        self.request_bytes = request_bytes;
        self
    }

    /// Record the limit that stopped this request.
    pub fn with_limit(mut self, limit: GateLimit) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Record the hash of the manifest that authorized this request, if one matched.
    pub fn with_matched_manifest(mut self, matched_manifest_hash: Option<String>) -> Self {
        self.matched_manifest_hash = matched_manifest_hash;
        self
    }

    pub fn write_to(&self, directory: &Path) -> io::Result<PathBuf> {
        fs::create_dir_all(directory)?;
        let filename = format!(
            "gate-{}-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp(),
            GATE_RECEIPT_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = directory.join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        serde_json::to_writer(&mut file, self).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GateRefusal {
    pub schema_version: String,
    pub code: String,
    pub message: String,
    pub findings: Vec<EgressFinding>,
}

impl GateRefusal {
    pub fn blocked(findings: Vec<EgressFinding>) -> Self {
        Self::with_code(
            "BOUNDARY_FAILED",
            "outbound request blocked by airlock gate",
            findings,
        )
    }

    /// The gate refused to forward a request for a reason that is not a screening finding:
    /// no manifest matches its hash, the body is unreadable, malformed or too large, or
    /// the request target is invalid.
    pub fn denied(findings: Vec<EgressFinding>) -> Self {
        Self::with_code(
            "E_GATE_DENIED",
            "outbound request denied by airlock gate",
            findings,
        )
    }

    pub fn with_code(
        code: impl Into<String>,
        message: impl Into<String>,
        findings: Vec<EgressFinding>,
    ) -> Self {
        Self {
            schema_version: "airlock.gate_refusal.v1".to_owned(),
            code: code.into(),
            message: message.into(),
            findings,
        }
    }
}
