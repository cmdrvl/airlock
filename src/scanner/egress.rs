use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use boundary_detectors::shingle_bloom::ShingleBloom;
use boundary_detectors::{Pack, ScanConfig, Scanner};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hash::blake3_hash;
use crate::policy::{AirlockPolicy, DetectorPack};

pub const MAX_GATE_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROTECTED_BLOOM_BYTES: usize = 67_108_904;
pub const DEFAULT_PROTECTED_BLOOM_MIN_HITS: usize = 8;
const MAX_DECODED_BYTES: usize = MAX_GATE_REQUEST_BYTES * 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressFinding {
    pub artifact_class: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressScan {
    pub request_hash: String,
    pub findings: Vec<EgressFinding>,
    pub blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressScanError {
    RequestTooLarge,
    InvalidJson,
}

impl std::fmt::Display for EgressScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestTooLarge => f.write_str("request exceeds the egress scan limit"),
            Self::InvalidJson => f.write_str("request body must be valid JSON"),
        }
    }
}

impl std::error::Error for EgressScanError {}

pub fn load_protected_bloom(path: &Path) -> Result<ShingleBloom, String> {
    if !path.is_absolute() {
        return Err("protected Bloom path must be absolute".to_owned());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| "protected Bloom is unreadable")?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_PROTECTED_BLOOM_BYTES as u64 {
        return Err("protected Bloom must be a regular file within the size limit".to_owned());
    }
    check_private_bloom_permissions(path, &metadata)?;

    let file = File::open(path).map_err(|_| "protected Bloom is unreadable")?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| "protected Bloom is unreadable")?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_PROTECTED_BLOOM_BYTES as u64 {
        return Err("protected Bloom must be a regular file within the size limit".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
            return Err("protected Bloom changed while it was opened".to_owned());
        }
    }
    check_private_bloom_permissions(path, &opened_metadata)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PROTECTED_BLOOM_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "protected Bloom is unreadable")?;
    if bytes.len() > MAX_PROTECTED_BLOOM_BYTES {
        return Err("protected Bloom exceeds the size limit".to_owned());
    }
    let bloom = ShingleBloom::from_bytes(&bytes)
        .map_err(|_| "protected Bloom has an invalid BDBL v1 format".to_owned())?;
    if bloom.inserted_shingles() == 0 {
        return Err("protected Bloom contains no protected shingles".to_owned());
    }
    Ok(bloom)
}

#[cfg(unix)]
fn check_private_bloom_permissions(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err("protected Bloom file must have mode 0600".to_owned());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::metadata(parent).map_err(|_| "protected Bloom directory is unreadable")?;
    if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err("protected Bloom directory must have mode 0700".to_owned());
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_bloom_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<(), String> {
    Ok(())
}

pub fn egress_scanner(
    policy: &AirlockPolicy,
    bloom: Option<ShingleBloom>,
    min_hits: usize,
) -> Scanner {
    let default_config = ScanConfig::default();
    let mut config = ScanConfig {
        packs: policy
            .detectors
            .iter()
            .map(|detector| detector.boundary_pack())
            .collect(),
        tabular_min_rows: policy
            .tabular_min_rows
            .unwrap_or(default_config.tabular_min_rows),
        max_input_bytes: MAX_GATE_REQUEST_BYTES,
        max_decoded_bytes: MAX_DECODED_BYTES,
        max_decode_depth: 2,
        shingle_min_hits: min_hits.max(1),
        ..default_config
    };
    if bloom.is_some() && !config.packs.contains(&Pack::ProtectedCorpus) {
        config.packs.push(Pack::ProtectedCorpus);
    }
    match bloom {
        Some(bloom) => Scanner::with_bloom(config, bloom),
        None => Scanner::new(config),
    }
}

pub fn scan_policy_proxy_request(
    policy: &AirlockPolicy,
    body: &[u8],
    scanner: &Scanner,
) -> Result<EgressScan, EgressScanError> {
    scan_policy_proxy_request_with_media(policy, body, scanner, &HashSet::new())
}

pub fn scan_policy_proxy_request_with_media(
    policy: &AirlockPolicy,
    body: &[u8],
    scanner: &Scanner,
    base64_media_pointers: &HashSet<String>,
) -> Result<EgressScan, EgressScanError> {
    if body.len() > MAX_GATE_REQUEST_BYTES {
        return Err(EgressScanError::RequestTooLarge);
    }
    let request: Value = serde_json::from_slice(body).map_err(|_| EgressScanError::InvalidJson)?;
    let patterns: Vec<Regex> = policy
        .forbidden_patterns
        .iter()
        .filter_map(|entry| Regex::new(&entry.pattern).ok())
        .collect();
    let mut findings = Vec::new();
    let mut blocking = false;
    let context = ScanContext {
        policy,
        patterns: &patterns,
        scanner,
        base64_media_pointers,
    };
    scan_value(
        &context,
        &request,
        "",
        false,
        None,
        &mut findings,
        &mut blocking,
    );
    findings.sort_by(|left, right| {
        left.artifact_class
            .cmp(&right.artifact_class)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.key_path.cmp(&right.key_path))
            .then_with(|| left.span_hash.cmp(&right.span_hash))
    });
    findings.dedup();
    Ok(EgressScan {
        request_hash: blake3_hash(body),
        findings,
        blocking,
    })
}

/// What a scan needs besides the node being visited. It is the same for every recursive call.
#[derive(Clone, Copy)]
struct ScanContext<'a> {
    policy: &'a AirlockPolicy,
    patterns: &'a [Regex],
    scanner: &'a Scanner,
    base64_media_pointers: &'a HashSet<String>,
}

fn scan_value(
    context: &ScanContext<'_>,
    value: &Value,
    pointer: &str,
    in_multimodal: bool,
    field_name: Option<&str>,
    findings: &mut Vec<EgressFinding>,
    blocking: &mut bool,
) {
    let ScanContext {
        policy,
        patterns,
        scanner,
        base64_media_pointers,
    } = *context;
    let multimodal = in_multimodal || is_multimodal_node(value);
    if multimodal && policy.allow_multimodal != Some(true) {
        *blocking = true;
        findings.push(EgressFinding {
            artifact_class: "MULTIMODAL_ATTACHMENT".to_owned(),
            rule_id: "MULTIMODAL_ATTACHMENT_BLOCKED".to_owned(),
            key_path: nonempty_pointer(pointer),
            span_hash: None,
        });
        return;
    }

    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                if policy
                    .forbidden_keys
                    .iter()
                    .any(|forbidden| forbidden == key)
                {
                    *blocking = true;
                    findings.push(EgressFinding {
                        artifact_class: "POLICY_FORBIDDEN_KEY".to_owned(),
                        rule_id: "POLICY_FORBIDDEN_KEY".to_owned(),
                        key_path: Some(pointer_child(pointer, key)),
                        span_hash: None,
                    });
                }
                scan_value(
                    context,
                    child,
                    &pointer_child(pointer, key),
                    multimodal,
                    Some(key),
                    findings,
                    blocking,
                );
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_value(
                    context,
                    child,
                    &format!("{pointer}/{index}"),
                    multimodal,
                    field_name,
                    findings,
                    blocking,
                );
            }
        }
        Value::String(text) => {
            let contextual_text = field_name
                .map(|name| format!("{name}={text}"))
                .unwrap_or_else(|| text.clone());
            if contextual_text.len() > scanner.config().max_input_bytes {
                *blocking = true;
                findings.push(EgressFinding {
                    artifact_class: "DETECTOR_SCAN_REFUSED".to_owned(),
                    rule_id: "DETECTOR_INPUT_LIMIT".to_owned(),
                    key_path: nonempty_pointer(pointer),
                    span_hash: Some(blake3_hash(contextual_text.as_bytes())),
                });
                return;
            }
            if patterns.iter().any(|pattern| pattern.is_match(text)) {
                *blocking = true;
                findings.push(EgressFinding {
                    artifact_class: "POLICY_FORBIDDEN_PATTERN".to_owned(),
                    rule_id: "POLICY_FORBIDDEN_PATTERN".to_owned(),
                    key_path: nonempty_pointer(pointer),
                    span_hash: None,
                });
            }
            let inspect_media =
                base64_media_pointers.contains(pointer) && policy.allow_multimodal == Some(true);
            let decoded_candidates = if patterns.is_empty() && !inspect_media {
                Vec::new()
            } else {
                boundary_detectors::blobs::extract_decodable_candidates(text, MAX_DECODED_BYTES)
            };
            if decoded_candidates.iter().any(|candidate| {
                let decoded_text = String::from_utf8_lossy(&candidate.decoded);
                patterns
                    .iter()
                    .any(|pattern| pattern.is_match(&decoded_text))
            }) {
                *blocking = true;
                findings.push(EgressFinding {
                    artifact_class: "POLICY_FORBIDDEN_PATTERN".to_owned(),
                    rule_id: "POLICY_FORBIDDEN_PATTERN".to_owned(),
                    key_path: nonempty_pointer(pointer),
                    span_hash: None,
                });
            }
            let detector_findings = if inspect_media {
                decoded_candidates
                    .into_iter()
                    .flat_map(|candidate| scanner.scan_bytes(&candidate.decoded))
                    .collect::<Vec<_>>()
            } else {
                scanner.scan_str(&contextual_text)
            };
            for finding in detector_findings {
                let detector_pack = match finding.pack {
                    Pack::Secrets => Some(DetectorPack::Secrets),
                    Pack::Pii => Some(DetectorPack::Pii),
                    Pack::Tabular => Some(DetectorPack::Tabular),
                    Pack::Blobs => Some(DetectorPack::Blobs),
                    Pack::Paths => Some(DetectorPack::Paths),
                    Pack::ProtectedCorpus => None,
                };
                let warning_only =
                    detector_pack.is_some_and(|pack| policy.detectors_warn_only.contains(&pack));
                if !warning_only {
                    *blocking = true;
                }
                findings.push(EgressFinding {
                    artifact_class: match finding.pack {
                        Pack::ProtectedCorpus => "PROTECTED_CORPUS_MATCH",
                        _ => "DETECTED_SENSITIVE",
                    }
                    .to_owned(),
                    rule_id: finding.rule_id,
                    key_path: nonempty_pointer(pointer),
                    span_hash: Some(finding.match_hash),
                });
            }
        }
        _ => {}
    }
}

fn nonempty_pointer(pointer: &str) -> Option<String> {
    (!pointer.is_empty()).then(|| pointer.to_owned())
}

fn pointer_child(base: &str, segment: &str) -> String {
    format!("{base}/{}", segment.replace('~', "~0").replace('/', "~1"))
}

fn is_multimodal_node(value: &Value) -> bool {
    if let Some(text) = value.as_str() {
        let lower = text.to_ascii_lowercase();
        return lower.starts_with("data:image/")
            || lower.starts_with("data:application/pdf")
            || lower.starts_with("data:application/vnd.");
    }
    let Some(fields) = value.as_object() else {
        return false;
    };
    fields.iter().any(|(key, value)| {
        let key = key.to_ascii_lowercase();
        let marker = value.as_str().unwrap_or_default().to_ascii_lowercase();
        (key == "type"
            && (marker.contains("image")
                || marker.contains("document")
                || marker.contains("input_file")))
            || ((key == "mime_type" || key == "media_type")
                && (marker.starts_with("image/")
                    || marker == "application/pdf"
                    || marker.starts_with("application/vnd.")))
            || ((key == "url" || key == "uri") && marker.starts_with("data:image/"))
            || (matches!(
                key.as_str(),
                "image"
                    | "images"
                    | "image_url"
                    | "image_data"
                    | "document"
                    | "documents"
                    | "file"
                    | "file_data"
                    | "file_url"
                    | "file_id"
                    | "input_file"
            ) && !value.is_null())
    })
}

#[cfg(test)]
mod tests {
    use boundary_detectors::shingle_bloom::{BloomConfig, ShingleBloom};

    use super::*;

    fn policy() -> AirlockPolicy {
        AirlockPolicy {
            forbidden_keys: vec!["secret".to_owned()],
            forbidden_patterns: vec![crate::policy::ForbiddenPattern {
                pattern: "client-[0-9]+".to_owned(),
                description: None,
                artifact_class: None,
            }],
            ..AirlockPolicy::default()
        }
    }

    #[test]
    fn blocks_policy_key_pattern_and_multimodal_content_without_echoing_values() {
        let policy = policy();
        let scanner = egress_scanner(&policy, None, DEFAULT_PROTECTED_BLOOM_MIN_HITS);
        let body = br#"{"messages":[{"content":"client-123"},{"content":{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}}],"secret":"private"}"#;
        let scan = scan_policy_proxy_request(&policy, body, &scanner).unwrap();
        assert!(scan.blocking);
        assert!(
            scan.findings
                .iter()
                .any(|finding| finding.rule_id == "POLICY_FORBIDDEN_KEY")
        );
        assert!(
            scan.findings
                .iter()
                .any(|finding| finding.rule_id == "POLICY_FORBIDDEN_PATTERN")
        );
        assert!(
            scan.findings
                .iter()
                .any(|finding| finding.rule_id == "MULTIMODAL_ATTACHMENT_BLOCKED")
        );
        let encoded = serde_json::to_string(&scan.findings).unwrap();
        assert!(!encoded.contains("client-123"));
        assert!(!encoded.contains("private"));
    }

    #[test]
    fn protected_bloom_finds_matching_content() {
        let protected = "north-star confidential transaction thesis includes unique protected text from an acquisition memo with distinct deal terms";
        let mut bloom = ShingleBloom::new(BloomConfig::default());
        bloom.insert_text(protected);
        let policy = AirlockPolicy::default();
        let scanner = egress_scanner(&policy, Some(bloom), 3);
        let body = serde_json::json!({"messages":[{"content":protected}]}).to_string();
        let scan = scan_policy_proxy_request(&policy, body.as_bytes(), &scanner).unwrap();
        assert!(scan.blocking);
        assert!(
            scan.findings
                .iter()
                .any(|finding| finding.rule_id == "PROTECTED_CORPUS_MATCH")
        );
        assert!(
            !serde_json::to_string(&scan.findings)
                .unwrap()
                .contains("north-star")
        );
    }

    #[test]
    fn forbidden_patterns_are_checked_after_base64_decoding() {
        let policy = policy();
        let scanner = egress_scanner(&policy, None, DEFAULT_PROTECTED_BLOOM_MIN_HITS);
        let body = br#"{"messages":[{"content":"cHJlZml4IGNsaWVudC0xMjMgcHJpdmF0ZSBzdWZmaXg="}]}"#;
        let scan = scan_policy_proxy_request(&policy, body, &scanner).unwrap();
        assert!(
            scan.findings
                .iter()
                .any(|finding| finding.rule_id == "POLICY_FORBIDDEN_PATTERN")
        );
    }

    #[test]
    fn protected_bloom_loader_requires_an_absolute_private_nonempty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("protected-corpus.bdbl");
        let mut bloom = ShingleBloom::new(BloomConfig::default());
        bloom.insert_text(
            "a nonempty protected corpus for this loader integration test with enough words and bytes",
        );
        let encoded = bloom.to_bytes();
        assert_eq!(&encoded[..4], b"BDBL");
        assert_eq!(encoded[4], 1, "veil handoff format is BDBL v1");
        std::fs::write(&path, encoded).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(load_protected_bloom(&path).is_ok());
        assert!(load_protected_bloom(Path::new("relative.bdbl")).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(load_protected_bloom(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let empty_path = dir.path().join("empty.bdbl");
        std::fs::write(
            &empty_path,
            ShingleBloom::new(BloomConfig::default()).to_bytes(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&empty_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(load_protected_bloom(&empty_path).is_err());
    }

    #[test]
    fn refuses_oversize_and_malformed_requests_without_scanning_a_prefix() {
        let policy = policy();
        let scanner = egress_scanner(&policy, None, DEFAULT_PROTECTED_BLOOM_MIN_HITS);
        let large = vec![b'a'; MAX_GATE_REQUEST_BYTES + 1];
        assert_eq!(
            scan_policy_proxy_request(&policy, &large, &scanner),
            Err(EgressScanError::RequestTooLarge)
        );
        assert_eq!(
            scan_policy_proxy_request(&policy, b"{", &scanner),
            Err(EgressScanError::InvalidJson)
        );
    }

    #[test]
    fn detector_packs_are_opt_in_and_warn_only_findings_do_not_block() {
        let request = br#"{"messages":[{"content":"AWS key AKIAIOSFODNN7EXAMPLE"}]}"#;
        let baseline = AirlockPolicy::default();
        let baseline_scanner = egress_scanner(&baseline, None, DEFAULT_PROTECTED_BLOOM_MIN_HITS);
        let baseline_scan =
            scan_policy_proxy_request(&baseline, request, &baseline_scanner).unwrap();
        assert!(!baseline_scan.blocking);
        assert!(baseline_scan.findings.is_empty());

        let mut enabled = AirlockPolicy::default();
        enabled.detectors.push(DetectorPack::Secrets);
        let enabled_scanner = egress_scanner(&enabled, None, DEFAULT_PROTECTED_BLOOM_MIN_HITS);
        let enabled_scan = scan_policy_proxy_request(&enabled, request, &enabled_scanner).unwrap();
        assert!(enabled_scan.blocking);
        let finding = enabled_scan
            .findings
            .iter()
            .find(|finding| finding.rule_id == "SECRET_AWS_ACCESS_KEY")
            .expect("enabled secrets pack should report the AWS key");
        assert_eq!(finding.artifact_class, "DETECTED_SENSITIVE");
        assert_eq!(finding.key_path.as_deref(), Some("/messages/0/content"));
        assert!(finding.span_hash.as_deref().unwrap().starts_with("blake3:"));

        enabled.detectors_warn_only.push(DetectorPack::Secrets);
        let warn_only_scanner = egress_scanner(&enabled, None, DEFAULT_PROTECTED_BLOOM_MIN_HITS);
        let warn_only_scan =
            scan_policy_proxy_request(&enabled, request, &warn_only_scanner).unwrap();
        assert!(!warn_only_scan.blocking);
        assert_eq!(warn_only_scan.findings.len(), 1);
        assert_eq!(
            warn_only_scan.findings[0].artifact_class,
            "DETECTED_SENSITIVE"
        );
    }
}
