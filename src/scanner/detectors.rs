use boundary_detectors::{ScanConfig, Scanner};
use serde_json::Value;

use crate::hash::blake3_hash;
use crate::policy::{AirlockPolicy, DetectorPack};
use crate::types::Finding;

const MAX_DETECTOR_INPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct DetectorScan {
    pub findings: Vec<Finding>,
    pub blocking_paths: Vec<String>,
}

pub fn scan_payload(policy: &AirlockPolicy, payload: &Value, root_path: &str) -> DetectorScan {
    if policy.detectors.is_empty() {
        return DetectorScan::default();
    }

    let default_config = ScanConfig::default();
    let scanner = Scanner::new(ScanConfig {
        packs: policy
            .detectors
            .iter()
            .map(|detector| detector.boundary_pack())
            .collect(),
        tabular_min_rows: policy
            .tabular_min_rows
            .unwrap_or(default_config.tabular_min_rows),
        max_input_bytes: MAX_DETECTOR_INPUT_BYTES,
        ..default_config
    });
    let mut result = DetectorScan::default();
    scan_value(
        &scanner,
        policy,
        payload,
        root_path.to_owned(),
        None,
        &mut result,
    );
    result
}

fn scan_value(
    scanner: &Scanner,
    policy: &AirlockPolicy,
    value: &Value,
    path: String,
    field_name: Option<&str>,
    result: &mut DetectorScan,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                scan_value(
                    scanner,
                    policy,
                    child,
                    format!("{path}.{key}"),
                    Some(key),
                    result,
                );
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_value(
                    scanner,
                    policy,
                    child,
                    format!("{path}[{index}]"),
                    field_name,
                    result,
                );
            }
        }
        Value::String(text) => {
            let contextual_text = match field_name {
                Some(name) => format!("{name}={text}"),
                None => text.clone(),
            };
            if contextual_text.len() > MAX_DETECTOR_INPUT_BYTES {
                let finding = Finding {
                    key_path: path.clone(),
                    sample_value: None,
                    artifact_class: "DETECTOR_SCAN_REFUSED".to_owned(),
                    matched_rule: "detector_input_limit".to_owned(),
                    span_hash: Some(blake3_hash(contextual_text.as_bytes())),
                };
                result.findings.push(finding);
                push_unique_path(&mut result.blocking_paths, path);
                return;
            }

            for hit in scanner.scan_str(&contextual_text) {
                let detector = match hit.pack {
                    boundary_detectors::Pack::Secrets => DetectorPack::Secrets,
                    boundary_detectors::Pack::Pii => DetectorPack::Pii,
                    boundary_detectors::Pack::Tabular => DetectorPack::Tabular,
                    boundary_detectors::Pack::Blobs => DetectorPack::Blobs,
                    boundary_detectors::Pack::Paths => DetectorPack::Paths,
                    boundary_detectors::Pack::ProtectedCorpus => continue,
                };
                result.findings.push(Finding {
                    key_path: path.clone(),
                    sample_value: None,
                    artifact_class: "DETECTED_SENSITIVE".to_owned(),
                    matched_rule: hit.rule_id,
                    span_hash: Some(hit.match_hash),
                });
                if !policy.detectors_warn_only.contains(&detector) {
                    push_unique_path(&mut result.blocking_paths, path.clone());
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn push_unique_path(paths: &mut Vec<String>, path: String) {
    if !paths.contains(&path) {
        paths.push(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DetectorPack;
    use serde_json::json;

    fn scan(detector: DetectorPack, payload: Value) -> DetectorScan {
        let mut policy = AirlockPolicy::default();
        policy.detectors.push(detector);
        scan_payload(&policy, &payload, "request")
    }

    #[test]
    fn secrets_pack_detects_assignments_without_echoing_values() {
        let result = scan(
            DetectorPack::Secrets,
            json!({
                "api_key": "q8Z9kL2mN5pR7tV9xY1bC4dF6hJ8",
                "placeholder": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        );
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.matched_rule == "SECRET_HIGH_ENTROPY_ASSIGNMENT")
            .expect("high-entropy secret assignment should be detected");
        assert_eq!(finding.key_path, "request.api_key");
        assert_eq!(finding.artifact_class, "DETECTED_SENSITIVE");
        assert!(finding.sample_value.is_none());
        assert!(finding.span_hash.as_deref().unwrap().starts_with("blake3:"));
        assert!(
            !serde_json::to_string(&result.findings)
                .unwrap()
                .contains("q8Z9kL2mN5pR7tV9xY1bC4dF6hJ8")
        );
        assert_eq!(result.blocking_paths, ["request.api_key"]);
    }

    #[test]
    fn pii_pack_detects_ssn_card_email_phone_and_iban_but_ignores_invalid_card() {
        let result = scan(
            DetectorPack::Pii,
            json!({
                "ssn": "123-45-6789",
                "card": "4111 1111 1111 1111",
                "email": "alice@example.com",
                "phone": "+14155552671",
                "iban": "GB82WEST12345698765432",
                "invalid_card": "4111 1111 1111 1112"
            }),
        );
        let rules = result
            .findings
            .iter()
            .map(|finding| finding.matched_rule.as_str())
            .collect::<Vec<_>>();
        assert!(rules.contains(&"PII_US_SSN"));
        assert!(rules.contains(&"PII_PAYMENT_CARD"));
        assert!(rules.contains(&"PII_EMAIL"));
        assert!(rules.contains(&"PII_PHONE_E164"));
        assert!(rules.contains(&"PII_IBAN"));
        assert!(
            !result
                .findings
                .iter()
                .any(|finding| finding.key_path == "request.invalid_card")
        );
        assert_eq!(result.findings.len(), 5);
        assert_eq!(result.blocking_paths.len(), 5);
    }

    #[test]
    fn tabular_pack_requires_repeated_delimited_rows() {
        let result = scan(
            DetectorPack::Tabular,
            json!({
                "table": "name,email,amount\nAlice,a@example.com,10\nBob,b@example.com,11\nCarol,c@example.com,12\nDave,d@example.com,13\nEve,e@example.com,14",
                "short": "a,b,c\n1,2,3\n4,5,6"
            }),
        );
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].matched_rule, "TABULAR_CSV_BLOCK");
        assert_eq!(result.findings[0].key_path, "request.table");
    }

    #[test]
    fn tabular_pack_uses_the_policy_row_threshold() {
        let payload = json!({"table":"a,b,c\n1,2,3\n4,5,6"});
        let mut policy = AirlockPolicy {
            detectors: vec![DetectorPack::Tabular],
            ..AirlockPolicy::default()
        };
        assert!(
            scan_payload(&policy, &payload, "request")
                .findings
                .is_empty()
        );

        policy.tabular_min_rows = Some(3);
        let result = scan_payload(&policy, &payload, "request");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].matched_rule, "TABULAR_CSV_BLOCK");
    }

    #[test]
    fn blobs_pack_detects_large_base64_and_data_uris() {
        let encoded = "A".repeat(512);
        let result = scan(
            DetectorPack::Blobs,
            json!({
                "blob": encoded,
                "uri": "data:application/octet-stream;base64,AAAAAAAAAAAAAAAAAAAAAAAA",
                "ordinary": "short plain text"
            }),
        );
        let paths = result
            .findings
            .iter()
            .map(|finding| finding.key_path.as_str())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"request.blob"));
        assert!(paths.contains(&"request.uri"));
        assert!(!paths.contains(&"request.ordinary"));
    }

    #[test]
    fn paths_pack_detects_absolute_home_and_file_uris_only() {
        let result = scan(
            DetectorPack::Paths,
            json!({
                "absolute": "/Users/alice/private/report.pdf",
                "home": "~/deal-room/notes.txt",
                "uri": "file:///private/var/tmp/source.pdf",
                "relative": "reports/quarterly.csv"
            }),
        );
        let paths = result
            .findings
            .iter()
            .map(|finding| finding.key_path.as_str())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"request.absolute"));
        assert!(paths.contains(&"request.home"));
        assert!(paths.contains(&"request.uri"));
        assert!(!paths.contains(&"request.relative"));
    }

    #[test]
    fn detector_packs_are_opt_in_and_warn_only_hits_do_not_block() {
        let payload = json!({"ssn":"123-45-6789"});
        assert!(
            scan_payload(&AirlockPolicy::default(), &payload, "request")
                .findings
                .is_empty()
        );

        let mut policy = AirlockPolicy::default();
        policy.detectors.push(DetectorPack::Pii);
        policy.detectors_warn_only.push(DetectorPack::Pii);
        let result = scan_payload(&policy, &payload, "request");
        assert_eq!(result.findings.len(), 1);
        assert!(result.blocking_paths.is_empty());
    }
}
