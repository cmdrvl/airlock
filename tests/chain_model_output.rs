//! al-210 D-a: MODEL_OUTPUT. An earlier turn's response enters the next prompt, anchored to the
//! gate receipt that recorded it, and the claim for the turn follows ruling D2(b): model output
//! caps the claim at RAW_DOCUMENT_ABSENT unless a blocking detector pack screened it clean.
//!
//! Everything runs the real `airlock` binary. The receipts in most tests are built here from the
//! response bytes: they are test inputs, not gate output, and prove nothing about the gate. One
//! test (`a_receipt_the_real_gate_wrote_anchors_the_chain`) runs the real `airlock gate` against a
//! loopback origin and feeds its own receipt to `assemble`, so the receipt format the check reads
//! is the format the producer writes. The origin there is a loopback mock; no other network is
//! touched. Every payload is fabricated, including the AWS-shaped token.

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use airlock::adapter::{
    Adapter, AnthropicMessagesAdapter, OpenAiResponsesAdapter, TransportConfig,
};
use airlock::hash::blake3_hash;
use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};
use tiny_http::{Response, Server};

const OPENAI: &str = "openai_responses";
const ANTHROPIC: &str = "anthropic_messages";
const ADAPTERS: [&str; 2] = [OPENAI, ANTHROPIC];

/// Random characters in the shape of an AWS access key id. Not a real key.
const FAKE_AWS_KEY: &str = "AKIAJ3QXK7M2ZP9WNB4D";
const ALL_PACKS: &str = "detectors: [secrets, pii, tabular, blobs, paths]\n";
const ALL_PACKS_WARN_ONLY: &str = "detectors: [secrets, pii, tabular, blobs, paths]\n\
                                   detectors_warn_only: [secrets, pii, tabular, blobs, paths]\n";
/// `pii` blocks, `secrets` only warns.
const ONE_BLOCKING_ONE_WARN: &str = "detectors: [secrets, pii]\ndetectors_warn_only: [secrets]\n";

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_json(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// The committed response fixture for `adapter`, edited by `edit`, as the bytes a gate would hash.
fn response_bytes(adapter: &str, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let file = match adapter {
        OPENAI => "fixtures/chain/openai_responses_reply.json",
        _ => "fixtures/chain/anthropic_messages_reply.json",
    };
    let mut value = read_json(&repo(file));
    edit(&mut value);
    serde_json::to_vec(&value).expect("serialize response")
}

fn set(value: &mut Value, pointer: &str, new: Value) {
    *value
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("fixture has no {pointer}")) = new;
}

/// Where the first assistant text sits in the fixture for `adapter`.
fn text_pointer(adapter: &str) -> &'static str {
    match adapter {
        OPENAI => "/output/1/content/0/text",
        _ => "/content/1/text",
    }
}

/// A receipt as `airlock gate` writes one for an admitted, forwarded, 200 exchange.
fn receipt_for(response: &[u8]) -> Value {
    json!({
        "gate_version": "airlock.gate.v1",
        "mode": "strict-manifest",
        "achieved_claim": "STRICT_TELEMETRY_ONLY",
        "request_hash": blake3_hash(b"fixture request"),
        "response_hash": blake3_hash(response),
        "upstream_status": 200,
        "blocked": false,
        "findings": [],
        "timestamp": "2026-11-25T00:00:00Z",
        "matched_manifest_hash": blake3_hash(b"fixture prior manifest"),
    })
}

/// What `verify` said about one turn.
#[derive(Debug)]
struct Observed {
    exit: i32,
    claim: String,
    binding: String,
    findings: BTreeSet<String>,
    /// The reason recorded for not reaching STRICT_TELEMETRY_ONLY, when there is one.
    strict_reason: Option<String>,
    strict_paths: Vec<String>,
}

struct Chain {
    adapter: String,
    response: PathBuf,
    receipt: PathBuf,
}

struct Assembled {
    output: Output,
    prompt: PathBuf,
    provenance: PathBuf,
}

impl Assembled {
    fn refusal(&self) -> Value {
        serde_json::from_slice(&self.output.stdout).unwrap_or(Value::Null)
    }
}

struct Work {
    dir: TempDir,
}

impl Work {
    fn new() -> Self {
        Self {
            dir: tempdir().expect("tempdir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, bytes).expect("write");
        path
    }

    /// `fixtures/annotated_mode/policy.yaml` with `extra` YAML lines appended.
    fn policy(&self, name: &str, extra: &str) -> PathBuf {
        let mut text = fs::read_to_string(repo("fixtures/annotated_mode/policy.yaml"))
            .expect("read the annotated_mode policy");
        text.push_str(extra);
        self.write(name, text.as_bytes())
    }

    /// The annotated_mode policy with one more rule (YAML, two-space list item) first in `allowed_keys`.
    fn policy_with_rule(&self, name: &str, rule: &str) -> PathBuf {
        let text = fs::read_to_string(repo("fixtures/annotated_mode/policy.yaml"))
            .expect("read the annotated_mode policy")
            .replacen("allowed_keys:\n", &format!("allowed_keys:\n{rule}"), 1);
        self.write(name, text.as_bytes())
    }

    fn chain(&self, adapter: &str, response: &[u8], stem: &str) -> Chain {
        Chain {
            adapter: adapter.to_owned(),
            response: self.write(&format!("{stem}.response.json"), response),
            receipt: self.write(
                &format!("{stem}.receipt.json"),
                &serde_json::to_vec(&receipt_for(response)).expect("serialize receipt"),
            ),
        }
    }

    fn assemble(&self, policy: &Path, mode: &str, stem: &str, chain: Option<&Chain>) -> Assembled {
        let prompt = self.path(&format!("{stem}.prompt.json"));
        let provenance = self.path(&format!("{stem}.provenance.json"));
        let mut command = Command::cargo_bin("airlock").expect("airlock binary");
        command
            .args(["assemble", "--policy"])
            .arg(policy)
            .arg("--input")
            .arg(repo("fixtures/annotated_mode/strategy_space.json"))
            .arg("--system-prompt")
            .arg(repo("fixtures/annotated_mode/system_prompt.txt"))
            .args(["--boundary-mode", mode, "--out"])
            .arg(&prompt)
            .arg("--provenance-out")
            .arg(&provenance)
            .arg("--no-witness");
        if let Some(chain) = chain {
            command
                .arg("--prior-receipt")
                .arg(&chain.receipt)
                .arg("--response")
                .arg(&chain.response)
                .args(["--response-adapter", &chain.adapter]);
        }
        Assembled {
            output: command.output().expect("run assemble"),
            prompt,
            provenance,
        }
    }

    fn verify(&self, policy: &Path, assembled: &Assembled, stem: &str) -> Observed {
        let request = json!({
            "model": "gpt-5",
            "messages": read_json(&assembled.prompt)["messages"].clone(),
        });
        self.verify_request(
            policy,
            &assembled.prompt,
            &assembled.provenance,
            &request,
            stem,
        )
    }

    fn verify_request(
        &self,
        policy: &Path,
        prompt: &Path,
        provenance: &Path,
        request: &Value,
        stem: &str,
    ) -> Observed {
        let request_path = self.write(
            &format!("{stem}.request.json"),
            &serde_json::to_vec(request).expect("serialize request"),
        );
        let output = Command::cargo_bin("airlock")
            .expect("airlock binary")
            .args(["verify", "--no-sign", "--no-witness", "--policy"])
            .arg(policy)
            .arg("--prompt")
            .arg(prompt)
            .arg("--provenance")
            .arg(provenance)
            .arg("--request")
            .arg(&request_path)
            .arg("--out")
            .arg(self.path(&format!("{stem}.manifest.json")))
            .args(["--require-claim", "RAW_DOCUMENT_ABSENT"])
            .output()
            .expect("run verify");
        let manifest: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "verify wrote no manifest (exit {:?}): {error}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout)
            )
        });
        let findings = manifest["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|finding| {
                let class = finding["artifact_class"].as_str().unwrap_or_default();
                if class == "DETECTED_SENSITIVE" {
                    format!(
                        "DETECTED_SENSITIVE:{}",
                        finding["matched_rule"].as_str().unwrap_or_default()
                    )
                } else {
                    class.to_owned()
                }
            })
            .collect();
        let strict = manifest["blocked_reasons"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|reason| reason["claim_attempted"] == "STRICT_TELEMETRY_ONLY");
        Observed {
            exit: output.status.code().unwrap_or(-1),
            claim: manifest["achieved_claim"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            binding: manifest["binding_status"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            findings,
            strict_reason: strict.and_then(|reason| reason["reason"].as_str().map(str::to_owned)),
            strict_paths: strict
                .and_then(|reason| reason["offending_paths"].as_array())
                .into_iter()
                .flatten()
                .filter_map(|path| path.as_str().map(str::to_owned))
                .collect(),
        }
    }

    /// Assemble one chained turn and verify it. Panics if assemble refuses: use `assemble` directly
    /// for tests about refusals.
    fn turn(
        &self,
        policy_extra: &str,
        mode: &str,
        adapter: &str,
        response: &[u8],
        stem: &str,
    ) -> Observed {
        let policy = self.policy(&format!("{stem}.policy.yaml"), policy_extra);
        let chain = self.chain(adapter, response, stem);
        let assembled = self.assemble(&policy, mode, stem, Some(&chain));
        assert_eq!(
            assembled.output.status.code(),
            Some(0),
            "assemble refused: {}",
            String::from_utf8_lossy(&assembled.output.stdout)
        );
        self.verify(&policy, &assembled, stem)
    }
}

fn model_output_records(provenance: &Path) -> Vec<Value> {
    read_json(provenance)["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|record| {
            record["prompt_path"]
                .as_str()
                .is_some_and(|path| path.starts_with("messages[1].content.prior_turn"))
        })
        .cloned()
        .collect()
}

/// The assistant text in both response fixtures.
const FIXTURE_TEXT: &str =
    "Family F-17 ranks highest on header coverage; I will look up its lineage.";

// --- what assemble builds -------------------------------------------------------------------

#[test]
fn a_response_enters_the_prompt_as_model_output_and_every_leaf_has_a_record() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let response = response_bytes(adapter, |_| {});
        let policy = work.policy("p.yaml", "");
        let chain = work.chain(adapter, &response, "t1");
        let assembled = work.assemble(&policy, "ANNOTATED", "t1", Some(&chain));
        assert_eq!(assembled.output.status.code(), Some(0), "{adapter}");

        let prompt = read_json(&assembled.prompt);
        let call_id = if adapter == OPENAI {
            "call_fx_0001"
        } else {
            "toolu_fx_0001"
        };
        assert_eq!(
            prompt["messages"][1]["content"]["prior_turn"]["model_output"],
            json!([
                {"kind": "text", "text": FIXTURE_TEXT},
                {
                    "kind": "tool_use",
                    "id": call_id,
                    "name": "lineage_lookup",
                    "input": {"depth": 2, "family_id": "F-17"}
                }
            ]),
            "{adapter}"
        );
        assert_eq!(
            prompt["messages"][1]["content"]["family_id"], "bdc_schedule_of_investments",
            "{adapter}: the policy's own fields still cross"
        );
        let prompt_text = fs::read_to_string(&assembled.prompt).expect("read prompt");
        assert!(
            !prompt_text.contains("NOT-ADMITTED"),
            "{adapter}: reasoning, thinking and refusal blocks must not be admitted"
        );

        let (id_path, name_path, depth_path, family_path, text_path) = if adapter == OPENAI {
            (
                "output[2].call_id",
                "output[2].name",
                "output[2].arguments.depth",
                "output[2].arguments.family_id",
                "output[1].content[0].text",
            )
        } else {
            (
                "content[2].id",
                "content[2].name",
                "content[2].input.depth",
                "content[2].input.family_id",
                "content[1].text",
            )
        };
        let base = "messages[1].content.prior_turn.model_output";
        let expected_sources = [
            (
                format!("{base}[0].kind"),
                "template.prior_turn.kind",
                "TELEMETRY",
            ),
            (format!("{base}[0].text"), text_path, "MODEL_OUTPUT"),
            (
                format!("{base}[1].kind"),
                "template.prior_turn.kind",
                "TELEMETRY",
            ),
            (format!("{base}[1].id"), id_path, "MODEL_OUTPUT"),
            (format!("{base}[1].name"), name_path, "MODEL_OUTPUT"),
            (format!("{base}[1].input.depth"), depth_path, "MODEL_OUTPUT"),
            (
                format!("{base}[1].input.family_id"),
                family_path,
                "MODEL_OUTPUT",
            ),
        ];
        let records = model_output_records(&assembled.provenance);
        assert_eq!(
            records.len(),
            expected_sources.len(),
            "{adapter}: {records:#?}"
        );
        let response_hash = blake3_hash(&response);
        for (prompt_path, source_path, class) in &expected_sources {
            let record = records
                .iter()
                .find(|record| record["prompt_path"] == prompt_path.as_str())
                .unwrap_or_else(|| panic!("{adapter}: no record for {prompt_path}"));
            assert_eq!(
                record["source_path"], *source_path,
                "{adapter} {prompt_path}"
            );
            assert_eq!(record["boundary_class"], *class, "{adapter} {prompt_path}");
            assert_eq!(
                record["admitted_boundary_modes"],
                json!(["ANNOTATED", "TELEMETRY_ONLY"]),
                "{adapter} {prompt_path}"
            );
            if *class == "MODEL_OUTPUT" {
                assert_eq!(record["source_artifact_hash"], response_hash.as_str());
                assert_eq!(record["policy_rule_id"], "chain.model_output");
                assert_eq!(record["transformation_kind"], "COPY");
            }
        }
    }
}

#[test]
fn assembling_with_a_response_twice_gives_identical_bytes() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let response = response_bytes(adapter, |_| {});
        let policy = work.policy("p.yaml", "");
        let chain = work.chain(adapter, &response, "t");
        let first = work.assemble(&policy, "TELEMETRY_ONLY", "a", Some(&chain));
        let second = work.assemble(&policy, "TELEMETRY_ONLY", "b", Some(&chain));
        assert_eq!(first.output.status.code(), Some(0), "{adapter}");
        assert_eq!(
            fs::read(&first.prompt).expect("read"),
            fs::read(&second.prompt).expect("read"),
            "{adapter}: prompt"
        );
        assert_eq!(
            fs::read(&first.provenance).expect("read"),
            fs::read(&second.provenance).expect("read"),
            "{adapter}: provenance"
        );
    }
}

#[test]
fn a_response_altered_by_one_byte_is_refused_and_nothing_is_written() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let response = response_bytes(adapter, |_| {});
        let policy = work.policy("p.yaml", "");
        let honest = work.chain(adapter, &response, "t");
        // The receipt still records the honest hash; the response on disk differs by one byte.
        let mut altered = response.clone();
        altered.push(b' ');
        fs::write(&honest.response, &altered).expect("alter response");

        let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", Some(&honest));
        assert_eq!(assembled.output.status.code(), Some(2), "{adapter}");
        let refusal = assembled.refusal();
        assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT", "{adapter}");
        assert_eq!(
            refusal["refusal"]["detail"]["field"], "prior_receipt.response_hash",
            "{adapter}"
        );
        assert_eq!(
            refusal["refusal"]["detail"]["receipt_response_hash"],
            blake3_hash(&response).as_str()
        );
        assert_eq!(
            refusal["refusal"]["detail"]["response_hash"],
            blake3_hash(&altered).as_str()
        );
        assert!(
            !assembled.prompt.exists(),
            "{adapter}: no prompt on refusal"
        );
        assert!(
            !assembled.provenance.exists(),
            "{adapter}: no provenance on refusal"
        );
    }
}

#[test]
fn receipts_that_cannot_anchor_a_chain_are_refused_by_field() {
    type Edit = fn(&mut Value);
    let cases: [(&str, Edit); 6] = [
        ("prior_receipt.blocked", |r| r["blocked"] = json!(true)),
        ("prior_receipt.upstream_status", |r| {
            r["upstream_status"] = json!(500)
        }),
        ("prior_receipt.gate_version", |r| {
            r["gate_version"] = json!("airlock.gate.v0")
        }),
        ("prior_receipt.response_hash", |r| {
            r.as_object_mut()
                .expect("receipt object")
                .remove("response_hash");
        }),
        // A policy-proxy receipt records no matched manifest.
        ("prior_receipt.matched_manifest_hash", |r| {
            r.as_object_mut()
                .expect("receipt object")
                .remove("matched_manifest_hash");
        }),
        ("prior_receipt.response_hash", |r| {
            r["response_hash"] = json!(blake3_hash(b"some other response"));
        }),
    ];
    for (expected_field, edit) in cases {
        let work = Work::new();
        let response = response_bytes(ANTHROPIC, |_| {});
        let policy = work.policy("p.yaml", "");
        let chain = work.chain(ANTHROPIC, &response, "t");
        let mut receipt = read_json(&chain.receipt);
        edit(&mut receipt);
        fs::write(
            &chain.receipt,
            serde_json::to_vec(&receipt).expect("serialize"),
        )
        .expect("write receipt");

        let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", Some(&chain));
        assert_eq!(assembled.output.status.code(), Some(2), "{expected_field}");
        let refusal = assembled.refusal();
        assert_eq!(
            refusal["refusal"]["code"], "E_BAD_INPUT",
            "{expected_field}"
        );
        assert_eq!(refusal["refusal"]["detail"]["field"], expected_field);
        assert!(
            !assembled.prompt.exists(),
            "{expected_field}: nothing written"
        );
    }
}

#[test]
fn responses_that_are_not_model_output_are_refused_even_with_a_matching_receipt() {
    type Edit = fn(&mut Value);
    let cases: [(&str, &str, Edit, &str); 5] = [
        (
            ANTHROPIC,
            "an error body",
            |r| {
                *r =
                    json!({"type": "error", "error": {"type": "overloaded_error", "message": "x"}});
            },
            "type",
        ),
        (
            ANTHROPIC,
            "only thinking",
            |r| {
                set(
                    r,
                    "/content",
                    json!([{"type": "thinking", "thinking": "x", "signature": "s"}]),
                );
            },
            "content",
        ),
        (
            OPENAI,
            "an error object",
            |r| {
                r["error"] = json!({"code": "server_error", "message": "x"});
            },
            "error",
        ),
        (
            OPENAI,
            "only reasoning",
            |r| {
                set(
                    r,
                    "/output",
                    json!([{"type": "reasoning", "id": "rs_1", "summary": []}]),
                );
            },
            "output",
        ),
        (
            OPENAI,
            "not a Responses object",
            |r| r["object"] = json!("chat.completion"),
            "object",
        ),
    ];
    for (adapter, label, edit, expected_field) in cases {
        let work = Work::new();
        let response = response_bytes(adapter, edit);
        let policy = work.policy("p.yaml", "");
        let chain = work.chain(adapter, &response, "t");
        let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", Some(&chain));
        assert_eq!(assembled.output.status.code(), Some(2), "{adapter} {label}");
        let refusal = assembled.refusal();
        assert_eq!(
            refusal["refusal"]["code"], "E_BAD_INPUT",
            "{adapter} {label}"
        );
        assert_eq!(
            refusal["refusal"]["detail"]["field"], expected_field,
            "{adapter} {label}"
        );
        assert!(
            !assembled.prompt.exists(),
            "{adapter} {label}: nothing written"
        );
    }
}

#[test]
fn a_streamed_body_and_an_adapter_without_an_unwrapper_are_refused() {
    let work = Work::new();
    let policy = work.policy("p.yaml", "");

    let sse = b"data: {\"type\":\"response.output_text.delta\"}\n\n".to_vec();
    let chain = work.chain(OPENAI, &sse, "sse");
    let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "sse", Some(&chain));
    assert_eq!(assembled.output.status.code(), Some(2));
    assert!(
        assembled.refusal()["refusal"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("streamed responses are not supported")),
        "{:?}",
        assembled.refusal()
    );

    let response = response_bytes(OPENAI, |_| {});
    let chain = work.chain("gemini_generate_content", &response, "gem");
    let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "gem", Some(&chain));
    assert_eq!(assembled.output.status.code(), Some(2));
    let refusal = assembled.refusal();
    assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT");
    assert_eq!(
        refusal["refusal"]["detail"]["supported"],
        json!(["openai_responses", "anthropic_messages"])
    );
}

#[test]
fn the_three_chain_flags_come_only_together() {
    let work = Work::new();
    let response = response_bytes(OPENAI, |_| {});
    let chain = work.chain(OPENAI, &response, "t");
    let policy = work.policy("p.yaml", "");
    for flags in [
        vec![
            "--response".to_owned(),
            chain.response.display().to_string(),
        ],
        vec![
            "--prior-receipt".to_owned(),
            chain.receipt.display().to_string(),
        ],
        vec!["--response-adapter".to_owned(), OPENAI.to_owned()],
    ] {
        let prompt = work.path("lone.prompt.json");
        let output = Command::cargo_bin("airlock")
            .expect("airlock binary")
            .args(["assemble", "--policy"])
            .arg(&policy)
            .arg("--input")
            .arg(repo("fixtures/annotated_mode/strategy_space.json"))
            .arg("--out")
            .arg(&prompt)
            .arg("--provenance-out")
            .arg(work.path("lone.provenance.json"))
            .arg("--no-witness")
            .args(&flags)
            .output()
            .expect("run assemble");
        assert_ne!(
            output.status.code(),
            Some(0),
            "{flags:?} must not be accepted alone"
        );
        assert!(!prompt.exists(), "{flags:?}: nothing written");
    }
}

#[test]
fn a_policy_cannot_assign_model_output_or_use_the_reserved_key() {
    let work = Work::new();
    let response = response_bytes(ANTHROPIC, |_| {});
    let chain = work.chain(ANTHROPIC, &response, "t");

    let relabel = work.policy_with_rule(
        "relabel.yaml",
        "  - key_path: extra_note\n    boundary_class: MODEL_OUTPUT\n",
    );
    let reserved =
        work.policy_with_rule("reserved.yaml", "  - key_path: prior_turn.model_output\n");
    for (label, policy, with_chain) in [
        ("MODEL_OUTPUT override", &relabel, false),
        ("MODEL_OUTPUT override with a response", &relabel, true),
        ("reserved key", &reserved, false),
        ("reserved key with a response", &reserved, true),
    ] {
        let assembled = work.assemble(policy, "TELEMETRY_ONLY", "t", with_chain.then_some(&chain));
        assert_eq!(assembled.output.status.code(), Some(2), "{label}");
        assert_eq!(
            assembled.refusal()["refusal"]["code"],
            "E_BAD_POLICY",
            "{label}"
        );
        assert!(!assembled.prompt.exists(), "{label}: nothing written");
    }
}

// --- what verify makes of it ----------------------------------------------------------------

#[test]
fn without_a_blocking_detector_pack_model_output_caps_the_claim_and_says_why() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let observed = work.turn(
            "",
            "TELEMETRY_ONLY",
            adapter,
            &response_bytes(adapter, |_| {}),
            "t",
        );
        assert_eq!(observed.exit, 0, "{adapter}: {observed:?}");
        assert_eq!(observed.binding, "BOUND", "{adapter}");
        assert_eq!(
            observed.claim, "RAW_DOCUMENT_ABSENT",
            "{adapter}: {observed:?}"
        );
        let reason = observed.strict_reason.unwrap_or_default();
        assert!(
            reason.contains("model output from an earlier turn"),
            "{adapter}: the cap must be explained, got {reason:?}"
        );
        assert_eq!(
            observed.strict_paths,
            vec!["messages[1].content.prior_turn".to_owned()],
            "{adapter}"
        );
    }
}

#[test]
fn model_output_screened_clean_by_a_blocking_pack_earns_strict_in_telemetry_only() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let observed = work.turn(
            ALL_PACKS,
            "TELEMETRY_ONLY",
            adapter,
            &response_bytes(adapter, |_| {}),
            "t",
        );
        assert_eq!(observed.exit, 0, "{adapter}: {observed:?}");
        assert_eq!(
            observed.claim, "STRICT_TELEMETRY_ONLY",
            "{adapter}: {observed:?}"
        );
        assert!(
            observed.findings.is_empty(),
            "{adapter}: the fixture text must pass every pack, got {:?}",
            observed.findings
        );
    }
}

#[test]
fn annotated_mode_keeps_its_ceiling_with_clean_model_output() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let observed = work.turn(
            ALL_PACKS,
            "ANNOTATED",
            adapter,
            &response_bytes(adapter, |_| {}),
            "t",
        );
        assert_eq!(observed.exit, 0, "{adapter}");
        assert_eq!(
            observed.claim, "RAW_DOCUMENT_ABSENT",
            "{adapter}: {observed:?}"
        );
    }
}

#[test]
fn a_secret_in_model_text_or_in_a_tool_call_fails_the_boundary_under_a_blocking_pack() {
    for adapter in ADAPTERS {
        let leak_in_text = response_bytes(adapter, |r| {
            set(
                r,
                text_pointer(adapter),
                json!(format!("The key is {FAKE_AWS_KEY} for the lookup.")),
            );
        });
        let leak_in_tool_call = response_bytes(adapter, |r| {
            if adapter == OPENAI {
                set(
                    r,
                    "/output/2/arguments",
                    json!(format!("{{\"family_id\":\"{FAKE_AWS_KEY}\",\"depth\":2}}")),
                );
            } else {
                set(r, "/content/2/input/family_id", json!(FAKE_AWS_KEY));
            }
        });
        for (label, response) in [("text", leak_in_text), ("tool call", leak_in_tool_call)] {
            let work = Work::new();
            let observed = work.turn(ALL_PACKS, "TELEMETRY_ONLY", adapter, &response, "t");
            assert_eq!(observed.exit, 1, "{adapter} {label}: {observed:?}");
            assert_eq!(observed.claim, "BOUNDARY_FAILED", "{adapter} {label}");
            assert!(
                observed
                    .findings
                    .contains("DETECTED_SENSITIVE:SECRET_AWS_ACCESS_KEY"),
                "{adapter} {label}: {:?}",
                observed.findings
            );
        }
    }
}

#[test]
fn forbidden_patterns_apply_to_model_output_even_with_no_detector_pack() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let response = response_bytes(adapter, |r| {
            set(
                r,
                text_pointer(adapter),
                json!("Rendering <table><tr><td>x</td></tr></table> now."),
            );
        });
        let observed = work.turn("", "TELEMETRY_ONLY", adapter, &response, "t");
        assert_eq!(observed.exit, 1, "{adapter}: {observed:?}");
        assert_eq!(observed.claim, "BOUNDARY_FAILED", "{adapter}");
        assert!(
            observed.findings.contains("raw_html"),
            "{adapter}: {:?}",
            observed.findings
        );
    }
}

#[test]
fn packs_that_only_warn_never_screen_model_output() {
    for adapter in ADAPTERS {
        // All packs warn-only and a clean response: no pack blocks, so nothing screened it.
        let work = Work::new();
        let clean = work.turn(
            ALL_PACKS_WARN_ONLY,
            "TELEMETRY_ONLY",
            adapter,
            &response_bytes(adapter, |_| {}),
            "clean",
        );
        assert_eq!(clean.exit, 0, "{adapter}: {clean:?}");
        assert_eq!(clean.claim, "RAW_DOCUMENT_ABSENT", "{adapter}: {clean:?}");

        // One blocking pack, one warn-only pack that finds a secret: a blocking pack exists, but
        // the response is not clean. The warn-only hit does not fail the boundary; it caps the claim.
        let leak = response_bytes(adapter, |r| {
            set(
                r,
                text_pointer(adapter),
                json!(format!("The key is {FAKE_AWS_KEY} for the lookup.")),
            );
        });
        let work = Work::new();
        let dirty = work.turn(
            ONE_BLOCKING_ONE_WARN,
            "TELEMETRY_ONLY",
            adapter,
            &leak,
            "dirty",
        );
        assert_eq!(dirty.exit, 0, "{adapter}: {dirty:?}");
        assert_eq!(dirty.claim, "RAW_DOCUMENT_ABSENT", "{adapter}: {dirty:?}");
        assert!(
            dirty
                .findings
                .contains("DETECTED_SENSITIVE:SECRET_AWS_ACCESS_KEY"),
            "{adapter}: the warn-only hit is still reported: {:?}",
            dirty.findings
        );
    }
}

#[test]
fn deleting_the_model_output_provenance_labels_does_not_lift_the_cap() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy("p.yaml", "");
        let chain = work.chain(adapter, &response_bytes(adapter, |_| {}), "t");
        let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", Some(&chain));
        assert_eq!(assembled.output.status.code(), Some(0), "{adapter}");

        let mut provenance = read_json(&assembled.provenance);
        let records = provenance["records"].as_array_mut().expect("records array");
        let before = records.len();
        records.retain(|record| record["boundary_class"] != "MODEL_OUTPUT");
        assert!(
            records.len() < before,
            "{adapter}: the test must delete something"
        );
        let stripped = work.write(
            "stripped.provenance.json",
            &serde_json::to_vec(&provenance).expect("serialize"),
        );
        let request = json!({
            "model": "gpt-5",
            "messages": read_json(&assembled.prompt)["messages"].clone(),
        });
        let observed =
            work.verify_request(&policy, &assembled.prompt, &stripped, &request, "stripped");
        assert!(
            observed.findings.contains("provenance_gap"),
            "{adapter}: the gap is recorded: {:?}",
            observed.findings
        );
        assert_eq!(
            observed.claim, "RAW_DOCUMENT_ABSENT",
            "{adapter}: the cap comes from the prompt's structure, not its labels: {observed:?}"
        );
    }
}

#[test]
fn a_prompt_with_no_response_still_earns_strict_under_a_policy_with_no_detectors() {
    // Control: the cap is specific to model output. Nothing changes for a turn without one.
    let work = Work::new();
    let policy = work.policy("p.yaml", "");
    let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "plain", None);
    assert_eq!(assembled.output.status.code(), Some(0));
    assert!(read_json(&assembled.prompt)["messages"][1]["content"]["prior_turn"].is_null());
    let observed = work.verify(&policy, &assembled, "plain");
    assert_eq!(observed.claim, "STRICT_TELEMETRY_ONLY", "{observed:?}");
}

// --- the adapters carry the new content -----------------------------------------------------

#[test]
fn the_adapters_restore_a_prompt_that_carries_prior_turn_exactly() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy("p.yaml", "");
        let chain = work.chain(adapter, &response_bytes(adapter, |_| {}), "t");
        let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", Some(&chain));
        let prompt = read_json(&assembled.prompt);

        let mut config = TransportConfig::new("model-under-test");
        config.max_tokens = Some(64);
        let (wire, restored) = if adapter == OPENAI {
            let wire = OpenAiResponsesAdapter.wrap(&prompt, &config).expect("wrap");
            let restored = OpenAiResponsesAdapter.unwrap(&wire).expect("unwrap");
            (wire, restored)
        } else {
            let wire = AnthropicMessagesAdapter
                .wrap(&prompt, &config)
                .expect("wrap");
            let restored = AnthropicMessagesAdapter.unwrap(&wire).expect("unwrap");
            (wire, restored)
        };
        assert_eq!(
            restored["messages"], prompt["messages"],
            "{adapter}: binding compares these, so they must be identical"
        );
        assert!(wire.is_object(), "{adapter}");
    }
}

// --- a receipt the real gate wrote ----------------------------------------------------------

struct Origin {
    address: SocketAddr,
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

/// A loopback origin that answers every request with `reply`.
fn start_origin(reply: Vec<u8>) -> Origin {
    let server = Server::http("127.0.0.1:0").expect("bind origin");
    let address = server.server_addr().to_ip().expect("origin address");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            let mut request = match server.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(request)) => request,
                Ok(None) => continue,
                Err(_) => break,
            };
            let mut body = Vec::new();
            let _ = request.as_reader().read_to_end(&mut body);
            let _ = request.respond(Response::from_data(reply.clone()));
        }
    });
    Origin {
        address,
        stop,
        worker: Some(worker),
    }
}

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

fn start_strict_gate(
    upstream: SocketAddr,
    manifests: &Path,
    receipts: &Path,
    witness: &Path,
) -> Gate {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["gate", "--mode", "strict-manifest", "--upstream"])
        .arg(format!("http://{upstream}"))
        .args(["--listen", "127.0.0.1:0", "--manifest-dir"])
        .arg(manifests)
        .arg("--out-dir")
        .arg(receipts)
        // No default signing key may be picked up from whoever runs the tests.
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .env("EPISTEMIC_WITNESS", witness)
        .env_remove("ALL_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("NO_PROXY")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start gate");
    let mut stderr = BufReader::new(child.stderr.take().expect("gate stderr"));
    let mut line = String::new();
    stderr.read_line(&mut line).expect("gate first line");
    let address = line
        .trim()
        .strip_prefix("airlock gate listening on ")
        .unwrap_or_else(|| panic!("gate did not start: {line}"))
        .parse()
        .expect("gate address");
    // Keep draining stderr so the gate never blocks on a full pipe.
    thread::spawn(move || for _ in stderr.lines().map_while(Result::ok) {});
    Gate { child, address }
}

fn wait_for_forwarded_receipt(directory: &Path) -> (PathBuf, Value) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        for entry in fs::read_dir(directory).into_iter().flatten().flatten() {
            let path = entry.path();
            if let Some(receipt) = fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                && receipt["response_hash"].is_string()
            {
                return (path, receipt);
            }
        }
        assert!(
            Instant::now() < deadline,
            "the gate wrote no forwarded receipt"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_receipt_the_real_gate_wrote_anchors_the_chain() {
    let work = Work::new();
    let policy = work.policy("p.yaml", ALL_PACKS);

    // Turn 0: assemble, verify into a manifest directory the strict gate reads.
    let turn0 = work.assemble(&policy, "TELEMETRY_ONLY", "turn0", None);
    assert_eq!(turn0.output.status.code(), Some(0));
    let request = serde_json::to_vec(&json!({
        "model": "gpt-5",
        "messages": read_json(&turn0.prompt)["messages"].clone(),
    }))
    .expect("serialize request");
    let request_path = work.write("turn0.request.json", &request);
    let manifests = work.path("manifests");
    fs::create_dir(&manifests).expect("manifest dir");
    let verified = Command::cargo_bin("airlock")
        .expect("airlock binary")
        .args(["verify", "--no-sign", "--no-witness", "--policy"])
        .arg(&policy)
        .arg("--prompt")
        .arg(&turn0.prompt)
        .arg("--provenance")
        .arg(&turn0.provenance)
        .arg("--request")
        .arg(&request_path)
        .arg("--out")
        .arg(manifests.join("turn0.json"))
        .output()
        .expect("run verify");
    assert_eq!(verified.status.code(), Some(0), "turn 0 must verify");

    // The model's reply goes through the real gate, which records the receipt.
    let reply = response_bytes(ANTHROPIC, |_| {});
    let origin = start_origin(reply.clone());
    let receipts = work.path("receipts");
    let gate = start_strict_gate(
        origin.address,
        &manifests,
        &receipts,
        &work.path("witness.jsonl"),
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let response = agent
        .post(&format!("http://{}/v1/chat/completions", gate.address))
        .header("Content-Type", "application/json")
        .send(request.clone())
        .expect("post through the gate");
    assert_eq!(
        response.status().as_u16(),
        200,
        "the gate must forward the matched request"
    );
    let mut relayed = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut relayed)
        .expect("read relayed response");
    assert_eq!(relayed, reply, "the gate relays the origin's bytes");
    let (receipt_path, receipt) = wait_for_forwarded_receipt(&receipts);
    assert_eq!(receipt["blocked"], false);
    assert_eq!(receipt["upstream_status"], 200);
    drop(gate);

    // Turn 1: the gate's own receipt and the bytes the client received.
    let response_path = work.write("turn0.response.json", &relayed);
    let chain = Chain {
        adapter: ANTHROPIC.to_owned(),
        response: response_path,
        receipt: receipt_path,
    };
    let turn1 = work.assemble(&policy, "TELEMETRY_ONLY", "turn1", Some(&chain));
    assert_eq!(
        turn1.output.status.code(),
        Some(0),
        "assemble refused the gate's own receipt: {}",
        String::from_utf8_lossy(&turn1.output.stdout)
    );
    let records = model_output_records(&turn1.provenance);
    assert!(
        records
            .iter()
            .filter(|record| record["boundary_class"] == "MODEL_OUTPUT")
            .all(|record| record["source_artifact_hash"] == receipt["response_hash"]),
        "every MODEL_OUTPUT record names the response hash the gate recorded"
    );
    let observed = work.verify(&policy, &turn1, "turn1");
    assert_eq!(observed.claim, "STRICT_TELEMETRY_ONLY", "{observed:?}");
}
