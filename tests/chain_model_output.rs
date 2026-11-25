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
use airlock::hash::{blake3_hash, jcs_blake3_hash};
use airlock::manifest::AirlockManifest;
use airlock::output::canonical_json_bytes;
use assert_cmd::Command;
use jsonschema::validator_for;
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

/// A receipt as `airlock gate` writes one for an admitted, forwarded, 200 exchange that matched
/// the manifest whose hash is `matched_manifest_hash`.
fn receipt_for(response: &[u8], matched_manifest_hash: &str) -> Value {
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
        "matched_manifest_hash": matched_manifest_hash,
    })
}

/// A manifest's hash as the gate computes it: the canonical JSON of the parsed manifest.
fn manifest_hash(path: &Path) -> String {
    serde_json::from_slice::<AirlockManifest>(&fs::read(path).expect("read manifest"))
        .unwrap_or_else(|error| panic!("parse manifest {}: {error}", path.display()))
        .hash()
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
    /// The manifest of the earlier turn; the receipt's matched_manifest_hash is its hash.
    prior_manifest: PathBuf,
    /// Raw `--tool-result` values, `TOOL_USE_ID=PATH`.
    tool_results: Vec<String>,
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

    /// A real turn-0 manifest: assemble and verify with no chain under the baseline policy.
    /// Returns its path.
    fn turn_zero(&self, stem: &str) -> PathBuf {
        let policy = self.policy(&format!("{stem}.policy.yaml"), "");
        let assembled = self.assemble(&policy, "TELEMETRY_ONLY", stem, None);
        assert_eq!(
            assembled.output.status.code(),
            Some(0),
            "turn 0 assemble refused: {}",
            String::from_utf8_lossy(&assembled.output.stdout)
        );
        let observed = self.verify(&policy, &assembled, stem);
        assert_eq!(observed.exit, 0, "turn 0 must verify: {observed:?}");
        self.path(&format!("{stem}.manifest.json"))
    }

    /// A chain whose prior turn is a real manifest and whose receipt names exactly that manifest.
    fn chain(&self, adapter: &str, response: &[u8], stem: &str) -> Chain {
        let prior_manifest = self.turn_zero(&format!("{stem}.turn0"));
        Chain {
            adapter: adapter.to_owned(),
            response: self.write(&format!("{stem}.response.json"), response),
            receipt: self.write(
                &format!("{stem}.receipt.json"),
                &serde_json::to_vec(&receipt_for(response, &manifest_hash(&prior_manifest)))
                    .expect("serialize receipt"),
            ),
            prior_manifest,
            tool_results: Vec::new(),
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
                .args(["--response-adapter", &chain.adapter])
                .arg("--prior-manifest")
                .arg(&chain.prior_manifest);
            for spec in &chain.tool_results {
                command.args(["--tool-result", spec]);
            }
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
fn the_four_chain_flags_come_only_together() {
    // al-210 D-c added --prior-manifest to what D-a called "the three chain flags" (named in the
    // evidence): each flag alone, and every set missing exactly one, must be refused.
    let work = Work::new();
    let response = response_bytes(OPENAI, |_| {});
    let chain = work.chain(OPENAI, &response, "t");
    let policy = work.policy("p.yaml", "");
    let all = [
        ("--prior-receipt", chain.receipt.display().to_string()),
        ("--response", chain.response.display().to_string()),
        ("--response-adapter", OPENAI.to_owned()),
        (
            "--prior-manifest",
            chain.prior_manifest.display().to_string(),
        ),
    ];
    let mut sets: Vec<Vec<String>> = Vec::new();
    for (index, (flag, value)) in all.iter().enumerate() {
        // The flag alone.
        sets.push(vec![(*flag).to_owned(), value.clone()]);
        // Every flag but this one.
        sets.push(
            all.iter()
                .enumerate()
                .filter(|(other, _)| *other != index)
                .flat_map(|(_, (flag, value))| [(*flag).to_owned(), value.clone()])
                .collect(),
        );
    }
    for flags in sets {
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
        prior_manifest: manifests.join("turn0.json"),
        tool_results: Vec::new(),
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
    // The hash `assemble` computed for the prior manifest is the one the real gate stamped into
    // its receipt, so a chain link can be walked back to the receipt that anchors it.
    assert_eq!(
        read_json(&turn1.provenance)["chain"],
        json!({
            "prior_manifest_hash": receipt["matched_manifest_hash"],
            "turn_index": 1,
        }),
        "the link names the manifest the real gate matched"
    );
    let observed = work.verify(&policy, &turn1, "turn1");
    assert_eq!(observed.claim, "STRICT_TELEMETRY_ONLY", "{observed:?}");
}

// --- tool results (al-210 D-b) --------------------------------------------------------------

/// A tool-result artifact with a non-ASCII character and a trailing newline, so a passing test
/// shows the bytes crossed verbatim: no trimming, no normalization.
const TOOL_ARTIFACT: &str = "{\"family_id\":\"F-17\",\"lineage\":[\"F-3\",\"F-9\"],\"depth\":2,\"note\":\"café lineage\"}\n";
const PRIOR_TURN_PATH: &str = "messages[1].content.prior_turn";
const TOOL_RESULTS_PATH: &str = "messages[1].content.prior_turn.tool_results";
const TOOL_RESULT_POINTER: &str = "/messages/1/content/prior_turn/tool_results/0";

/// The `tool_use` id in the response fixture for `adapter`.
fn call_id(adapter: &str) -> &'static str {
    match adapter {
        OPENAI => "call_fx_0001",
        _ => "toolu_fx_0001",
    }
}

/// Where that id sits in the response fixture.
fn call_id_source(adapter: &str) -> &'static str {
    match adapter {
        OPENAI => "output[2].call_id",
        _ => "content[2].id",
    }
}

/// `declared_tool_results` YAML for these artifacts' exact texts.
fn declaring(artifacts: &[&str]) -> String {
    let mut yaml = String::from("declared_tool_results:\n");
    for artifact in artifacts {
        yaml.push_str(&format!(
            "  - artifact_hash: {}\n    description: test artifact\n",
            blake3_hash(artifact.as_bytes())
        ));
    }
    yaml
}

impl Work {
    /// A chain whose response's tool call is answered by `artifact`.
    fn chain_with_tool_result(&self, adapter: &str, stem: &str, artifact: &str) -> Chain {
        let mut chain = self.chain(adapter, &response_bytes(adapter, |_| {}), stem);
        let path = self.write(&format!("{stem}.tool.txt"), artifact.as_bytes());
        chain
            .tool_results
            .push(format!("{}={}", call_id(adapter), path.display()));
        chain
    }

    /// Assemble `chain` in TELEMETRY_ONLY under `policy`, requiring success.
    fn assemble_chain(&self, policy: &Path, stem: &str, chain: &Chain) -> Assembled {
        let assembled = self.assemble(policy, "TELEMETRY_ONLY", stem, Some(chain));
        assert_eq!(
            assembled.output.status.code(),
            Some(0),
            "assemble refused: {}",
            String::from_utf8_lossy(&assembled.output.stdout)
        );
        assembled
    }
}

fn record_at(records: &[Value], prompt_path: &str) -> Value {
    records
        .iter()
        .find(|record| record["prompt_path"] == prompt_path)
        .cloned()
        .unwrap_or_else(|| panic!("no provenance record for {prompt_path}"))
}

fn provenance_schema() -> jsonschema::Validator {
    validator_for(&read_json(&repo("schemas/prompt_provenance.schema.json")))
        .expect("compile the provenance schema")
}

#[test]
fn a_declared_tool_result_earns_strict_and_every_leaf_has_a_record() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy(
            "p.yaml",
            &format!("{ALL_PACKS}{}", declaring(&[TOOL_ARTIFACT])),
        );
        let chain = work.chain_with_tool_result(adapter, "t", TOOL_ARTIFACT);
        let assembled = work.assemble_chain(&policy, "t", &chain);

        assert_eq!(
            read_json(&assembled.prompt)["messages"][1]["content"]["prior_turn"]["tool_results"],
            json!([{
                "kind": "tool_result",
                "tool_use_id": call_id(adapter),
                "content": TOOL_ARTIFACT,
            }]),
            "{adapter}"
        );

        let records = model_output_records(&assembled.provenance);
        let under_result = records
            .iter()
            .filter(|record| {
                record["prompt_path"]
                    .as_str()
                    .is_some_and(|path| path.starts_with(&format!("{TOOL_RESULTS_PATH}[0]")))
            })
            .count();
        assert_eq!(under_result, 3, "{adapter}: kind, tool_use_id and content");

        let kind = record_at(&records, &format!("{TOOL_RESULTS_PATH}[0].kind"));
        assert_eq!(kind["boundary_class"], "TELEMETRY", "{adapter}");
        assert_eq!(kind["source_path"], "template.prior_turn.kind", "{adapter}");
        assert_eq!(kind["policy_rule_id"], "chain.kind", "{adapter}");

        let id = record_at(&records, &format!("{TOOL_RESULTS_PATH}[0].tool_use_id"));
        assert_eq!(id["boundary_class"], "MODEL_OUTPUT", "{adapter}");
        assert_eq!(id["source_path"], call_id_source(adapter), "{adapter}");
        assert_eq!(
            id["source_artifact_hash"],
            blake3_hash(&response_bytes(adapter, |_| {})).as_str(),
            "{adapter}"
        );

        let content = record_at(&records, &format!("{TOOL_RESULTS_PATH}[0].content"));
        assert_eq!(content["boundary_class"], "TOOL_RESULT", "{adapter}");
        assert_eq!(content["policy_rule_id"], "chain.tool_result", "{adapter}");
        assert_eq!(content["transformation_kind"], "COPY", "{adapter}");
        assert_eq!(
            content["source_artifact_hash"],
            blake3_hash(TOOL_ARTIFACT.as_bytes()).as_str(),
            "{adapter}: the hash of the artifact's exact bytes"
        );
        assert_eq!(
            content["source_path"],
            format!("tool_result.{}", call_id(adapter)).as_str(),
            "{adapter}"
        );
        assert_eq!(
            content["admitted_boundary_modes"],
            json!(["ANNOTATED", "TELEMETRY_ONLY"]),
            "{adapter}"
        );

        provenance_schema()
            .validate(&read_json(&assembled.provenance))
            .unwrap_or_else(|error| panic!("{adapter}: provenance fails its schema: {error}"));

        let observed = work.verify(&policy, &assembled, "t");
        assert_eq!(observed.exit, 0, "{adapter}: {observed:?}");
        assert_eq!(
            observed.claim, "STRICT_TELEMETRY_ONLY",
            "{adapter}: {observed:?}"
        );
        assert!(
            observed.findings.is_empty(),
            "{adapter}: {:?}",
            observed.findings
        );
    }
}

#[test]
fn an_undeclared_tool_result_crosses_but_caps_the_claim_and_is_recorded_as_derived_text() {
    for adapter in ADAPTERS {
        // Two ways to be undeclared: the policy declares nothing, or declares some other artifact.
        for (label, declared) in [
            ("nothing declared", String::new()),
            (
                "another artifact declared",
                declaring(&["some other artifact\n"]),
            ),
        ] {
            let work = Work::new();
            let policy = work.policy("p.yaml", &format!("{ALL_PACKS}{declared}"));
            let chain = work.chain_with_tool_result(adapter, "t", TOOL_ARTIFACT);
            let assembled = work.assemble_chain(&policy, "t", &chain);

            assert_eq!(
                read_json(&assembled.prompt)["messages"][1]["content"]["prior_turn"]["tool_results"]
                    [0]["content"],
                TOOL_ARTIFACT,
                "{adapter} {label}: the content still crosses"
            );
            let records = model_output_records(&assembled.provenance);
            let content = record_at(&records, &format!("{TOOL_RESULTS_PATH}[0].content"));
            assert_eq!(
                content["boundary_class"], "DERIVED_TEXT",
                "{adapter} {label}"
            );
            assert_eq!(
                content["policy_rule_id"], "chain.tool_result.undeclared",
                "{adapter} {label}"
            );
            provenance_schema()
                .validate(&read_json(&assembled.provenance))
                .unwrap_or_else(|error| {
                    panic!("{adapter} {label}: provenance fails its schema: {error}")
                });

            let observed = work.verify(&policy, &assembled, "t");
            assert_eq!(observed.exit, 0, "{adapter} {label}: {observed:?}");
            assert_eq!(
                observed.claim, "RAW_DOCUMENT_ABSENT",
                "{adapter} {label}: {observed:?}"
            );
            let reason = observed.strict_reason.clone().unwrap_or_default();
            assert!(
                reason.contains("not a declared artifact"),
                "{adapter} {label}: {reason:?}"
            );
            assert!(
                !reason.contains("model output from an earlier turn"),
                "{adapter} {label}: the model output was screened clean, so only the tool result is blamed: {reason:?}"
            );
            assert_eq!(
                observed.strict_paths,
                vec![format!("{TOOL_RESULTS_PATH}[0]")],
                "{adapter} {label}"
            );
        }
    }
}

#[test]
fn one_byte_of_difference_from_the_declared_artifact_makes_it_undeclared() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy(
            "p.yaml",
            &format!("{ALL_PACKS}{}", declaring(&[TOOL_ARTIFACT])),
        );

        let declared_chain = work.chain_with_tool_result(adapter, "same", TOOL_ARTIFACT);
        let declared = work.assemble_chain(&policy, "same", &declared_chain);
        let control = work.verify(&policy, &declared, "same");
        assert_eq!(
            control.claim, "STRICT_TELEMETRY_ONLY",
            "{adapter}: the declared bytes: {control:?}"
        );

        let altered_text = format!("{TOOL_ARTIFACT} ");
        let altered_chain = work.chain_with_tool_result(adapter, "altered", &altered_text);
        let altered = work.assemble_chain(&policy, "altered", &altered_chain);
        let observed = work.verify(&policy, &altered, "altered");
        assert_eq!(
            observed.claim, "RAW_DOCUMENT_ABSENT",
            "{adapter}: one trailing space: {observed:?}"
        );
        assert!(
            observed
                .strict_reason
                .unwrap_or_default()
                .contains("not a declared artifact"),
            "{adapter}"
        );
    }
}

#[test]
fn provenance_labels_do_not_decide_the_tool_result_claim() {
    for adapter in ADAPTERS {
        let content_path = format!("{TOOL_RESULTS_PATH}[0].content");

        // An undeclared artifact whose content record is relabelled TOOL_RESULT is still capped.
        let work = Work::new();
        let policy = work.policy("p.yaml", ALL_PACKS);
        let chain = work.chain_with_tool_result(adapter, "t", TOOL_ARTIFACT);
        let assembled = work.assemble_chain(&policy, "t", &chain);
        let mut provenance = read_json(&assembled.provenance);
        let record = provenance["records"]
            .as_array_mut()
            .expect("records array")
            .iter_mut()
            .find(|record| record["prompt_path"] == content_path.as_str())
            .expect("the content record");
        record["boundary_class"] = json!("TOOL_RESULT");
        record["policy_rule_id"] = json!("chain.tool_result");
        let relabelled = work.write(
            "relabelled.provenance.json",
            &serde_json::to_vec(&provenance).expect("serialize"),
        );
        let request = json!({
            "model": "gpt-5",
            "messages": read_json(&assembled.prompt)["messages"].clone(),
        });
        let observed = work.verify_request(
            &policy,
            &assembled.prompt,
            &relabelled,
            &request,
            "relabelled",
        );
        assert_eq!(
            observed.claim, "RAW_DOCUMENT_ABSENT",
            "{adapter}: a label cannot declare an artifact: {observed:?}"
        );

        // A declared artifact whose records are deleted keeps its claim: the gap is advisory.
        let work = Work::new();
        let policy = work.policy(
            "p.yaml",
            &format!("{ALL_PACKS}{}", declaring(&[TOOL_ARTIFACT])),
        );
        let chain = work.chain_with_tool_result(adapter, "t", TOOL_ARTIFACT);
        let assembled = work.assemble_chain(&policy, "t", &chain);
        let mut provenance = read_json(&assembled.provenance);
        let records = provenance["records"].as_array_mut().expect("records array");
        let before = records.len();
        records.retain(|record| {
            !record["prompt_path"]
                .as_str()
                .is_some_and(|path| path.starts_with(TOOL_RESULTS_PATH))
        });
        assert_eq!(
            before - records.len(),
            3,
            "{adapter}: deletes the three records"
        );
        let stripped = work.write(
            "stripped.provenance.json",
            &serde_json::to_vec(&provenance).expect("serialize"),
        );
        let observed = work.verify_request(
            &policy,
            &assembled.prompt,
            &stripped,
            &json!({
                "model": "gpt-5",
                "messages": read_json(&assembled.prompt)["messages"].clone(),
            }),
            "stripped",
        );
        assert!(
            observed.findings.contains("provenance_gap"),
            "{adapter}: {:?}",
            observed.findings
        );
        assert_eq!(
            observed.claim, "STRICT_TELEMETRY_ONLY",
            "{adapter}: labels are advisory in both directions: {observed:?}"
        );
    }
}

#[test]
fn a_declared_tool_result_does_not_stand_in_for_the_detector_screen() {
    for adapter in ADAPTERS {
        // Declared, but the policy has no detector packs: the model output is unscreened, and that,
        // not the tool result, is what the reason names.
        let work = Work::new();
        let policy = work.policy("p.yaml", &declaring(&[TOOL_ARTIFACT]));
        let chain = work.chain_with_tool_result(adapter, "t", TOOL_ARTIFACT);
        let assembled = work.assemble_chain(&policy, "t", &chain);
        let observed = work.verify(&policy, &assembled, "t");
        assert_eq!(
            observed.claim, "RAW_DOCUMENT_ABSENT",
            "{adapter}: {observed:?}"
        );
        let reason = observed.strict_reason.clone().unwrap_or_default();
        assert!(
            reason.contains("model output from an earlier turn"),
            "{adapter}: {reason:?}"
        );
        assert!(
            !reason.contains("tool result from an earlier turn"),
            "{adapter}: {reason:?}"
        );
        assert_eq!(
            observed.strict_paths,
            vec![PRIOR_TURN_PATH.to_owned()],
            "{adapter}"
        );
    }
}

#[test]
fn one_reason_names_both_caps_when_both_apply() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy("p.yaml", "");
        let chain = work.chain_with_tool_result(adapter, "t", TOOL_ARTIFACT);
        let assembled = work.assemble_chain(&policy, "t", &chain);
        let observed = work.verify(&policy, &assembled, "t");
        assert_eq!(
            observed.claim, "RAW_DOCUMENT_ABSENT",
            "{adapter}: {observed:?}"
        );
        let reason = observed.strict_reason.clone().unwrap_or_default();
        assert!(
            reason.contains("model output from an earlier turn")
                && reason.contains("not a declared artifact"),
            "{adapter}: {reason:?}"
        );
        assert_eq!(
            observed.strict_paths,
            vec![
                PRIOR_TURN_PATH.to_owned(),
                format!("{TOOL_RESULTS_PATH}[0]")
            ],
            "{adapter}"
        );
    }
}

#[test]
fn declaring_an_artifact_does_not_exempt_it_from_the_detectors() {
    for adapter in ADAPTERS {
        let leaky = format!("{{\"token\":\"{FAKE_AWS_KEY}\"}}\n");
        let work = Work::new();
        let policy = work.policy(
            "p.yaml",
            &format!("{ALL_PACKS}{}", declaring(&[leaky.as_str()])),
        );
        let chain = work.chain_with_tool_result(adapter, "t", &leaky);
        let assembled = work.assemble_chain(&policy, "t", &chain);
        let observed = work.verify(&policy, &assembled, "t");
        assert_eq!(observed.exit, 1, "{adapter}: {observed:?}");
        assert_eq!(observed.claim, "BOUNDARY_FAILED", "{adapter}");
        assert!(
            observed
                .findings
                .contains("DETECTED_SENSITIVE:SECRET_AWS_ACCESS_KEY"),
            "{adapter}: {:?}",
            observed.findings
        );
    }
}

#[test]
fn the_tool_result_claim_follows_the_prompt_not_how_it_was_made() {
    type Edit = fn(&mut Value);
    let cases: [(&str, Edit, String); 5] = [
        (
            "tool_results is not a list",
            |p| {
                set(
                    p,
                    "/messages/1/content/prior_turn/tool_results",
                    json!("not a list"),
                )
            },
            TOOL_RESULTS_PATH.to_owned(),
        ),
        (
            "a smuggled key beside a declared content",
            |p| p.pointer_mut(TOOL_RESULT_POINTER).expect("entry")["note"] = json!("smuggled"),
            format!("{TOOL_RESULTS_PATH}[0]"),
        ),
        (
            "the wrong kind",
            |p| p.pointer_mut(TOOL_RESULT_POINTER).expect("entry")["kind"] = json!("text"),
            format!("{TOOL_RESULTS_PATH}[0]"),
        ),
        (
            "content edited after assembly",
            |p| {
                set(
                    p,
                    "/messages/1/content/prior_turn/tool_results/0/content",
                    json!(format!("{TOOL_ARTIFACT}tampered")),
                )
            },
            format!("{TOOL_RESULTS_PATH}[0]"),
        ),
        (
            "an entry that is a bare string",
            |p| set(p, TOOL_RESULT_POINTER, json!("a bare string")),
            format!("{TOOL_RESULTS_PATH}[0]"),
        ),
    ];
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy(
            "p.yaml",
            &format!("{ALL_PACKS}{}", declaring(&[TOOL_ARTIFACT])),
        );
        let chain = work.chain_with_tool_result(adapter, "t", TOOL_ARTIFACT);
        let assembled = work.assemble_chain(&policy, "t", &chain);
        let control = work.verify(&policy, &assembled, "control");
        assert_eq!(
            control.claim, "STRICT_TELEMETRY_ONLY",
            "{adapter}: the unedited prompt: {control:?}"
        );

        for (index, (label, edit, expected_path)) in cases.iter().enumerate() {
            let mut prompt = read_json(&assembled.prompt);
            edit(&mut prompt);
            // `verify` refuses a provenance whose prompt_payload_hash is not the prompt's, and
            // that hash is no secret. So each case is the self-consistent pair anyone editing
            // both files would produce: the edited prompt, and provenance carrying its hash.
            let mut provenance = read_json(&assembled.provenance);
            provenance["prompt_payload_hash"] =
                json!(jcs_blake3_hash(&prompt).expect("hash the edited prompt"));
            let prompt_path = work.write(
                &format!("case{index}.prompt.json"),
                &serde_json::to_vec(&prompt).expect("serialize"),
            );
            let provenance_path = work.write(
                &format!("case{index}.provenance.json"),
                &serde_json::to_vec(&provenance).expect("serialize"),
            );
            let request = json!({"model": "gpt-5", "messages": prompt["messages"].clone()});
            let observed = work.verify_request(
                &policy,
                &prompt_path,
                &provenance_path,
                &request,
                &format!("case{index}"),
            );
            assert_eq!(
                observed.claim, "RAW_DOCUMENT_ABSENT",
                "{adapter} {label}: {observed:?}"
            );
            assert!(
                observed.strict_paths.contains(expected_path),
                "{adapter} {label}: {:?}",
                observed.strict_paths
            );
            let reason = observed.strict_reason.clone().unwrap_or_default();
            assert!(
                reason.contains("not a declared artifact"),
                "{adapter} {label}: {reason:?}"
            );
        }
    }
}

struct Refused<'a> {
    label: &'a str,
    specs: Vec<String>,
    code: &'a str,
    field: Option<&'a str>,
}

#[test]
fn tool_results_that_cannot_be_admitted_are_refused_and_nothing_is_written() {
    for adapter in ADAPTERS {
        let id = call_id(adapter);
        let work = Work::new();
        let policy = work.policy("p.yaml", "");
        let response = response_bytes(adapter, |_| {});
        let good = work.write("good.tool.txt", TOOL_ARTIFACT.as_bytes());
        let binary = work.write("binary.tool.bin", &[0xff, 0xfe, 0x00, 0x80]);
        let missing = work.path("missing.tool.txt");
        let good = good.display();
        let cases = [
            Refused {
                label: "an id the response does not contain",
                specs: vec![format!("toolu_nope={good}")],
                code: "E_BAD_INPUT",
                field: Some("tool_result.tool_use_id"),
            },
            Refused {
                label: "the same id twice",
                specs: vec![format!("{id}={good}"), format!("{id}={good}")],
                code: "E_BAD_INPUT",
                field: Some("tool_result.tool_use_id"),
            },
            Refused {
                label: "a file that is not UTF-8",
                specs: vec![format!("{id}={}", binary.display())],
                code: "E_BAD_INPUT",
                field: Some("tool_result"),
            },
            Refused {
                label: "no equals sign",
                specs: vec![id.to_owned()],
                code: "E_BAD_INPUT",
                field: Some("tool_result"),
            },
            Refused {
                label: "an empty id",
                specs: vec![format!("={good}")],
                code: "E_BAD_INPUT",
                field: Some("tool_result"),
            },
            Refused {
                label: "an empty path",
                specs: vec![format!("{id}=")],
                code: "E_BAD_INPUT",
                field: Some("tool_result"),
            },
            Refused {
                label: "a file that does not exist",
                specs: vec![format!("{id}={}", missing.display())],
                code: "E_MISSING_FILE",
                field: None,
            },
        ];
        for case in cases {
            let mut chain = work.chain(adapter, &response, "t");
            chain.tool_results = case.specs;
            let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", Some(&chain));
            assert_eq!(
                assembled.output.status.code(),
                Some(2),
                "{adapter} {}",
                case.label
            );
            let refusal = assembled.refusal();
            assert_eq!(
                refusal["refusal"]["code"], case.code,
                "{adapter} {}",
                case.label
            );
            if let Some(field) = case.field {
                assert_eq!(
                    refusal["refusal"]["detail"]["field"], field,
                    "{adapter} {}",
                    case.label
                );
            }
            assert!(
                !assembled.prompt.exists() && !assembled.provenance.exists(),
                "{adapter} {}: nothing is written on refusal",
                case.label
            );
        }

        // The unknown-id refusal tells the operator which ids are valid.
        let mut chain = work.chain(adapter, &response, "t");
        chain.tool_results = vec![format!("toolu_nope={good}")];
        let refusal = work
            .assemble(&policy, "TELEMETRY_ONLY", "t", Some(&chain))
            .refusal();
        assert_eq!(
            refusal["refusal"]["detail"]["known_tool_use_ids"],
            json!([id]),
            "{adapter}"
        );
    }
}

#[test]
fn tool_result_comes_only_with_the_chain_flags() {
    let work = Work::new();
    let response = response_bytes(OPENAI, |_| {});
    let chain = work.chain(OPENAI, &response, "t");
    let artifact = work.write("a.tool.txt", TOOL_ARTIFACT.as_bytes());
    let policy = work.policy("p.yaml", "");
    let spec = format!("{}={}", call_id(OPENAI), artifact.display());
    let receipt = chain.receipt.display().to_string();
    let response_path = chain.response.display().to_string();
    let prior_manifest = chain.prior_manifest.display().to_string();
    for (label, flags) in [
        ("alone", vec!["--tool-result", spec.as_str()]),
        (
            "without the adapter",
            vec![
                "--tool-result",
                spec.as_str(),
                "--prior-receipt",
                receipt.as_str(),
                "--response",
                response_path.as_str(),
                "--prior-manifest",
                prior_manifest.as_str(),
            ],
        ),
        (
            "without the prior manifest",
            vec![
                "--tool-result",
                spec.as_str(),
                "--prior-receipt",
                receipt.as_str(),
                "--response",
                response_path.as_str(),
                "--response-adapter",
                OPENAI,
            ],
        ),
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
            "{label} must not be accepted"
        );
        assert!(!prompt.exists(), "{label}: nothing written");
    }
}

/// Add a second tool call to a response fixture.
fn with_second_tool_call(adapter: &str, response: &mut Value) {
    if adapter == OPENAI {
        response["output"]
            .as_array_mut()
            .expect("output array")
            .push(json!({
                "type": "function_call",
                "id": "fc_fx_0002",
                "call_id": "call_fx_0002",
                "name": "lineage_lookup",
                "arguments": "{\"family_id\":\"F-3\",\"depth\":1}",
                "status": "completed",
            }));
    } else {
        response["content"]
            .as_array_mut()
            .expect("content array")
            .push(json!({
                "type": "tool_use",
                "id": "toolu_fx_0002",
                "name": "lineage_lookup",
                "input": {"family_id": "F-3", "depth": 1},
            }));
    }
}

#[test]
fn tool_results_follow_the_responses_order_not_the_flag_order() {
    const SECOND_ARTIFACT: &str = "{\"family_id\":\"F-3\",\"lineage\":[],\"depth\":1}\n";
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy(
            "p.yaml",
            &format!(
                "{ALL_PACKS}{}",
                declaring(&[TOOL_ARTIFACT, SECOND_ARTIFACT])
            ),
        );
        let response = response_bytes(adapter, |r| with_second_tool_call(adapter, r));
        let first_id = call_id(adapter);
        let second_id = if adapter == OPENAI {
            "call_fx_0002"
        } else {
            "toolu_fx_0002"
        };
        let first = work.write("first.tool.txt", TOOL_ARTIFACT.as_bytes());
        let second = work.write("second.tool.txt", SECOND_ARTIFACT.as_bytes());
        let first_spec = format!("{first_id}={}", first.display());
        let second_spec = format!("{second_id}={}", second.display());

        let mut forward = work.chain(adapter, &response, "fwd");
        forward.tool_results = vec![first_spec.clone(), second_spec.clone()];
        // The same prior turn (same receipt, same manifest), so only the flag order differs. A
        // second `work.chain` would write its own turn-0 manifest, which carries a timestamp, and
        // the link to it would legitimately differ.
        let reverse = Chain {
            adapter: forward.adapter.clone(),
            response: forward.response.clone(),
            receipt: forward.receipt.clone(),
            prior_manifest: forward.prior_manifest.clone(),
            tool_results: vec![second_spec, first_spec],
        };

        let a = work.assemble_chain(&policy, "fwd", &forward);
        let b = work.assemble_chain(&policy, "rev", &reverse);
        let c = work.assemble_chain(&policy, "again", &forward);
        for (label, other) in [("reversed flags", &b), ("same flags again", &c)] {
            assert_eq!(
                fs::read(&a.prompt).expect("read"),
                fs::read(&other.prompt).expect("read"),
                "{adapter} {label}: prompt bytes"
            );
            assert_eq!(
                fs::read(&a.provenance).expect("read"),
                fs::read(&other.provenance).expect("read"),
                "{adapter} {label}: provenance bytes"
            );
        }

        let results =
            read_json(&a.prompt)["messages"][1]["content"]["prior_turn"]["tool_results"].clone();
        assert_eq!(results[0]["tool_use_id"], first_id, "{adapter}");
        assert_eq!(results[1]["tool_use_id"], second_id, "{adapter}");
        assert_eq!(results[1]["content"], SECOND_ARTIFACT, "{adapter}");

        let observed = work.verify(&policy, &a, "fwd");
        assert_eq!(
            observed.claim, "STRICT_TELEMETRY_ONLY",
            "{adapter}: {observed:?}"
        );
    }
}

#[test]
fn a_policy_cannot_assign_tool_result() {
    let work = Work::new();
    let policy = work.policy_with_rule(
        "relabel.yaml",
        "  - key_path: extra_note\n    boundary_class: TOOL_RESULT\n",
    );
    let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", None);
    assert_eq!(assembled.output.status.code(), Some(2));
    let refusal = assembled.refusal();
    assert_eq!(refusal["refusal"]["code"], "E_BAD_POLICY");
    assert!(
        refusal["refusal"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("TOOL_RESULT")),
        "{refusal}"
    );
    assert!(!assembled.prompt.exists());
}

#[test]
fn the_policy_schema_accepts_what_the_loader_accepts_for_declared_tool_results() {
    let schema = validator_for(&read_json(&repo("schemas/airlock_policy.schema.json")))
        .expect("compile the policy schema");
    let work = Work::new();
    let policy_path = work.policy(
        "p.yaml",
        &format!("{ALL_PACKS}{}", declaring(&[TOOL_ARTIFACT, "second\n"])),
    );
    let yaml: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(&policy_path).expect("read policy")).expect("parse yaml");
    let policy: Value = serde_json::to_value(yaml).expect("yaml as json");
    schema
        .validate(&policy)
        .unwrap_or_else(|error| panic!("the schema rejects a policy the loader accepts: {error}"));

    let with_entries = |entries: Value| {
        let mut edited = policy.clone();
        edited["declared_tool_results"] = entries;
        edited
    };
    let good = blake3_hash(b"x");
    let uppercase = good.to_uppercase();
    for bad in [
        json!([{"artifact_hash": "blake3:abc"}]),
        json!([{"artifact_hash": uppercase}]),
        json!([{"artifact_hash": good.replace("blake3:", "sha256:")}]),
        json!([{"artifact_hash": good, "tool": "lineage_lookup"}]),
        json!([{"description": "no hash"}]),
    ] {
        assert!(
            !schema.is_valid(&with_entries(bad.clone())),
            "the schema must reject {bad}"
        );
    }
}

#[test]
fn the_adapters_restore_a_prompt_that_carries_tool_results_exactly() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy(
            "p.yaml",
            &format!("{ALL_PACKS}{}", declaring(&[TOOL_ARTIFACT])),
        );
        let chain = work.chain_with_tool_result(adapter, "t", TOOL_ARTIFACT);
        let assembled = work.assemble_chain(&policy, "t", &chain);
        let prompt = read_json(&assembled.prompt);

        let mut config = TransportConfig::new("model-under-test");
        config.max_tokens = Some(64);
        let restored = if adapter == OPENAI {
            let wire = OpenAiResponsesAdapter.wrap(&prompt, &config).expect("wrap");
            OpenAiResponsesAdapter.unwrap(&wire).expect("unwrap")
        } else {
            let wire = AnthropicMessagesAdapter
                .wrap(&prompt, &config)
                .expect("wrap");
            AnthropicMessagesAdapter.unwrap(&wire).expect("unwrap")
        };
        assert_eq!(
            restored["messages"], prompt["messages"],
            "{adapter}: binding compares these, so they must be identical, newline and é included"
        );
    }
}

// --- chain manifests (al-210 D-c) -----------------------------------------------------------

fn manifest_schema() -> jsonschema::Validator {
    validator_for(&read_json(&repo("schemas/airlock.v0.schema.json")))
        .expect("compile the manifest schema")
}

/// Assemble one chained turn and verify it (unsigned), requiring both to succeed. Returns the
/// chain it followed, the assembled files and the path of the manifest `verify` wrote.
fn chained_turn(work: &Work, adapter: &str, stem: &str) -> (Chain, Assembled, PathBuf) {
    let policy = work.policy(&format!("{stem}.policy.yaml"), ALL_PACKS);
    let chain = work.chain(adapter, &response_bytes(adapter, |_| {}), stem);
    let assembled = work.assemble_chain(&policy, stem, &chain);
    let observed = work.verify(&policy, &assembled, stem);
    assert_eq!(observed.exit, 0, "{adapter}: {observed:?}");
    let manifest = work.path(&format!("{stem}.manifest.json"));
    (chain, assembled, manifest)
}

/// `verify` with its whole output kept: the process output and where the manifest would be.
fn verify_raw(
    work: &Work,
    policy: &Path,
    prompt: &Path,
    provenance: &Path,
    stem: &str,
) -> (Output, PathBuf) {
    let request = json!({"model": "gpt-5", "messages": read_json(prompt)["messages"].clone()});
    let request_path = work.write(
        &format!("{stem}.request.json"),
        &serde_json::to_vec(&request).expect("serialize request"),
    );
    let manifest = work.path(&format!("{stem}.manifest.json"));
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
        .arg(&manifest)
        .output()
        .expect("run verify");
    (output, manifest)
}

fn stdout_refusal(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
}

#[test]
fn a_chained_turn_writes_a_v0_4_manifest_naming_the_manifest_the_receipt_matched() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let (chain, assembled, manifest_path) = chained_turn(&work, adapter, "t");

        // Turn 0 is the manifest verify has always written: v0.3, no chain member.
        let prior = read_json(&chain.prior_manifest);
        assert_eq!(prior["manifest_version"], "airlock.v0.3", "{adapter}");
        assert!(prior.get("chain").is_none(), "{adapter}");

        let expected = json!({
            "prior_manifest_hash": manifest_hash(&chain.prior_manifest),
            "turn_index": 1,
        });
        assert_eq!(
            read_json(&chain.receipt)["matched_manifest_hash"],
            expected["prior_manifest_hash"],
            "{adapter}: the receipt names the manifest the link names"
        );
        let provenance = read_json(&assembled.provenance);
        assert_eq!(provenance["chain"], expected, "{adapter}");
        let manifest = read_json(&manifest_path);
        assert_eq!(manifest["manifest_version"], "airlock.v0.4", "{adapter}");
        assert_eq!(manifest["chain"], expected, "{adapter}");
        for member in ["bytes_crossed", "attestation", "prompt_provenance_hash"] {
            assert!(
                manifest.get(member).is_some(),
                "{adapter}: v0.4 keeps {member}"
            );
        }

        // The manifest's provenance hash covers the link: it is the hash of the provenance with
        // the member in it, and not the hash of the provenance without it.
        let hash_of = |value: &Value| blake3_hash(&canonical_json_bytes(value));
        let mut without = provenance.clone();
        without.as_object_mut().expect("object").remove("chain");
        assert_eq!(
            manifest["prompt_provenance_hash"],
            hash_of(&provenance).as_str(),
            "{adapter}"
        );
        assert_ne!(
            manifest["prompt_provenance_hash"],
            hash_of(&without).as_str(),
            "{adapter}"
        );

        manifest_schema()
            .validate(&manifest)
            .unwrap_or_else(|error| panic!("{adapter}: manifest fails its schema: {error}"));
        provenance_schema()
            .validate(&provenance)
            .unwrap_or_else(|error| panic!("{adapter}: provenance fails its schema: {error}"));
    }
}

#[test]
fn the_next_turn_is_index_two_and_a_v0_2_or_v0_3_manifest_can_anchor_turn_one() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let (_, _, one) = chained_turn(&work, adapter, "one");
        let response = response_bytes(adapter, |_| {});
        let policy = work.policy("two.policy.yaml", ALL_PACKS);
        let chain_after = |prior: &Path, stem: &str| Chain {
            adapter: adapter.to_owned(),
            response: work.write(&format!("{stem}.response.json"), &response),
            receipt: work.write(
                &format!("{stem}.receipt.json"),
                &serde_json::to_vec(&receipt_for(&response, &manifest_hash(prior)))
                    .expect("serialize receipt"),
            ),
            prior_manifest: prior.to_path_buf(),
            tool_results: Vec::new(),
        };

        // A turn that follows a chained (v0.4) manifest is one further along, and names that
        // manifest rather than the turn-0 one before it.
        let chain = chain_after(&one, "two");
        let assembled = work.assemble_chain(&policy, "two", &chain);
        let observed = work.verify(&policy, &assembled, "two");
        assert_eq!(observed.exit, 0, "{adapter}: {observed:?}");
        let manifest = read_json(&work.path("two.manifest.json"));
        assert_eq!(manifest["manifest_version"], "airlock.v0.4", "{adapter}");
        assert_eq!(
            manifest["chain"],
            json!({"prior_manifest_hash": manifest_hash(&one), "turn_index": 2}),
            "{adapter}"
        );
        assert_ne!(
            manifest["chain"]["prior_manifest_hash"],
            read_json(&one)["chain"]["prior_manifest_hash"],
            "{adapter}: turn 2 names turn 1's manifest, not turn 0's"
        );

        // Manifests written before v0.4 can still start a chain.
        for golden in ["expected_manifest.json", "expected_manifest_v0_3.json"] {
            let prior = repo(&format!("fixtures/clean_telemetry_only/{golden}"));
            let chain = chain_after(&prior, &format!("legacy-{golden}"));
            let assembled = work.assemble_chain(&policy, &format!("legacy-{golden}"), &chain);
            assert_eq!(
                read_json(&assembled.provenance)["chain"],
                json!({"prior_manifest_hash": manifest_hash(&prior), "turn_index": 1}),
                "{adapter} {golden}"
            );
        }
    }
}

#[test]
fn a_prompt_with_no_prior_turn_still_gets_a_v0_3_manifest_and_provenance_with_no_chain_key() {
    let work = Work::new();
    let policy = work.policy("p.yaml", ALL_PACKS);
    let plain = work.assemble(&policy, "TELEMETRY_ONLY", "plain", None);
    assert_eq!(plain.output.status.code(), Some(0));
    let provenance = read_json(&plain.provenance);
    assert!(
        provenance.get("chain").is_none(),
        "no chain key at all, not a null one: {provenance}"
    );
    let observed = work.verify(&policy, &plain, "plain");
    assert_eq!(observed.exit, 0, "{observed:?}");
    let manifest = read_json(&work.path("plain.manifest.json"));
    assert_eq!(manifest["manifest_version"], "airlock.v0.3");
    assert!(manifest.get("chain").is_none());
    manifest_schema()
        .validate(&manifest)
        .unwrap_or_else(|error| panic!("a v0.3 manifest fails its schema: {error}"));
}

#[test]
fn a_receipt_paired_with_the_wrong_manifest_is_refused_before_anything_is_written() {
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy("p.yaml", ALL_PACKS);
        let mut chain = work.chain(adapter, &response_bytes(adapter, |_| {}), "t");
        let intended = manifest_hash(&chain.prior_manifest);
        // A different real manifest: same shape, different files, so a different hash.
        chain.prior_manifest = work.turn_zero("other");
        let other = manifest_hash(&chain.prior_manifest);
        assert_ne!(intended, other, "{adapter}: the two manifests must differ");

        let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", Some(&chain));
        assert_eq!(assembled.output.status.code(), Some(2), "{adapter}");
        let refusal = assembled.refusal();
        assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT", "{adapter}");
        let detail = &refusal["refusal"]["detail"];
        assert_eq!(detail["field"], "prior_manifest.hash", "{adapter}");
        assert_eq!(
            detail["receipt_matched_manifest_hash"],
            intended.as_str(),
            "{adapter}"
        );
        assert_eq!(detail["manifest_hash"], other.as_str(), "{adapter}");
        assert!(
            !assembled.prompt.exists() && !assembled.provenance.exists(),
            "{adapter}: nothing is written"
        );
    }
}

#[test]
fn a_prior_manifest_that_cannot_anchor_a_chain_is_refused_by_field() {
    type Edit = fn(&mut Value);
    let edits: [(&str, Edit); 3] = [
        ("prior_manifest.manifest_version", |m| {
            m["manifest_version"] = json!("airlock.v0.5");
        }),
        // v0.4 without its chain member.
        ("prior_manifest.chain", |m| {
            m["manifest_version"] = json!("airlock.v0.4");
        }),
        // A chain member on a version that may not carry one.
        ("prior_manifest.chain", |m| {
            m["chain"] = json!({
                "prior_manifest_hash": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
                "turn_index": 1,
            });
        }),
    ];
    let work = Work::new();
    let policy = work.policy("p.yaml", ALL_PACKS);
    let mut cases: Vec<(String, &str, Vec<u8>)> = vec![
        ("not JSON".to_owned(), "prior_manifest", b"nope".to_vec()),
        (
            "an empty object".to_owned(),
            "prior_manifest",
            b"{}".to_vec(),
        ),
    ];
    let chain = work.chain(OPENAI, &response_bytes(OPENAI, |_| {}), "t");
    for (index, (field, edit)) in edits.iter().enumerate() {
        let mut manifest = read_json(&chain.prior_manifest);
        edit(&mut manifest);
        cases.push((
            format!("edit {index}"),
            field,
            serde_json::to_vec(&manifest).expect("serialize"),
        ));
    }
    for (label, field, bytes) in cases {
        let mut chain = work.chain(OPENAI, &response_bytes(OPENAI, |_| {}), "t");
        chain.prior_manifest = work.write("bad.manifest.json", &bytes);
        let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", Some(&chain));
        assert_eq!(assembled.output.status.code(), Some(2), "{label}");
        let refusal = assembled.refusal();
        assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT", "{label}");
        assert_eq!(refusal["refusal"]["detail"]["field"], field, "{label}");
        assert!(!assembled.prompt.exists(), "{label}: nothing is written");
    }

    let mut missing = work.chain(OPENAI, &response_bytes(OPENAI, |_| {}), "t");
    missing.prior_manifest = work.path("no-such-manifest.json");
    let assembled = work.assemble(&policy, "TELEMETRY_ONLY", "t", Some(&missing));
    assert_eq!(assembled.output.status.code(), Some(2));
    assert_eq!(assembled.refusal()["refusal"]["code"], "E_MISSING_FILE");
}

#[test]
fn verify_refuses_a_provenance_that_disagrees_with_the_prompt_about_the_chain() {
    type Edit = fn(&mut Value);
    for adapter in ADAPTERS {
        let work = Work::new();
        let policy = work.policy("p.yaml", ALL_PACKS);
        let chain = work.chain(adapter, &response_bytes(adapter, |_| {}), "c");
        let chained = work.assemble_chain(&policy, "c", &chain);
        let plain = work.assemble(&policy, "TELEMETRY_ONLY", "plain", None);
        assert_eq!(plain.output.status.code(), Some(0), "{adapter}");

        let cases: [(&str, &Assembled, Edit, Option<&str>); 5] = [
            (
                "a chained prompt whose link was removed",
                &chained,
                |p| {
                    p.as_object_mut().expect("object").remove("chain");
                },
                Some("has no chain link"),
            ),
            (
                "a prompt with no prior turn that gained a link",
                &plain,
                |p| {
                    p["chain"] = json!({
                        "prior_manifest_hash": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
                        "turn_index": 1,
                    });
                },
                Some("has no prior_turn"),
            ),
            (
                "a link with index 0",
                &chained,
                |p| p["chain"]["turn_index"] = json!(0),
                Some("chain link is invalid"),
            ),
            (
                "a link with an uppercase hash",
                &chained,
                |p| {
                    let upper = p["chain"]["prior_manifest_hash"]
                        .as_str()
                        .expect("hash")
                        .to_uppercase();
                    p["chain"]["prior_manifest_hash"] = json!(upper);
                },
                Some("chain link is invalid"),
            ),
            (
                "a link with a member it does not have",
                &chained,
                |p| {
                    p["chain"]["response_hash"] = json!(
                        "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                    );
                },
                None,
            ),
        ];
        for (index, (label, assembled, edit, message)) in cases.iter().enumerate() {
            let mut provenance = read_json(&assembled.provenance);
            edit(&mut provenance);
            let provenance_path = work.write(
                &format!("case{index}.provenance.json"),
                &serde_json::to_vec(&provenance).expect("serialize"),
            );
            let (output, manifest) = verify_raw(
                &work,
                &policy,
                &assembled.prompt,
                &provenance_path,
                &format!("case{index}"),
            );
            assert_eq!(output.status.code(), Some(2), "{adapter} {label}");
            assert!(
                !manifest.exists(),
                "{adapter} {label}: no manifest is written on refusal"
            );
            if let Some(message) = message {
                let refusal = stdout_refusal(&output);
                assert_eq!(
                    refusal["refusal"]["code"], "E_BAD_PROVENANCE",
                    "{adapter} {label}"
                );
                assert!(
                    refusal["refusal"]["message"]
                        .as_str()
                        .is_some_and(|text| text.contains(message)),
                    "{adapter} {label}: {refusal}"
                );
            }
        }
    }
}

fn airlock_with_home(home: &Path) -> Command {
    let mut command = Command::cargo_bin("airlock").expect("airlock binary");
    command.env("HOME", home).env_remove("USERPROFILE");
    command
}

#[test]
fn the_signature_covers_the_chain_member_and_a_downgrade_to_v0_3_fails() {
    type Edit = fn(&mut Value);
    let work = Work::new();
    let home = tempdir().expect("home");
    let keygen = airlock_with_home(home.path())
        .arg("keygen")
        .output()
        .expect("keygen");
    assert_eq!(keygen.status.code(), Some(0), "keygen must succeed");

    let policy = work.policy("p.yaml", ALL_PACKS);
    let chain = work.chain(OPENAI, &response_bytes(OPENAI, |_| {}), "s");
    let assembled = work.assemble_chain(&policy, "s", &chain);
    let request = json!({
        "model": "gpt-5",
        "messages": read_json(&assembled.prompt)["messages"].clone(),
    });
    let request_path = work.write(
        "s.request.json",
        &serde_json::to_vec(&request).expect("serialize"),
    );
    let signed = work.path("s.signed.manifest.json");
    let verified = airlock_with_home(home.path())
        .args(["verify", "--no-witness", "--policy"])
        .arg(&policy)
        .arg("--prompt")
        .arg(&assembled.prompt)
        .arg("--provenance")
        .arg(&assembled.provenance)
        .arg("--request")
        .arg(&request_path)
        .arg("--out")
        .arg(&signed)
        .output()
        .expect("run signing verify");
    assert_eq!(
        verified.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&verified.stdout)
    );
    let manifest = read_json(&signed);
    assert_eq!(manifest["manifest_version"], "airlock.v0.4");
    assert!(
        manifest.get("signature").is_some(),
        "verify signs by default"
    );

    let check = |path: &Path| {
        airlock_with_home(home.path())
            .arg("verify-manifest")
            .arg(path)
            .output()
            .expect("run verify-manifest")
    };
    let intact = check(&signed);
    assert_eq!(
        intact.status.code(),
        Some(0),
        "a signed v0.4 manifest verifies: {}",
        String::from_utf8_lossy(&intact.stdout)
    );

    let edits: [(&str, Edit); 4] = [
        ("turn_index changed", |m| {
            m["chain"]["turn_index"] = json!(2)
        }),
        ("prior_manifest_hash changed", |m| {
            m["chain"]["prior_manifest_hash"] =
                json!("blake3:0000000000000000000000000000000000000000000000000000000000000000");
        }),
        ("chain removed", |m| {
            m.as_object_mut().expect("object").remove("chain");
        }),
        ("downgraded to v0.3 with the chain stripped", |m| {
            m["manifest_version"] = json!("airlock.v0.3");
            m.as_object_mut().expect("object").remove("chain");
        }),
    ];
    for (index, (label, edit)) in edits.iter().enumerate() {
        let mut altered = manifest.clone();
        edit(&mut altered);
        let path = work.write(
            &format!("altered{index}.manifest.json"),
            &serde_json::to_vec(&altered).expect("serialize"),
        );
        let output = check(&path);
        assert_eq!(output.status.code(), Some(2), "{label}");
        assert_eq!(
            stdout_refusal(&output)["refusal"]["detail"]["reason"],
            "signature_mismatch",
            "{label}"
        );
    }
}

#[test]
fn the_schemas_agree_with_the_loader_about_chain_members() {
    let work = Work::new();
    let (_, assembled, manifest_path) = chained_turn(&work, OPENAI, "t");
    let manifests = manifest_schema();
    let provenances = provenance_schema();
    let manifest = read_json(&manifest_path);
    let provenance = read_json(&assembled.provenance);
    assert!(manifests.is_valid(&manifest));
    assert!(provenances.is_valid(&provenance));

    type Edit = fn(&mut Value);
    let bad_manifests: [(&str, Edit); 7] = [
        ("v0.4 without its chain member", |m| {
            m.as_object_mut().expect("object").remove("chain");
        }),
        ("v0.3 with a chain member", |m| {
            m["manifest_version"] = json!("airlock.v0.3");
        }),
        ("v0.2 with a chain member", |m| {
            m["manifest_version"] = json!("airlock.v0.2");
        }),
        ("a chain with index 0", |m| {
            m["chain"]["turn_index"] = json!(0)
        }),
        ("a chain with a fractional index", |m| {
            m["chain"]["turn_index"] = json!(1.5);
        }),
        ("a chain with an uppercase hash", |m| {
            let upper = m["chain"]["prior_manifest_hash"]
                .as_str()
                .expect("hash")
                .to_uppercase();
            m["chain"]["prior_manifest_hash"] = json!(upper);
        }),
        ("a chain with an extra member", |m| {
            m["chain"]["response_hash"] =
                json!("blake3:0000000000000000000000000000000000000000000000000000000000000000");
        }),
    ];
    for (label, edit) in bad_manifests {
        let mut altered = manifest.clone();
        edit(&mut altered);
        assert!(
            !manifests.is_valid(&altered),
            "the schema must reject {label}"
        );
    }

    let bad_provenances: [(&str, Edit); 4] = [
        ("index 0", |p| p["chain"]["turn_index"] = json!(0)),
        ("a short hash", |p| {
            p["chain"]["prior_manifest_hash"] = json!("blake3:abc");
        }),
        ("an extra member", |p| p["chain"]["note"] = json!("x")),
        ("a missing index", |p| {
            p["chain"]
                .as_object_mut()
                .expect("object")
                .remove("turn_index");
        }),
    ];
    for (label, edit) in bad_provenances {
        let mut altered = provenance.clone();
        edit(&mut altered);
        assert!(
            !provenances.is_valid(&altered),
            "the provenance schema must reject a chain with {label}"
        );
    }
}

#[test]
fn explain_reports_the_chain_in_text_and_json_and_says_nothing_for_other_versions() {
    let work = Work::new();
    let (chain, _, manifest_path) = chained_turn(&work, ANTHROPIC, "t");
    let link = read_json(&manifest_path)["chain"].clone();
    let hash = link["prior_manifest_hash"]
        .as_str()
        .expect("hash")
        .to_owned();

    let explain = |path: &Path, json: bool| {
        let mut command = Command::cargo_bin("airlock").expect("airlock binary");
        command.args(["explain", "--manifest"]).arg(path);
        if json {
            command.arg("--json");
        }
        let output = command.output().expect("run explain");
        assert_eq!(output.status.code(), Some(0), "explain must succeed");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let text = explain(&manifest_path, false);
    assert!(
        text.contains("Chain: turn 1") && text.contains(&hash),
        "{text}"
    );
    let json: Value = serde_json::from_str(&explain(&manifest_path, true)).expect("explain json");
    assert_eq!(json["chain"], link);

    // A manifest with no chain member explains exactly as before: no line, no key.
    let prior_text = explain(&chain.prior_manifest, false);
    assert!(!prior_text.contains("Chain:"), "{prior_text}");
    let prior_json: Value =
        serde_json::from_str(&explain(&chain.prior_manifest, true)).expect("explain json");
    assert!(prior_json.get("chain").is_none(), "{prior_json}");
}

/// One request through a real strict-manifest gate in front of an origin that answers `reply`:
/// the receipt the gate wrote (path and contents) and the bytes the client got back.
fn exchange_through_gate(
    work: &Work,
    stem: &str,
    manifests: &Path,
    request: &[u8],
    reply: &[u8],
) -> (PathBuf, Value, Vec<u8>) {
    let origin = start_origin(reply.to_vec());
    let receipts = work.path(&format!("{stem}.receipts"));
    let gate = start_strict_gate(
        origin.address,
        manifests,
        &receipts,
        &work.path(&format!("{stem}.witness.jsonl")),
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let response = agent
        .post(&format!("http://{}/v1/chat/completions", gate.address))
        .header("Content-Type", "application/json")
        .send(request.to_vec())
        .expect("post through the gate");
    assert_eq!(
        response.status().as_u16(),
        200,
        "{stem}: the gate must forward the request its manifest matches"
    );
    let mut relayed = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut relayed)
        .expect("read relayed response");
    assert_eq!(relayed, reply, "{stem}: the gate relays the origin's bytes");
    let (path, receipt) = wait_for_forwarded_receipt(&receipts);
    drop(gate);
    (path, receipt, relayed)
}

#[test]
fn a_three_turn_chain_runs_through_the_real_gate_with_v0_4_manifests() {
    let work = Work::new();
    let policy = work.policy("p.yaml", ALL_PACKS);
    let manifests = work.path("manifests");
    fs::create_dir(&manifests).expect("manifest dir");
    let reply_text = |text: &'static str| {
        response_bytes(ANTHROPIC, |reply| {
            set(reply, text_pointer(ANTHROPIC), json!(text));
        })
    };

    // Turn 0: no chain, so airlock.v0.3 as always.
    let turn0 = work.assemble(&policy, "TELEMETRY_ONLY", "turn0", None);
    assert_eq!(turn0.output.status.code(), Some(0));
    let observed = work.verify(&policy, &turn0, "turn0");
    assert_eq!(observed.exit, 0, "{observed:?}");
    fs::copy(
        work.path("turn0.manifest.json"),
        manifests.join("turn0.json"),
    )
    .expect("copy turn 0 manifest");
    let (receipt0_path, receipt0, relayed0) = exchange_through_gate(
        &work,
        "gate0",
        &manifests,
        &fs::read(work.path("turn0.request.json")).expect("turn 0 request"),
        &reply_text("Reply to turn zero."),
    );

    // Turn 1 follows turn 0 and is airlock.v0.4.
    let chain1 = Chain {
        adapter: ANTHROPIC.to_owned(),
        response: work.write("turn0.response.json", &relayed0),
        receipt: receipt0_path,
        prior_manifest: manifests.join("turn0.json"),
        tool_results: Vec::new(),
    };
    let turn1 = work.assemble_chain(&policy, "turn1", &chain1);
    let observed = work.verify(&policy, &turn1, "turn1");
    assert_eq!(observed.claim, "STRICT_TELEMETRY_ONLY", "{observed:?}");
    let manifest1 = read_json(&work.path("turn1.manifest.json"));
    assert_eq!(manifest1["manifest_version"], "airlock.v0.4");
    assert_eq!(
        manifest1["chain"],
        json!({"prior_manifest_hash": receipt0["matched_manifest_hash"], "turn_index": 1})
    );

    // The gate starts with a v0.4 manifest in its directory and forwards the request it matches.
    fs::copy(
        work.path("turn1.manifest.json"),
        manifests.join("turn1.json"),
    )
    .expect("copy turn 1 manifest");
    let (receipt1_path, receipt1, relayed1) = exchange_through_gate(
        &work,
        "gate1",
        &manifests,
        &fs::read(work.path("turn1.request.json")).expect("turn 1 request"),
        &reply_text("Reply to turn one."),
    );
    assert_eq!(
        receipt1["matched_manifest_hash"],
        manifest_hash(&manifests.join("turn1.json")).as_str(),
        "the gate and the library hash a v0.4 manifest the same way, chain member included"
    );

    // Turn 2 follows turn 1.
    let chain2 = Chain {
        adapter: ANTHROPIC.to_owned(),
        response: work.write("turn1.response.json", &relayed1),
        receipt: receipt1_path,
        prior_manifest: manifests.join("turn1.json"),
        tool_results: Vec::new(),
    };
    let turn2 = work.assemble_chain(&policy, "turn2", &chain2);
    let observed = work.verify(&policy, &turn2, "turn2");
    assert_eq!(observed.claim, "STRICT_TELEMETRY_ONLY", "{observed:?}");
    let manifest2 = read_json(&work.path("turn2.manifest.json"));
    assert_eq!(manifest2["manifest_version"], "airlock.v0.4");
    assert_eq!(
        manifest2["chain"],
        json!({"prior_manifest_hash": receipt1["matched_manifest_hash"], "turn_index": 2})
    );
    assert_ne!(
        manifest2["chain"]["prior_manifest_hash"], manifest1["chain"]["prior_manifest_hash"],
        "each link names its own prior manifest"
    );
}
