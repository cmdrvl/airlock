//! al-ii8: the tamper matrix, from Rust.
//!
//! `fixtures/tamper_matrix.json` holds the cases, the ops that tamper with them and the expected
//! result per cell. `tests/e2e_tamper_matrix.sh` applies the ops with jq against the release
//! binary and writes `docs/tamper-matrix.md`; this test applies the same ops natively with
//! serde_json against the debug binary and checks the same expectations, so each interpreter
//! checks the other. It also checks that the committed doc's rows match the fixture, so a
//! hand-edited doc fails `cargo test` and not only the CI regeneration diff.
//!
//! A cell is `assemble` then `verify --no-sign --no-witness --require-claim <require_claim>` on
//! the (possibly tampered) request. Nothing here opens a network connection.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use airlock::hash::blake3_hash;
use airlock::manifest::AirlockManifest;
use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::tempdir;

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_json(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn fixture() -> Value {
    let fixture = read_json(&repo("fixtures/tamper_matrix.json"));
    assert!(
        fixture["cases"].is_array(),
        "fixtures/tamper_matrix.json must parse and hold a cases array"
    );
    fixture
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Apply one request-site op to a wrapped request. Mirrors the jq in tests/e2e_tamper_matrix.sh.
fn apply_request_op(request: &mut Value, op: &Value) -> Result<(), String> {
    match op["op"].as_str().unwrap_or_default() {
        "reverse_messages" => {
            let messages = request["messages"]
                .as_array_mut()
                .ok_or("request has no messages array")?;
            messages.reverse();
            Ok(())
        }
        "alter_last_byte" => {
            let pointer = op["pointer"]
                .as_str()
                .ok_or("alter_last_byte needs a pointer")?;
            let leaf = request
                .pointer_mut(pointer)
                .ok_or_else(|| format!("no value at {pointer}"))?;
            let mut text = leaf
                .as_str()
                .ok_or_else(|| format!("{pointer} is not a string"))?
                .to_owned();
            text.pop();
            text.push('!');
            *leaf = Value::String(text);
            Ok(())
        }
        "add_top_level_key" => {
            let key = op["key"].as_str().ok_or("add_top_level_key needs a key")?;
            request
                .as_object_mut()
                .ok_or("request is not an object")?
                .insert(key.to_owned(), op["value"].clone());
            Ok(())
        }
        "append_user_message" => {
            let text = op["text"]
                .as_str()
                .ok_or("append_user_message needs text")?;
            request["messages"]
                .as_array_mut()
                .ok_or("request has no messages array")?
                .push(json!({"role": "user", "content": text}));
            Ok(())
        }
        "append_assistant_message" => {
            let text = op["text"]
                .as_str()
                .ok_or("append_assistant_message needs text")?;
            request["messages"]
                .as_array_mut()
                .ok_or("request has no messages array")?
                .push(json!({"role": "assistant", "content": text}));
            Ok(())
        }
        "append_tool_message" => {
            let text = op["text"]
                .as_str()
                .ok_or("append_tool_message needs text")?;
            let id = op["tool_call_id"]
                .as_str()
                .ok_or("append_tool_message needs a tool_call_id")?;
            request["messages"]
                .as_array_mut()
                .ok_or("request has no messages array")?
                .push(json!({"role": "tool", "tool_call_id": id, "content": text}));
            Ok(())
        }
        other => Err(format!("unknown request op: {other}")),
    }
}

struct Matrix {
    policy: PathBuf,
    input: PathBuf,
    system_prompt: PathBuf,
    model: String,
    require_claim: String,
    leak_pointer: String,
    chain: Value,
}

impl Matrix {
    fn load(fixture: &Value) -> Self {
        let text = |key: &str| fixture[key].as_str().unwrap_or_default().to_owned();
        Self {
            policy: repo(&text("policy")),
            input: repo(&text("input")),
            system_prompt: repo(&text("system_prompt")),
            model: text("model"),
            require_claim: text("require_claim"),
            leak_pointer: text("leak_pointer"),
            chain: fixture["chain"].clone(),
        }
    }

    /// `airlock assemble` over `input`, with `extra` arguments appended (the chain flags for a
    /// chain_turn cell, none otherwise); returns (prompt, provenance) paths inside `dir`.
    fn assemble(
        &self,
        input: &Path,
        mode: &str,
        dir: &Path,
        stem: &str,
        extra: &[String],
    ) -> Result<(PathBuf, PathBuf), String> {
        let prompt = dir.join(format!("{stem}.prompt.json"));
        let provenance = dir.join(format!("{stem}.provenance.json"));
        let output = Command::cargo_bin("airlock")
            .map_err(|error| error.to_string())?
            .args(["assemble", "--policy"])
            .arg(&self.policy)
            .arg("--input")
            .arg(input)
            .arg("--system-prompt")
            .arg(&self.system_prompt)
            .args(["--boundary-mode", mode, "--out"])
            .arg(&prompt)
            .arg("--provenance-out")
            .arg(&provenance)
            .arg("--no-witness")
            .args(extra)
            .output()
            .map_err(|error| error.to_string())?;
        if output.status.code() != Some(0) {
            return Err(format!(
                "assemble refused (exit {:?}): {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout)
            ));
        }
        Ok((prompt, provenance))
    }

    fn wrap(&self, prompt: &Path) -> Value {
        json!({"model": self.model, "messages": read_json(prompt)["messages"].clone()})
    }

    /// A chain_turn cell: `assemble` chained onto the committed prior manifest through a receipt
    /// built here in the shape `airlock gate` writes, then the same verify as every other cell.
    /// Mirrors the jq in tests/e2e_tamper_matrix.sh.
    fn chain_turn(
        &self,
        ops: &[Value],
        mode: &str,
        dir: &Path,
        stem: &str,
    ) -> Result<Value, String> {
        let text = |value: &Value, what: &str| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("fixture chain is missing {what}"))
        };
        let response_key = ops
            .iter()
            .find(|op| op["op"] == "admit_response")
            .and_then(|op| op["response"].as_str())
            .ok_or("a chain_turn case needs an admit_response op")?;
        let response = &self.chain["responses"][response_key];
        let response_file = text(&response["file"], &format!("responses.{response_key}.file"))?;
        let response_hash = text(&response["hash"], &format!("responses.{response_key}.hash"))?;

        let receipt_path = dir.join(format!("{stem}.receipt.json"));
        let receipt = json!({
            "gate_version": "airlock.gate.v1",
            "mode": "strict-manifest",
            "achieved_claim": "STRICT_TELEMETRY_ONLY",
            "request_hash": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
            "response_hash": response_hash,
            "upstream_status": 200,
            "blocked": false,
            "findings": [],
            "timestamp": "2026-11-25T00:00:00Z",
            "matched_manifest_hash": self.chain["prior_manifest_hash"],
        });
        fs::write(
            &receipt_path,
            serde_json::to_vec(&receipt).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;

        let mut extra = vec![
            "--prior-receipt".to_owned(),
            receipt_path.display().to_string(),
            "--response".to_owned(),
            repo(&response_file).display().to_string(),
            "--response-adapter".to_owned(),
            text(&self.chain["adapter"], "adapter")?,
            "--prior-manifest".to_owned(),
            repo(&text(&self.chain["prior_manifest"], "prior_manifest")?)
                .display()
                .to_string(),
        ];
        for op in ops.iter().filter(|op| op["op"] == "admit_tool_result") {
            let key = op["artifact"]
                .as_str()
                .ok_or("admit_tool_result needs an artifact")?;
            let file = text(
                &self.chain["artifacts"][key]["file"],
                &format!("artifacts.{key}.file"),
            )?;
            extra.push("--tool-result".to_owned());
            extra.push(format!(
                "{}={}",
                text(&self.chain["tool_use_id"], "tool_use_id")?,
                repo(&file).display()
            ));
        }

        let (prompt, provenance) = self.assemble(&self.input, mode, dir, stem, &extra)?;
        let request = self.wrap(&prompt);
        self.verify(&prompt, &provenance, &request, dir, stem)
    }

    /// `airlock verify` on `request`; returns {exit, claim, binding, findings}.
    fn verify(
        &self,
        prompt: &Path,
        provenance: &Path,
        request: &Value,
        dir: &Path,
        stem: &str,
    ) -> Result<Value, String> {
        let request_path = dir.join(format!("{stem}.request.json"));
        fs::write(
            &request_path,
            serde_json::to_vec(request).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let output = Command::cargo_bin("airlock")
            .map_err(|error| error.to_string())?
            .args(["verify", "--no-sign", "--no-witness", "--policy"])
            .arg(&self.policy)
            .arg("--prompt")
            .arg(prompt)
            .arg("--provenance")
            .arg(provenance)
            .arg("--request")
            .arg(&request_path)
            .arg("--out")
            .arg(dir.join(format!("{stem}.manifest.json")))
            .args(["--require-claim", &self.require_claim])
            .output()
            .map_err(|error| error.to_string())?;
        let manifest: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
            format!(
                "verify wrote no manifest (exit {:?}): {error}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout)
            )
        })?;
        let findings: BTreeSet<String> = manifest["findings"]
            .as_array()
            .map(|items| {
                items
                    .iter()
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
                    .collect()
            })
            .unwrap_or_default();
        Ok(json!({
            "exit": output.status.code(),
            "claim": manifest["achieved_claim"],
            "binding": manifest["binding_status"],
            "findings": findings,
        }))
    }
}

#[test]
fn the_fixture_gives_every_case_an_expectation_for_every_mode() {
    let fixture = fixture();
    let modes = strings(&fixture["modes"]);
    assert!(!modes.is_empty(), "the fixture lists no modes");
    let mut seen = BTreeSet::new();
    for case in fixture["cases"].as_array().into_iter().flatten() {
        let id = case["id"].as_str().unwrap_or_default();
        assert!(seen.insert(id.to_owned()), "duplicate case id {id}");
        assert!(
            matches!(
                case["site"].as_str(),
                Some("request" | "input_leak" | "chain_turn")
            ),
            "case {id} has an unknown site"
        );
        if case["site"] == "chain_turn" {
            let ops = case["ops"].as_array().cloned().unwrap_or_default();
            let response = ops
                .first()
                .and_then(|op| op["response"].as_str())
                .unwrap_or_default();
            assert!(
                ops.first().is_some_and(|op| op["op"] == "admit_response")
                    && fixture["chain"]["responses"][response].is_object(),
                "chain_turn case {id} must start with an admit_response op naming a response in the fixture's chain block"
            );
            for op in ops.iter().skip(1) {
                let artifact = op["artifact"].as_str().unwrap_or_default();
                assert!(
                    op["op"] == "admit_tool_result"
                        && fixture["chain"]["artifacts"][artifact].is_object(),
                    "chain_turn case {id}: every op after the first must be admit_tool_result naming an artifact in the fixture's chain block"
                );
            }
        }
        if case["site"] == "input_leak" {
            assert!(
                case["ops"][0]["op"] == "set_input" && case["ops"][0]["value"].is_string(),
                "input_leak case {id} must start with a set_input op carrying a string value"
            );
        }
        for mode in &modes {
            let expect = &case["expect"][mode.as_str()];
            assert!(
                expect["exit"].is_number()
                    && expect["claim"].is_string()
                    && expect["binding"].is_string()
                    && expect["findings"].is_array(),
                "case {id} has no complete expectation for {mode}"
            );
            let findings = strings(&expect["findings"]);
            let mut sorted = findings.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                findings, sorted,
                "case {id} {mode}: findings must be sorted and unique (the order jq and Rust both produce)"
            );
        }
    }
}

/// The chain constants are hashes of committed bytes. The bash harness cannot compute them and
/// trusts them; here they are recomputed from the files with the library, so a file edited
/// without its constant (or the reverse) fails `cargo test` and not only the cell that uses it.
/// Which artifacts the policy declares is checked against the policy text for the same reason.
#[test]
fn the_chain_constants_are_the_hashes_of_the_files_they_name() {
    let fixture = fixture();
    let chain = &fixture["chain"];
    for group in ["responses", "artifacts"] {
        let entries = chain[group].as_object().cloned().unwrap_or_default();
        assert!(!entries.is_empty(), "fixture chain.{group} is empty");
        for (name, entry) in entries {
            let file = entry["file"].as_str().unwrap_or_default();
            let bytes = fs::read(repo(file)).unwrap_or_default();
            assert!(
                !bytes.is_empty(),
                "chain.{group}.{name}: {file} is missing or empty"
            );
            assert_eq!(
                entry["hash"].as_str().unwrap_or_default(),
                blake3_hash(&bytes),
                "chain.{group}.{name}: the committed hash is not the hash of {file}"
            );
        }
    }

    let prior =
        fs::read(repo(chain["prior_manifest"].as_str().unwrap_or_default())).unwrap_or_default();
    let prior: AirlockManifest = serde_json::from_slice(&prior)
        .expect("the prior manifest named by the fixture must parse as a manifest");
    assert_eq!(
        chain["prior_manifest_hash"].as_str().unwrap_or_default(),
        prior.hash(),
        "chain.prior_manifest_hash is not the gate hash of the prior manifest"
    );

    let policy = fs::read_to_string(repo(fixture["policy"].as_str().unwrap_or_default()))
        .unwrap_or_default();
    for (name, entry) in chain["artifacts"].as_object().cloned().unwrap_or_default() {
        assert_eq!(
            policy.contains(entry["hash"].as_str().unwrap_or("no hash")),
            entry["declared_in_policy"] == true,
            "chain.artifacts.{name}: declared_in_policy disagrees with the matrix policy"
        );
    }
}

#[test]
fn every_cell_matches_its_committed_expectation() {
    let fixture = fixture();
    let matrix = Matrix::load(&fixture);
    let dir = tempdir().expect("temporary directory");
    let mut mismatches = Vec::new();
    let mut cells = 0;

    for mode in strings(&fixture["modes"]) {
        let (base_prompt, base_provenance) = matrix
            .assemble(
                &matrix.input,
                &mode,
                dir.path(),
                &format!("base-{mode}"),
                &[],
            )
            .expect("the honest assemble must succeed");
        let base_request = matrix.wrap(&base_prompt);

        for case in fixture["cases"].as_array().into_iter().flatten() {
            let id = case["id"].as_str().unwrap_or_default();
            let stem = format!("{id}-{mode}");
            let expected = &case["expect"][mode.as_str()];
            let ops = case["ops"].as_array().cloned().unwrap_or_default();

            let observed = match case["site"].as_str() {
                Some("request") => {
                    let mut request = base_request.clone();
                    let applied: Result<(), String> = ops
                        .iter()
                        .try_for_each(|op| apply_request_op(&mut request, op));
                    applied.and_then(|()| {
                        matrix.verify(&base_prompt, &base_provenance, &request, dir.path(), &stem)
                    })
                }
                Some("input_leak") => {
                    let mut input = read_json(&matrix.input);
                    let leak = ops.first().map_or(Value::Null, |op| op["value"].clone());
                    let slot = input.pointer_mut(&matrix.leak_pointer);
                    match slot {
                        Some(slot) => {
                            *slot = leak;
                            let leaked = dir.path().join(format!("{stem}.input.json"));
                            fs::write(&leaked, serde_json::to_vec(&input).unwrap_or_default())
                                .map_err(|error| error.to_string())
                                .and_then(|()| {
                                    matrix.assemble(&leaked, &mode, dir.path(), &stem, &[])
                                })
                                .and_then(|(prompt, provenance)| {
                                    let request = matrix.wrap(&prompt);
                                    matrix.verify(&prompt, &provenance, &request, dir.path(), &stem)
                                })
                        }
                        None => Err(format!("no value at {}", matrix.leak_pointer)),
                    }
                }
                Some("chain_turn") => matrix.chain_turn(&ops, &mode, dir.path(), &stem),
                other => Err(format!("unknown site {other:?}")),
            };

            cells += 1;
            match observed {
                Ok(observed) if observed == *expected => {}
                Ok(observed) => mismatches.push(format!(
                    "{id} [{mode}]\n    expected {expected}\n    observed {observed}"
                )),
                Err(error) => mismatches.push(format!("{id} [{mode}]: {error}")),
            }
        }
    }

    assert!(cells > 0, "no cells ran");
    assert!(
        mismatches.is_empty(),
        "{} of {cells} cells differ from fixtures/tamper_matrix.json:\n  {}",
        mismatches.len(),
        mismatches.join("\n  ")
    );
}

/// The committed doc is generated by the script from observed runs. Here its rows are checked
/// against the fixture, so editing the doc by hand (or changing the fixture without regenerating
/// it) fails `cargo test`.
#[test]
fn the_committed_doc_rows_match_the_fixture() -> Result<(), String> {
    let fixture = fixture();
    let doc = fs::read_to_string(repo("docs/tamper-matrix.md"))
        .expect("docs/tamper-matrix.md must exist; run tests/e2e_tamper_matrix.sh");

    let mut rows = Vec::new();
    for line in doc.lines().filter(|line| line.starts_with("| `")) {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        assert_eq!(cells.len(), 7, "malformed table row: {line}");
        let findings: Vec<String> = if cells[6] == "none" {
            Vec::new()
        } else {
            cells[6]
                .split(", ")
                .map(|finding| finding.trim_matches('`').to_owned())
                .collect()
        };
        rows.push((
            cells[0].trim_matches('`').to_owned(),
            cells[2].to_owned(),
            cells[3].parse::<i64>().unwrap_or(-1),
            cells[4].to_owned(),
            cells[5].to_owned(),
            findings,
        ));
    }

    let modes = strings(&fixture["modes"]);
    let cases = fixture["cases"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        rows.len(),
        cases.len() * modes.len(),
        "the doc must have exactly one row per case and mode"
    );
    for case in &cases {
        let id = case["id"].as_str().unwrap_or_default();
        for mode in &modes {
            let expect = &case["expect"][mode.as_str()];
            let Some(row) = rows.iter().find(|row| row.0 == id && row.1 == *mode) else {
                return Err(format!(
                    "docs/tamper-matrix.md has no row for {id} [{mode}]"
                ));
            };
            assert_eq!(
                (row.2, row.3.as_str(), row.4.as_str(), &row.5),
                (
                    expect["exit"].as_i64().unwrap_or(-2),
                    expect["claim"].as_str().unwrap_or_default(),
                    expect["binding"].as_str().unwrap_or_default(),
                    &strings(&expect["findings"]),
                ),
                "docs/tamper-matrix.md row for {id} [{mode}] differs from the fixture"
            );
        }
    }
    Ok(())
}
