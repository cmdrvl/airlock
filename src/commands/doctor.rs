use std::io::{self, Write};

use serde_json::{Map, Value, json};

use crate::cli::{DoctorArgs, DoctorCommands, DoctorJsonArgs, REFUSAL, UNHEALTHY, VERIFY_PASS};
use crate::output::{canonical_json, operator_json};
use crate::paths;
use crate::witness;

/// `schema_version` of every doctor report (family contract `cmdrvl.doctor.v1`).
const DOCTOR_SCHEMA_VERSION: &str = "cmdrvl.doctor.v1";
/// Airlock's read-only doctor guarantee. Renamed from the pre-v1 `contract` string
/// because `contract` now carries the `operator.v1` document in capabilities mode.
const READ_ONLY_DOCTOR_CONTRACT: &str = "cmdrvl.read_only_doctor.v1";
const OPERATOR_SCHEMA_VERSION: &str = "operator.v1";
const MANIFEST_SCHEMA_JSON: &str = include_str!("../../schemas/airlock.v0.schema.json");
const CHECK_FIX: &str = "rebuild airlock from a release tree: the embedded operator.json or manifest schema does not match this binary";

const SIDE_EFFECTS: &[&str] = &[
    "reads_stdin",
    "reads_policy_files",
    "reads_prompt_files",
    "reads_provenance_files",
    "reads_request_files",
    "reads_manifest_files",
    "executes_boundary_scan",
    "opens_witness_ledger",
    "appends_witness_ledger",
    "creates_witness_directory",
    "reads_config_files",
    "writes_config_files",
    "writes_migration_logs",
    "writes_deprecation_notices",
    "writes_prompt_payload",
    "writes_prompt_provenance",
    "writes_manifest",
    "writes_doctor_artifacts",
    "uses_network",
    "changes_cwd",
    "rewrites_policy",
    "invokes_adapters",
];

#[derive(Debug, Clone)]
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
    /// Remediation, reported only when the check fails.
    fix: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct Diagnostics {
    operator_version: String,
    operator_schema_version: String,
    manifest_schema_title: String,
    witness_ledger_path: String,
    checks: Vec<Check>,
}

impl Diagnostics {
    fn ok(&self) -> bool {
        self.checks.iter().all(|check| check.ok)
    }

    fn status(&self) -> &'static str {
        if self.ok() { "healthy" } else { "unhealthy" }
    }

    /// `0` healthy, `1` unhealthy. Never `2`: that is reserved for usage errors.
    fn exit_code(&self) -> u8 {
        if self.ok() { VERIFY_PASS } else { UNHEALTHY }
    }

    fn failed(&self) -> Vec<&Check> {
        self.checks.iter().filter(|check| !check.ok).collect()
    }
}

pub fn run(args: DoctorArgs) -> u8 {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    run_with_writer(args, &mut stdout, &mut stderr)
}

pub fn run_with_writer(args: DoctorArgs, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let diagnostics = collect_diagnostics();

    if args.robot_triage {
        return write_json(
            stdout,
            stderr,
            &triage_value(&diagnostics),
            diagnostics.exit_code(),
        );
    }

    let command = args
        .command
        .unwrap_or(DoctorCommands::Health(DoctorJsonArgs { json: args.json }));

    match command {
        DoctorCommands::Health(format) => {
            if args.json || format.json {
                write_json(
                    stdout,
                    stderr,
                    &health_value(&diagnostics),
                    diagnostics.exit_code(),
                )
            } else {
                write_text(stdout, &human_health(&diagnostics), diagnostics.exit_code())
            }
        }
        DoctorCommands::Capabilities(format) => {
            if args.json || format.json {
                write_json(
                    stdout,
                    stderr,
                    &capabilities_value(&diagnostics),
                    diagnostics.exit_code(),
                )
            } else {
                write_text(stdout, &human_capabilities(), diagnostics.exit_code())
            }
        }
        DoctorCommands::Triage(format) => {
            if args.json || format.json {
                write_json(
                    stdout,
                    stderr,
                    &triage_value(&diagnostics),
                    diagnostics.exit_code(),
                )
            } else {
                write_text(stdout, &human_triage(&diagnostics), diagnostics.exit_code())
            }
        }
        DoctorCommands::RobotDocs => write_text(stdout, &robot_docs(), VERIFY_PASS),
    }
}

/// Human `airlock capabilities` text for the top-level alias (no `--json`).
pub fn run_capabilities_text(stdout: &mut impl Write) -> u8 {
    write_text(stdout, &human_capabilities(), VERIFY_PASS)
}

fn collect_diagnostics() -> Diagnostics {
    collect_diagnostics_from(operator_json(), MANIFEST_SCHEMA_JSON)
}

fn collect_diagnostics_from(operator_src: &str, schema_src: &str) -> Diagnostics {
    let operator = serde_json::from_str::<Value>(operator_src);
    let manifest_schema = serde_json::from_str::<Value>(schema_src);
    let operator_version = operator_field(&operator, "/tool_version");
    let operator_schema_version = operator_field(&operator, "/schema_version");
    let manifest_schema_title = schema_title(&manifest_schema);
    let doctor_advertised = operator
        .as_ref()
        .ok()
        .and_then(|value| value.get("commands"))
        .and_then(Value::as_array)
        .is_some_and(|commands| commands.iter().any(|command| command["name"] == "doctor"));
    let witness_ledger_path = witness::default_witness_path().display().to_string();

    let checks = vec![
        Check {
            name: "operator_manifest_embedded_json",
            ok: operator.is_ok(),
            detail: parse_detail(&operator),
            fix: Some(CHECK_FIX),
        },
        Check {
            name: "operator_manifest_schema_version",
            ok: operator_schema_version == OPERATOR_SCHEMA_VERSION,
            detail: format!(
                "operator.json schema_version={operator_schema_version}; expected {OPERATOR_SCHEMA_VERSION}"
            ),
            fix: Some(CHECK_FIX),
        },
        Check {
            name: "operator_manifest_version_matches_binary",
            ok: operator_version == env!("CARGO_PKG_VERSION"),
            detail: format!(
                "operator.json tool_version={operator_version}; binary version={}",
                env!("CARGO_PKG_VERSION")
            ),
            fix: Some(CHECK_FIX),
        },
        Check {
            name: "operator_manifest_doctor_command",
            ok: doctor_advertised,
            detail: "operator.json advertises doctor command discovery".to_owned(),
            fix: Some(CHECK_FIX),
        },
        Check {
            name: "manifest_schema_embedded_json",
            ok: manifest_schema.is_ok(),
            detail: parse_detail(&manifest_schema),
            fix: Some(CHECK_FIX),
        },
        Check {
            name: "manifest_schema_title",
            ok: manifest_schema_title == "airlock manifest schema",
            detail: format!("title={manifest_schema_title}"),
            fix: Some(CHECK_FIX),
        },
        Check {
            name: "doctor_dispatch_read_only",
            ok: true,
            detail:
                "doctor dispatch does not call assemble, verify, explain, or witness query paths"
                    .to_owned(),
            fix: None,
        },
        Check {
            name: "witness_path_resolves_without_open",
            ok: true,
            detail: witness_ledger_path.clone(),
            fix: None,
        },
        Check {
            name: "config_footprint_declared",
            ok: true,
            detail: "implicit witness state is rooted under ~/.cmdrvl/state/witness".to_owned(),
            fix: None,
        },
        Check {
            name: "fix_mode_disabled",
            ok: true,
            detail: "no doctor --fix argument or fixer registry is exposed".to_owned(),
            fix: None,
        },
    ];

    Diagnostics {
        operator_version,
        operator_schema_version,
        manifest_schema_title,
        witness_ledger_path,
        checks,
    }
}

fn operator_field(operator: &Result<Value, serde_json::Error>, pointer: &str) -> String {
    match operator {
        Ok(value) => value
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or("<missing>")
            .to_owned(),
        Err(error) => format!("parse error: {error}"),
    }
}

fn schema_title(schema: &Result<Value, serde_json::Error>) -> String {
    match schema {
        Ok(value) => value
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("<missing title>")
            .to_owned(),
        Err(error) => format!("parse error: {error}"),
    }
}

fn parse_detail(result: &Result<Value, serde_json::Error>) -> String {
    match result {
        Ok(_) => "embedded JSON parses".to_owned(),
        Err(error) => format!("embedded JSON parse failed: {error}"),
    }
}

/// `cmdrvl.doctor.v1` findings: one per check. A failing check is an `error`
/// finding, so `healthy` is exactly "no error finding".
fn findings_value(checks: &[&Check]) -> Value {
    Value::Array(
        checks
            .iter()
            .map(|check| {
                let mut finding = json!({
                    "id": check.name,
                    "severity": if check.ok { "info" } else { "error" },
                    "message": check.detail,
                });
                if !check.ok
                    && let Some(fix) = check.fix
                {
                    finding["fix"] = json!(fix);
                }
                finding
            })
            .collect(),
    )
}

/// `cmdrvl.doctor.v1`, mode `health`. The pre-v1 detail fields (`ok`, `status`,
/// `version`, `read_only`, `witness`, `config_footprint`, `side_effects`, `fixers`,
/// `checks`) remain as additive extras; the old `schema` id is superseded by
/// `schema_version`, and the old `contract` string is now `read_only_contract`.
fn health_value(diagnostics: &Diagnostics) -> Value {
    let all: Vec<&Check> = diagnostics.checks.iter().collect();
    json!({
        "schema_version": DOCTOR_SCHEMA_VERSION,
        "mode": "health",
        "tool": witness::TOOL_NAME,
        "tool_version": env!("CARGO_PKG_VERSION"),
        "healthy": diagnostics.ok(),
        "findings": findings_value(&all),
        "version": env!("CARGO_PKG_VERSION"),
        "ok": diagnostics.ok(),
        "status": diagnostics.status(),
        "read_only": true,
        "read_only_contract": READ_ONLY_DOCTOR_CONTRACT,
        "operator_manifest": {
            "schema_version": diagnostics.operator_schema_version,
            "tool_version": diagnostics.operator_version
        },
        "schemas": {
            "manifest": diagnostics.manifest_schema_title
        },
        "witness": {
            "ledger_path": diagnostics.witness_ledger_path,
            "opened": false,
            "appended": false,
            "directory_created": false
        },
        "config_footprint": paths::config_footprint(),
        "side_effects": side_effects_value(),
        "fixers": [],
        "checks": checks_value(&diagnostics.checks)
    })
}

/// `cmdrvl.doctor.v1`, mode `capabilities`. `contract` is the `operator.v1`
/// document, identical to `airlock capabilities --json`. The report describes the
/// tool and inspects only the embedded manifest, so its findings are the failed
/// embedded-asset checks (none on a healthy build).
fn capabilities_value(diagnostics: &Diagnostics) -> Value {
    let mut value = json!({
        "schema_version": DOCTOR_SCHEMA_VERSION,
        "mode": "capabilities",
        "tool": witness::TOOL_NAME,
        "tool_version": env!("CARGO_PKG_VERSION"),
        "healthy": diagnostics.ok(),
        "findings": findings_value(&diagnostics.failed()),
        "version": env!("CARGO_PKG_VERSION"),
        "read_only": true,
        "read_only_contract": READ_ONLY_DOCTOR_CONTRACT,
        "agent_entrypoints": {
            "triage_json": "airlock doctor triage --json",
            "capabilities_json": "airlock capabilities --json",
            "robot_docs": "airlock robot-docs guide",
            "core_flow": [
                "airlock assemble --policy <POLICY> --input <JSON>... --out prompt_payload.json --provenance-out prompt_provenance.json",
                "airlock verify --policy <POLICY> --prompt prompt_payload.json --provenance prompt_provenance.json --request request.json --out airlock_manifest.json",
                "airlock explain --manifest airlock_manifest.json --json"
            ]
        },
        "composition": {
            "family": {
                "name": "cmdrvl-boundary-attestation",
                "siblings": [
                    {"tool": "veil", "capabilities": "veil capabilities --json"},
                    {"tool": "fingerprint", "capabilities": "fingerprint capabilities --json"},
                    {"tool": "benchmark", "capabilities": "benchmark capabilities --json"},
                    {"tool": "assess", "capabilities": "assess capabilities --json"},
                    {"tool": "lock", "capabilities": "lock capabilities --json"},
                    {"tool": "pack", "capabilities": "pack capabilities --json"}
                ]
            },
            "role": "boundary attestation primitive between deterministic evidence and model execution",
            "position": "after deterministic evidence preparation and before model request execution",
            "accepts": ["airlock policy", "policy-approved JSON inputs", "prompt payload", "prompt provenance", "model request"],
            "produces": ["prompt_payload.json", "prompt_provenance.json", "airlock_manifest.json"],
            "canonical_chain": [
                "airlock assemble --policy <POLICY> --input <JSON>... --out prompt_payload.json --provenance-out prompt_provenance.json",
                "airlock verify --policy <POLICY> --prompt prompt_payload.json --provenance prompt_provenance.json --request request.json --out airlock_manifest.json",
                "pack seal airlock_manifest.json prompt_provenance.json --output evidence/airlock/"
            ],
            "agent_rules": [
                "Use veil before airlock to prevent raw sensitive reads from entering the agent context.",
                "Use airlock when evidence-derived prompt material is about to cross a model boundary.",
                "Use benchmark and assess after model execution when correctness scoring and action classification are needed.",
                "Seal airlock manifests with pack alongside downstream reports."
            ]
        },
        "config_footprint": paths::config_footprint(),
        "side_effects": side_effects_value(),
        "fixers": []
    });

    if let Ok(contract) = serde_json::from_str::<Value>(operator_json()) {
        value["contract"] = contract;
    }
    value
}

/// `cmdrvl.doctor.v1`, mode `triage`. `next_actions` is never empty when unhealthy.
fn triage_value(diagnostics: &Diagnostics) -> Value {
    let failed = diagnostics.failed();
    let mut next_actions: Vec<String> = failed
        .iter()
        .filter_map(|check| check.fix.map(|fix| format!("{}: {fix}", check.name)))
        .collect();
    if !diagnostics.ok() && next_actions.is_empty() {
        next_actions.push("run `airlock doctor --json` for details".to_owned());
    }

    let mut value = health_value(diagnostics);
    value["mode"] = json!("triage");
    value["next_actions"] = json!(next_actions);
    value["summary"] = json!({
        "message": if diagnostics.ok() {
            "airlock doctor checks passed"
        } else {
            "airlock doctor checks found unhealthy diagnostics"
        },
        "capabilities": "airlock capabilities --json",
        "robot_docs": "airlock robot-docs guide",
        "failed_checks": failed.len()
    });
    value
}

fn side_effects_value() -> Value {
    let mut effects = Map::new();
    for name in SIDE_EFFECTS {
        effects.insert((*name).to_owned(), Value::Bool(false));
    }
    Value::Object(effects)
}

fn checks_value(checks: &[Check]) -> Value {
    Value::Array(
        checks
            .iter()
            .map(|check| {
                json!({
                    "name": check.name,
                    "ok": check.ok,
                    "detail": check.detail
                })
            })
            .collect(),
    )
}

fn human_health(diagnostics: &Diagnostics) -> String {
    let mut lines = vec![
        format!("airlock doctor health: {}", diagnostics.status()),
        format!("version: {}", env!("CARGO_PKG_VERSION")),
        format!("report: {DOCTOR_SCHEMA_VERSION}"),
        format!("read_only_contract: {READ_ONLY_DOCTOR_CONTRACT}"),
        format!(
            "operator_manifest: {} ({})",
            diagnostics.operator_version, diagnostics.operator_schema_version
        ),
        format!("manifest_schema: {}", diagnostics.manifest_schema_title),
        "side_effects: none".to_owned(),
        "fixers: none".to_owned(),
        "checks:".to_owned(),
    ];

    for check in &diagnostics.checks {
        let status = if check.ok { "ok" } else { "fail" };
        lines.push(format!("- {}: {status} ({})", check.name, check.detail));
    }

    lines.join("\n")
}

fn human_triage(diagnostics: &Diagnostics) -> String {
    let mut lines = vec![format!("airlock doctor triage: {}", diagnostics.status())];
    let failed = diagnostics.failed();
    if failed.is_empty() {
        lines.push("next_actions: none".to_owned());
    } else {
        lines.push("next_actions:".to_owned());
        for check in failed {
            lines.push(format!(
                "- {}: {}",
                check.name,
                check
                    .fix
                    .unwrap_or("run `airlock doctor --json` for details")
            ));
        }
    }
    lines.join("\n")
}

fn human_capabilities() -> String {
    [
        "airlock capabilities",
        "commands:",
        "- assemble --policy <POLICY> --input <JSON>... --out <PROMPT> --provenance-out <PROVENANCE>",
        "- verify --policy <POLICY> --prompt <PROMPT> --provenance <PROVENANCE> --request <REQUEST> --out <MANIFEST>",
        "- explain --manifest <MANIFEST> [--json]",
        "- witness query|last|count [filters] [--json]",
        "- doctor [--json]",
        "- doctor capabilities --json",
        "- doctor triage --json",
        "- doctor robot-docs",
        "agent_entrypoints:",
        "- airlock capabilities --json   (operator.v1 contract, same document as --describe)",
        "- airlock doctor triage --json",
        "- airlock robot-docs guide",
        "read_only: true",
        "side_effects: none",
        "fixers: none",
    ]
    .join("\n")
}

fn robot_docs() -> String {
    [
        "# airlock doctor robot docs",
        "",
        "Read-only commands:",
        "- `airlock capabilities --json` emits the `operator.v1` contract (same document as `airlock --describe`).",
        "- `airlock doctor [--json]` reports embedded manifest, schema, dispatch, and witness-path health as `cmdrvl.doctor.v1` (mode `health`).",
        "- `airlock doctor capabilities --json` is `cmdrvl.doctor.v1` mode `capabilities`; its `contract` is the `capabilities --json` document.",
        "- `airlock doctor triage --json` is `cmdrvl.doctor.v1` mode `triage` with `next_actions`.",
        "- `airlock robot-docs guide` prints this compact agent-facing reference.",
        "- `airlock doctor robot-docs` prints the same reference.",
        "- Deprecated aliases: `airlock doctor health [--json]`, `airlock doctor --robot-triage`, `airlock --robot-triage` (same document as `doctor triage --json`).",
        "- `airlock explain --manifest <MANIFEST> --json` summarizes a manifest without re-verifying it.",
        "",
        "Safety contract:",
        "- The doctor surface does not read policy, prompt, provenance, request, or manifest files.",
        "- The doctor surface does not run boundary scanners, adapters, assemble, verify, explain, or witness queries.",
        "- The doctor surface does not open, append, or create witness ledger files.",
        "- The implicit witness ledger fallback is `~/.cmdrvl/state/witness/witness.jsonl`; `EPISTEMIC_WITNESS` remains an explicit operator override.",
        "- No `doctor --fix` mode exists in this slice.",
        "",
        "Composition:",
        "- Use `veil` before airlock to keep raw sensitive files out of agent context.",
        "- Assemble: `airlock assemble --policy <POLICY> --input <JSON>... --out prompt_payload.json --provenance-out prompt_provenance.json`.",
        "- Verify: `airlock verify --policy <POLICY> --prompt prompt_payload.json --provenance prompt_provenance.json --request request.json --out airlock_manifest.json`.",
        "- Seal: `pack seal airlock_manifest.json prompt_provenance.json --output evidence/airlock/`.",
        "",
        "Exit codes:",
        "- doctor: `0` healthy, `1` unhealthy (an `error` finding), `2` usage error only.",
        "- other read-only surfaces: `0` on success.",
    ]
    .join("\n")
}

fn write_json(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    value: &Value,
    exit_code: u8,
) -> u8 {
    let rendered = canonical_json(value);
    if let Err(error) = writeln!(stdout, "{rendered}") {
        let _ = writeln!(stderr, "airlock doctor: failed to write JSON: {error}");
        return REFUSAL;
    }
    exit_code
}

fn write_text(stdout: &mut impl Write, text: &str, exit_code: u8) -> u8 {
    let _ = writeln!(stdout, "{text}");
    exit_code
}

#[cfg(test)]
mod tests {
    use spine_rules::doctor::{DoctorMode, DoctorReport, check_doctor_run};

    use super::*;

    const BROKEN_OPERATOR: &str = "{ not json";

    fn healthy() -> Diagnostics {
        collect_diagnostics()
    }

    fn unhealthy() -> Diagnostics {
        collect_diagnostics_from(BROKEN_OPERATOR, MANIFEST_SCHEMA_JSON)
    }

    fn rendered(value: &Value) -> Vec<u8> {
        canonical_json(value).into_bytes()
    }

    #[test]
    fn healthy_build_has_no_failed_checks() {
        let diagnostics = healthy();
        assert!(
            diagnostics.ok(),
            "embedded assets must be healthy: {:?}",
            diagnostics.failed()
        );
        assert_eq!(diagnostics.exit_code(), VERIFY_PASS);
    }

    #[test]
    fn healthy_reports_conform_to_family_doctor_contract() {
        let diagnostics = healthy();
        for (mode, value) in [
            (DoctorMode::Health, health_value(&diagnostics)),
            (DoctorMode::Capabilities, capabilities_value(&diagnostics)),
            (DoctorMode::Triage, triage_value(&diagnostics)),
        ] {
            let violations = check_doctor_run(mode, &rendered(&value), Some(0));
            assert!(violations.is_empty(), "{mode:?}: {violations:?}");
        }
    }

    #[test]
    fn unhealthy_reports_conform_and_exit_one_never_two() {
        let diagnostics = unhealthy();
        assert!(!diagnostics.ok());
        assert_eq!(diagnostics.exit_code(), UNHEALTHY);
        assert_eq!(UNHEALTHY, 1);

        for (mode, value) in [
            (DoctorMode::Health, health_value(&diagnostics)),
            (DoctorMode::Triage, triage_value(&diagnostics)),
        ] {
            let violations = check_doctor_run(mode, &rendered(&value), Some(1));
            assert!(violations.is_empty(), "{mode:?}: {violations:?}");
            // The same report returned with exit 2 must be rejected by the contract.
            let wrong = check_doctor_run(mode, &rendered(&value), Some(2));
            assert!(
                !wrong.is_empty(),
                "{mode:?}: exit 2 for unhealthy must fail"
            );
        }
    }

    #[test]
    fn unhealthy_findings_carry_error_severity_and_fix() {
        let report = DoctorReport::parse(&canonical_json(&health_value(&unhealthy()))).unwrap();
        assert!(!report.healthy);
        let failing: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.severity == spine_rules::doctor::Severity::Error)
            .collect();
        assert!(
            failing
                .iter()
                .any(|finding| finding.id == "operator_manifest_embedded_json")
        );
        assert!(failing.iter().all(|finding| finding.fix.is_some()));
    }

    #[test]
    fn triage_next_actions_are_non_empty_when_unhealthy_and_empty_when_healthy() {
        let sick = triage_value(&unhealthy());
        assert!(!sick["next_actions"].as_array().unwrap().is_empty());
        let well = triage_value(&healthy());
        assert_eq!(well["next_actions"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn capabilities_contract_is_the_embedded_operator_document() {
        let value = capabilities_value(&healthy());
        let embedded: Value = serde_json::from_str(operator_json()).unwrap();
        assert_eq!(value["contract"], embedded);
        assert_eq!(value["contract"]["schema_version"], "operator.v1");
    }

    #[test]
    fn wrong_operator_schema_version_is_an_error_finding() {
        let operator = operator_json().replace("\"operator.v1\"", "\"operator.v0\"");
        let diagnostics = collect_diagnostics_from(&operator, MANIFEST_SCHEMA_JSON);
        assert!(!diagnostics.ok());
        assert!(
            diagnostics
                .failed()
                .iter()
                .any(|check| check.name == "operator_manifest_schema_version")
        );
    }

    #[test]
    fn capabilities_disable_every_side_effect() {
        let value = capabilities_value(&healthy());
        let effects = value["side_effects"].as_object().unwrap();

        assert!(!effects.is_empty());
        assert!(
            effects
                .values()
                .all(|enabled| enabled.as_bool() == Some(false))
        );
        assert_eq!(value["fixers"].as_array().map(Vec::len), Some(0));
        assert_eq!(
            value["agent_entrypoints"]["capabilities_json"],
            "airlock capabilities --json"
        );
        assert!(
            value["contract"]["commands"]
                .as_array()
                .unwrap()
                .iter()
                .any(|command| command["name"] == "explain")
        );
    }

    #[test]
    fn health_reports_read_only_contract_and_footprint() {
        let value = health_value(&healthy());

        assert_eq!(value["schema_version"], DOCTOR_SCHEMA_VERSION);
        assert_eq!(value["tool"], witness::TOOL_NAME);
        assert_eq!(value["read_only_contract"], READ_ONLY_DOCTOR_CONTRACT);
        assert_eq!(value["read_only"], true);
        assert_eq!(
            value["config_footprint"]["managed_state_paths"][0],
            paths::CANONICAL_WITNESS
        );
    }
}
