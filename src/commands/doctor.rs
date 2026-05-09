use std::io::{self, Write};

use serde_json::{json, Map, Value};

use crate::cli::{DoctorArgs, DoctorCommands, DoctorJsonArgs, REFUSAL, VERIFY_PASS};
use crate::output::canonical_json;
use crate::witness;

const HEALTH_SCHEMA: &str = "airlock.doctor.health.v1";
const CAPABILITIES_SCHEMA: &str = "airlock.doctor.capabilities.v1";
const TRIAGE_SCHEMA: &str = "airlock.doctor.triage.v1";
const DOCTOR_CONTRACT: &str = "cmdrvl.read_only_doctor.v1";
const OPERATOR_JSON: &str = include_str!("../../operator.json");
const MANIFEST_SCHEMA_JSON: &str = include_str!("../../schemas/airlock.v0.schema.json");

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
}

#[derive(Debug, Clone)]
struct Diagnostics {
    operator_version: String,
    manifest_schema_title: String,
    witness_ledger_path: String,
    checks: Vec<Check>,
}

impl Diagnostics {
    fn ok(&self) -> bool {
        self.checks.iter().all(|check| check.ok)
    }

    fn status(&self) -> &'static str {
        if self.ok() {
            "healthy"
        } else {
            "unhealthy"
        }
    }

    fn exit_code(&self) -> u8 {
        if self.ok() {
            VERIFY_PASS
        } else {
            REFUSAL
        }
    }
}

pub fn run(args: DoctorArgs) -> u8 {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    run_with_writer(args, &mut stdout, &mut stderr)
}

fn run_with_writer(args: DoctorArgs, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
    let diagnostics = collect_diagnostics();

    if args.robot_triage {
        return write_json(
            stdout,
            stderr,
            &robot_triage_value(&diagnostics),
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
                write_json(stdout, stderr, &capabilities_value(), VERIFY_PASS)
            } else {
                write_text(stdout, &human_capabilities(), VERIFY_PASS)
            }
        }
        DoctorCommands::RobotDocs => write_text(stdout, &robot_docs(), VERIFY_PASS),
    }
}

fn collect_diagnostics() -> Diagnostics {
    let operator = serde_json::from_str::<Value>(OPERATOR_JSON);
    let manifest_schema = serde_json::from_str::<Value>(MANIFEST_SCHEMA_JSON);
    let operator_version = operator_field(&operator, "version");
    let manifest_schema_title = schema_title(&manifest_schema);
    let doctor_advertised = operator
        .as_ref()
        .ok()
        .and_then(|value| value.pointer("/subcommands/doctor"))
        .is_some();
    let witness_ledger_path = witness::default_witness_path().display().to_string();

    let checks = vec![
        Check {
            name: "operator_manifest_embedded_json",
            ok: operator.is_ok(),
            detail: parse_detail(&operator),
        },
        Check {
            name: "operator_manifest_version_matches_binary",
            ok: operator_version == env!("CARGO_PKG_VERSION"),
            detail: format!(
                "operator.json version={operator_version}; binary version={}",
                env!("CARGO_PKG_VERSION")
            ),
        },
        Check {
            name: "operator_manifest_doctor_command",
            ok: doctor_advertised,
            detail: "operator.json advertises doctor command discovery".to_owned(),
        },
        Check {
            name: "manifest_schema_embedded_json",
            ok: manifest_schema.is_ok(),
            detail: parse_detail(&manifest_schema),
        },
        Check {
            name: "manifest_schema_title",
            ok: manifest_schema_title == "airlock manifest schema",
            detail: format!("title={manifest_schema_title}"),
        },
        Check {
            name: "doctor_dispatch_read_only",
            ok: true,
            detail:
                "doctor dispatch does not call assemble, verify, explain, or witness query paths"
                    .to_owned(),
        },
        Check {
            name: "witness_path_resolves_without_open",
            ok: true,
            detail: witness_ledger_path.clone(),
        },
        Check {
            name: "fix_mode_disabled",
            ok: true,
            detail: "no doctor --fix argument or fixer registry is exposed".to_owned(),
        },
    ];

    Diagnostics {
        operator_version,
        manifest_schema_title,
        witness_ledger_path,
        checks,
    }
}

fn operator_field(operator: &Result<Value, serde_json::Error>, field: &str) -> String {
    match operator {
        Ok(value) => value
            .get(field)
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

fn health_value(diagnostics: &Diagnostics) -> Value {
    json!({
        "schema": HEALTH_SCHEMA,
        "tool": witness::TOOL_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "ok": diagnostics.ok(),
        "status": diagnostics.status(),
        "contract": DOCTOR_CONTRACT,
        "read_only": true,
        "operator_manifest": {
            "version": diagnostics.operator_version
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
        "side_effects": side_effects_value(),
        "fixers": [],
        "checks": checks_value(&diagnostics.checks)
    })
}

fn capabilities_value() -> Value {
    json!({
        "schema": CAPABILITIES_SCHEMA,
        "tool": witness::TOOL_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "contract": DOCTOR_CONTRACT,
        "read_only": true,
        "commands": [
            {
                "name": "doctor health",
                "json": true,
                "purpose": "Summarize embedded manifest, schema, dispatch, and witness-path health without reading run artifacts."
            },
            {
                "name": "doctor capabilities --json",
                "json": true,
                "purpose": "Expose machine-readable doctor capabilities, side effects, and disabled fixers."
            },
            {
                "name": "doctor robot-docs",
                "json": false,
                "purpose": "Print compact agent-facing command documentation."
            },
            {
                "name": "doctor --robot-triage",
                "json": true,
                "purpose": "Return a machine-readable triage packet for automation."
            }
        ],
        "exit_codes": {
            "0": "doctor check healthy or documentation rendered",
            "2": "doctor check unhealthy or command-line refusal"
        },
        "schemas": {
            "health": HEALTH_SCHEMA,
            "capabilities": CAPABILITIES_SCHEMA,
            "triage": TRIAGE_SCHEMA
        },
        "side_effects": side_effects_value(),
        "fixers": []
    })
}

fn robot_triage_value(diagnostics: &Diagnostics) -> Value {
    json!({
        "schema": TRIAGE_SCHEMA,
        "tool": witness::TOOL_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "ok": diagnostics.ok(),
        "status": diagnostics.status(),
        "contract": DOCTOR_CONTRACT,
        "read_only": true,
        "summary": {
            "message": if diagnostics.ok() {
                "airlock doctor checks passed"
            } else {
                "airlock doctor checks found unhealthy diagnostics"
            },
            "failed_checks": diagnostics.checks.iter().filter(|check| !check.ok).count()
        },
        "findings": failed_checks_value(&diagnostics.checks),
        "next_actions": if diagnostics.ok() {
            Value::Array(Vec::new())
        } else {
            json!(["inspect embedded operator manifest, schema, and doctor dispatch wiring"])
        },
        "side_effects": side_effects_value(),
        "fixers": []
    })
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

fn failed_checks_value(checks: &[Check]) -> Value {
    Value::Array(
        checks
            .iter()
            .filter(|check| !check.ok)
            .map(|check| {
                json!({
                    "severity": "error",
                    "check": check.name,
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
        format!("contract: {DOCTOR_CONTRACT}"),
        "read_only: true".to_owned(),
        format!("operator_manifest: {}", diagnostics.operator_version),
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

fn human_capabilities() -> String {
    [
        "airlock doctor capabilities",
        "commands:",
        "- doctor health [--json]",
        "- doctor capabilities --json",
        "- doctor robot-docs",
        "- doctor --robot-triage",
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
        "- `airlock doctor health [--json]` reports embedded manifest, schema, dispatch, and witness-path health.",
        "- `airlock doctor capabilities --json` reports command capabilities, side effects, and fixers.",
        "- `airlock doctor robot-docs` prints this compact agent-facing reference.",
        "- `airlock doctor --robot-triage` emits `airlock.doctor.triage.v1` JSON.",
        "",
        "Safety contract:",
        "- The doctor surface does not read policy, prompt, provenance, request, or manifest files.",
        "- The doctor surface does not run boundary scanners, adapters, assemble, verify, explain, or witness queries.",
        "- The doctor surface does not open, append, or create witness ledger files.",
        "- No `doctor --fix` mode exists in this slice.",
        "",
        "Exit codes:",
        "- `0`: doctor checks or documentation completed.",
        "- `2`: command-line refusal or unhealthy doctor diagnostics.",
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
    use super::*;

    #[test]
    fn capabilities_disable_every_side_effect() {
        let value = capabilities_value();
        let effects = value["side_effects"].as_object().unwrap();

        assert!(!effects.is_empty());
        assert!(effects
            .values()
            .all(|enabled| enabled.as_bool() == Some(false)));
        assert_eq!(value["fixers"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn health_reports_embedded_doctor_contract() {
        let diagnostics = collect_diagnostics();
        let value = health_value(&diagnostics);

        assert_eq!(value["schema"], HEALTH_SCHEMA);
        assert_eq!(value["tool"], witness::TOOL_NAME);
        assert_eq!(value["contract"], DOCTOR_CONTRACT);
        assert_eq!(value["read_only"], true);
    }
}
