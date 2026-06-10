pub mod exit;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::types::{BoundaryMode, ClaimLevel};

pub use exit::{REFUSAL, VERIFY_PARTIAL, VERIFY_PASS};

#[derive(Debug, Parser)]
#[command(
    name = "airlock",
    about = "Prove what crossed the model boundary",
    long_about = "Assemble proof-carrying model prompts, verify exactly what crossed the model boundary, and inspect local witness receipts.",
    after_help = "Agent entry points:\n  airlock --robot-triage\n  airlock capabilities --json\n  airlock robot-docs guide\n\nCore flow:\n  airlock assemble --policy <POLICY> --input <JSON>... --out prompt_payload.json --provenance-out prompt_provenance.json\n  airlock verify --policy <POLICY> --prompt prompt_payload.json --provenance prompt_provenance.json --request request.json --out airlock_manifest.json\n  airlock explain --manifest airlock_manifest.json --json",
    disable_version_flag = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(
        long,
        help = "Emit embedded operator metadata as canonical JSON and exit"
    )]
    pub describe: bool,

    #[arg(long, help = "Emit the airlock manifest JSON Schema and exit")]
    pub schema: bool,

    #[arg(long = "version", help = "Emit 'airlock <version>' and exit")]
    pub print_version: bool,

    #[arg(
        long = "robot-triage",
        help = "Emit read-only machine triage JSON without reading run artifacts or witness ledgers"
    )]
    pub robot_triage: bool,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum Commands {
    #[command(about = "Assemble deterministic prompt_payload.json and prompt_provenance.json")]
    Assemble(AssembleArgs),
    #[command(about = "Verify a prompt/request boundary and emit airlock_manifest.json")]
    Verify(VerifyArgs),
    #[command(about = "Render an airlock manifest as text or machine-readable explanation JSON")]
    Explain(ExplainArgs),
    #[command(about = "Read-only health, capabilities, robot docs, and triage for agents")]
    Doctor(DoctorArgs),
    #[command(about = "Alias for 'airlock doctor capabilities'; use --json for machine output")]
    Capabilities(DoctorJsonArgs),
    #[command(
        name = "robot-docs",
        about = "Alias for 'airlock doctor robot-docs'; accepts optional 'guide'"
    )]
    RobotDocs(RobotDocsArgs),
    #[command(subcommand, about = "Query the local witness ledger")]
    Witness(WitnessCommands),
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(
    after_help = "Example:\n  airlock assemble --policy rules/tournament_baseline.yaml --input strategy_space.json --out prompt_payload.json --provenance-out prompt_provenance.json --boundary-mode TELEMETRY_ONLY --no-witness"
)]
pub struct AssembleArgs {
    #[arg(long, help = "Boundary policy YAML file")]
    pub policy: PathBuf,

    #[arg(long, required = true, num_args = 1.., help = "Input JSON artifact; repeat for multiple upstream artifacts")]
    pub input: Vec<PathBuf>,

    #[arg(
        long = "system-prompt",
        help = "Optional UTF-8 system prompt file included in provenance"
    )]
    pub system_prompt: Option<PathBuf>,

    #[arg(
        long = "boundary-mode",
        default_value_t = BoundaryMode::Annotated,
        value_parser = parse_boundary_mode,
        help = "Boundary exposure mode: ANNOTATED or TELEMETRY_ONLY"
    )]
    pub boundary_mode: BoundaryMode,

    #[arg(long, help = "Path to write prompt_payload.json")]
    pub out: PathBuf,

    #[arg(long = "provenance-out", help = "Path to write prompt_provenance.json")]
    pub provenance_out: PathBuf,

    #[arg(long = "no-witness", help = "Skip ambient witness ledger recording")]
    pub no_witness: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(
    after_help = "Example:\n  airlock verify --policy rules/tournament_baseline.yaml --prompt prompt_payload.json --provenance prompt_provenance.json --request request.json --out airlock_manifest.json --require-claim RAW_DOCUMENT_ABSENT"
)]
pub struct VerifyArgs {
    #[arg(long, help = "Boundary policy YAML used during assembly")]
    pub policy: PathBuf,

    #[arg(long, help = "prompt_payload.json produced by airlock assemble")]
    pub prompt: PathBuf,

    #[arg(long, help = "prompt_provenance.json produced by airlock assemble")]
    pub provenance: PathBuf,

    #[arg(long, help = "Transport-wrapped model request JSON")]
    pub request: PathBuf,

    #[arg(long, help = "Path to write airlock_manifest.json")]
    pub out: PathBuf,

    #[arg(
        long = "require-claim",
        value_parser = parse_claim_level,
        help = "Minimum acceptable claim: BOUNDARY_FAILED, RAW_DOCUMENT_ABSENT, or STRICT_TELEMETRY_ONLY"
    )]
    pub require_claim: Option<ClaimLevel>,

    #[arg(long = "no-witness", help = "Skip ambient witness ledger recording")]
    pub no_witness: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(
    after_help = "Examples:\n  airlock explain --manifest airlock_manifest.json\n  airlock explain --manifest airlock_manifest.json --json"
)]
pub struct ExplainArgs {
    #[arg(long, help = "airlock_manifest.json to explain")]
    pub manifest: PathBuf,

    #[arg(long, help = "Emit machine-readable explanation JSON")]
    pub json: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(
    after_help = "Read-only agent surfaces:\n  airlock doctor health --json\n  airlock doctor capabilities --json\n  airlock doctor robot-docs\n  airlock doctor --robot-triage"
)]
pub struct DoctorArgs {
    #[arg(long = "robot-triage", help = "Emit read-only triage JSON for agents")]
    pub robot_triage: bool,

    #[arg(long, help = "Emit JSON where the selected doctor command supports it")]
    pub json: bool,

    #[command(subcommand)]
    pub command: Option<DoctorCommands>,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum DoctorCommands {
    #[command(about = "Read-only embedded health diagnostics")]
    Health(DoctorJsonArgs),
    #[command(about = "Machine-readable command, side-effect, and config contract")]
    Capabilities(DoctorJsonArgs),
    #[command(name = "robot-docs", about = "Paste-ready agent operating guide")]
    RobotDocs,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct DoctorJsonArgs {
    #[arg(long, help = "Emit JSON")]
    pub json: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct RobotDocsArgs {
    #[command(subcommand)]
    pub command: Option<RobotDocsCommands>,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum RobotDocsCommands {
    #[command(about = "Print the agent operating guide")]
    Guide,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum WitnessCommands {
    #[command(about = "List matching witness records")]
    Query(WitnessQueryArgs),
    #[command(about = "Show the newest matching witness record")]
    Last(WitnessLastArgs),
    #[command(about = "Count matching witness records")]
    Count(WitnessCountArgs),
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct WitnessQueryArgs {
    #[command(flatten)]
    pub filters: WitnessFilterArgs,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct WitnessLastArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct WitnessCountArgs {
    #[command(flatten)]
    pub filters: WitnessFilterArgs,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq, Default)]
pub struct WitnessFilterArgs {
    #[arg(long, help = "Filter by witness tool name")]
    pub tool: Option<String>,

    #[arg(long, help = "Filter records at or after an RFC3339 timestamp")]
    pub since: Option<String>,

    #[arg(long, help = "Filter records at or before an RFC3339 timestamp")]
    pub until: Option<String>,

    #[arg(
        long,
        help = "Filter by witness outcome, such as VERIFIED or VERIFY_PARTIAL"
    )]
    pub outcome: Option<String>,

    #[arg(
        long = "input-hash",
        help = "Filter by substring of an input content hash"
    )]
    pub input_hash: Option<String>,

    #[arg(long, help = "Maximum number of records to return")]
    pub limit: Option<usize>,
}

fn normalize_enum_input(value: &str) -> String {
    value.trim().replace('-', "_").to_ascii_uppercase()
}

fn parse_boundary_mode(value: &str) -> Result<BoundaryMode, String> {
    match normalize_enum_input(value).as_str() {
        "ANNOTATED" => Ok(BoundaryMode::Annotated),
        "TELEMETRY_ONLY" => Ok(BoundaryMode::TelemetryOnly),
        other => Err(format!(
            "invalid boundary mode '{other}'; expected ANNOTATED or TELEMETRY_ONLY"
        )),
    }
}

fn parse_claim_level(value: &str) -> Result<ClaimLevel, String> {
    match normalize_enum_input(value).as_str() {
        "BOUNDARY_FAILED" => Ok(ClaimLevel::BoundaryFailed),
        "RAW_DOCUMENT_ABSENT" => Ok(ClaimLevel::RawDocumentAbsent),
        "STRICT_TELEMETRY_ONLY" => Ok(ClaimLevel::StrictTelemetryOnly),
        other => Err(format!(
            "invalid claim level '{other}'; expected BOUNDARY_FAILED, RAW_DOCUMENT_ABSENT, or STRICT_TELEMETRY_ONLY"
        )),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn parses_assemble_args_with_defaults() {
        let cli = Cli::try_parse_from([
            "airlock",
            "assemble",
            "--policy",
            "policy.yaml",
            "--input",
            "strategy.json",
            "--out",
            "prompt.json",
            "--provenance-out",
            "provenance.json",
        ])
        .unwrap();

        let command = cli.command.unwrap();
        assert!(matches!(&command, Commands::Assemble(_)));
        let Commands::Assemble(args) = command else {
            return;
        };
        assert_eq!(args.policy, PathBuf::from("policy.yaml"));
        assert_eq!(args.input, vec![PathBuf::from("strategy.json")]);
        assert_eq!(args.boundary_mode, BoundaryMode::Annotated);
        assert!(!args.no_witness);
    }

    #[test]
    fn parses_verify_args_with_required_claim() {
        let cli = Cli::try_parse_from([
            "airlock",
            "verify",
            "--policy",
            "policy.yaml",
            "--prompt",
            "prompt.json",
            "--provenance",
            "provenance.json",
            "--request",
            "request.json",
            "--out",
            "manifest.json",
            "--require-claim",
            "raw_document_absent",
            "--no-witness",
        ])
        .unwrap();

        let command = cli.command.unwrap();
        assert!(matches!(&command, Commands::Verify(_)));
        let Commands::Verify(args) = command else {
            return;
        };
        assert_eq!(args.require_claim, Some(ClaimLevel::RawDocumentAbsent));
        assert!(args.no_witness);
    }

    #[test]
    fn parses_witness_query_filters() {
        let cli = Cli::try_parse_from([
            "airlock",
            "witness",
            "query",
            "--tool",
            "airlock",
            "--since",
            "2026-03-26T00:00:00Z",
            "--until",
            "2026-03-27T00:00:00Z",
            "--outcome",
            "VERIFIED",
            "--input-hash",
            "abc123",
            "--limit",
            "10",
            "--json",
        ])
        .unwrap();

        let command = cli.command.unwrap();
        assert!(matches!(
            &command,
            Commands::Witness(WitnessCommands::Query(_))
        ));
        let Commands::Witness(WitnessCommands::Query(args)) = command else {
            return;
        };
        assert_eq!(args.filters.tool.as_deref(), Some("airlock"));
        assert_eq!(args.filters.limit, Some(10));
        assert!(args.json);
    }

    #[test]
    fn parses_doctor_health_json() {
        let cli = Cli::try_parse_from(["airlock", "doctor", "health", "--json"]).unwrap();

        let command = cli.command.unwrap();
        assert!(matches!(&command, Commands::Doctor(_)));
        let Commands::Doctor(args) = command else {
            return;
        };
        assert!(matches!(&args.command, Some(DoctorCommands::Health(_))));
        let Some(DoctorCommands::Health(format)) = args.command else {
            return;
        };
        assert!(format.json);
        assert!(!args.robot_triage);
    }

    #[test]
    fn parses_doctor_robot_triage() {
        let cli = Cli::try_parse_from(["airlock", "doctor", "--robot-triage"]).unwrap();

        let command = cli.command.unwrap();
        assert!(matches!(&command, Commands::Doctor(_)));
        let Commands::Doctor(args) = command else {
            return;
        };
        assert!(args.robot_triage);
        assert!(args.command.is_none());
    }

    #[test]
    fn parses_witness_last_json_flag() {
        let cli = Cli::try_parse_from(["airlock", "witness", "last", "--json"]).unwrap();

        let command = cli.command.unwrap();
        assert!(matches!(
            &command,
            Commands::Witness(WitnessCommands::Last(_))
        ));
        let Commands::Witness(WitnessCommands::Last(args)) = command else {
            return;
        };
        assert!(args.json);
    }

    #[test]
    fn rejects_unknown_boundary_mode() {
        let err = Cli::try_parse_from([
            "airlock",
            "assemble",
            "--policy",
            "policy.yaml",
            "--input",
            "strategy.json",
            "--boundary-mode",
            "invalid",
            "--out",
            "prompt.json",
            "--provenance-out",
            "provenance.json",
        ])
        .unwrap_err();

        assert!(err.to_string().contains("invalid boundary mode"));
    }
}
