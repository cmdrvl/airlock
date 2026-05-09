pub mod exit;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::types::{BoundaryMode, ClaimLevel};

pub use exit::{REFUSAL, VERIFY_PARTIAL, VERIFY_PASS};

#[derive(Debug, Parser)]
#[command(
    name = "airlock",
    about = "Prove what crossed the model boundary",
    disable_version_flag = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(long)]
    pub describe: bool,

    #[arg(long)]
    pub schema: bool,

    #[arg(long = "version")]
    pub print_version: bool,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum Commands {
    Assemble(AssembleArgs),
    Verify(VerifyArgs),
    Explain(ExplainArgs),
    Doctor(DoctorArgs),
    #[command(subcommand)]
    Witness(WitnessCommands),
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct AssembleArgs {
    #[arg(long)]
    pub policy: PathBuf,

    #[arg(long, required = true, num_args = 1..)]
    pub input: Vec<PathBuf>,

    #[arg(long = "system-prompt")]
    pub system_prompt: Option<PathBuf>,

    #[arg(
        long = "boundary-mode",
        default_value_t = BoundaryMode::Annotated,
        value_parser = parse_boundary_mode
    )]
    pub boundary_mode: BoundaryMode,

    #[arg(long)]
    pub out: PathBuf,

    #[arg(long = "provenance-out")]
    pub provenance_out: PathBuf,

    #[arg(long = "no-witness")]
    pub no_witness: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct VerifyArgs {
    #[arg(long)]
    pub policy: PathBuf,

    #[arg(long)]
    pub prompt: PathBuf,

    #[arg(long)]
    pub provenance: PathBuf,

    #[arg(long)]
    pub request: PathBuf,

    #[arg(long)]
    pub out: PathBuf,

    #[arg(long = "require-claim", value_parser = parse_claim_level)]
    pub require_claim: Option<ClaimLevel>,

    #[arg(long = "no-witness")]
    pub no_witness: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct ExplainArgs {
    #[arg(long)]
    pub manifest: PathBuf,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct DoctorArgs {
    #[arg(long = "robot-triage")]
    pub robot_triage: bool,

    #[arg(long)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Option<DoctorCommands>,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum DoctorCommands {
    Health(DoctorJsonArgs),
    Capabilities(DoctorJsonArgs),
    #[command(name = "robot-docs")]
    RobotDocs,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct DoctorJsonArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum WitnessCommands {
    Query(WitnessQueryArgs),
    Last(WitnessLastArgs),
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
    #[arg(long)]
    pub tool: Option<String>,

    #[arg(long)]
    pub since: Option<String>,

    #[arg(long)]
    pub until: Option<String>,

    #[arg(long)]
    pub outcome: Option<String>,

    #[arg(long = "input-hash")]
    pub input_hash: Option<String>,

    #[arg(long)]
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
