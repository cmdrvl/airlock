pub mod exit;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::types::{BoundaryMode, ClaimLevel};

pub use exit::{REFUSAL, UNHEALTHY, VERIFY_PARTIAL, VERIFY_PASS};

#[derive(Debug, Parser)]
#[command(
    name = "airlock",
    about = "Prove what crossed the model boundary",
    long_about = "Assemble proof-carrying model prompts, verify exactly what crossed the model boundary, and inspect local witness receipts.",
    after_help = "Agent entry points:\n  airlock doctor triage --json\n  airlock capabilities --json\n  airlock robot-docs guide\n\nCore flow:\n  airlock assemble --policy <POLICY> --input <JSON>... --out prompt_payload.json --provenance-out prompt_provenance.json\n  airlock verify --policy <POLICY> --prompt prompt_payload.json --provenance prompt_provenance.json --request request.json --out airlock_manifest.json\n  airlock explain --manifest airlock_manifest.json --json",
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
        help = "Deprecated alias of `doctor triage --json` (read-only; never reads run artifacts or witness ledgers)"
    )]
    pub robot_triage: bool,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum Commands {
    #[command(about = "Assemble deterministic prompt_payload.json and prompt_provenance.json")]
    Assemble(AssembleArgs),
    #[command(about = "Verify a prompt/request boundary and emit airlock_manifest.json")]
    Verify(VerifyArgs),
    #[command(
        about = "Verify an assembled prompt, then send it to a model endpoint and record what crossed"
    )]
    Send(SendArgs),
    #[command(about = "Generate the Ed25519 key pair that `verify` signs manifests with")]
    Keygen(KeygenArgs),
    #[command(
        name = "verify-manifest",
        about = "Check the Ed25519 signature on an airlock manifest"
    )]
    VerifyManifest(VerifyManifestArgs),
    #[command(
        subcommand,
        about = "Check the chain of turns an airlock manifest belongs to"
    )]
    Chain(ChainCommands),
    #[command(about = "Render an airlock manifest as text or machine-readable explanation JSON")]
    Explain(ExplainArgs),
    #[command(about = "Read-only health, capabilities, robot docs, and triage for agents")]
    Doctor(DoctorArgs),
    #[command(about = "Emit the operator.v1 contract (same document as --describe) with --json")]
    Capabilities(DoctorJsonArgs),
    #[command(
        name = "robot-docs",
        about = "Alias for 'airlock doctor robot-docs'; accepts optional 'guide'"
    )]
    RobotDocs(RobotDocsArgs),
    #[command(subcommand, about = "Query the local witness ledger")]
    Witness(WitnessCommands),
    #[command(about = "Run a loopback HTTP/SSE egress gate")]
    Gate(GateArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum GateMode {
    #[value(name = "strict-manifest")]
    StrictManifest,
    #[value(name = "policy-proxy")]
    PolicyProxy,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(
    after_help = "Examples:\n  airlock gate --mode policy-proxy --policy policy.yaml --upstream https://api.openai.com --protected-bloom protected-corpus.bdbl\n  airlock gate --mode strict-manifest --manifest-dir manifests --upstream https://api.openai.com"
)]
pub struct GateArgs {
    #[arg(
        long,
        value_enum,
        help = "Gate contract: strict-manifest or policy-proxy"
    )]
    pub mode: GateMode,

    #[arg(long, help = "Provider base URL to which requests are forwarded")]
    pub upstream: String,

    #[arg(long, help = "Boundary policy required by policy-proxy mode")]
    pub policy: Option<PathBuf>,

    #[arg(
        long,
        help = "Optional transport declaration for provider selection or generic_json screening"
    )]
    pub transport: Option<PathBuf>,

    #[arg(
        long = "manifest-dir",
        help = "Pre-verified Airlock manifests required by strict-manifest mode"
    )]
    pub manifest_dir: Option<PathBuf>,

    #[arg(
        long,
        help = "Strict-manifest mode: Ed25519 public key to check each signed manifest against. Without it the gate uses ~/.cmdrvl/secrets/airlock/ed25519.pub when that file exists, and otherwise does not check signatures. An unsigned manifest is always accepted"
    )]
    pub pubkey: Option<PathBuf>,

    #[arg(
        long = "protected-bloom",
        help = "Opaque BDBL v1 Bloom filter exported by veil"
    )]
    pub protected_bloom: Option<PathBuf>,

    #[arg(
        long,
        default_value = "127.0.0.1:8787",
        help = "Loopback address for the local proxy"
    )]
    pub listen: String,

    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=600), help = "Strict upstream timeout in seconds")]
    pub timeout_seconds: u64,

    #[arg(
        long = "max-request-bytes",
        value_parser = clap::value_parser!(u64).range(1..=1_073_741_824),
        help = "Largest request body to read, in bytes (default 33554432 in strict-manifest mode; policy-proxy defaults to and cannot exceed its 4194304 byte scan limit)"
    )]
    pub max_request_bytes: Option<u64>,

    #[arg(
        long = "require-claim",
        value_parser = parse_claim_level,
        help = "Strict-manifest mode: lowest claim a matching manifest may carry (BOUNDARY_FAILED, RAW_DOCUMENT_ABSENT, or STRICT_TELEMETRY_ONLY); a request whose manifest is weaker is denied"
    )]
    pub require_claim: Option<ClaimLevel>,

    #[arg(
        long = "out-dir",
        default_value = "airlock-gate",
        help = "Directory for gate receipts"
    )]
    pub out_dir: PathBuf,

    #[arg(long = "no-witness", help = "Skip ambient witness ledger recording")]
    pub no_witness: bool,
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

    #[arg(
        long,
        visible_alias = "output",
        help = "Path to write prompt_payload.json"
    )]
    pub out: PathBuf,

    #[arg(long = "provenance-out", help = "Path to write prompt_provenance.json")]
    pub provenance_out: PathBuf,

    #[arg(
        long = "not-crossed-out",
        help = "Optional path to write not_crossed.json: every input field that did not cross, as path, source artifact hash, value hash and reason (values are never written)"
    )]
    pub not_crossed_out: Option<PathBuf>,

    #[arg(
        long = "prior-receipt",
        requires_all = ["response", "response_adapter", "prior_manifest"],
        help = "Gate receipt (airlock.gate.v1) that recorded the earlier response. Its response_hash must equal the hash of --response, it must be an admitted 2xx exchange, and it must name a matched manifest. A receipt is unsigned JSON, so this link is only as strong as the file's custody"
    )]
    pub prior_receipt: Option<PathBuf>,

    #[arg(
        long,
        requires_all = ["prior_receipt", "response_adapter", "prior_manifest"],
        help = "Provider response body from the earlier turn, exactly as received (JSON, not a stream). Its text and tool calls enter the prompt as MODEL_OUTPUT under prior_turn"
    )]
    pub response: Option<PathBuf>,

    #[arg(
        long = "response-adapter",
        requires_all = ["prior_receipt", "response", "prior_manifest"],
        help = "Provider that produced --response: openai_responses or anthropic_messages"
    )]
    pub response_adapter: Option<String>,

    #[arg(
        long = "prior-manifest",
        requires_all = ["prior_receipt", "response", "response_adapter"],
        help = "The manifest of the earlier turn. Its hash must equal the receipt's matched_manifest_hash, so a receipt paired with the wrong manifest is refused before anything is written. The new prompt's chain link records that hash and the next turn_index (1 after a manifest with no chain link); the manifest verify writes for it is airlock.v0.4"
    )]
    pub prior_manifest: Option<PathBuf>,

    #[arg(
        long = "tool-result",
        value_name = "TOOL_USE_ID=PATH",
        requires_all = ["prior_receipt", "response", "response_adapter", "prior_manifest"],
        help = "A tool result that answers a tool call in --response (repeatable). PATH is a UTF-8 text artifact, embedded verbatim. The strict claim needs the policy's declared_tool_results to list the blake3 hash of its exact bytes; an undeclared tool result is admitted but caps the claim at RAW_DOCUMENT_ABSENT"
    )]
    pub tool_result: Vec<String>,

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

    #[arg(
        long,
        help = "Optional transport declaration JSON with an explicit adapter and, for generic_json, JSON pointers"
    )]
    pub transport: Option<PathBuf>,

    #[arg(
        long,
        visible_alias = "output",
        help = "Path to write airlock_manifest.json"
    )]
    pub out: PathBuf,

    #[arg(
        long = "require-claim",
        value_parser = parse_claim_level,
        help = "Minimum acceptable claim: BOUNDARY_FAILED, RAW_DOCUMENT_ABSENT, or STRICT_TELEMETRY_ONLY"
    )]
    pub require_claim: Option<ClaimLevel>,

    #[arg(
        long = "not-crossed",
        help = "Optional not_crossed.json from airlock assemble --not-crossed-out; its entries are copied into the manifest. Without it the manifest records no negative inventory"
    )]
    pub not_crossed: Option<PathBuf>,

    #[arg(
        long = "no-sign",
        help = "Write the manifest without an Ed25519 signature (for CI without a key). By default verify signs with the key from `airlock keygen` and refuses if there is none"
    )]
    pub no_sign: bool,

    #[arg(long = "no-witness", help = "Skip ambient witness ledger recording")]
    pub no_witness: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(
    after_help = "Builds the request from the assembled prompt, verifies it, and POSTs exactly the bytes the manifest hashes. The manifest records what crossed: `transmission` says whether the request was sent, to which host, and what came back.\n\nThe request is sent only if the achieved claim is at least --require-claim, which defaults to RAW_DOCUMENT_ABSENT: a request that failed the boundary check is never sent unless you ask for BOUNDARY_FAILED.\n\nExit codes: 0 sent and a response was received (any HTTP status; read transmission.response_status), 1 claim below --require-claim and nothing was sent, 2 refusal (detail.sent says whether the body may have reached the endpoint).\n\nExample:\n  OPENAI_API_KEY=... airlock send --policy rules/tournament_baseline.yaml --prompt prompt_payload.json --provenance prompt_provenance.json --transport send_transport.json --request-out request.json --out airlock_manifest.json --response-out response.json"
)]
pub struct SendArgs {
    #[arg(long, help = "Boundary policy YAML used during assembly")]
    pub policy: PathBuf,

    #[arg(long, help = "prompt_payload.json produced by airlock assemble")]
    pub prompt: PathBuf,

    #[arg(long, help = "prompt_provenance.json produced by airlock assemble")]
    pub provenance: PathBuf,

    #[arg(
        long,
        help = "Send transport JSON: adapter, model, url, api_key_env, and optionally params, headers, auth_header, timeout_seconds, max_response_bytes. The API key is read from the environment variable api_key_env and never stored"
    )]
    pub transport: PathBuf,

    #[arg(
        long,
        visible_alias = "output",
        help = "Path to write airlock_manifest.json"
    )]
    pub out: PathBuf,

    #[arg(
        long = "request-out",
        help = "Path to write the exact request bytes that are sent (the manifest's replay_ref). Owner-only"
    )]
    pub request_out: PathBuf,

    #[arg(
        long = "response-out",
        help = "Path to write the response body as received. Owner-only. Written only for a complete response"
    )]
    pub response_out: Option<PathBuf>,

    #[arg(
        long = "require-claim",
        value_parser = parse_claim_level,
        help = "Minimum claim to send at: BOUNDARY_FAILED, RAW_DOCUMENT_ABSENT, or STRICT_TELEMETRY_ONLY. Default RAW_DOCUMENT_ABSENT"
    )]
    pub require_claim: Option<ClaimLevel>,

    #[arg(
        long = "not-crossed",
        help = "Optional not_crossed.json from airlock assemble --not-crossed-out; its entries are copied into the manifest"
    )]
    pub not_crossed: Option<PathBuf>,

    #[arg(
        long = "no-sign",
        help = "Write the manifest without an Ed25519 signature (for CI without a key). By default send signs with the key from `airlock keygen` and refuses if there is none"
    )]
    pub no_sign: bool,

    #[arg(long = "no-witness", help = "Skip ambient witness ledger recording")]
    pub no_witness: bool,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(
    after_help = "Writes ed25519.key (owner-only) and ed25519.pub under ~/.cmdrvl/secrets/airlock/. Never overwrites an existing key. Prints the public key and its fingerprint, never the secret.\n\nExample:\n  airlock keygen"
)]
pub struct KeygenArgs {}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(
    after_help = "Exit 0 when the signature is valid, 2 with a refusal when the manifest is unsigned, altered, signed by another key, or is not airlock.v0.3.\n\nExamples:\n  airlock verify-manifest airlock_manifest.json\n  airlock verify-manifest airlock_manifest.json --pubkey signer.pub"
)]
pub struct VerifyManifestArgs {
    #[arg(help = "airlock_manifest.json whose signature to check")]
    pub manifest: PathBuf,

    #[arg(
        long,
        help = "Public key file (hex, as written by airlock keygen). Defaults to ~/.cmdrvl/secrets/airlock/ed25519.pub"
    )]
    pub pubkey: Option<PathBuf>,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum ChainCommands {
    #[command(about = "Walk a manifest's chain back to turn 0 and check every link")]
    Verify(ChainVerifyArgs),
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(
    after_help = "Examples:\n  airlock chain verify turn3.manifest.json --manifest-dir manifests\n  airlock chain verify turn3.manifest.json --manifest-dir manifests --receipt-dir receipts --pubkey ed25519.pub\n\nThis checks that the hashes of a conversation's manifests, provenance files and gate receipts agree with each other. The gate receipt is unsigned: it does not prove who produced a receipt or a manifest."
)]
pub struct ChainVerifyArgs {
    #[arg(help = "airlock_manifest.json of the newest turn to check")]
    pub manifest: PathBuf,

    #[arg(
        long = "manifest-dir",
        help = "Directory holding the earlier turns' manifests and their prompt provenance files"
    )]
    pub manifest_dir: PathBuf,

    #[arg(
        long = "receipt-dir",
        help = "Directory of gate receipts. Without it the receipts are not checked, and the report says so"
    )]
    pub receipt_dir: Option<PathBuf>,

    #[arg(
        long,
        help = "Public key file (hex, as written by airlock keygen). Signed manifests in the chain are checked with it; without it signatures are not checked"
    )]
    pub pubkey: Option<PathBuf>,
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
    after_help = "Read-only agent surfaces (cmdrvl.doctor.v1; exit 0 healthy, 1 unhealthy, 2 usage error):\n  airlock doctor --json\n  airlock doctor capabilities --json\n  airlock doctor triage --json\n  airlock doctor robot-docs\n\nDeprecated aliases: `doctor health`, `doctor --robot-triage`, `airlock --robot-triage`."
)]
pub struct DoctorArgs {
    #[arg(
        long = "robot-triage",
        help = "Deprecated alias of `doctor triage --json`"
    )]
    pub robot_triage: bool,

    #[arg(long, help = "Emit JSON where the selected doctor command supports it")]
    pub json: bool,

    #[command(subcommand)]
    pub command: Option<DoctorCommands>,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum DoctorCommands {
    #[command(
        about = "Deprecated alias of `doctor [--json]`: read-only embedded health diagnostics"
    )]
    Health(DoctorJsonArgs),
    #[command(
        about = "cmdrvl.doctor.v1 capabilities report whose `contract` is the operator.v1 manifest"
    )]
    Capabilities(DoctorJsonArgs),
    #[command(about = "cmdrvl.doctor.v1 triage report with next_actions")]
    Triage(DoctorJsonArgs),
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
    #[command(
        about = "Check the prev_hash chain of airlock entries in the ledger (a tamper hint, not a proof)"
    )]
    Verify(WitnessVerifyArgs),
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
pub struct WitnessVerifyArgs {
    #[arg(
        long = "expect-head",
        value_name = "HASH",
        help = "Fail unless the chain's head is HASH, a blake3:<64 hex> value an earlier run printed and you kept somewhere the ledger's writers cannot reach. Without it, removing the newest entries or rewriting the whole ledger goes unnoticed"
    )]
    pub expect_head: Option<String>,

    #[arg(long, help = "Emit the report as JSON")]
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
    fn parses_explicit_gate_modes_and_protected_bloom() {
        let cli = Cli::try_parse_from([
            "airlock",
            "gate",
            "--mode",
            "policy-proxy",
            "--policy",
            "policy.yaml",
            "--upstream",
            "https://api.openai.com",
            "--transport",
            "transport.json",
            "--protected-bloom",
            "protected-corpus.bdbl",
            "--no-witness",
        ])
        .unwrap();
        let args = match cli.command {
            Some(Commands::Gate(args)) => args,
            _ => panic!("expected gate command"),
        };
        assert_eq!(args.mode, GateMode::PolicyProxy);
        assert_eq!(args.policy, Some(PathBuf::from("policy.yaml")));
        assert_eq!(args.transport, Some(PathBuf::from("transport.json")));
        assert_eq!(
            args.protected_bloom,
            Some(PathBuf::from("protected-corpus.bdbl"))
        );
        assert!(args.no_witness);

        let strict = Cli::try_parse_from([
            "airlock",
            "gate",
            "--mode",
            "strict-manifest",
            "--manifest-dir",
            "manifests",
            "--upstream",
            "https://api.openai.com",
        ])
        .unwrap();
        let args = match strict.command {
            Some(Commands::Gate(args)) => args,
            _ => panic!("expected strict gate command"),
        };
        assert_eq!(args.mode, GateMode::StrictManifest);
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
    fn parses_doctor_triage_json() {
        let cli = Cli::try_parse_from(["airlock", "doctor", "triage", "--json"]).unwrap();

        let command = cli.command.unwrap();
        assert!(matches!(&command, Commands::Doctor(_)));
        let Commands::Doctor(args) = command else {
            return;
        };
        assert!(matches!(&args.command, Some(DoctorCommands::Triage(_))));
        let Some(DoctorCommands::Triage(format)) = args.command else {
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
    fn parses_witness_verify_flags() {
        let cli = Cli::try_parse_from([
            "airlock",
            "witness",
            "verify",
            "--expect-head",
            "blake3:abc",
            "--json",
        ])
        .unwrap();

        let command = cli.command.unwrap();
        assert!(matches!(
            &command,
            Commands::Witness(WitnessCommands::Verify(_))
        ));
        let Commands::Witness(WitnessCommands::Verify(args)) = command else {
            return;
        };
        assert_eq!(args.expect_head.as_deref(), Some("blake3:abc"));
        assert!(args.json);

        let cli = Cli::try_parse_from(["airlock", "witness", "verify"]).unwrap();
        let command = cli.command.unwrap();
        assert!(matches!(
            &command,
            Commands::Witness(WitnessCommands::Verify(_))
        ));
        let Commands::Witness(WitnessCommands::Verify(args)) = command else {
            return;
        };
        assert_eq!(args.expect_head, None);
        assert!(!args.json);
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
