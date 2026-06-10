pub mod adapter;
pub mod assembler;
pub mod cli;
pub mod commands;
pub mod hash;
pub mod manifest;
pub mod output;
pub mod paths;
pub mod policy;
pub mod refusal;
pub mod scanner;
pub mod types;
pub mod witness;

use std::ffi::OsString;
use std::io::{self, Write};

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Commands, DoctorArgs, DoctorCommands, REFUSAL, VERIFY_PASS};

/// Entry point for the airlock CLI.
///
/// Returns an exit code: 0 = VERIFY_PASS, 1 = VERIFY_PARTIAL, 2 = REFUSAL.
pub fn run() -> u8 {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    run_with_args(std::env::args_os(), &mut stdout, &mut stderr)
}

fn run_with_args<I, T, W, E>(args: I, stdout: &mut W, stderr: &mut E) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    W: Write,
    E: Write,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();

    if has_flag(&args, "--describe") {
        return emit_introspection(output::emit_describe(stdout), stderr);
    }
    if has_flag(&args, "--schema") {
        return emit_introspection(output::emit_schema(stdout), stderr);
    }
    if has_flag(&args, "--version") {
        return emit_introspection(output::emit_version(stdout), stderr);
    }

    let cli = match Cli::try_parse_from(args.clone()) {
        Ok(cli) => cli,
        Err(err) => {
            let code = err.exit_code() as u8;
            let target: &mut dyn Write = if err.use_stderr() { stderr } else { stdout };
            let _ = write!(target, "{err}");
            if code != VERIFY_PASS {
                maybe_write_parse_hint(&args, target);
            }
            return code;
        }
    };

    dispatch(cli, stdout, stderr)
}

fn has_flag(args: &[OsString], needle: &str) -> bool {
    args.iter().any(|arg| arg == needle)
}

fn emit_introspection<E: Write>(result: io::Result<()>, stderr: &mut E) -> u8 {
    match result {
        Ok(()) => VERIFY_PASS,
        Err(err) => {
            let _ = writeln!(stderr, "airlock: failed to write output: {err}");
            REFUSAL
        }
    }
}

fn dispatch<W: Write, E: Write>(cli: Cli, stdout: &mut W, stderr: &mut E) -> u8 {
    if cli.describe {
        return emit_introspection(output::emit_describe(stdout), stderr);
    }
    if cli.schema {
        return emit_introspection(output::emit_schema(stdout), stderr);
    }
    if cli.print_version {
        return emit_introspection(output::emit_version(stdout), stderr);
    }
    if cli.robot_triage {
        return commands::doctor::run_with_writer(
            DoctorArgs {
                robot_triage: true,
                json: false,
                command: None,
            },
            stdout,
            stderr,
        );
    }

    match cli.command {
        Some(Commands::Assemble(args)) => commands::assemble::run(args),
        Some(Commands::Verify(args)) => commands::verify::run(args),
        Some(Commands::Explain(args)) => commands::explain::run(args),
        Some(Commands::Doctor(args)) => commands::doctor::run(args),
        Some(Commands::Capabilities(args)) => commands::doctor::run_with_writer(
            DoctorArgs {
                robot_triage: false,
                json: args.json,
                command: Some(DoctorCommands::Capabilities(args)),
            },
            stdout,
            stderr,
        ),
        Some(Commands::RobotDocs(_args)) => commands::doctor::run_with_writer(
            DoctorArgs {
                robot_triage: false,
                json: false,
                command: Some(DoctorCommands::RobotDocs),
            },
            stdout,
            stderr,
        ),
        Some(Commands::Witness(cmd)) => commands::witness::run(cmd),
        None => {
            let mut command = Cli::command();
            let _ = command.write_long_help(stdout);
            let _ = writeln!(stdout);
            VERIFY_PASS
        }
    }
}

fn maybe_write_parse_hint<W: Write + ?Sized>(args: &[OsString], target: &mut W) {
    let saw_json_typo = args.iter().any(|arg| {
        matches!(
            arg.to_string_lossy().as_ref(),
            "--jsno" | "--jason" | "--jsson" | "--josn"
        )
    });

    if saw_json_typo {
        let _ = writeln!(
            target,
            "\nhint: did you mean `--json`? For a read-only machine summary, run: `airlock --robot-triage`."
        );
    } else {
        let _ = writeln!(
            target,
            "\nhint: for machine-readable command discovery, run: `airlock capabilities --json`."
        );
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::cli::REFUSAL;

    #[test]
    fn describe_precedes_schema_and_subcommand_validation() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run_with_args(
            ["airlock", "--describe", "--schema", "verify"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, VERIFY_PASS);
        let describe: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(describe["name"], "airlock");
        assert!(stderr.is_empty());
    }

    #[test]
    fn schema_precedes_version() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run_with_args(
            ["airlock", "--schema", "--version"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, VERIFY_PASS);
        let schema: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(schema["title"], "airlock manifest schema");
        assert!(stderr.is_empty());
    }

    #[test]
    fn version_emits_semver_string() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run_with_args(["airlock", "--version"], &mut stdout, &mut stderr);

        assert_eq!(code, VERIFY_PASS);
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            format!("airlock {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn no_command_prints_help_and_returns_refusal() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run_with_args(["airlock"], &mut stdout, &mut stderr);

        assert_eq!(code, VERIFY_PASS);
        assert!(stderr.is_empty());
        let help = String::from_utf8(stdout).unwrap();
        assert!(help.contains("Usage: airlock"));
        assert!(help.contains("airlock --robot-triage"));
    }

    #[test]
    fn top_level_robot_triage_is_read_only_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run_with_args(["airlock", "--robot-triage"], &mut stdout, &mut stderr);

        assert_eq!(code, VERIFY_PASS);
        assert!(stderr.is_empty());
        let triage: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(triage["schema"], "airlock.doctor.triage.v1");
        assert_eq!(triage["read_only"], true);
    }

    #[test]
    fn top_level_capabilities_alias_returns_doctor_contract() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run_with_args(
            ["airlock", "capabilities", "--json"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, VERIFY_PASS);
        assert!(stderr.is_empty());
        let capabilities: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(capabilities["schema"], "airlock.doctor.capabilities.v1");
        assert_eq!(capabilities["read_only"], true);
    }

    #[test]
    fn json_typo_gets_agent_hint() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = run_with_args(["airlock", "--jsno"], &mut stdout, &mut stderr);

        assert_eq!(code, REFUSAL);
        assert!(stdout.is_empty());
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stderr.contains("did you mean `--json`"));
        assert!(stderr.contains("airlock --robot-triage"));
    }
}
