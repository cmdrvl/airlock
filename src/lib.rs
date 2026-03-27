pub mod adapter;
pub mod assembler;
pub mod cli;
pub mod commands;
pub mod hash;
pub mod manifest;
pub mod output;
pub mod policy;
pub mod refusal;
pub mod scanner;
pub mod types;
pub mod witness;

use std::ffi::OsString;
use std::io::{self, Write};

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Commands, REFUSAL, VERIFY_PASS};

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

    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let code = err.exit_code() as u8;
            let target: &mut dyn Write = if err.use_stderr() { stderr } else { stdout };
            let _ = write!(target, "{err}");
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

    match cli.command {
        Some(Commands::Assemble(args)) => commands::assemble::run(args),
        Some(Commands::Verify(args)) => commands::verify::run(args),
        Some(Commands::Explain(args)) => commands::explain::run(args),
        Some(Commands::Witness(cmd)) => commands::witness::run(cmd),
        None => {
            let _ = writeln!(
                stderr,
                "error: no subcommand or introspection flag provided"
            );
            let mut command = Cli::command();
            let _ = command.write_long_help(stderr);
            let _ = writeln!(stderr);
            REFUSAL
        }
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

        assert_eq!(code, REFUSAL);
        assert!(stdout.is_empty());
        let help = String::from_utf8(stderr).unwrap();
        assert!(help.contains("Usage: airlock"));
        assert!(help.contains("error: no subcommand or introspection flag provided"));
    }
}
