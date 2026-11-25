//! `operator.json` is what `airlock --describe` and `airlock capabilities` print, and it is what an
//! agent reads to learn the CLI. These tests keep it from silently falling behind the clap
//! definitions, which is how `airlock chain` and five `assemble` flags went undeclared (al-210).
//!
//! Commands are compared by name for the whole CLI. Flags are compared, in both directions, only
//! for the commands in `FLAG_CHECKED`. `verify` and `send` (`--not-crossed-out`) already lack
//! flags that exist in the CLI; that older gap is not yet closed, so it is left visible here
//! rather than listed as an exception. `gate` was in the same state until al-3pz declared its
//! three missing flags and added it to the list.

use std::collections::BTreeSet;

use airlock::cli::Cli;
use clap::{Command, CommandFactory};
use serde_json::Value;

const OPERATOR_JSON: &str = include_str!("../operator.json");

/// Commands whose declared flags must be exactly the CLI's. `chain` is checked through its
/// `verify` subcommand, whose flags `operator.json` lists on the `chain` entry.
const FLAG_CHECKED: [&str; 3] = ["assemble", "chain", "gate"];

fn operator() -> Value {
    serde_json::from_str(OPERATOR_JSON).expect("operator.json is valid JSON")
}

fn operator_command<'a>(operator: &'a Value, name: &str) -> &'a Value {
    let found = operator["commands"]
        .as_array()
        .expect("operator.json has a commands array")
        .iter()
        .find(|command| command["name"] == name);
    assert!(found.is_some(), "operator.json has no command {name}");
    found.expect("checked by the assertion above")
}

/// Every `--long` flag the command takes, visible aliases included, without `--help`.
fn cli_flags(command: &Command) -> BTreeSet<String> {
    let mut flags = BTreeSet::new();
    for arg in command.get_arguments() {
        for long in arg.get_long_and_visible_aliases().into_iter().flatten() {
            flags.insert(format!("--{long}"));
        }
    }
    flags.remove("--help");
    flags.remove("--version");
    flags
}

/// The flags operator.json declares for a command: each option's flag and its aliases.
fn operator_flags(command: &Value) -> BTreeSet<String> {
    let mut flags = BTreeSet::new();
    for option in command["options"].as_array().into_iter().flatten() {
        flags.insert(
            option["flag"]
                .as_str()
                .expect("every option has a flag")
                .to_owned(),
        );
        for alias in option["aliases"].as_array().into_iter().flatten() {
            flags.insert(alias.as_str().expect("an alias is a string").to_owned());
        }
    }
    flags
}

#[test]
fn operator_json_declares_every_command_the_cli_has_and_no_other() {
    let cli = Cli::command();
    let in_cli: BTreeSet<String> = cli
        .get_subcommands()
        .map(|command| command.get_name().to_owned())
        .filter(|name| name != "help")
        .collect();
    let operator = operator();
    let in_operator: BTreeSet<String> = operator["commands"]
        .as_array()
        .expect("operator.json has a commands array")
        .iter()
        .map(|command| {
            command["name"]
                .as_str()
                .expect("a command has a name")
                .to_owned()
        })
        .collect();

    let undeclared: Vec<&String> = in_cli.difference(&in_operator).collect();
    let unknown: Vec<&String> = in_operator.difference(&in_cli).collect();
    assert!(
        undeclared.is_empty(),
        "commands the CLI has and operator.json does not declare: {undeclared:?}"
    );
    assert!(
        unknown.is_empty(),
        "commands operator.json declares and the CLI does not have: {unknown:?}"
    );
}

#[test]
fn operator_json_declares_exactly_the_flags_of_the_commands_it_is_checked_for() {
    let cli = Cli::command();
    let operator = operator();
    for name in FLAG_CHECKED {
        let found = cli.find_subcommand(name);
        assert!(found.is_some(), "the CLI has no command {name}");
        let command = found.expect("checked by the assertion above");
        // `chain` has no flags of its own: operator.json lists `chain verify`'s on its entry.
        let flags = match command.find_subcommand("verify") {
            Some(verify) if name == "chain" => cli_flags(verify),
            _ => cli_flags(command),
        };
        let declared = operator_flags(operator_command(&operator, name));

        let undeclared: Vec<&String> = flags.difference(&declared).collect();
        let unknown: Vec<&String> = declared.difference(&flags).collect();
        assert!(
            undeclared.is_empty(),
            "{name}: flags the CLI takes and operator.json does not declare: {undeclared:?}"
        );
        assert!(
            unknown.is_empty(),
            "{name}: flags operator.json declares and the CLI does not take: {unknown:?}"
        );
    }
}
