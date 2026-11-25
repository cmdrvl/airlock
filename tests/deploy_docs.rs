//! docs/deploy/egress-firewall.md is operator-facing: people copy its commands and rules.
//! These tests stop it drifting from the real CLI. They need no firewall and no privileges.

use std::net::SocketAddr;
use std::path::PathBuf;

use airlock::cli::{Cli, Commands, GateArgs, GateMode};
use clap::Parser;
use regex::Regex;

fn doc() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/deploy/egress-firewall.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// Fenced code blocks as (language tag, body).
fn fenced_blocks(text: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        match (&mut current, line.strip_prefix("```")) {
            (None, Some(tag)) => current = Some((tag.trim().to_owned(), String::new())),
            (Some(_), Some(_)) => blocks.extend(current.take()),
            (Some((_, body)), None) => {
                body.push_str(line);
                body.push('\n');
            }
            (None, None) => {}
        }
    }
    assert!(current.is_none(), "unterminated code fence in the doc");
    blocks
}

/// Every `airlock gate ...` command in any block, backslash continuations joined,
/// split into argv. The doc keeps these quote-free so whitespace splitting is exact.
fn gate_commands(blocks: &[(String, String)]) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for (_, body) in blocks {
        let joined = body.replace("\\\n", " ");
        for line in joined.lines() {
            let line = line.trim();
            if line.starts_with("airlock gate") {
                assert!(
                    !line.contains(['\'', '"']),
                    "keep airlock gate commands in the doc quote-free: {line}"
                );
                commands.push(line.split_whitespace().map(str::to_owned).collect());
            }
        }
    }
    commands
}

fn gate_args(argv: &[String]) -> GateArgs {
    match Cli::try_parse_from(argv).unwrap().command {
        Some(Commands::Gate(args)) => args,
        other => panic!("not a gate command: {argv:?} parsed as {other:?}"),
    }
}

fn default_listen() -> SocketAddr {
    let argv = [
        "airlock",
        "gate",
        "--mode",
        "strict-manifest",
        "--upstream",
        "https://api.openai.com",
    ]
    .map(str::to_owned);
    gate_args(&argv).listen.parse().unwrap()
}

#[test]
fn every_gate_command_in_the_deploy_doc_parses_with_the_real_cli() {
    let commands = gate_commands(&fenced_blocks(&doc()));
    let parsed: Vec<GateArgs> = commands
        .iter()
        .map(|argv| {
            Cli::try_parse_from(argv)
                .unwrap_or_else(|error| panic!("doc command {argv:?} does not parse: {error}"));
            gate_args(argv)
        })
        .collect();
    assert!(
        parsed
            .iter()
            .any(|args| args.mode == GateMode::StrictManifest)
            && parsed.iter().any(|args| args.mode == GateMode::PolicyProxy),
        "the doc should show both gate modes, found {} command(s)",
        parsed.len()
    );
    let default = default_listen();
    for args in &parsed {
        assert_eq!(
            args.listen.parse::<SocketAddr>().unwrap(),
            default,
            "doc commands must listen where the firewall rules and base URLs point"
        );
    }
}

#[test]
fn firewall_rules_and_base_urls_name_the_gate_listen_address() {
    let text = doc();
    let blocks = fenced_blocks(&text);
    let listen = default_listen();
    assert!(listen.ip().is_loopback());
    let (ip, port) = (listen.ip(), listen.port());

    // The narrow-profile rules must open exactly the gate's loopback address and port.
    let nft_rule = format!("ip daddr {ip} tcp dport {port} accept");
    let pf_rule = format!("to {ip} port {port} user");
    assert!(
        blocks
            .iter()
            .any(|(tag, body)| tag == "nft" && body.contains(&nft_rule)),
        "no nft block contains `{nft_rule}`"
    );
    assert!(
        blocks
            .iter()
            .any(|(tag, body)| tag == "pf" && body.contains(&pf_rule)),
        "no pf block contains `{pf_rule}`"
    );

    // Every other loopback ip:port written anywhere in the doc must be the same address.
    let loopback = Regex::new(r"127\.0\.0\.1:(\d+)").unwrap();
    let mentioned: Vec<u16> = loopback
        .captures_iter(&text)
        .map(|captures| captures[1].parse().unwrap())
        .collect();
    assert!(
        mentioned.len() >= 4,
        "expected the commands and base URLs to name the listen address"
    );
    assert!(
        mentioned.iter().all(|mentioned| *mentioned == port),
        "doc mentions loopback ports {mentioned:?} but the gate listens on {port}"
    );
}

/// The Seatbelt profile is run for real by tests/egress_seatbelt.rs, but only on macOS. This is
/// the part of that contract every platform can check: the block denies outbound, opens one
/// exception, takes the gate's port as a parameter, and the command that applies it passes the
/// gate's default listen port.
#[test]
fn the_seatbelt_profile_denies_outbound_and_opens_only_the_gate_port() {
    let text = doc();
    let blocks = fenced_blocks(&text);
    let profiles: Vec<&str> = blocks
        .iter()
        .filter(|(tag, _)| tag == "seatbelt")
        .map(|(_, body)| body.as_str())
        .collect();
    assert_eq!(
        profiles.len(),
        1,
        "the doc must hold exactly one `seatbelt` block"
    );
    // Judge the code only: a commented-out `; (deny network-outbound)` must not count.
    let profile = profiles[0]
        .lines()
        .map(|line| line.split(';').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let profile = profile.as_str();
    assert!(
        profile.contains("(deny network-outbound)"),
        "the profile must deny all outbound network, not a subset:\n{profile}"
    );
    assert_eq!(
        profile.matches("(allow network-outbound").count(),
        1,
        "the profile must open exactly one exception:\n{profile}"
    );
    assert!(
        profile.contains(r#"(param "GATE_PORT")"#),
        "the exception must be the gate's port, taken as a parameter:\n{profile}"
    );

    let port = default_listen().port();
    let applied: Vec<u16> = Regex::new(r"-D GATE_PORT=(\d+)")
        .unwrap()
        .captures_iter(&text)
        .map(|captures| captures[1].parse().unwrap())
        .collect();
    assert!(
        !applied.is_empty() && applied.iter().all(|applied| *applied == port),
        "the doc applies the profile with GATE_PORT {applied:?} but the gate listens on {port}"
    );
}

#[test]
fn every_refusal_code_the_gate_schema_allows_has_a_row_in_the_doc() {
    let schema_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas/airlock_gate.v1.schema.json");
    let schema: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&schema_path).unwrap()).unwrap();
    let codes: Vec<&str> = schema["$defs"]["refusal"]["properties"]["code"]["enum"]
        .as_array()
        .expect("the gate schema lists refusal codes")
        .iter()
        .map(|code| code.as_str().unwrap())
        .collect();
    assert!(
        codes.len() >= 4,
        "unexpectedly few refusal codes: {codes:?}"
    );

    let text = doc();
    for code in codes {
        assert!(
            text.contains(&format!("| `{code}` |")),
            "the refusal table in the doc has no row for `{code}`"
        );
    }
}
