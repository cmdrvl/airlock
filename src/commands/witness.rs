use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::cli::{
    WitnessCommands, WitnessCountArgs, WitnessFilterArgs, WitnessLastArgs, WitnessQueryArgs,
    WitnessVerifyArgs,
};
use crate::output::canonical_json;
use crate::refusal::RefusalEnvelope;
use crate::witness::{self, WitnessError, WitnessFilters, WitnessRecord, chain};

pub fn run(args: WitnessCommands) -> u8 {
    let mut stdout = io::stdout();
    run_with_writer(args, &witness::default_witness_path(), &mut stdout)
}

// Exit codes for the read-only witness commands: an empty result (no ledger, no records, or
// a filter that matches nothing) is success, exit 0, per the spine-rules family contract.
// Exit 1 is reserved for a negative verdict or an unhealthy doctor; of the witness commands
// only `verify` uses it, for a broken chain or a head that is not the expected one.
// Anything that stops the ledger being read or the filters being parsed is a refusal,
// exit 2. Only the exit code reports "nothing matched": `query --json` prints `[]`,
// `count --json` prints `{"count":0}` and `last --json` prints `null`.

fn run_with_writer(args: WitnessCommands, ledger_path: &Path, stdout: &mut impl Write) -> u8 {
    match args {
        WitnessCommands::Query(args) => run_query(args, ledger_path, stdout),
        WitnessCommands::Last(args) => run_last(args, ledger_path, stdout),
        WitnessCommands::Count(args) => run_count(args, ledger_path, stdout),
        WitnessCommands::Verify(args) => run_verify(args, ledger_path, stdout),
    }
}

/// `blake3:` followed by 64 lowercase hex digits, the form of a chain hash.
fn is_chain_hash(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn run_verify(args: WitnessVerifyArgs, ledger_path: &Path, stdout: &mut impl Write) -> u8 {
    if let Some(expected) = &args.expect_head
        && !is_chain_hash(expected)
    {
        return RefusalEnvelope::bad_input_with_next_command(
            "--expect-head must be blake3: followed by 64 lowercase hex digits",
            json!({ "flag": "--expect-head", "value": expected }),
            "airlock witness verify --json".to_string(),
        )
        .write_to(stdout);
    }

    let report = match chain::verify_chain_at(ledger_path) {
        Ok(report) => report,
        Err(error) => {
            return RefusalEnvelope::witness_error(
                "failed to read witness ledger",
                json!({
                    "path": ledger_path.display().to_string(),
                    "error": error.to_string(),
                }),
            )
            .write_to(stdout);
        }
    };

    let head_differs = args
        .expect_head
        .as_ref()
        .is_some_and(|expected| report.head.as_ref() != Some(expected));
    let status = if !report.is_intact() {
        "CHAIN_BROKEN"
    } else if head_differs {
        "HEAD_MISMATCH"
    } else {
        "CHAIN_OK"
    };

    if args.json {
        let mut value = serde_json::to_value(&report).expect("chain report should serialize");
        value["status"] = json!(status);
        value["ledger"] = json!(ledger_path.display().to_string());
        value["expected_head"] = json!(args.expect_head);
        write_json(stdout, &value);
    } else {
        write_chain_report(
            stdout,
            status,
            ledger_path,
            &report,
            args.expect_head.as_deref(),
        );
    }

    if status == "CHAIN_OK" { 0 } else { 1 }
}

/// The SCREAMING_SNAKE_CASE name a reason has in the JSON report, so the text report shows the
/// same name rather than a second spelling.
fn reason_name(reason: &impl serde::Serialize) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn write_chain_report(
    stdout: &mut impl Write,
    status: &str,
    ledger_path: &Path,
    report: &chain::ChainReport,
    expected_head: Option<&str>,
) {
    let _ = writeln!(stdout, "WITNESS CHAIN: {status}");
    let _ = writeln!(stdout);
    let _ = writeln!(stdout, "Ledger: {}", ledger_path.display());
    let _ = writeln!(
        stdout,
        "Airlock entries: {} ({} chained, {} without prev_hash)",
        report.airlock_entries, report.chained, report.unchained
    );
    if report.skipped_lines > 0 {
        let _ = writeln!(stdout, "Lines that are not JSON: {}", report.skipped_lines);
    }
    let _ = writeln!(
        stdout,
        "Head: {}",
        report
            .head
            .as_deref()
            .unwrap_or("none (no airlock entries)")
    );
    if let Some(expected) = expected_head {
        let _ = writeln!(stdout, "Expected head: {expected}");
    }
    for chain_break in &report.breaks {
        let _ = writeln!(
            stdout,
            "BREAK at line {}: {} (expected {}, found {})",
            chain_break.line,
            reason_name(&chain_break.reason),
            chain_break.expected.as_deref().unwrap_or("-"),
            chain_break.found.as_deref().unwrap_or("-"),
        );
    }
    for warning in &report.warnings {
        let _ = writeln!(
            stdout,
            "WARNING at line {}: {}",
            warning.line,
            reason_name(&warning.reason)
        );
    }
    let _ = writeln!(stdout);
    let _ = writeln!(
        stdout,
        "A hash chain is a tamper hint, not a proof: it cannot show that the newest entries were not removed, or that the ledger was not rewritten whole. Keep the head somewhere the ledger's writers cannot reach and pass it as --expect-head."
    );
}

fn run_query(args: WitnessQueryArgs, ledger_path: &Path, stdout: &mut impl Write) -> u8 {
    let filters = match parse_filters(&args.filters, true) {
        Ok(filters) => filters,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let records = match load_filtered_records(ledger_path, &filters) {
        Ok(records) => records,
        Err(refusal) => return refusal.write_to(stdout),
    };

    if args.json {
        let json = serde_json::to_value(&records).expect("witness query records should serialize");
        write_json(stdout, &json);
    } else if records.is_empty() {
        let _ = writeln!(stdout, "No witness records found");
    } else {
        let _ = writeln!(stdout, "WITNESS LEDGER ({} records)", records.len());
        let _ = writeln!(stdout);
        for record in &records {
            let _ = writeln!(stdout, "{}", format_query_row(record));
        }
    }

    0
}

fn run_last(args: WitnessLastArgs, ledger_path: &Path, stdout: &mut impl Write) -> u8 {
    let filters = WitnessFilters::default();
    let record = match load_filtered_records(ledger_path, &filters) {
        Ok(records) => records.into_iter().next(),
        Err(refusal) => return refusal.write_to(stdout),
    };

    match record {
        Some(record) => {
            if args.json {
                let json = serde_json::to_value(&record).expect("witness record should serialize");
                write_json(stdout, &json);
            } else {
                let _ = writeln!(stdout, "WITNESS RECORD");
                let _ = writeln!(stdout);
                let _ = writeln!(stdout, "Timestamp: {}", record.timestamp);
                let _ = writeln!(stdout, "Command: {}", record.command);
                let _ = writeln!(stdout, "Outcome: {}", record.outcome);
                let _ = writeln!(stdout, "Inputs: {}", input_summary(&record));
                let _ = writeln!(stdout, "Stdout bytes: {}", record.stdout_bytes);
            }
        }
        None => {
            if args.json {
                write_json(stdout, &Value::Null);
            } else {
                let _ = writeln!(stdout, "No witness records found");
            }
        }
    }

    0
}

fn run_count(args: WitnessCountArgs, ledger_path: &Path, stdout: &mut impl Write) -> u8 {
    let filters = match parse_filters(&args.filters, true) {
        Ok(filters) => filters,
        Err(refusal) => return refusal.write_to(stdout),
    };

    let count = match load_filtered_records(ledger_path, &filters) {
        Ok(records) => records.len(),
        Err(refusal) => return refusal.write_to(stdout),
    };

    if args.json {
        write_json(stdout, &json!({ "count": count }));
    } else {
        let _ = writeln!(stdout, "{count}");
    }

    0
}

fn parse_filters(
    args: &WitnessFilterArgs,
    default_tool: bool,
) -> Result<WitnessFilters, RefusalEnvelope> {
    Ok(WitnessFilters {
        tool: if let Some(tool) = &args.tool {
            Some(tool.clone())
        } else if default_tool {
            Some(witness::TOOL_NAME.to_string())
        } else {
            None
        },
        since: parse_filter_timestamp(args.since.as_deref(), "--since")?,
        until: parse_filter_timestamp(args.until.as_deref(), "--until")?,
        outcome: args.outcome.clone(),
        input_hash: args.input_hash.clone(),
        limit: args.limit,
    })
}

fn parse_filter_timestamp(
    value: Option<&str>,
    flag: &str,
) -> Result<Option<DateTime<Utc>>, RefusalEnvelope> {
    match value {
        Some(value) => DateTime::parse_from_rfc3339(value)
            .map(|timestamp| Some(timestamp.with_timezone(&Utc)))
            .map_err(|error| {
                RefusalEnvelope::bad_input_with_next_command(
                    format!("{flag} must be an ISO 8601 datetime"),
                    json!({
                        "flag": flag,
                        "value": value,
                        "error": error.to_string(),
                    }),
                    format!("airlock witness query {flag} 2026-01-15T00:00:00Z --json"),
                )
            }),
        None => Ok(None),
    }
}

fn load_filtered_records(
    ledger_path: &Path,
    filters: &WitnessFilters,
) -> Result<Vec<WitnessRecord>, RefusalEnvelope> {
    if !ledger_path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(ledger_path).map_err(|error| {
        RefusalEnvelope::witness_error(
            "failed to open witness ledger",
            json!({
                "path": ledger_path.display().to_string(),
                "error": error.to_string(),
            }),
        )
    })?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|error| {
            RefusalEnvelope::witness_error(
                "failed to read witness ledger",
                json!({
                    "path": ledger_path.display().to_string(),
                    "error": error.to_string(),
                }),
            )
        })?;

        if line.trim().is_empty() {
            continue;
        }

        let record = match serde_json::from_str::<WitnessRecord>(&line) {
            Ok(record) => record,
            Err(_) => continue,
        };

        let timestamp = match parse_record_timestamp(&record) {
            Ok(timestamp) => timestamp,
            Err(_) => continue,
        };

        if matches_filters(&record, timestamp, filters) {
            records.push((timestamp, record));
        }
    }

    records.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    let mut records: Vec<WitnessRecord> = records.into_iter().map(|(_, record)| record).collect();
    if let Some(limit) = filters.limit {
        records.truncate(limit);
    }

    Ok(records)
}

fn parse_record_timestamp(record: &WitnessRecord) -> Result<DateTime<Utc>, WitnessError> {
    DateTime::parse_from_rfc3339(&record.timestamp)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| WitnessError::InvalidTimestamp(record.timestamp.clone()))
}

fn matches_filters(
    record: &WitnessRecord,
    timestamp: DateTime<Utc>,
    filters: &WitnessFilters,
) -> bool {
    if let Some(tool) = &filters.tool
        && &record.tool != tool
    {
        return false;
    }

    if let Some(outcome) = &filters.outcome
        && &record.outcome != outcome
    {
        return false;
    }

    if let Some(since) = filters.since
        && timestamp < since
    {
        return false;
    }

    if let Some(until) = filters.until
        && timestamp > until
    {
        return false;
    }

    if let Some(input_hash) = &filters.input_hash {
        return record
            .inputs
            .iter()
            .any(|input| input.hash.contains(input_hash));
    }

    true
}

fn write_json(stdout: &mut impl Write, value: &Value) {
    let _ = stdout.write_all(canonical_json(value).as_bytes());
    let _ = stdout.write_all(b"\n");
}

fn format_query_row(record: &WitnessRecord) -> String {
    format!(
        "{}  {:<8} {:<15} {}",
        record.timestamp,
        record.command,
        record.outcome,
        input_summary(record)
    )
}

fn input_summary(record: &WitnessRecord) -> String {
    if record.inputs.is_empty() {
        return "(no inputs)".to_string();
    }

    record
        .inputs
        .iter()
        .map(|input| input.path.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{WitnessCountArgs, WitnessFilterArgs, WitnessLastArgs, WitnessQueryArgs};
    use crate::witness::WitnessInput;

    fn sample_record(
        command: &str,
        outcome: &str,
        timestamp: &str,
        input_hash: &str,
    ) -> WitnessRecord {
        WitnessRecord {
            witness_version: witness::WITNESS_VERSION.to_string(),
            tool: witness::TOOL_NAME.to_string(),
            command: command.to_string(),
            timestamp: timestamp.to_string(),
            outcome: outcome.to_string(),
            exit_code: 0,
            inputs: vec![WitnessInput {
                path: "policy.yaml".to_string(),
                hash: input_hash.to_string(),
            }],
            params: json!({"boundary_mode": "ANNOTATED"}),
            stdout_hash: "blake3:stdout".to_string(),
            stdout_bytes: 128,
            prev_hash: None,
        }
    }

    fn write_ledger(path: &Path, lines: &[String]) {
        fs::write(path, lines.join("")).unwrap();
    }

    #[test]
    fn query_filters_and_skips_corrupted_lines() {
        let tempdir = tempfile::tempdir().unwrap();
        let ledger_path = tempdir.path().join("witness.jsonl");
        write_ledger(
            &ledger_path,
            &[
                format!(
                    "{}\n",
                    canonical_json(
                        &serde_json::to_value(sample_record(
                            "verify",
                            "VERIFIED",
                            "2024-01-15T10:30:00Z",
                            "blake3:aaa111"
                        ))
                        .unwrap()
                    )
                ),
                "{not valid json}\n".to_string(),
                format!(
                    "{}\n",
                    canonical_json(
                        &serde_json::to_value(sample_record(
                            "verify",
                            "VERIFY_PARTIAL",
                            "2024-01-16T10:30:00Z",
                            "blake3:bbb222"
                        ))
                        .unwrap()
                    )
                ),
            ],
        );
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            WitnessCommands::Query(WitnessQueryArgs {
                filters: WitnessFilterArgs {
                    tool: None,
                    since: Some("2024-01-16T00:00:00Z".to_string()),
                    until: Some("2024-01-16T23:59:59Z".to_string()),
                    outcome: Some("VERIFY_PARTIAL".to_string()),
                    input_hash: Some("bbb".to_string()),
                    limit: Some(10),
                },
                json: false,
            }),
            &ledger_path,
            &mut stdout,
        );

        assert_eq!(exit_code, 0);
        let rendered = String::from_utf8(stdout).unwrap();
        assert!(rendered.contains("WITNESS LEDGER (1 records)"));
        assert!(rendered.contains("VERIFY_PARTIAL"));
        assert!(!rendered.contains("VERIFIED"));
    }

    #[test]
    fn query_json_outputs_array() {
        let tempdir = tempfile::tempdir().unwrap();
        let ledger_path = tempdir.path().join("witness.jsonl");
        write_ledger(
            &ledger_path,
            &[format!(
                "{}\n",
                canonical_json(
                    &serde_json::to_value(sample_record(
                        "assemble",
                        "ASSEMBLED",
                        "2024-01-15T10:29:00Z",
                        "blake3:aaa111"
                    ))
                    .unwrap()
                )
            )],
        );
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            WitnessCommands::Query(WitnessQueryArgs {
                filters: WitnessFilterArgs {
                    tool: None,
                    since: None,
                    until: None,
                    outcome: None,
                    input_hash: None,
                    limit: None,
                },
                json: true,
            }),
            &ledger_path,
            &mut stdout,
        );

        assert_eq!(exit_code, 0);
        let value: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(value[0]["outcome"], "ASSEMBLED");
    }

    #[test]
    fn last_returns_most_recent_record_and_handles_empty_ledgers() {
        let tempdir = tempfile::tempdir().unwrap();
        let ledger_path = tempdir.path().join("witness.jsonl");
        let mut stdout = Vec::new();

        let empty_exit = run_with_writer(
            WitnessCommands::Last(WitnessLastArgs { json: false }),
            &ledger_path,
            &mut stdout,
        );
        assert_eq!(empty_exit, 0, "an empty ledger is success, not exit 1");
        assert_eq!(
            String::from_utf8(stdout.clone()).unwrap(),
            "No witness records found\n"
        );

        write_ledger(
            &ledger_path,
            &[
                format!(
                    "{}\n",
                    canonical_json(
                        &serde_json::to_value(sample_record(
                            "assemble",
                            "ASSEMBLED",
                            "2024-01-15T10:29:00Z",
                            "blake3:aaa111"
                        ))
                        .unwrap()
                    )
                ),
                format!(
                    "{}\n",
                    canonical_json(
                        &serde_json::to_value(sample_record(
                            "verify",
                            "VERIFIED",
                            "2024-01-15T10:30:00Z",
                            "blake3:bbb222"
                        ))
                        .unwrap()
                    )
                ),
            ],
        );
        stdout.clear();

        let exit_code = run_with_writer(
            WitnessCommands::Last(WitnessLastArgs { json: false }),
            &ledger_path,
            &mut stdout,
        );

        assert_eq!(exit_code, 0);
        let rendered = String::from_utf8(stdout).unwrap();
        assert!(rendered.contains("WITNESS RECORD"));
        assert!(rendered.contains("Timestamp: 2024-01-15T10:30:00Z"));
        assert!(rendered.contains("Outcome: VERIFIED"));
    }

    #[test]
    fn count_outputs_plain_and_json_results() {
        let tempdir = tempfile::tempdir().unwrap();
        let ledger_path = tempdir.path().join("witness.jsonl");
        write_ledger(
            &ledger_path,
            &[
                format!(
                    "{}\n",
                    canonical_json(
                        &serde_json::to_value(sample_record(
                            "verify",
                            "VERIFIED",
                            "2024-01-15T10:30:00Z",
                            "blake3:aaa111"
                        ))
                        .unwrap()
                    )
                ),
                format!(
                    "{}\n",
                    canonical_json(
                        &serde_json::to_value(sample_record(
                            "verify",
                            "VERIFY_PARTIAL",
                            "2024-01-16T10:30:00Z",
                            "blake3:bbb222"
                        ))
                        .unwrap()
                    )
                ),
            ],
        );
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            WitnessCommands::Count(WitnessCountArgs {
                filters: WitnessFilterArgs {
                    tool: None,
                    since: None,
                    until: None,
                    outcome: Some("VERIFIED".to_string()),
                    input_hash: None,
                    limit: None,
                },
                json: false,
            }),
            &ledger_path,
            &mut stdout,
        );

        assert_eq!(exit_code, 0);
        assert_eq!(String::from_utf8(stdout).unwrap(), "1\n");

        let mut json_stdout = Vec::new();
        let json_exit = run_with_writer(
            WitnessCommands::Count(WitnessCountArgs {
                filters: WitnessFilterArgs {
                    tool: None,
                    since: None,
                    until: None,
                    outcome: Some("MISSING".to_string()),
                    input_hash: None,
                    limit: None,
                },
                json: true,
            }),
            &ledger_path,
            &mut json_stdout,
        );

        assert_eq!(json_exit, 0, "a count of 0 is success, not exit 1");
        let value: Value = serde_json::from_slice(&json_stdout).unwrap();
        assert_eq!(value["count"], 0);
    }

    #[test]
    fn query_with_no_matches_exits_zero_and_prints_an_empty_array() {
        let tempdir = tempfile::tempdir().unwrap();
        let absent_ledger = tempdir.path().join("witness.jsonl");
        let filters = || WitnessFilterArgs {
            tool: None,
            since: None,
            until: None,
            outcome: None,
            input_hash: None,
            limit: None,
        };

        let mut json_stdout = Vec::new();
        let json_exit = run_with_writer(
            WitnessCommands::Query(WitnessQueryArgs {
                filters: filters(),
                json: true,
            }),
            &absent_ledger,
            &mut json_stdout,
        );
        assert_eq!(json_exit, 0, "an empty query result is success, not exit 1");
        let value: Value = serde_json::from_slice(&json_stdout).unwrap();
        assert_eq!(value, json!([]));

        let mut text_stdout = Vec::new();
        let text_exit = run_with_writer(
            WitnessCommands::Query(WitnessQueryArgs {
                filters: filters(),
                json: false,
            }),
            &absent_ledger,
            &mut text_stdout,
        );
        assert_eq!(text_exit, 0);
        assert_eq!(
            String::from_utf8(text_stdout).unwrap(),
            "No witness records found\n"
        );
    }

    #[test]
    fn invalid_since_filter_emits_structured_refusal() {
        let tempdir = tempfile::tempdir().unwrap();
        let ledger_path = tempdir.path().join("witness.jsonl");
        let mut stdout = Vec::new();

        let exit_code = run_with_writer(
            WitnessCommands::Query(WitnessQueryArgs {
                filters: WitnessFilterArgs {
                    tool: None,
                    since: Some("not-a-date".to_string()),
                    until: None,
                    outcome: None,
                    input_hash: None,
                    limit: None,
                },
                json: false,
            }),
            &ledger_path,
            &mut stdout,
        );

        assert_eq!(exit_code, 2);
        let refusal: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(refusal["refusal"]["code"], "E_BAD_INPUT");
    }
}
