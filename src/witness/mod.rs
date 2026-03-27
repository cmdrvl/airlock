use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::output::canonical_json;

pub const WITNESS_VERSION: &str = "witness.v0";
pub const TOOL_NAME: &str = "airlock";

/// An input artifact recorded in the witness ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessInput {
    pub path: String,
    pub hash: String,
}

/// A single witness ledger entry following the `witness.v0` contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessRecord {
    pub witness_version: String,
    pub tool: String,
    pub command: String,
    pub timestamp: String,
    pub outcome: String,
    pub exit_code: u8,
    pub inputs: Vec<WitnessInput>,
    pub params: Value,
    pub stdout_hash: String,
    pub stdout_bytes: usize,
}

impl WitnessRecord {
    pub fn input(path: impl Into<String>, hash: impl Into<String>) -> WitnessInput {
        WitnessInput {
            path: path.into(),
            hash: hash.into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command: impl Into<String>,
        outcome: impl Into<String>,
        exit_code: u8,
        inputs: Vec<WitnessInput>,
        params: Value,
        stdout_hash: impl Into<String>,
        stdout_bytes: usize,
    ) -> Self {
        Self::with_timestamp(
            command,
            outcome,
            exit_code,
            inputs,
            params,
            stdout_hash,
            stdout_bytes,
            Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_timestamp(
        command: impl Into<String>,
        outcome: impl Into<String>,
        exit_code: u8,
        inputs: Vec<WitnessInput>,
        params: Value,
        stdout_hash: impl Into<String>,
        stdout_bytes: usize,
        timestamp: impl Into<String>,
    ) -> Self {
        let params = match params {
            Value::Object(_) => params,
            other => Value::Object(Map::from_iter([("value".to_owned(), other)])),
        };

        Self {
            witness_version: WITNESS_VERSION.to_string(),
            tool: TOOL_NAME.to_string(),
            command: command.into(),
            timestamp: timestamp.into(),
            outcome: outcome.into(),
            exit_code,
            inputs,
            params,
            stdout_hash: stdout_hash.into(),
            stdout_bytes,
        }
    }

    pub fn to_jsonl_line(&self) -> String {
        let value = serde_json::to_value(self).expect("witness record should serialize");
        format!("{}\n", canonical_json(&value))
    }
}

/// Filters for witness ledger queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessFilters {
    pub tool: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub outcome: Option<String>,
    pub input_hash: Option<String>,
    pub limit: Option<usize>,
}

impl Default for WitnessFilters {
    fn default() -> Self {
        Self {
            tool: Some(TOOL_NAME.to_string()),
            since: None,
            until: None,
            outcome: None,
            input_hash: None,
            limit: None,
        }
    }
}

#[derive(Debug)]
pub enum WitnessError {
    Io(std::io::Error),
    InvalidRecord { line: usize, error: String },
    InvalidTimestamp(String),
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "witness I/O error: {error}"),
            Self::InvalidRecord { line, error } => {
                write!(f, "invalid witness record on line {line}: {error}")
            }
            Self::InvalidTimestamp(value) => write!(f, "invalid witness timestamp: {value}"),
        }
    }
}

impl std::error::Error for WitnessError {}

impl From<std::io::Error> for WitnessError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Resolve the default witness ledger path.
pub fn default_witness_path() -> PathBuf {
    default_witness_path_from(
        env::var_os("EPISTEMIC_WITNESS"),
        env::var_os("HOME"),
        env::var_os("USERPROFILE"),
    )
}

fn default_witness_path_from(
    epistemic_witness: Option<OsString>,
    home: Option<OsString>,
    userprofile: Option<OsString>,
) -> PathBuf {
    if let Some(path) = non_empty_path(epistemic_witness) {
        return path;
    }

    if let Some(path) = non_empty_path(home) {
        return path.join(".epistemic/witness.jsonl");
    }

    if let Some(path) = non_empty_path(userprofile) {
        return path.join(".epistemic/witness.jsonl");
    }

    PathBuf::from(".epistemic/witness.jsonl")
}

fn non_empty_path(value: Option<OsString>) -> Option<PathBuf> {
    value
        .filter(|candidate| !candidate.is_empty())
        .map(PathBuf::from)
}

/// Append a witness record to the default ledger path.
pub fn append_witness(record: WitnessRecord) -> Result<(), WitnessError> {
    append_witness_at(&default_witness_path(), &record)
}

/// Append a witness record to the given ledger path.
pub fn append_witness_at(path: &Path, record: &WitnessRecord) -> Result<(), WitnessError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(record.to_jsonl_line().as_bytes())?;
    Ok(())
}

/// Best-effort append that preserves the original domain exit code.
pub fn maybe_append_witness(
    record: WitnessRecord,
    enabled: bool,
    domain_exit: u8,
    stderr: &mut impl Write,
) -> u8 {
    maybe_append_witness_at(
        &default_witness_path(),
        &record,
        enabled,
        domain_exit,
        stderr,
    )
}

/// Best-effort append to an explicit path that preserves the original domain exit code.
pub fn maybe_append_witness_at(
    path: &Path,
    record: &WitnessRecord,
    enabled: bool,
    domain_exit: u8,
    stderr: &mut impl Write,
) -> u8 {
    if !enabled {
        return domain_exit;
    }

    if let Err(error) = append_witness_at(path, record) {
        let _ = writeln!(stderr, "airlock: witness append failed: {error}");
    }

    domain_exit
}

/// Query witness records from the default ledger path.
pub fn query(filters: &WitnessFilters) -> Result<Vec<WitnessRecord>, WitnessError> {
    query_at(&default_witness_path(), filters)
}

/// Query witness records from an explicit ledger path.
pub fn query_at(path: &Path, filters: &WitnessFilters) -> Result<Vec<WitnessRecord>, WitnessError> {
    let records = load_records_at(path)?;
    let mut filtered = Vec::new();

    for (record, timestamp) in records {
        if matches_filters(&record, timestamp, filters) {
            filtered.push((timestamp, record));
        }
    }

    filtered.sort_by_key(|entry| std::cmp::Reverse(entry.0));

    let mut records: Vec<WitnessRecord> = filtered.into_iter().map(|(_, record)| record).collect();
    if let Some(limit) = filters.limit {
        records.truncate(limit);
    }

    Ok(records)
}

/// Return the most recent witness record from the default ledger path.
pub fn last() -> Result<Option<WitnessRecord>, WitnessError> {
    last_at(&default_witness_path())
}

/// Return the most recent witness record from an explicit ledger path.
pub fn last_at(path: &Path) -> Result<Option<WitnessRecord>, WitnessError> {
    Ok(query_at(path, &WitnessFilters::default())?
        .into_iter()
        .next())
}

/// Count witness records matching the filters from the default ledger path.
pub fn count(filters: &WitnessFilters) -> Result<usize, WitnessError> {
    count_at(&default_witness_path(), filters)
}

/// Count witness records matching the filters from an explicit ledger path.
pub fn count_at(path: &Path, filters: &WitnessFilters) -> Result<usize, WitnessError> {
    Ok(query_at(path, filters)?.len())
}

fn load_records_at(path: &Path) -> Result<Vec<(WitnessRecord, DateTime<Utc>)>, WitnessError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let record = serde_json::from_str::<WitnessRecord>(&line).map_err(|error| {
            WitnessError::InvalidRecord {
                line: index + 1,
                error: error.to_string(),
            }
        })?;

        let timestamp = parse_timestamp(&record.timestamp)?;
        records.push((record, timestamp));
    }

    Ok(records)
}

fn matches_filters(
    record: &WitnessRecord,
    timestamp: DateTime<Utc>,
    filters: &WitnessFilters,
) -> bool {
    if let Some(tool) = &filters.tool {
        if &record.tool != tool {
            return false;
        }
    }

    if let Some(outcome) = &filters.outcome {
        if &record.outcome != outcome {
            return false;
        }
    }

    if let Some(since) = filters.since {
        if timestamp < since {
            return false;
        }
    }

    if let Some(until) = filters.until {
        if timestamp > until {
            return false;
        }
    }

    if let Some(input_hash) = &filters.input_hash {
        return record
            .inputs
            .iter()
            .any(|input| input.hash.contains(input_hash));
    }

    true
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, WitnessError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| WitnessError::InvalidTimestamp(value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn sample_record(
        command: &str,
        outcome: &str,
        timestamp: &str,
        input_hash: &str,
    ) -> WitnessRecord {
        WitnessRecord::with_timestamp(
            command,
            outcome,
            0,
            vec![WitnessRecord::input("policy.yaml", input_hash)],
            json!({"boundary_mode": "ANNOTATED"}),
            "blake3:stdout",
            128,
            timestamp,
        )
    }

    #[test]
    fn default_witness_path_prefers_epistemic_witness_env() {
        let path = default_witness_path_from(
            Some(OsString::from("/tmp/custom-witness.jsonl")),
            Some(OsString::from("/tmp/home")),
            None,
        );

        assert_eq!(path, PathBuf::from("/tmp/custom-witness.jsonl"));
    }

    #[test]
    fn default_witness_path_uses_home_when_env_missing() {
        let path = default_witness_path_from(None, Some(OsString::from("/tmp/home")), None);

        assert_eq!(path, PathBuf::from("/tmp/home/.epistemic/witness.jsonl"));
    }

    #[test]
    fn append_witness_writes_valid_jsonl_and_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/witness.jsonl");
        let record = sample_record("verify", "VERIFIED", "2024-01-15T10:30:00Z", "blake3:abc");

        append_witness_at(&path, &record).unwrap();

        let contents = fs::read_to_string(path).unwrap();
        assert!(contents.ends_with('\n'));
        let parsed: WitnessRecord = serde_json::from_str(contents.trim_end()).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn append_failure_does_not_change_domain_exit_code() {
        let dir = tempdir().unwrap();
        let record = sample_record(
            "assemble",
            "ASSEMBLED",
            "2024-01-15T10:30:00Z",
            "blake3:abc",
        );
        let mut stderr = Vec::new();

        let exit_code = maybe_append_witness_at(dir.path(), &record, true, 1, &mut stderr);

        assert_eq!(exit_code, 1);
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stderr.contains("witness append failed"));
    }

    #[test]
    fn no_witness_skips_append_entirely() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        let record = sample_record(
            "assemble",
            "ASSEMBLED",
            "2024-01-15T10:30:00Z",
            "blake3:abc",
        );
        let mut stderr = Vec::new();

        let exit_code = maybe_append_witness_at(&path, &record, false, 0, &mut stderr);

        assert_eq!(exit_code, 0);
        assert!(!path.exists());
        assert!(stderr.is_empty());
    }

    #[test]
    fn query_filters_by_outcome_date_and_input_hash() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        let records = [
            sample_record(
                "verify",
                "VERIFIED",
                "2024-01-15T10:30:00Z",
                "blake3:aaa111",
            ),
            sample_record(
                "verify",
                "VERIFY_PARTIAL",
                "2024-01-16T10:30:00Z",
                "blake3:bbb222",
            ),
            sample_record(
                "assemble",
                "ASSEMBLED",
                "2024-01-17T10:30:00Z",
                "blake3:ccc333",
            ),
        ];

        for record in &records {
            append_witness_at(&path, record).unwrap();
        }

        let filters = WitnessFilters {
            outcome: Some("VERIFY_PARTIAL".to_string()),
            since: Some(
                DateTime::parse_from_rfc3339("2024-01-16T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            until: Some(
                DateTime::parse_from_rfc3339("2024-01-16T23:59:59Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            input_hash: Some("bbb".to_string()),
            limit: Some(5),
            ..WitnessFilters::default()
        };

        let result = query_at(&path, &filters).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].outcome, "VERIFY_PARTIAL");
        assert_eq!(result[0].timestamp, "2024-01-16T10:30:00Z");
    }

    #[test]
    fn last_returns_most_recent_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        append_witness_at(
            &path,
            &sample_record("verify", "VERIFIED", "2024-01-15T10:30:00Z", "blake3:abc"),
        )
        .unwrap();
        append_witness_at(
            &path,
            &sample_record(
                "verify",
                "VERIFY_PARTIAL",
                "2024-01-16T10:30:00Z",
                "blake3:def",
            ),
        )
        .unwrap();

        let record = last_at(&path).unwrap().unwrap();

        assert_eq!(record.timestamp, "2024-01-16T10:30:00Z");
        assert_eq!(record.outcome, "VERIFY_PARTIAL");
    }

    #[test]
    fn count_returns_filtered_total() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        append_witness_at(
            &path,
            &sample_record("verify", "VERIFIED", "2024-01-15T10:30:00Z", "blake3:aaa"),
        )
        .unwrap();
        append_witness_at(
            &path,
            &sample_record("verify", "VERIFIED", "2024-01-16T10:30:00Z", "blake3:bbb"),
        )
        .unwrap();
        append_witness_at(
            &path,
            &sample_record(
                "assemble",
                "ASSEMBLED",
                "2024-01-17T10:30:00Z",
                "blake3:ccc",
            ),
        )
        .unwrap();

        let filters = WitnessFilters {
            outcome: Some("VERIFIED".to_string()),
            ..WitnessFilters::default()
        };

        assert_eq!(count_at(&path, &filters).unwrap(), 2);
    }

    #[test]
    fn query_missing_ledger_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.jsonl");

        let result = query_at(&path, &WitnessFilters::default()).unwrap();

        assert!(result.is_empty());
        assert_eq!(count_at(&path, &WitnessFilters::default()).unwrap(), 0);
        assert!(last_at(&path).unwrap().is_none());
    }
}
