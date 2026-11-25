pub mod chain;

use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::hash::blake3_hash;
use crate::output::canonical_json;
use crate::paths;

pub const WITNESS_VERSION: &str = "witness.v0";
pub const TOOL_NAME: &str = "airlock";

/// The `prev_hash` of an airlock entry that has no airlock entry before it in the ledger.
pub const GENESIS_PREV_HASH: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

/// How long an append waits for another airlock process to release the ledger lock.
const LOCK_WAIT: Duration = Duration::from_secs(2);
const LOCK_POLL: Duration = Duration::from_millis(10);
/// How much of the ledger's tail one read covers when looking for the previous airlock entry.
const TAIL_BLOCK: usize = 64 * 1024;

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
    /// Hash of the exact bytes of the previous airlock line in the ledger, set by
    /// [`append_witness_at`] when it writes the entry under the ledger lock. Absent on entries
    /// written before the chain existed, and on entries written when the ledger could not be
    /// locked. A tamper hint, not a proof: see the README.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
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
            prev_hash: None,
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
    paths::default_witness_path()
}

/// How an entry reached the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOutcome {
    /// The entry was written under the ledger lock and carries `prev_hash`.
    Chained,
    /// The entry was written without a chain link because the ledger could not be locked. The
    /// next entry links over it.
    Unchained { reason: String },
}

/// Append a witness record to the default ledger path.
pub fn append_witness(record: WitnessRecord) -> Result<AppendOutcome, WitnessError> {
    let path = paths::prepare_witness_path_for_append()?;
    append_witness_at(&path, &record)
}

/// Append a witness record to the given ledger path.
///
/// The ledger is shared with other tools that append without locking, so the chain covers only
/// airlock's own entries: `prev_hash` is the hash of the exact bytes of the last line whose
/// `tool` is `airlock` (or [`GENESIS_PREV_HASH`] when there is none). Finding that line and
/// writing the new one happen under an exclusive lock on the ledger file, so two airlock
/// processes, or two gate threads, cannot both link to the same predecessor. Whatever
/// `prev_hash` the caller put on `record` is replaced.
pub fn append_witness_at(
    path: &Path,
    record: &WitnessRecord,
) -> Result<AppendOutcome, WitnessError> {
    append_with_lock_wait(path, record, LOCK_WAIT)
}

fn append_with_lock_wait(
    path: &Path,
    record: &WitnessRecord,
    lock_wait: Duration,
) -> Result<AppendOutcome, WitnessError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;

    // The lock is released when `file` is dropped, after the write.
    match lock_exclusive(&file, lock_wait) {
        Ok(()) => {
            let tail = scan_tail(&mut file, TAIL_BLOCK)?;
            let mut chained = record.clone();
            chained.prev_hash = Some(
                tail.last_airlock_hash
                    .unwrap_or_else(|| GENESIS_PREV_HASH.to_string()),
            );
            let mut bytes = Vec::new();
            if !tail.ends_with_newline {
                // A crash left a last line with no newline: end it rather than glue onto it.
                bytes.push(b'\n');
            }
            bytes.extend_from_slice(chained.to_jsonl_line().as_bytes());
            file.write_all(&bytes)?;
            Ok(AppendOutcome::Chained)
        }
        Err(reason) => {
            file.write_all(record.to_jsonl_line().as_bytes())?;
            Ok(AppendOutcome::Unchained { reason })
        }
    }
}

fn lock_exclusive(file: &File, wait: Duration) -> Result<(), String> {
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "another process held the ledger lock for {} ms",
                        wait.as_millis()
                    ));
                }
                thread::sleep(LOCK_POLL);
            }
            Err(TryLockError::Error(error)) => {
                return Err(format!("the ledger could not be locked ({error})"));
            }
        }
    }
}

/// Whether a parsed ledger line is an airlock entry: a JSON object whose `tool` is `airlock`.
/// The writer and `witness verify` both use this, so they agree on what counts.
pub(crate) fn is_airlock_entry(value: &Value) -> bool {
    value.get("tool").and_then(Value::as_str) == Some(TOOL_NAME)
}

/// The chain hash of `line` (its exact bytes, without the newline) when it is an airlock entry.
/// `None` for every other line, including one that is not JSON.
pub(crate) fn airlock_line_hash(line: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(line).ok()?;
    is_airlock_entry(&value).then(|| blake3_hash(line))
}

#[derive(Debug, PartialEq, Eq)]
struct TailScan {
    /// Hash of the last airlock line in the ledger, if any.
    last_airlock_hash: Option<String>,
    /// False when the ledger is non-empty and its last byte is not a newline.
    ends_with_newline: bool,
}

/// Find the last airlock line by reading the ledger backwards, `block` bytes at a time. Only
/// as much of the file as it takes to find one is read; a ledger with no airlock line is read
/// whole, once.
fn scan_tail(file: &mut File, block: usize) -> io::Result<TailScan> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(TailScan {
            last_airlock_hash: None,
            ends_with_newline: true,
        });
    }
    let mut last_byte = [0u8; 1];
    file.seek(SeekFrom::Start(len - 1))?;
    file.read_exact(&mut last_byte)?;
    let ends_with_newline = last_byte[0] == b'\n';
    let found = |last_airlock_hash| TailScan {
        last_airlock_hash,
        ends_with_newline,
    };

    // Pieces of one line whose start lies before the block being read, in file order.
    let mut right: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pos = len;
    while pos > 0 {
        let start = pos.saturating_sub(block.max(1) as u64);
        let mut buf = vec![0u8; (pos - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buf)?;
        pos = start;

        let Some(last_newline) = buf.iter().rposition(|byte| *byte == b'\n') else {
            // No line starts or ends in this block: it is the middle of a longer line.
            right.push_front(buf);
            continue;
        };

        // The line after the block's last newline continues into the pieces to its right.
        let mut line = buf[last_newline + 1..].to_vec();
        for piece in right.drain(..) {
            line.extend_from_slice(&piece);
        }
        if let Some(hash) = airlock_line_hash(&line) {
            return Ok(found(Some(hash)));
        }

        // Lines that lie wholly inside the block, last to first.
        let mut end = last_newline;
        while let Some(newline) = buf[..end].iter().rposition(|byte| *byte == b'\n') {
            if let Some(hash) = airlock_line_hash(&buf[newline + 1..end]) {
                return Ok(found(Some(hash)));
            }
            end = newline;
        }
        // What is left starts before this block (or is the first line of the file).
        right.push_front(buf[..end].to_vec());
    }

    let first_line: Vec<u8> = right.into_iter().flatten().collect();
    Ok(found(airlock_line_hash(&first_line)))
}

/// Best-effort append that preserves the original domain exit code.
pub fn maybe_append_witness(
    record: WitnessRecord,
    enabled: bool,
    domain_exit: u8,
    stderr: &mut impl Write,
) -> u8 {
    if !enabled {
        return domain_exit;
    }

    match paths::prepare_witness_path_for_append() {
        Ok(path) => maybe_append_witness_at(&path, &record, true, domain_exit, stderr),
        Err(error) => {
            let _ = writeln!(stderr, "airlock: witness append failed: {error}");
            domain_exit
        }
    }
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

    let prepared_path;
    let append_path = if path == paths::default_witness_path() {
        match paths::prepare_witness_path_for_append() {
            Ok(path) => {
                prepared_path = path;
                prepared_path.as_path()
            }
            Err(error) => {
                let _ = writeln!(stderr, "airlock: witness append failed: {error}");
                return domain_exit;
            }
        }
    } else {
        path
    };

    report_append_result(append_witness_at(append_path, record), stderr);

    domain_exit
}

/// Witness problems are warnings only (spine rule R-017): they never change the exit code.
fn report_append_result(result: Result<AppendOutcome, WitnessError>, stderr: &mut impl Write) {
    match result {
        Ok(AppendOutcome::Chained) => {}
        Ok(AppendOutcome::Unchained { reason }) => {
            let _ = writeln!(
                stderr,
                "airlock: witness entry written without a chain link: {reason}"
            );
        }
        Err(error) => {
            let _ = writeln!(stderr, "airlock: witness append failed: {error}");
        }
    }
}

/// Query witness records from the default ledger path.
pub fn query(filters: &WitnessFilters) -> Result<Vec<WitnessRecord>, WitnessError> {
    let path = paths::prepare_witness_path_for_query()?;
    query_at(&path, filters)
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
    let path = paths::prepare_witness_path_for_query()?;
    last_at(&path)
}

/// Return the most recent witness record from an explicit ledger path.
pub fn last_at(path: &Path) -> Result<Option<WitnessRecord>, WitnessError> {
    Ok(query_at(path, &WitnessFilters::default())?
        .into_iter()
        .next())
}

/// Count witness records matching the filters from the default ledger path.
pub fn count(filters: &WitnessFilters) -> Result<usize, WitnessError> {
    let path = paths::prepare_witness_path_for_query()?;
    count_at(&path, filters)
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
    fn append_witness_writes_valid_jsonl_and_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/witness.jsonl");
        let record = sample_record("verify", "VERIFIED", "2024-01-15T10:30:00Z", "blake3:abc");

        append_witness_at(&path, &record).unwrap();

        let contents = fs::read_to_string(path).unwrap();
        assert!(contents.ends_with('\n'));
        let parsed: WitnessRecord = serde_json::from_str(contents.trim_end()).unwrap();
        // The only difference from what was passed in is the chain link: this is the first
        // airlock entry in the ledger, so it links to the genesis hash.
        assert_eq!(
            parsed,
            WitnessRecord {
                prev_hash: Some(GENESIS_PREV_HASH.to_string()),
                ..record
            }
        );
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

    // ---- prev_hash chain ----

    /// The lines of a ledger file, without newlines, blank lines skipped.
    fn ledger_lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .split('\n')
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn prev_hash_of(line: &str) -> Option<String> {
        let value: Value = serde_json::from_str(line).unwrap();
        value
            .get("prev_hash")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    fn hash_of(line: &str) -> String {
        blake3_hash(line.as_bytes())
    }

    fn numbered(n: usize) -> WitnessRecord {
        sample_record(
            &format!("verify-{n}"),
            "VERIFIED",
            "2024-01-15T10:30:00Z",
            "blake3:abc",
        )
    }

    #[test]
    fn genesis_hash_has_the_shape_of_a_blake3_hash() {
        assert_eq!(GENESIS_PREV_HASH.len(), "blake3:".len() + 64);
        assert!(GENESIS_PREV_HASH.starts_with("blake3:"));
        assert!(
            GENESIS_PREV_HASH["blake3:".len()..]
                .chars()
                .all(|c| c == '0')
        );
    }

    #[test]
    fn a_record_without_prev_hash_serializes_exactly_as_before_the_chain_existed() {
        let line = sample_record("verify", "VERIFIED", "2024-01-15T10:30:00Z", "blake3:abc")
            .to_jsonl_line();

        assert_eq!(
            line,
            "{\"command\":\"verify\",\"exit_code\":0,\"inputs\":[{\"hash\":\"blake3:abc\",\"path\":\"policy.yaml\"}],\"outcome\":\"VERIFIED\",\"params\":{\"boundary_mode\":\"ANNOTATED\"},\"stdout_bytes\":128,\"stdout_hash\":\"blake3:stdout\",\"timestamp\":\"2024-01-15T10:30:00Z\",\"tool\":\"airlock\",\"witness_version\":\"witness.v0\"}\n"
        );
    }

    #[test]
    fn the_first_entry_links_to_genesis_and_each_next_to_the_exact_previous_line() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");

        for n in 0..3 {
            assert_eq!(
                append_witness_at(&path, &numbered(n)).unwrap(),
                AppendOutcome::Chained
            );
        }

        let lines = ledger_lines(&path);
        assert_eq!(lines.len(), 3);
        assert_eq!(prev_hash_of(&lines[0]).as_deref(), Some(GENESIS_PREV_HASH));
        assert_eq!(prev_hash_of(&lines[1]), Some(hash_of(&lines[0])));
        assert_eq!(prev_hash_of(&lines[2]), Some(hash_of(&lines[1])));
    }

    #[test]
    fn a_prev_hash_the_caller_sets_is_replaced_by_the_real_link() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        let mut record = numbered(0);
        record.prev_hash = Some("blake3:caller-chose-this".to_string());

        append_witness_at(&path, &record).unwrap();

        let lines = ledger_lines(&path);
        assert_eq!(prev_hash_of(&lines[0]).as_deref(), Some(GENESIS_PREV_HASH));
    }

    #[test]
    fn the_first_chained_entry_commits_to_the_last_legacy_airlock_line() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        let legacy: Vec<String> = (0..2).map(|n| numbered(n).to_jsonl_line()).collect();
        fs::write(&path, legacy.concat()).unwrap();

        append_witness_at(&path, &numbered(2)).unwrap();

        let lines = ledger_lines(&path);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], legacy[0].trim_end());
        assert_eq!(lines[1], legacy[1].trim_end());
        assert_eq!(prev_hash_of(&lines[0]), None);
        assert_eq!(prev_hash_of(&lines[2]), Some(hash_of(&lines[1])));
    }

    #[test]
    fn other_tools_lines_and_garbage_are_never_links() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        append_witness_at(&path, &numbered(0)).unwrap();
        let first = ledger_lines(&path).remove(0);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"tool\":\"rvl\",\"outcome\":\"ok\"}\nnot json at all\n\n")
            .unwrap();
        drop(file);

        append_witness_at(&path, &numbered(1)).unwrap();

        let lines = ledger_lines(&path);
        assert_eq!(lines.len(), 4);
        assert_eq!(prev_hash_of(lines.last().unwrap()), Some(hash_of(&first)));
    }

    #[test]
    fn a_torn_final_fragment_is_ended_not_glued_onto() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        append_witness_at(&path, &numbered(0)).unwrap();
        let first = ledger_lines(&path).remove(0);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"tool\":\"airlock\",\"comm").unwrap();
        drop(file);

        append_witness_at(&path, &numbered(1)).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.split('\n').collect();
        assert_eq!(lines[1], "{\"tool\":\"airlock\",\"comm");
        let appended = lines[2];
        assert!(serde_json::from_str::<WitnessRecord>(appended).is_ok());
        assert_eq!(prev_hash_of(appended), Some(hash_of(&first)));
        assert!(contents.ends_with('\n'));
    }

    #[test]
    fn a_complete_airlock_line_missing_only_its_newline_is_linked_and_ended() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        let unterminated = numbered(0).to_jsonl_line().trim_end().to_owned();
        fs::write(&path, &unterminated).unwrap();

        append_witness_at(&path, &numbered(1)).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.split('\n').collect();
        assert_eq!(lines[0], unterminated);
        assert_eq!(prev_hash_of(lines[1]), Some(hash_of(&unterminated)));
    }

    #[test]
    fn airlock_line_hash_needs_a_top_level_airlock_tool() {
        let hash = |line: &str| airlock_line_hash(line.as_bytes());
        assert_eq!(
            hash("{\"tool\":\"airlock\"}"),
            Some(hash_of("{\"tool\":\"airlock\"}"))
        );
        assert_eq!(hash("{\"tool\":\"rvl\"}"), None);
        assert_eq!(hash("{\"tool\":\"airlockish\"}"), None);
        assert_eq!(hash("{\"tool\":5}"), None);
        assert_eq!(hash("{\"x\":{\"tool\":\"airlock\"}}"), None);
        assert_eq!(hash("[\"airlock\"]"), None);
        assert_eq!(hash("not json"), None);
        assert_eq!(hash(""), None);
    }

    /// The same answer as `scan_tail`, from reading the whole file.
    fn reference_scan(content: &[u8]) -> TailScan {
        TailScan {
            last_airlock_hash: content
                .split(|byte| *byte == b'\n')
                .rev()
                .find_map(airlock_line_hash),
            ends_with_newline: content.last().is_none_or(|byte| *byte == b'\n'),
        }
    }

    fn scan_file(dir: &Path, content: &[u8], block: usize) -> TailScan {
        let path = dir.join("scan.jsonl");
        fs::write(&path, content).unwrap();
        let mut file = File::open(&path).unwrap();
        scan_tail(&mut file, block).unwrap()
    }

    #[test]
    fn the_tail_scan_agrees_with_a_whole_file_read_for_every_block_size() {
        // A fixed-seed generator so the ledgers are the same every run.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        let dir = tempdir().unwrap();
        let mut compared = 0;
        for _ in 0..150 {
            let mut content = Vec::new();
            for _ in 0..next(7) {
                let line = match next(8) {
                    0 | 1 => sample_record(
                        &"c".repeat(1 + next(200)),
                        "VERIFIED",
                        "2024-01-15T10:30:00Z",
                        "blake3:abc",
                    )
                    .to_jsonl_line()
                    .trim_end()
                    .to_owned(),
                    2 => format!("{{\"tool\":\"rvl\",\"pad\":\"{}\"}}", "x".repeat(next(300))),
                    3 => "not json at all".to_owned(),
                    4 => String::new(),
                    5 => "{\"x\":{\"tool\":\"airlock\"}}".to_owned(),
                    6 => format!(
                        "{{\"tool\":\"airlock\",\"pad\":\"{}\"",
                        "y".repeat(next(90))
                    ),
                    _ => "{\"tool\":\"airlockish\"}".to_owned(),
                };
                content.extend_from_slice(line.as_bytes());
                content.push(b'\n');
            }
            if next(3) == 0 && content.last() == Some(&b'\n') {
                content.pop();
            }
            let expected = reference_scan(&content);
            for block in [1, 2, 3, 5, 8, 13, 64, 1000, TAIL_BLOCK] {
                assert_eq!(
                    scan_file(dir.path(), &content, block),
                    expected,
                    "block {block}, ledger {:?}",
                    String::from_utf8_lossy(&content)
                );
                compared += 1;
            }
        }
        assert_eq!(compared, 150 * 9);
    }

    #[test]
    fn a_line_longer_than_many_blocks_is_still_found_and_hashed_whole() {
        let dir = tempdir().unwrap();
        let long = sample_record(
            &"z".repeat(5000),
            "VERIFIED",
            "2024-01-15T10:30:00Z",
            "blake3:abc",
        )
        .to_jsonl_line();
        let content = format!("{long}{{\"tool\":\"rvl\"}}\n");

        let scan = scan_file(dir.path(), content.as_bytes(), 7);

        assert_eq!(scan.last_airlock_hash, Some(hash_of(long.trim_end())));
    }

    #[test]
    fn a_held_lock_leaves_the_entry_unchained_and_the_next_one_links_over_it() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("witness.jsonl");
        append_witness_at(&path, &numbered(0)).unwrap();
        let holder = OpenOptions::new().append(true).open(&path).unwrap();
        holder.lock().unwrap();

        let outcome =
            append_with_lock_wait(&path, &numbered(1), Duration::from_millis(40)).unwrap();
        let mut stderr = Vec::new();
        report_append_result(Ok(outcome.clone()), &mut stderr);

        let reason = match &outcome {
            AppendOutcome::Unchained { reason } => reason.clone(),
            AppendOutcome::Chained => String::new(),
        };
        assert!(
            !reason.is_empty(),
            "expected an unchained entry, got {outcome:?}"
        );
        assert!(reason.contains("held the ledger lock"), "{reason}");
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stderr.contains("without a chain link"), "{stderr}");
        let lines = ledger_lines(&path);
        assert_eq!(lines.len(), 2, "the entry is written, not dropped");
        assert_eq!(prev_hash_of(&lines[1]), None);

        drop(holder);
        append_witness_at(&path, &numbered(2)).unwrap();
        let lines = ledger_lines(&path);
        assert_eq!(prev_hash_of(&lines[2]), Some(hash_of(&lines[1])));
    }

    #[test]
    fn concurrent_appends_from_many_threads_form_one_unbroken_chain() {
        use std::sync::{Arc, Barrier};

        const THREADS: usize = 8;
        const EACH: usize = 40;
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("witness.jsonl"));
        let barrier = Arc::new(Barrier::new(THREADS));
        let workers: Vec<_> = (0..THREADS)
            .map(|thread_index| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for n in 0..EACH {
                        let outcome =
                            append_witness_at(&path, &numbered(thread_index * EACH + n)).unwrap();
                        assert_eq!(outcome, AppendOutcome::Chained);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        let lines = ledger_lines(&path);
        assert_eq!(lines.len(), THREADS * EACH);
        assert_eq!(prev_hash_of(&lines[0]).as_deref(), Some(GENESIS_PREV_HASH));
        for pair in lines.windows(2) {
            assert_eq!(prev_hash_of(&pair[1]), Some(hash_of(&pair[0])));
        }
        let mut commands: Vec<String> = lines
            .iter()
            .map(|line| serde_json::from_str::<WitnessRecord>(line).unwrap().command)
            .collect();
        commands.sort();
        commands.dedup();
        assert_eq!(
            commands.len(),
            THREADS * EACH,
            "no entry lost or duplicated"
        );
    }
}
