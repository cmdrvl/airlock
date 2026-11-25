//! Checking the `prev_hash` chain that [`super::append_witness_at`] writes.
//!
//! The chain is a local tamper hint (spine rule R-016), not a proof. It catches an airlock
//! entry that was edited, deleted, inserted or reordered ahead of a later airlock entry, and
//! entries cut off the head of the ledger. It cannot catch entries removed from the tail, or a
//! whole ledger rewritten by someone who recomputes every hash. A head hash recorded somewhere
//! the ledger's writer cannot reach (`--expect-head`) is the only defence against those two.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use super::{GENESIS_PREV_HASH, WitnessError, is_airlock_entry};
use crate::hash::blake3_hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BreakReason {
    /// `prev_hash` is not the hash of the previous airlock line.
    PrevHashMismatch,
    /// The first airlock entry in the ledger claims a predecessor: what came before it was cut.
    FirstEntryHasPredecessor,
    /// `prev_hash` is present but is not a string.
    PrevHashMalformed,
}

/// An entry whose link does not hold. `line` is the 1-based line of the entry that carries the
/// bad link, which is the entry AFTER the one that was changed, removed or moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainBreak {
    pub line: usize,
    pub reason: BreakReason,
    pub expected: Option<String>,
    pub found: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WarningReason {
    /// An airlock entry with no `prev_hash` after chained entries began: an older airlock wrote
    /// it, or the ledger could not be locked. The entry after it still links over it.
    UnchainedAfterChainStart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainWarning {
    pub line: usize,
    pub reason: WarningReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainReport {
    pub airlock_entries: usize,
    pub chained: usize,
    pub unchained: usize,
    /// Non-blank lines that are not JSON. They are not airlock entries and are not counted as
    /// links; a damaged airlock entry shows up as a break on the entry after it.
    pub skipped_lines: usize,
    /// Hash of the last airlock line, the value to record and later pass as `--expect-head`.
    pub head: Option<String>,
    pub breaks: Vec<ChainBreak>,
    pub warnings: Vec<ChainWarning>,
}

impl ChainReport {
    pub fn is_intact(&self) -> bool {
        self.breaks.is_empty()
    }
}

/// Walk the airlock entries of the ledger at `path`, in file order, and check each link. A
/// missing ledger has no entries and no breaks.
pub fn verify_chain_at(path: &Path) -> Result<ChainReport, WitnessError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(report_for(std::iter::empty::<&[u8]>()));
        }
        Err(error) => return Err(error.into()),
    };
    Ok(report_for(bytes.split(|byte| *byte == b'\n')))
}

fn report_for<'a>(lines: impl Iterator<Item = &'a [u8]>) -> ChainReport {
    let mut report = ChainReport {
        airlock_entries: 0,
        chained: 0,
        unchained: 0,
        skipped_lines: 0,
        head: None,
        breaks: Vec::new(),
        warnings: Vec::new(),
    };
    // Hash of the previous airlock line, if there is one.
    let mut previous: Option<String> = None;
    let mut chain_started = false;

    for (index, line) in lines.enumerate() {
        let line_number = index + 1;
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(line) else {
            report.skipped_lines += 1;
            continue;
        };
        if !is_airlock_entry(&value) {
            continue;
        }
        report.airlock_entries += 1;

        match value.get("prev_hash") {
            None => {
                report.unchained += 1;
                if chain_started {
                    report.warnings.push(ChainWarning {
                        line: line_number,
                        reason: WarningReason::UnchainedAfterChainStart,
                    });
                }
            }
            Some(Value::String(found)) => {
                chain_started = true;
                report.chained += 1;
                match &previous {
                    None if found != GENESIS_PREV_HASH => report.breaks.push(ChainBreak {
                        line: line_number,
                        reason: BreakReason::FirstEntryHasPredecessor,
                        expected: Some(GENESIS_PREV_HASH.to_string()),
                        found: Some(found.clone()),
                    }),
                    Some(expected) if found != expected => report.breaks.push(ChainBreak {
                        line: line_number,
                        reason: BreakReason::PrevHashMismatch,
                        expected: Some(expected.clone()),
                        found: Some(found.clone()),
                    }),
                    _ => {}
                }
            }
            Some(_) => {
                chain_started = true;
                report.chained += 1;
                report.breaks.push(ChainBreak {
                    line: line_number,
                    reason: BreakReason::PrevHashMalformed,
                    expected: previous.clone(),
                    found: None,
                });
            }
        }
        previous = Some(blake3_hash(line));
    }

    report.head = previous;
    report
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;
    use crate::witness::{WitnessRecord, append_witness_at};

    fn record(n: usize) -> WitnessRecord {
        WitnessRecord::with_timestamp(
            format!("verify-{n}"),
            "VERIFIED",
            0,
            vec![WitnessRecord::input("policy.yaml", "blake3:abc")],
            json!({}),
            "blake3:stdout",
            1,
            "2024-01-15T10:30:00Z",
        )
    }

    fn chained_ledger(dir: &Path, entries: usize) -> std::path::PathBuf {
        let path = dir.join("witness.jsonl");
        for n in 0..entries {
            append_witness_at(&path, &record(n)).unwrap();
        }
        path
    }

    fn lines_of(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .split('\n')
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn write_lines(path: &Path, lines: &[String]) {
        fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn a_missing_ledger_has_no_entries_and_no_breaks() {
        let dir = tempdir().unwrap();

        let report = verify_chain_at(&dir.path().join("missing.jsonl")).unwrap();

        assert_eq!(report.airlock_entries, 0);
        assert_eq!(report.head, None);
        assert!(report.is_intact());
    }

    #[test]
    fn an_untouched_chain_is_intact_and_its_head_is_the_hash_of_the_last_line() {
        let dir = tempdir().unwrap();
        let path = chained_ledger(dir.path(), 4);

        let report = verify_chain_at(&path).unwrap();

        assert!(report.is_intact(), "{report:?}");
        assert_eq!(
            (report.airlock_entries, report.chained, report.unchained),
            (4, 4, 0)
        );
        assert_eq!(
            report.head,
            Some(blake3_hash(lines_of(&path).last().unwrap().as_bytes()))
        );
    }

    #[test]
    fn editing_a_middle_entry_breaks_the_link_of_the_entry_after_it() {
        let dir = tempdir().unwrap();
        let path = chained_ledger(dir.path(), 4);
        let mut lines = lines_of(&path);
        lines[1] = lines[1].replace("VERIFIED", "VERIFYED");
        write_lines(&path, &lines);

        let report = verify_chain_at(&path).unwrap();

        assert_eq!(report.breaks.len(), 1);
        assert_eq!(report.breaks[0].line, 3);
        assert_eq!(report.breaks[0].reason, BreakReason::PrevHashMismatch);
    }

    #[test]
    fn cutting_entries_off_the_head_leaves_a_first_entry_that_claims_a_predecessor() {
        let dir = tempdir().unwrap();
        let path = chained_ledger(dir.path(), 3);
        let lines = lines_of(&path);
        write_lines(&path, &lines[1..]);

        let report = verify_chain_at(&path).unwrap();

        assert_eq!(report.breaks.len(), 1);
        assert_eq!(report.breaks[0].line, 1);
        assert_eq!(
            report.breaks[0].reason,
            BreakReason::FirstEntryHasPredecessor
        );
    }

    #[test]
    fn entries_before_the_chain_began_are_not_warnings_but_one_after_it_is() {
        let dir = tempdir().unwrap();
        let path = chained_ledger(dir.path(), 2);
        let mut lines = lines_of(&path);
        // Two entries as an older airlock wrote them, ahead of the chained ones.
        let mut legacy: Vec<String> = lines
            .iter()
            .map(|line| {
                let mut value: Value = serde_json::from_str(line).unwrap();
                value.as_object_mut().unwrap().remove("prev_hash");
                serde_json::to_string(&value).unwrap()
            })
            .collect();
        let after_chain = legacy[0].clone();
        legacy.append(&mut lines);
        legacy.push(after_chain);
        write_lines(&path, &legacy);

        let report = verify_chain_at(&path).unwrap();

        // The two legacy lines come first (no warning); the first chained entry still says
        // genesis, which is wrong now that something precedes it, so it is the one break.
        assert_eq!(report.unchained, 3);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].line, 5);
        assert_eq!(
            report.warnings[0].reason,
            WarningReason::UnchainedAfterChainStart
        );
        assert_eq!(report.breaks.len(), 1);
        assert_eq!(report.breaks[0].line, 3);
        assert_eq!(report.breaks[0].reason, BreakReason::PrevHashMismatch);
    }

    #[test]
    fn a_prev_hash_that_is_not_a_string_is_malformed() {
        let dir = tempdir().unwrap();
        let path = chained_ledger(dir.path(), 2);
        let mut lines = lines_of(&path);
        let mut value: Value = serde_json::from_str(&lines[1]).unwrap();
        value["prev_hash"] = json!(7);
        lines[1] = serde_json::to_string(&value).unwrap();
        write_lines(&path, &lines);

        let report = verify_chain_at(&path).unwrap();

        assert_eq!(report.breaks.len(), 1);
        assert_eq!(report.breaks[0].reason, BreakReason::PrevHashMalformed);
        assert_eq!(report.breaks[0].line, 2);
    }

    #[test]
    fn lines_that_are_not_json_are_skipped_and_counted_not_treated_as_links() {
        let dir = tempdir().unwrap();
        let path = chained_ledger(dir.path(), 2);
        let mut lines = lines_of(&path);
        lines.insert(1, "this is not json".to_owned());
        write_lines(&path, &lines);

        let report = verify_chain_at(&path).unwrap();

        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.skipped_lines, 1);
        assert_eq!(report.airlock_entries, 2);
    }

    #[test]
    fn an_airlock_entry_corrupted_into_non_json_breaks_the_entry_after_it() {
        let dir = tempdir().unwrap();
        let path = chained_ledger(dir.path(), 3);
        let mut lines = lines_of(&path);
        lines[1] = lines[1][..20].to_owned();
        write_lines(&path, &lines);

        let report = verify_chain_at(&path).unwrap();

        assert_eq!(report.skipped_lines, 1);
        assert_eq!(report.breaks.len(), 1);
        assert_eq!(report.breaks[0].line, 3);
    }

    #[test]
    fn the_writer_and_the_verifier_agree_on_the_segmentation_of_a_torn_ledger() {
        let dir = tempdir().unwrap();
        let path = chained_ledger(dir.path(), 2);
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        std::io::Write::write_all(&mut file, b"{\"tool\":\"airlock\",\"comm").unwrap();
        drop(file);
        append_witness_at(&path, &record(2)).unwrap();

        let report = verify_chain_at(&path).unwrap();

        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.airlock_entries, 3);
        assert_eq!(report.skipped_lines, 1);
    }
}
