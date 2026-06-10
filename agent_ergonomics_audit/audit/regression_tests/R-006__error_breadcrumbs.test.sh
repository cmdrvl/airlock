#!/usr/bin/env bash
set -euo pipefail

BIN="${AIRLOCK_BIN:-target/debug/airlock}"

set +e
typo_stderr="$("$BIN" --jsno 2>&1 >/dev/null)"
typo_status=$?
timestamp_stdout="$("$BIN" witness query --since yesterday --json 2>/dev/null)"
timestamp_status=$?
set -e

test "$typo_status" -eq 2
printf '%s\n' "$typo_stderr" | grep -F 'did you mean `--json`' >/dev/null
printf '%s\n' "$typo_stderr" | grep -F 'airlock --robot-triage' >/dev/null

test "$timestamp_status" -eq 2
printf '%s\n' "$timestamp_stdout" | jq -e '
  .refusal.code == "E_BAD_INPUT"
  and .refusal.next_command == "airlock witness query --since 2026-01-15T00:00:00Z --json"
' >/dev/null
