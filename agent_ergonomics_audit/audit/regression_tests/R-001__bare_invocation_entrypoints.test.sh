#!/usr/bin/env bash
set -euo pipefail

BIN="${AIRLOCK_BIN:-target/debug/airlock}"

output="$("$BIN")"
printf '%s\n' "$output" | grep -F "Usage: airlock" >/dev/null
printf '%s\n' "$output" | grep -F "airlock --robot-triage" >/dev/null
printf '%s\n' "$output" | grep -F "airlock capabilities --json" >/dev/null
printf '%s\n' "$output" | grep -F "airlock robot-docs guide" >/dev/null
