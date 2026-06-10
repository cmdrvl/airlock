#!/usr/bin/env bash
set -euo pipefail

BIN="${AIRLOCK_BIN:-target/debug/airlock}"

output="$("$BIN" robot-docs guide)"
printf '%s\n' "$output" | grep -F "airlock doctor robot docs" >/dev/null
printf '%s\n' "$output" | grep -F "airlock --robot-triage" >/dev/null
printf '%s\n' "$output" | grep -F "airlock explain --manifest <MANIFEST> --json" >/dev/null
