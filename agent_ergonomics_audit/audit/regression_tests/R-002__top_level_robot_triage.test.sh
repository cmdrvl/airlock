#!/usr/bin/env bash
set -euo pipefail

BIN="${AIRLOCK_BIN:-target/debug/airlock}"

"$BIN" --robot-triage | jq -e '
  .schema == "airlock.doctor.triage.v1"
  and .read_only == true
  and .summary.capabilities == "airlock capabilities --json"
  and .side_effects.reads_manifest_files == false
' >/dev/null
