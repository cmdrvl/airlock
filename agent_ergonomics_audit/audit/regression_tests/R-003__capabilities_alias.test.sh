#!/usr/bin/env bash
set -euo pipefail

BIN="${AIRLOCK_BIN:-target/debug/airlock}"

"$BIN" capabilities --json | jq -e '
  .schema == "airlock.doctor.capabilities.v1"
  and .agent_entrypoints.triage_json == "airlock --robot-triage"
  and .agent_entrypoints.robot_docs == "airlock robot-docs guide"
  and any(.commands[]; .name == "explain --json")
' >/dev/null
