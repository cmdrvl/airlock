#!/usr/bin/env bash
set -euo pipefail

BIN="${AIRLOCK_BIN:-target/debug/airlock}"

"$BIN" explain --manifest fixtures/annotated_mode/expected_manifest.json --json | jq -e '
  .schema == "airlock.explain.v1"
  and .claim.achieved == "RAW_DOCUMENT_ABSENT"
  and .proof.policy_id == "annotated_mode"
  and (.blocked_paths | index("messages[1].content.mutator_context.challenge_observation") != null)
' >/dev/null
