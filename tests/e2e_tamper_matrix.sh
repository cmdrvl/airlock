#!/usr/bin/env bash
# Tamper matrix e2e (al-ii8).
#
# Runs the real airlock binary over tampered requests and records, per cell, the exit code, the
# achieved claim, the binding status and the finding set. Expectations are committed in
# fixtures/tamper_matrix.json; tests/tamper_matrix.rs applies the same ops with serde_json and
# checks the same file, so each interpreter checks the other.
#
#   tests/e2e_tamper_matrix.sh                       build the release binary, run, write the doc
#   AIRLOCK_BIN=target/release/airlock tests/e2e_tamper_matrix.sh
#   TAMPER_MATRIX_DOC=/path/out.md tests/e2e_tamper_matrix.sh
#
# Every command, exit code, claim and finding set is logged as it happens (stdout and
# $WORK/run.log). The run does not stop at the first mismatch. docs/tamper-matrix.md is written
# only when every cell matches its expectation, so a failing run cannot leave a doc behind. The
# script creates one fresh temp directory and deletes nothing. It runs only `assemble` and
# `verify`: no network command, no key, no outbound traffic.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FIXTURE="$ROOT/fixtures/tamper_matrix.json"
DOC="${TAMPER_MATRIX_DOC:-$ROOT/docs/tamper-matrix.md}"

command -v jq >/dev/null 2>&1 || { echo "tamper-matrix: jq is required" >&2; exit 2; }
[ -f "$FIXTURE" ] || { echo "tamper-matrix: missing $FIXTURE" >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/airlock-tamper-matrix.XXXXXX") || exit 2
LOG="$WORK/run.log"
CELLS="$WORK/cells.jsonl"
: > "$LOG"
: > "$CELLS"

log() { printf '%s\n' "$*" | tee -a "$LOG"; }

# run <stdout-file> <command...>: log the command, run it, keep stderr in the log, set RC.
run() {
  out=$1
  shift
  log "+ $*"
  "$@" > "$out" 2>> "$LOG" < /dev/null
  RC=$?
  log "  exit=$RC"
}

if [ -n "${AIRLOCK_BIN:-}" ]; then
  case "$AIRLOCK_BIN" in
    /*) BIN=$AIRLOCK_BIN ;;
    *) BIN="$PWD/$AIRLOCK_BIN" ;;
  esac
else
  log "== building the release binary"
  (cd "$ROOT" && cargo build --release --locked) 2>&1 | tee -a "$LOG"
  [ "${PIPESTATUS[0]}" -eq 0 ] || { log "tamper-matrix: release build failed"; exit 2; }
  BIN="${CARGO_TARGET_DIR:-$ROOT/target}/release/airlock"
fi
[ -x "$BIN" ] || { log "tamper-matrix: $BIN is not an executable"; exit 2; }

fixture() { jq -r "$1" "$FIXTURE"; }
MODEL=$(fixture .model)
REQUIRE=$(fixture .require_claim)
POLICY="$ROOT/$(fixture .policy)"
INPUT="$ROOT/$(fixture .input)"
SYSTEM_PROMPT="$ROOT/$(fixture .system_prompt)"
LEAK_POINTER=$(fixture .leak_pointer)
CHAIN_ADAPTER=$(fixture .chain.adapter)
CHAIN_PRIOR_MANIFEST=$(fixture .chain.prior_manifest)
CHAIN_PRIOR_HASH=$(fixture .chain.prior_manifest_hash)
CHAIN_TOOL_USE_ID=$(fixture .chain.tool_use_id)

log "== tamper matrix"
log "binary:       $BIN"
log "version:      $("$BIN" --version 2>&1)"
log "fixture:      $FIXTURE"
log "work dir:     $WORK"
log "require:      $REQUIRE"

# Apply a case's request ops to a request JSON file; print the tampered request.
apply_request_ops() {
  jq -c --argjson ops "$2" '
    reduce $ops[] as $o (.;
      if   $o.op == "reverse_messages"   then .messages |= reverse
      elif $o.op == "alter_last_byte"    then
        (($o.pointer | split("/")[1:] | map(if test("^[0-9]+$") then tonumber else . end)) as $p
          | setpath($p; getpath($p) | .[:-1] + "!"))
      elif $o.op == "add_top_level_key"  then . + {($o.key): $o.value}
      elif $o.op == "append_user_message" then .messages += [{role: "user", content: $o.text}]
      elif $o.op == "append_assistant_message" then .messages += [{role: "assistant", content: $o.text}]
      elif $o.op == "append_tool_message" then
        .messages += [{role: "tool", tool_call_id: $o.tool_call_id, content: $o.text}]
      else error("unknown request op: \($o.op)") end)' "$1"
}

FAILS=0
CELL_COUNT=0

for MODE in $(fixture '.modes[]'); do
  log ""
  log "== mode $MODE"

  # One honest assemble per mode: the request site tampers a request wrapped from this prompt.
  # "base-" so no cell file (named <case id>-<mode>, including the case "clean") can collide with it.
  CLEAN="$WORK/base-$MODE"
  run "$CLEAN.assemble.out" "$BIN" assemble --policy "$POLICY" --input "$INPUT" \
    --system-prompt "$SYSTEM_PROMPT" --boundary-mode "$MODE" \
    --out "$CLEAN.prompt.json" --provenance-out "$CLEAN.provenance.json" --no-witness
  [ "$RC" -eq 0 ] || { log "tamper-matrix: clean assemble failed in $MODE"; exit 2; }
  jq -c --arg m "$MODEL" '{model: $m, messages: .messages}' "$CLEAN.prompt.json" > "$CLEAN.request.json"

  while IFS= read -r CASE <&3; do
    ID=$(printf '%s' "$CASE" | jq -r .id)
    SITE=$(printf '%s' "$CASE" | jq -r .site)
    TITLE=$(printf '%s' "$CASE" | jq -r .title)
    OPS=$(printf '%s' "$CASE" | jq -c .ops)
    CELL="$WORK/$ID-$MODE"
    log ""
    log "-- cell $ID ($SITE, $MODE): $TITLE"

    PROMPT="$CLEAN.prompt.json"
    PROVENANCE="$CLEAN.provenance.json"
    case "$SITE" in
      request)
        apply_request_ops "$CLEAN.request.json" "$OPS" > "$CELL.request.json"
        ;;
      input_leak)
        # The payload goes into an allowed field before assemble, so binding holds and only the
        # detectors and patterns can fail the claim.
        LEAK=$(printf '%s' "$OPS" | jq -r '.[0].value')
        jq -c --arg v "$LEAK" --arg p "$LEAK_POINTER" \
          'setpath(($p | split("/")[1:]); $v)' "$INPUT" > "$CELL.input.json"
        run "$CELL.assemble.out" "$BIN" assemble --policy "$POLICY" --input "$CELL.input.json" \
          --system-prompt "$SYSTEM_PROMPT" --boundary-mode "$MODE" \
          --out "$CELL.prompt.json" --provenance-out "$CELL.provenance.json" --no-witness
        if [ "$RC" -ne 0 ]; then
          log "  FAIL: assemble refused the leak input (exit $RC): $(head -c 300 "$CELL.assemble.out")"
          FAILS=$((FAILS + 1))
          continue
        fi
        PROMPT="$CELL.prompt.json"
        PROVENANCE="$CELL.provenance.json"
        jq -c --arg m "$MODEL" '{model: $m, messages: .messages}' "$PROMPT" > "$CELL.request.json"
        ;;
      chain_turn)
        # The model's reply (and any tool result) is admitted through the chain: assemble is given a
        # receipt in the gate's shape, the reply it vouches for, and the prior manifest. Every file
        # is a committed fixture and every hash a committed constant that the binary re-checks.
        RESPONSE_KEY=$(printf '%s' "$OPS" | jq -r '[.[] | select(.op == "admit_response")][0].response // empty')
        RESPONSE_FILE=$(fixture ".chain.responses[\"$RESPONSE_KEY\"].file // empty")
        RESPONSE_HASH=$(fixture ".chain.responses[\"$RESPONSE_KEY\"].hash // empty")
        if [ -z "$RESPONSE_KEY" ] || [ -z "$RESPONSE_FILE" ] || [ -z "$RESPONSE_HASH" ]; then
          log "  FAIL: chain_turn case has no usable admit_response op (response '$RESPONSE_KEY')"
          FAILS=$((FAILS + 1))
          continue
        fi
        jq -n --arg r "$RESPONSE_HASH" --arg m "$CHAIN_PRIOR_HASH" '{
            gate_version: "airlock.gate.v1",
            mode: "strict-manifest",
            achieved_claim: "STRICT_TELEMETRY_ONLY",
            request_hash: "blake3:0000000000000000000000000000000000000000000000000000000000000000",
            response_hash: $r,
            upstream_status: 200,
            blocked: false,
            findings: [],
            timestamp: "2026-11-25T00:00:00Z",
            matched_manifest_hash: $m
          }' > "$CELL.receipt.json"
        TOOL_ARGS=()
        TOOL_OK=1
        for ARTIFACT_KEY in $(printf '%s' "$OPS" | jq -r '.[] | select(.op == "admit_tool_result") | .artifact'); do
          ARTIFACT_FILE=$(fixture ".chain.artifacts[\"$ARTIFACT_KEY\"].file // empty")
          if [ -z "$ARTIFACT_FILE" ]; then
            log "  FAIL: no artifact '$ARTIFACT_KEY' in the fixture's chain block"
            TOOL_OK=0
          else
            TOOL_ARGS+=(--tool-result "$CHAIN_TOOL_USE_ID=$ROOT/$ARTIFACT_FILE")
          fi
        done
        if [ "$TOOL_OK" -ne 1 ]; then
          FAILS=$((FAILS + 1))
          continue
        fi
        # ${TOOL_ARGS[@]+...}: an empty array must not trip `set -u` on bash 3.2 (macOS).
        run "$CELL.assemble.out" "$BIN" assemble --policy "$POLICY" --input "$INPUT" \
          --system-prompt "$SYSTEM_PROMPT" --boundary-mode "$MODE" \
          --out "$CELL.prompt.json" --provenance-out "$CELL.provenance.json" --no-witness \
          --prior-receipt "$CELL.receipt.json" --response "$ROOT/$RESPONSE_FILE" \
          --response-adapter "$CHAIN_ADAPTER" --prior-manifest "$ROOT/$CHAIN_PRIOR_MANIFEST" \
          ${TOOL_ARGS[@]+"${TOOL_ARGS[@]}"}
        if [ "$RC" -ne 0 ]; then
          log "  FAIL: chained assemble refused (exit $RC): $(head -c 300 "$CELL.assemble.out")"
          FAILS=$((FAILS + 1))
          continue
        fi
        PROMPT="$CELL.prompt.json"
        PROVENANCE="$CELL.provenance.json"
        jq -c --arg m "$MODEL" '{model: $m, messages: .messages}' "$PROMPT" > "$CELL.request.json"
        ;;
      *)
        log "  FAIL: unknown site $SITE"
        FAILS=$((FAILS + 1))
        continue
        ;;
    esac

    run "$CELL.manifest.out" "$BIN" verify --no-sign --no-witness --policy "$POLICY" \
      --prompt "$PROMPT" --provenance "$PROVENANCE" --request "$CELL.request.json" \
      --out "$CELL.manifest.json" --require-claim "$REQUIRE"
    EXIT=$RC

    OBSERVED=$(jq -c --argjson exit "$EXIT" '{
        exit: $exit,
        claim: .achieved_claim,
        binding: .binding_status,
        findings: ([.findings[]
          | if .artifact_class == "DETECTED_SENSITIVE"
            then "DETECTED_SENSITIVE:" + .matched_rule
            else .artifact_class end] | unique)
      }' "$CELL.manifest.out" 2>> "$LOG")
    if [ -z "$OBSERVED" ]; then
      log "  FAIL: verify wrote no manifest (exit $EXIT): $(head -c 300 "$CELL.manifest.out")"
      FAILS=$((FAILS + 1))
      continue
    fi
    EXPECTED=$(fixture ".cases[] | select(.id == \"$ID\") | .expect[\"$MODE\"]" | jq -c .)

    log "  claim=$(printf '%s' "$OBSERVED" | jq -r .claim) binding=$(printf '%s' "$OBSERVED" | jq -r .binding) findings=$(printf '%s' "$OBSERVED" | jq -c .findings)"
    CELL_COUNT=$((CELL_COUNT + 1))
    if [ "$OBSERVED" = "$EXPECTED" ]; then
      log "  PASS"
    else
      log "  FAIL: expected $EXPECTED"
      log "        observed $OBSERVED"
      FAILS=$((FAILS + 1))
    fi
    printf '%s\n' "$OBSERVED" | jq -c --arg id "$ID" --arg site "$SITE" --arg title "$TITLE" --arg mode "$MODE" \
      '{id: $id, site: $site, title: $title, mode: $mode} + .' >> "$CELLS"
  done 3< <(jq -c '.cases[]' "$FIXTURE")
done

log ""
log "== summary: $CELL_COUNT cells run, $FAILS failed"
if [ "$FAILS" -ne 0 ]; then
  log "tamper-matrix: FAILED. $DOC was not written. Log: $LOG"
  exit 1
fi

# The doc is rendered from what was observed, never from the expectations.
TABLE_HEADER='| Case | Tamper | Mode | Exit | Claim | Binding | Findings |
| ---- | ------ | ---- | ---- | ----- | ------- | -------- |'
render_table() {
  printf '%s\n' "$TABLE_HEADER"
  jq -s -r --arg site "$1" '.[] | select(.site == $site)
    | "| `\(.id)` | \(.title) | \(.mode) | \(.exit) | \(.claim) | \(.binding) | "
      + (if (.findings | length) == 0 then "none" else (.findings | map("`" + . + "`") | join(", ")) end)
      + " |"' "$CELLS"
}

{
  cat <<EOF
# Tamper matrix

<!-- Generated by tests/e2e_tamper_matrix.sh from fixtures/tamper_matrix.json. Do not edit by hand:
     CI regenerates this file and fails on any difference. -->

What the \`airlock\` binary does with tampered requests. Each row is one real run of
\`airlock assemble\` (with the chain flags for the conversation-chain rows) followed by
\`airlock verify --no-sign --no-witness --require-claim $REQUIRE\`.
**Exit** is verify's exit code: 0 means the claim met the requirement, 1 means the achieved claim
fell below it (a sender requiring $REQUIRE would be stopped). **Findings** are the sorted
finding classes; a detector hit is written \`DETECTED_SENSITIVE:<rule>\` because every detector hit
shares one class and only the rule says which pack fired.

Both modes are assembled from \`fixtures/annotated_mode\` with \`fixtures/tamper_matrix/policy.yaml\`
(that policy, all five detector packs and two declared tool-result artifacts). That input carries derived text, so every ANNOTATED row
also has \`derived_text_field_hit\` (the scanner records one finding per derived-text leaf) and a
clean ANNOTATED request earns RAW_DOCUMENT_ABSENT, never STRICT_TELEMETRY_ONLY. The payloads are
fabricated; the AWS-shaped token is random, not a credential.

## Request tampered after assembly

The prompt was assembled honestly; the request that would be sent was then changed. Every changed
request is UNBOUND, so the claim fails on that alone; the content findings show that the detectors
also saw the injected bytes.

EOF
  render_table request
  cat <<EOF

## Content leaked through an allowed field

The same payloads placed in an allowed TELEMETRY field before assembly, with the request wrapped
honestly, so binding holds. Here the claim is decided by the detectors and forbidden patterns alone.

EOF
  render_table input_leak
  cat <<EOF

## Conversation chain: model output and tool results

A later turn carries the model's earlier reply (\`MODEL_OUTPUT\`) and the results of its tool calls
(\`TOOL_RESULT\`) back into the prompt. The only way either gets into a prompt is
\`airlock assemble --prior-receipt R --response RESPONSE --response-adapter ADAPTER --prior-manifest M\`,
plus \`--tool-result TOOL_USE_ID=PATH\` for a tool result. Each row below is that chained assemble,
then the same verify as every other row.

Every file is committed: the replies (\`fixtures/chain\`, \`fixtures/tamper_matrix/chain\`), the tool
artifacts beside them, and the prior manifest \`fixtures/clean_telemetry_only/expected_manifest.json\`.
The receipt is built by the harness in the shape \`airlock gate\` writes. **A gate receipt is unsigned,
and these were not written by a gate**, so these rows show what \`assemble\` and \`verify\` do with an
admitted reply, not that a receipt is genuine. The hashes in the fixture are re-checked by the binary on
every run: \`assemble\` refuses a reply that does not match its receipt, and a receipt that does not name
the prior manifest.

How to read them. A clean reply earns what the clean row at the top earns (STRICT_TELEMETRY_ONLY in
TELEMETRY_ONLY mode, because the detectors screened the reply). A leak in the reply or in a tool result
fails the boundary exactly as a leak in an allowed field does, and declaring a tool result's hash in the
policy does not exempt it from the detectors. A tool result the policy does not declare is admitted, but
the claim is capped at RAW_DOCUMENT_ABSENT. The cap shows in the TELEMETRY_ONLY \`tr_undeclared\` row
(compare \`tr_declared\`); in ANNOTATED mode the ceiling is already RAW_DOCUMENT_ABSENT, so nothing shows
there. The row has no finding, because the cap is carried by the manifest's strict reason, which this
table does not show. The
\`mo_smuggled\` and \`tr_smuggled\` rows, under "Request tampered after assembly", are the other half: a
reply or tool result put into the request without being admitted is UNBOUND.

EOF
  render_table chain_turn
  cat <<EOF

## What this does not cover

- **Short base64 is not flagged.** The blob detector's default minimum run is 512 characters, and at
  this revision the policy does not expose it (only \`tabular_min_rows\` is passed through). The
  \`leak_base64_short\` rows (96 characters) show it: they exit 0 and earn the claim
  (RAW_DOCUMENT_ABSENT, or STRICT_TELEMETRY_ONLY in TELEMETRY_ONLY mode). A base64 string under 512
  characters in an allowed field crosses the boundary unflagged. The same detectors screen model
  output and tool results, so the gap should apply there too; no chain row tests it.
- **Earlier turns.** The chain rows admit one reply, and its tool results, onto a fixed prior
  manifest. Tampering with an earlier turn (a changed manifest, a swapped provenance file, a receipt
  for another response, a broken chain of turns) is what \`airlock chain verify\` checks, and
  \`tests/chain_verify.rs\` runs those cases; they are not cells here. A reply whose bytes differ from
  its receipt is refused by \`assemble\` before any prompt exists (\`tests/chain_model_output.rs\`), so
  there is no manifest to put in a row.
- **Receipts are not authenticated.** A gate receipt is unsigned, and nothing in this matrix shows
  that a receipt came from a gate.
- **Other surfaces.** Manifest and signature tamper (\`verify-manifest\`), witness-chain tamper, the
  gate and \`send\` are not in this matrix.
- **Other payloads.** Each row is what this binary did with one fabricated payload at the revision
  that generated this file. It is not evidence about payloads outside the list.

## Regenerate

\`\`\`sh
tests/e2e_tamper_matrix.sh
\`\`\`

Needs \`jq\`. The script builds the release binary unless \`AIRLOCK_BIN\` names one, logs every
command, exit code, claim and finding set, and writes this file only if every row matches
\`fixtures/tamper_matrix.json\`. \`tests/tamper_matrix.rs\` runs the same matrix from Rust.
EOF
} > "$DOC"

log "wrote $DOC"
log "tamper-matrix: OK ($CELL_COUNT cells). Log: $LOG"
exit 0
