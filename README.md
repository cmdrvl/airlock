# airlock

![airlock: model boundary attestation. A painterly dashboard with a literal two-door airlock: LOCAL SIDE on the left holding four derived artifacts (schema_summary.json, shape_report.v0.json, rvl_report.v0.json, canon_mapping.v0.json) plus six raw files marked LOCAL ONLY, and MODEL SIDE on the right showing the model endpoint, tokens crossed, and request id. The chamber between the doors records the manifest assembly with bytes, prompt text length, endpoint, and timestamp. A what-crossed and what-did-NOT-cross split panel sits to the right. A customs declaration form on the desk lists every artifact that crossed with operator signature and a DECLARED rubber stamp.](docs/images/airlock.webp)

> *You can tell people the model never saw the document. Airlock lets you prove it.*

<div align="center">

[![CI](https://github.com/cmdrvl/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/cmdrvl/airlock/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/v/release/cmdrvl/airlock)](https://github.com/cmdrvl/airlock/releases)

**Prove what crossed the model boundary.**

</div>

---

You can tell people "the model never saw the document."

Airlock exists so you can **prove it**.

Airlock is the `cmdrvl` spine tool for **boundary attestation on model
inputs**. Every model interaction produces a manifest showing:

- the exact prompt payload that crossed
- the exact request payload that crossed
- the exact upstream artifacts that influenced it
- the exact claim level earned
- the exact prompt provenance map showing why each exposed fragment was admitted

That changes the conversation from:

- "trust us, the document never went into the model"

to:

- "inspect the manifest for the exact request that crossed the boundary"

## Install

### Homebrew (Recommended)

```bash
brew tap cmdrvl/tap
brew install cmdrvl/tap/airlock
```

### From Source

```bash
cargo install --git https://github.com/cmdrvl/airlock --tag v0.3.0
```

### Verify

```bash
airlock --version
# airlock 0.3.0
```

## Quick Start

```bash
# 0. Once per machine: create the Ed25519 key that `verify` signs manifests with
airlock keygen

# 1. Assemble a prompt payload from telemetry inputs + policy
airlock assemble \
  --policy rules/tournament_baseline.yaml \
  --input strategy_space.json \
  --out prompt_payload.json \
  --provenance-out prompt_provenance.json \
  --not-crossed-out not_crossed.json

# 2. Verify the boundary after transport wrapping (signs the manifest)
airlock verify \
  --policy rules/tournament_baseline.yaml \
  --prompt prompt_payload.json \
  --provenance prompt_provenance.json \
  --request request.json \
  --not-crossed not_crossed.json \
  --out airlock_manifest.json

# 3. Explain the manifest in human-readable form
airlock explain --manifest airlock_manifest.json

# 4. Check the manifest's signature against the public key
airlock verify-manifest airlock_manifest.json
```

`verify` signs by default and refuses to run without a usable key, so step 0 is
needed unless you pass `--no-sign` (for CI, which has no key) to get an unsigned
manifest. Step 4 and the `--not-crossed-out` / `--not-crossed` pair are optional.

### Egress gate

`airlock gate` exposes a loopback HTTP proxy for SDK driven conversations. Select
one of its two explicit evidence contracts:

```bash
# Screen each JSON turn against policy and detector packs.
airlock gate --mode policy-proxy \
  --policy rules/tournament_baseline.yaml \
  --transport provider.json \
  --upstream https://api.openai.com \
  --protected-bloom protected-corpus.bdbl

# Forward only request bodies whose canonical JSON hash appears in a bound verified manifest.
airlock gate --mode strict-manifest \
  --manifest-dir ./verified-manifests \
  --upstream https://api.openai.com
```

The listener binds to loopback only. Policy-proxy mode uses the pinned shared
`boundary-detectors` packs, policy denylists, and an optional opaque BDBL v1
shingle filter from veil. Invalid, oversized, or unreadable Bloom files prevent
startup; forbidden-policy, detector, and protected Bloom matches block the
turn with HTTP 403 and a redacted gate receipt. Base64 media and remote image or
document references are denied unless the policy explicitly sets
`allow_multimodal: true`. The optional
`protected_bloom_min_hits` policy field defaults to 8.
Policy regexes also run against bounded base64 and hex decode candidates;
detector packs recursively decode and rescan within their configured limits.
Generic detector packs are opt-in through the policy's `detectors` list. A
`detectors_warn_only` pack still records redacted findings with its JSON pointer
and matched-span hash in the gate receipt, then permits the request to continue;
other findings remain blocking.

Strict-manifest mode only accepts manifests with `binding_status: BOUND` and a
supported achieved claim. The gate parses each request as JSON and hashes its canonical representation.
After screening or a manifest match, it forwards those canonical JSON bytes so
the upstream receives the content Airlock checked.

A strict-manifest request the gate will not forward (no matching manifest, a
manifest below `--require-claim`, an unreadable, malformed or oversized body, an
invalid target) is refused with HTTP 403 and code `E_GATE_DENIED`; policy-proxy
refusals keep `BOUNDARY_FAILED`. `--require-claim RAW_DOCUMENT_ABSENT|STRICT_TELEMETRY_ONLY`
sets the lowest claim a matching manifest may carry (strict-manifest only).
`--max-request-bytes` caps the request body: 32 MiB by default in strict-manifest
mode, and policy-proxy mode keeps its 4 MiB scan limit and refuses a larger value.
A tripped size cap or upstream timeout is recorded in the receipt's `limit`.
`GET /airlock/health` answers 200 with the mode and what the gate enforces, and
writes no receipt. See `docs/deploy/egress-firewall.md` for running the gate as
the only route to a provider.

The optional `--transport` declaration pins a provider adapter, or supplies
the JSON pointers required by `generic_json`. Without it, the gate selects a
provider adapter from each request's shape and refuses conflicting
provider-specific shapes.

Allowed responses stream through the proxy while Airlock hashes the bytes. Gate
receipts are written under `airlock-gate/` by default, and witness records
include the gate mode, claim, request/response hashes, and request/response
byte counts. Authorization and provider key headers are forwarded but never
included in receipts or witness records. Set `--no-witness` to opt out of the
local ledger. `airlock explain --manifest <receipt>` describes a gate receipt.

### Doctor

```bash
airlock doctor [--json]
airlock doctor capabilities --json
airlock doctor triage --json
airlock doctor robot-docs
airlock capabilities --json
airlock robot-docs guide
```

The doctor surface is read-only. It does not read policy, prompt, provenance,
request, or manifest files; it does not open or append witness ledgers; and it
does not expose `doctor --fix`.

Every JSON doctor report is a `cmdrvl.doctor.v1` document (`schema_version`,
`mode`, `tool`, `tool_version`, `healthy`, `findings[]`). `doctor --json` is mode
`health`; `doctor capabilities --json` is mode `capabilities` and carries the
`operator.v1` contract in `contract`; `doctor triage --json` is mode `triage` and
carries `next_actions`. `healthy` is false exactly when a finding has severity
`error`. Exit `0` is healthy, `1` is unhealthy, `2` is a usage error only.

`airlock capabilities --json` emits the `operator.v1` contract, byte-identical to
`airlock --describe`. `airlock robot-docs guide` prints the compact agent
reference. `doctor health`, `doctor --robot-triage` and `airlock --robot-triage`
remain as deprecated aliases (`--robot-triage` is `doctor triage --json`).

The pre-v1 doctor `schema` id is superseded by `schema_version`, and the old
string-valued `contract` field is now `read_only_contract` (`contract` carries the
`operator.v1` document in capabilities mode). The other detail fields (`ok`,
`status`, `read_only`, `witness`, `config_footprint`, `side_effects`, `fixers`,
`checks`) are unchanged.

### Configuration Footprint

Airlock has no durable config file, cache, or lock. It manages two paths under
your home directory: the shared spine witness ledger
`~/.cmdrvl/state/witness/witness.jsonl`, and the manifest signing key pair in
`~/.cmdrvl/secrets/airlock/` (`ed25519.key`, mode 0600, and `ed25519.pub`).
`airlock keygen` is the only command that creates the secrets directory, and it
never overwrites a key. `doctor` lists the directory under
`config_footprint.managed_secret_paths` without opening it. On Unix, Airlock
refuses to use a signing key that group or others can read.

`EPISTEMIC_WITNESS` remains an explicit operator override. When the override is
not set, first use copies a legacy `~/.epistemic/witness.jsonl` or
`.epistemic/witness.jsonl` ledger into the canonical path, leaves the legacy file
in place, and records path-only migration/deprecation events under
`~/.cmdrvl/migrations/applied.jsonl` and
`~/.cmdrvl/notices/deprecated-paths.jsonl`.

Example output from `airlock explain`:

```text
AIRLOCK

Claim achieved: RAW_DOCUMENT_ABSENT
Boundary mode: ANNOTATED

Raw document artifacts: absent
Derived filing text: present

Bytes crossed: 18204
Attestation: self_attested (written by airlock verify, not by a send or gate receipt)
Signature: ed25519 by blake3:9f8e7d... (explain does not check it; run airlock verify-manifest)
Left out of the request: 2 fields (values are never stored):
  - html_path [FORBIDDEN_KEY] blake3:9451fd...
  - operator_note [NOT_ALLOWED] blake3:e492e0...

Why strict telemetry-only was not earned:
  - mutator_context.challenge_observation
  - mutator_context.challenge_profile.layout_notes[0]

Prompt provenance:
  - 27 prompt fragments emitted
  - 25 TELEMETRY
  - 2 DERIVED_TEXT

Policy: tournament_baseline (blake3:a1b2c3...)
Manifest hash: blake3:d4e5f6...
```

That is the point of the tool. Not just "the request looked okay," but "here is
the exact claim, the exact blocker, and the exact provenance of what crossed."

## Why Airlock Exists

Teams already know how to describe clean-room boundaries verbally:

- "the filing never goes into the model"
- "the model only sees metadata"
- "we keep the sensitive content outside the AI system"

Those are policy claims.

Airlock turns them into **mechanical claims with replayable proof artifacts**.

It does not score model outputs. It does not benchmark parser quality. It does
not seal evidence packs. It proves one narrow, high-value thing:

**what the model was exposed to, and what it was not exposed to.**

## The Core Idea

Airlock sits at the seam between deterministic evidence and model execution:

```text
document zone
  -> deterministic extraction / routing / benchmark / verify / assess
  -> bounded telemetry artifacts
  -> airlock assemble
  -> airlock verify
  -> model request / model response
  -> downstream evaluation / sealing / catalog
```

Upstream tooling can see the document.

Airlock proves what is allowed to cross into the model zone.

## What Makes Airlock Different

- **Inspectable boundary claims**: not generic "safe" or "unsafe", but explicit
  claim levels with deterministic verdicts.
- **Proof-carrying prompts**: Airlock emits `prompt_provenance.json`, a source
  map for the model boundary. Every prompt fragment has provenance.
- **Honest trust ceilings**: `RAW_DOCUMENT_ABSENT` and
  `STRICT_TELEMETRY_ONLY` are different claims and are not collapsed.
- **Thin adapter boundary**: model-vendor request formatting stays at the edge.
  The proof substrate stays vendor-neutral.
- **Native spine integration**: Airlock artifacts flow into
  `vacuum -> hash -> lock -> pack -> catalog`, not replace that chain.
- **Deterministic by design**: same inputs always produce the same prompt
  payload hash, the same provenance, and the same manifest.

## The Three Claim Levels

Airlock uses a strict claim hierarchy:

```text
BOUNDARY_FAILED < RAW_DOCUMENT_ABSENT < STRICT_TELEMETRY_ONLY
```

### `BOUNDARY_FAILED`

Forbidden material was detected in the request boundary. Airlock still emits a
manifest. The manifest is the record of failure.

### `RAW_DOCUMENT_ABSENT`

The model did not receive raw filing HTML, PDF paths, page images, SEC archive
URLs, section HTML, or row-level extracts.

### `STRICT_TELEMETRY_ONLY`

The stronger claim: the model saw only structured telemetry, with no
filing-derived descriptive prose crossing the boundary.

## Boundary Modes

Boundary mode declares how much filing-derived prose is allowed to cross the
boundary during prompt assembly.

### `ANNOTATED`

Structured telemetry plus bounded derived prose. This is the honest mode when
natural-language structural observations still carry real signal. Claim ceiling:
`RAW_DOCUMENT_ABSENT`.

### `TELEMETRY_ONLY`

Structured telemetry only. No filing-derived prose crosses. This is the
stronger trust contract. Claim ceiling: `STRICT_TELEMETRY_ONLY`.

Boundary mode is not a quality judgment. It is a declared exposure contract.

## CLI Reference

### `airlock assemble`

Deterministic prompt assembly from policy + inputs.

```bash
airlock assemble \
  --policy <PATH>           # Boundary policy (YAML)
  --input <PATH>...         # Input artifacts (JSON, one or more)
  --out <PATH>              # Output prompt_payload.json (alias: --output)
  --provenance-out <PATH>   # Output prompt_provenance.json
  --boundary-mode <MODE>    # ANNOTATED (default) or TELEMETRY_ONLY
  --system-prompt <PATH>    # Optional system prompt file
  --not-crossed-out <PATH>  # Optional: write the inventory of input fields that did not cross
  --no-witness              # Skip witness ledger recording
```

`--not-crossed-out` writes an `airlock.not_crossed.v1` file listing every input
field that did not reach the prompt: its path, the hash of the input artifact it
came from, the hash of its value, and why it stayed behind. The values themselves
are never written. Pass the file to `verify --not-crossed`.

### `airlock verify`

Verify a prompt + request against policy and emit a manifest.

```bash
airlock verify \
  --policy <PATH>           # Boundary policy (YAML)
  --prompt <PATH>           # prompt_payload.json from assemble
  --provenance <PATH>       # prompt_provenance.json from assemble
  --request <PATH>          # Transport-wrapped request (JSON)
  --out <PATH>              # Output airlock_manifest.json (alias: --output)
  --require-claim <LEVEL>   # Optional: fail if claim is below this level
  --not-crossed <PATH>      # Optional: not_crossed.json from assemble --not-crossed-out
  --no-sign                 # Write the manifest without a signature (for CI without a key)
  --no-witness              # Skip witness ledger recording
```

Before deriving a claim, `verify` unwraps the transport request through its
adapter and compares every message, in order, with the assembled prompt. This
includes the system prompt. It also flags top-level request fields outside
the adapter's declared transport schema. The manifest records
`binding_status: BOUND` for an exact match. Any missing, appended, reordered,
or altered message, or undeclared transport field, produces a
`REQUEST_UNBOUND` finding, records `binding_status: UNBOUND`, and sets the
achieved claim to `BOUNDARY_FAILED`. The finding does not echo the altered
message content.

`verify` writes an `airlock.v0.3` manifest (see [Manifest versions](#manifest-versions)).
`--not-crossed` copies the entries of an inventory from `assemble --not-crossed-out`
into it. `verify` refuses (`E_BAD_PROVENANCE`) an inventory that belongs to a
different policy, prompt payload, or boundary mode, or that has a malformed entry.
Without `--not-crossed` the manifest records no inventory, which is not the same
as an empty one.

By default `verify` then signs the manifest with the key that `airlock keygen`
created. It loads that key before it reads any input, so with no usable key it
refuses (`E_BAD_INPUT`, `next_command: airlock keygen`) instead of quietly
writing an unsigned manifest. `--no-sign` writes the manifest without a signature.

### `airlock explain`

Manifest rendering as human-readable text or deterministic explanation JSON.

```bash
airlock explain --manifest <PATH> [--json]
```

`--json` emits `airlock.explain.v1`, including the achieved claim, boundary
mode, manifest hash, proof hashes, blocked paths, findings, provenance summary,
and next commands.

For an `airlock.v0.3` manifest, `explain` also shows `bytes_crossed`,
`attestation`, the signature's algorithm and signer fingerprint, and what was
left out of the request: path, reason and value hash per field, never a value.
A missing inventory reads "not recorded" and an empty one reads "nothing", because
they are different claims. `--json` adds `bytes_crossed`, `attestation`,
`not_crossed` and `signature`, with `null` for a member the manifest lacks
(`signature: null` is an unsigned manifest; `not_crossed: null` is a `verify` run
that was given no inventory; `[]` means nothing was left out). `signature.checked`
is always `false`: `explain` does not verify the signature, `verify-manifest` does,
and the signature bytes are not repeated. An `airlock.v0.2` manifest explains
exactly as it did before v0.3.

`--manifest` also accepts an `airlock.gate.v1` gate receipt. The output then says
what the gate did (denied, forwarded, forwarded with an incomplete response, or
authorized but not delivered), the request and response sizes and hashes, the
matched manifest, any limit that tripped, and why each finding was raised;
`--json` emits `airlock.explain_gate.v1`.

### `airlock keygen`

Create the Ed25519 key pair that `verify` signs manifests with.

```bash
airlock keygen
```

Writes `ed25519.key` (the secret seed, hex, mode 0600) and `ed25519.pub` under
`~/.cmdrvl/secrets/airlock/` and prints JSON with the public key, its fingerprint
(`blake3:` over the 32 raw public-key bytes) and both paths. The secret is never
printed. `keygen` refuses (`E_BAD_INPUT`) when either file already exists, because
it never overwrites a key, and when the home directory is not set. It records
nothing in the witness ledger.

### `airlock verify-manifest`

Check the signature on a manifest.

```bash
airlock verify-manifest <MANIFEST> [--pubkey <PATH>]
```

`--pubkey` defaults to `~/.cmdrvl/secrets/airlock/ed25519.pub`. A valid signature
exits `0` with `{"command":"verify-manifest","verified":true,...}` naming the
signer fingerprint. Anything else is a refusal (exit `2`): `E_BAD_MANIFEST` with
`detail.reason` one of `unsigned`, `signature_mismatch`, `fingerprint_mismatch`,
`unsupported_manifest_version`, `unsupported_algorithm`, `malformed_signature` or
`not_an_object`, or `E_MISSING_FILE` for a missing manifest or key.

The signature covers the RFC 8785 canonical JSON of the whole manifest with its
`signature` member removed, so changing any other member, including one this
version does not know about, fails it. The public key is not embedded in the
manifest. The `public_key_fingerprint` it records only lets a wrong key fail with
`fingerprint_mismatch` instead of `signature_mismatch`; it sits inside the
excluded member, so the signature, not the fingerprint, is what authenticates.
Verification uses the strict Ed25519 check, so a small-order public key cannot
forge a signature. An `airlock.v0.2` manifest has no signature and is refused as
`unsupported_manifest_version`.

Two limits to know. `verify-manifest` checks the parsed JSON, so a manifest with a
repeated object key is read as `serde_json` reads it (the last value wins) and is
not rejected. And `airlock gate` accepts `airlock.v0.2` and `airlock.v0.3`
manifests but does not check their signatures. `verify-manifest` records nothing
in the witness ledger.

### `airlock doctor`

Read-only health, capability, and robot triage checks for agents.

```bash
airlock doctor [--json]               # cmdrvl.doctor.v1, mode health
airlock doctor capabilities --json    # mode capabilities; `contract` = operator.v1
airlock doctor triage --json          # mode triage; `next_actions`
airlock doctor robot-docs
airlock capabilities --json           # operator.v1 contract, same as --describe
airlock robot-docs guide
```

Deprecated aliases: `airlock doctor health [--json]`, `airlock doctor
--robot-triage`, `airlock --robot-triage`.

### `airlock witness`

Query the spine-standard witness ledger.
By default this is `~/.cmdrvl/state/witness/witness.jsonl`; set
`EPISTEMIC_WITNESS` to use an explicit operator-supplied ledger path.

```bash
airlock witness query [--tool T] [--since T] [--until T] [--outcome O] [--input-hash H] [--limit N] [--json]
airlock witness last [--json]
airlock witness count [--tool T] [--since T] [--until T] [--outcome O] [--input-hash H] [--json]
```

### Introspection Flags

```bash
airlock --describe   # Emit operator.json (operator.v1 contract)
airlock --schema     # Emit the manifest JSON Schema
airlock --version    # Emit version string
airlock --robot-triage # Deprecated alias of `doctor triage --json`
```

Flag precedence: `--describe` > `--schema` > `--version` > subcommand.
`--robot-triage` is read-only and has no witness side effects.

`operator.json` conforms to the `spine-rules` `operator.v1` contract
(`schema_version`, `tool_version`, `commands`, `exit_codes`, `refusals`,
`env_vars`, `formats`, `side_effects`, `pipeline`). It is enforced in CI by
`tests/golden_rules.rs` (`golden_rules_suite!`) and `ast-grep scan`.

### Exit Codes

| Code | Domain | Meaning |
|------|--------|---------|
| `0`  | positive | `VERIFY_PASS` — achieved claim meets or exceeds requirement; also a healthy `doctor` |
| `1`  | negative | `VERIFY_PARTIAL` — achieved claim is below `--require-claim`; also an unhealthy `doctor`; also `witness query\|last\|count` with no matching records |
| `2`  | error | `REFUSAL` — structured error (bad input, missing file, etc.) or CLI usage error |

Refusals emit structured JSON to stdout with a `refusal.code` field
(`E_BAD_POLICY`, `E_MISSING_FILE`, `E_BAD_INPUT`, etc.).

### Environment

| Variable | Effect |
|----------|--------|
| `EPISTEMIC_WITNESS` | Override the witness ledger path (default `~/.cmdrvl/state/witness/witness.jsonl`) |
| `HOME` (or `USERPROFILE`) | Where the signing key pair lives, `~/.cmdrvl/secrets/airlock/`. `keygen`, `verify` and `verify-manifest` refuse when it is unset or empty; there is no relative-path fallback. |
| `SOURCE_DATE_EPOCH` | Unix seconds. Pins the `verify` manifest `timestamp`, so identical inputs produce a byte-identical manifest. A set but malformed value is an `E_BAD_INPUT` refusal (exit 2, `detail.env`/`value`/`expected`), never a silent fallback to the clock. Witness records keep the real wall clock. |
| `NO_COLOR`, `TERM=dumb` | Airlock does not colorize output. No surface emits an ANSI escape when piped, with or without these set, and `NO_COLOR` wins over `CLICOLOR_FORCE` (regression-tested). |

## Transport adapters

`verify --transport <PATH>` accepts an optional JSON declaration with an
explicit adapter name and adapter-specific configuration. Without a declaration,
Airlock detects the provider request shape. `generic_json` requires declared
JSON pointers for system content and messages.

| Adapter | System content | Message/content encoding | Required configuration |
|---|---|---|---|
| `openai_chat_completions` | `messages` entries with role `system` | `messages[].content`; structured content is deterministic compact JSON text | Request `model`; no declaration for detected requests |
| `openai_responses` | Top-level `instructions` | `input` with message roles and text/image content parts | Request `model`; no declaration for detected requests |
| `anthropic_messages` | Top-level `system` | `messages[].content` text and typed image/document/tool blocks | Request `model`; no declaration for detected requests |
| `gemini_generate_content` | `systemInstruction.parts[].text` | `contents[].parts[]` text, inline data, or file references | Model resource in the request; no declaration for detected requests |
| `generic_json` | Declared JSON pointer | Declared message-array pointer and content pointers | `--transport` declaration with `adapter: generic_json` and pointers |

An explicit `adapter` in the transport declaration takes precedence over
shape detection. Otherwise Airlock detects Gemini from top-level `contents`,
OpenAI Responses from `input`, and Anthropic from `messages` when Anthropic-only
fields such as `system` or `stop_sequences` are present. A `messages` request
with only fields shared by Chat Completions and Anthropic defaults to Chat
Completions; declare `anthropic_messages` when that shared shape is Anthropic.
Conflicting provider-specific shapes refuse instead of choosing one.

## Proof-Carrying Prompt

This is the most important Airlock concept after the manifest itself.

Airlock emits three artifacts:

| Artifact | Purpose |
|----------|---------|
| `prompt_payload.json` | Deterministic model-facing content before transport wrapping |
| `prompt_provenance.json` | Source map: every prompt fragment traced to its upstream artifact, policy rule, and boundary class |
| `airlock_manifest.json` | Primary proof artifact: hashes, claim verdict, findings, blocked reasons, provenance summary |

The OpenAI Chat Completions adapter represents structured user-message content
as a single text content part containing deterministic compact JSON. Its
`unwrap()` method restores the assembled messages from that wire form so request
binding can compare them with the original prompt.

`prompt_provenance.json` records, for each emitted prompt fragment:

- where in the prompt it landed
- which upstream artifact produced it
- which source path it came from
- which policy rule admitted it
- which boundary class it belongs to (`TELEMETRY` or `DERIVED_TEXT`)

This is the difference between Airlock and the rest of the spine:

- `lock` / `pack`: provenance of truth
- `prompt_provenance.json`: provenance of exposure

If an auditor asks "what did the model actually see?", the answer is in
Airlock artifacts, not in operator memory.

### Manifest versions

`airlock.v0.2` is the earlier manifest. `airlock.v0.3`, which `verify` now writes,
adds four members, none of which a v0.2 manifest may carry (the schema forbids
it). Existing v0.2 manifests stay valid and unchanged, and `airlock gate` reads
both versions.

| Member | Meaning |
|--------|---------|
| `bytes_crossed` | Length in bytes of the RFC 8785 canonical request JSON that `request_payload_hash` covers |
| `attestation` | `self_attested`: written by `airlock verify`. `transmitted` and `gated` are reserved for send and gate receipts and are not written yet |
| `not_crossed` | Only when `verify` was given `--not-crossed`: one entry per input field that did not cross, with `path`, `source_artifact_hash`, `value_hash` and `reason` (`NOT_ALLOWED`, `FORBIDDEN_KEY`, `DERIVED_TEXT_EXCLUDED` or `SHADOWED_BY_EARLIER_INPUT`) |
| `signature` | Absent under `--no-sign`. `{algorithm: "ed25519", public_key_fingerprint, value}` over the manifest without this member |

`value_hash` is `blake3` over the RFC 8785 canonical JSON of the value that stayed
behind (an integer beyond 2^53, which that form refuses, hashes as its exact
decimal digits). The value itself is never stored, so the inventory proves a field
was left out and lets someone who holds the value confirm it was that one. It
covers the inputs `assemble` was given; it says nothing about anything else that
might have been left out of the request.

## Policy

Airlock policies are inspectable YAML files that define the boundary contract.
See [`rules/tournament_baseline.yaml`](./rules/tournament_baseline.yaml) for a
complete example.

```yaml
policy_id: tournament_baseline
version: airlock.v0

allowed_keys:
  - key_path: family_id
    description: Filing family identifier
    boundary_class: TELEMETRY

forbidden_keys:
  - html_path
  - section_html
  - pdf_path

forbidden_patterns:
  - pattern: "<[a-z][^>]*>"
    description: Raw HTML markup
  - pattern: "sec\\.gov/Archives"
    description: SEC archive URLs

derived_text_paths:
  - mutator_context.challenge_observation
  - mutator_context.challenge_profile.layout_notes

claim_levels:
  - BOUNDARY_FAILED
  - RAW_DOCUMENT_ABSENT
  - STRICT_TELEMETRY_ONLY

# Optional. Omitted or empty disables generic detector packs.
# detectors: [secrets, pii, tabular, blobs, paths]
# Optional subset of detectors; hits are reported without lowering the claim.
# detectors_warn_only: [pii]
# Optional repeated-row threshold for the tabular pack; defaults to 5.
# tabular_min_rows: 5
```

Policies can also compose partial files with `extends: [path-or-id, ...]`.
References resolve relative to the declaring policy; scalar values come from
the child, while lists merge in stable order. Forbidden keys and patterns are
monotonic. Detector packs are opt-in and inherited by stable union. Enforced
detector hits lower the claim to `BOUNDARY_FAILED`; `detectors_warn_only` keeps
the hit in findings while preserving the claim. Findings include the detector
rule id, JSON path, and matched-span hash, never the sensitive value. The
resolved policy hash is independent of include order, and verify records each
source file hash in the manifest's upstream artifact inventory. `explain --json`
includes detector findings from the manifest.

## What Airlock Proves vs. What It Does Not

### Airlock proves

- what exact prompt and request bytes crossed the boundary
- what upstream artifacts influenced those bytes
- what claim level was achieved
- why stronger claims failed
- which exact prompt fragments were `TELEMETRY` vs `DERIVED_TEXT`
- how many bytes crossed (`bytes_crossed`, v0.3)
- which input fields stayed behind and why, by hash, when `verify` was given the inventory (v0.3)
- that a signed manifest has not changed since it was signed with a given key (`verify-manifest`)

### Airlock does not prove

- who holds the signing key, or that it was not copied: the key is local and
  self-issued, so a signature shows the manifest is unaltered since signing, not
  who signed it
- that a v0.3 manifest was witnessed by anything but `airlock verify`
  (`attestation: self_attested`); `airlock gate` does not check signatures
- that the source document is true
- that the parser extracted the right facts
- that the model response is correct
- that a downstream operator made a sound decision
- that shell execution is safe

Those are separate problems handled by other spine tools or by adjacent systems.

## Where Airlock Fits in `cmdrvl`

Airlock is a native spine primitive, not a generic wrapper around model APIs.

| If you need... | Use |
|----------------|-----|
| Enumerate artifacts in scope | [`vacuum`](https://github.com/cmdrvl/vacuum) |
| Compute exact content hashes | [`hash`](https://github.com/cmdrvl/hash) |
| Match artifacts to structural families | [`fingerprint`](https://github.com/cmdrvl/fingerprint) |
| Pin artifact identity and tool versions | [`lock`](https://github.com/cmdrvl/lock) |
| Seal evidence into an immutable bundle | [`pack`](https://github.com/cmdrvl/pack) |
| Score against frozen gold truth | [`benchmark`](https://github.com/cmdrvl/benchmark) |
| Make deterministic policy decisions over reports | [`assess`](https://github.com/cmdrvl/assess) |
| Prove what crossed the model boundary | `airlock` |

## First Reference Application

The first reference workflow is the BDC Schedule of Investments tournament.
That is the right starting point because the tournament already has
deterministic harnesses, frozen gold sets, zero-regression evaluation, sealed
evidence patterns, and real model-boundary sensitivity.

## Roadmap

v0.3.0 is the current foundational release. Next:

1. Seal integration with `pack` for immutable manifest bundles
2. Register Airlock proofs in catalog
3. Multiple adapter support beyond OpenAI chat completions
4. Witness ledger rotation and archival

The implementation-grade detail lives in
[docs/airlock_plan.md](./docs/airlock_plan.md).

## Source of Truth

- **Spec and roadmap:** [docs/airlock_plan.md](./docs/airlock_plan.md)
- **Agent guidance:** [AGENTS.md](./AGENTS.md)
- **Harness-specific notes:** [Claude Code](./CLAUDE.md), [Gemini CLI](./GEMINI.md),
  [Codex](./CODEX.md)

If README and plan disagree, the plan wins.

## License

MIT

---

*`airlock` is part of the open-source toolchain from the [CMD+RVL](https://cmdrvl.com) lineage and AI enablement practice. MIT-licensed. Contributions welcome from any practice or stack.*
