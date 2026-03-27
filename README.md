# airlock

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
cargo install --git https://github.com/cmdrvl/airlock --tag v0.1.1
```

### Verify

```bash
airlock --version
# airlock 0.1.1
```

## Quick Start

```bash
# 1. Assemble a prompt payload from telemetry inputs + policy
airlock assemble \
  --policy rules/tournament_baseline.yaml \
  --input strategy_space.json \
  --out prompt_payload.json \
  --provenance-out prompt_provenance.json

# 2. Verify the boundary after transport wrapping
airlock verify \
  --policy rules/tournament_baseline.yaml \
  --prompt prompt_payload.json \
  --provenance prompt_provenance.json \
  --request request.json \
  --out airlock_manifest.json

# 3. Explain the manifest in human-readable form
airlock explain --manifest airlock_manifest.json
```

Example output from `airlock explain`:

```text
AIRLOCK

Claim achieved: RAW_DOCUMENT_ABSENT
Boundary mode: ANNOTATED

Raw document artifacts: absent
Derived filing text: present

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
  --out <PATH>              # Output prompt_payload.json
  --provenance-out <PATH>   # Output prompt_provenance.json
  --boundary-mode <MODE>    # ANNOTATED (default) or TELEMETRY_ONLY
  --system-prompt <PATH>    # Optional system prompt file
  --no-witness              # Skip witness ledger recording
```

### `airlock verify`

Verify a prompt + request against policy and emit a manifest.

```bash
airlock verify \
  --policy <PATH>           # Boundary policy (YAML)
  --prompt <PATH>           # prompt_payload.json from assemble
  --provenance <PATH>       # prompt_provenance.json from assemble
  --request <PATH>          # Transport-wrapped request (JSON)
  --out <PATH>              # Output airlock_manifest.json
  --require-claim <LEVEL>   # Optional: fail if claim is below this level
  --no-witness              # Skip witness ledger recording
```

### `airlock explain`

Human-readable manifest rendering.

```bash
airlock explain --manifest <PATH>
```

### `airlock witness`

Query the spine-standard witness ledger.

```bash
airlock witness query [--tool T] [--since T] [--until T] [--outcome O] [--input-hash H] [--limit N] [--json]
airlock witness last [--json]
airlock witness count [--tool T] [--since T] [--until T] [--outcome O] [--input-hash H] [--json]
```

### Introspection Flags

```bash
airlock --describe   # Emit operator.json (machine-readable metadata)
airlock --schema     # Emit the manifest JSON Schema
airlock --version    # Emit version string
```

Flag precedence: `--describe` > `--schema` > `--version` > subcommand.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | `VERIFY_PASS` — achieved claim meets or exceeds requirement |
| `1`  | `VERIFY_PARTIAL` — achieved claim is below the required level |
| `2`  | `REFUSAL` — structured error (bad input, missing file, etc.) |

Refusals emit structured JSON to stdout with a `refusal.code` field
(`E_BAD_POLICY`, `E_MISSING_FILE`, `E_BAD_INPUT`, etc.).

## Proof-Carrying Prompt

This is the most important Airlock concept after the manifest itself.

Airlock emits three artifacts:

| Artifact | Purpose |
|----------|---------|
| `prompt_payload.json` | Deterministic model-facing content before transport wrapping |
| `prompt_provenance.json` | Source map: every prompt fragment traced to its upstream artifact, policy rule, and boundary class |
| `airlock_manifest.json` | Primary proof artifact: hashes, claim verdict, findings, blocked reasons, provenance summary |

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
```

## What Airlock Proves vs. What It Does Not

### Airlock proves

- what exact prompt and request bytes crossed the boundary
- what upstream artifacts influenced those bytes
- what claim level was achieved
- why stronger claims failed
- which exact prompt fragments were `TELEMETRY` vs `DERIVED_TEXT`

### Airlock does not prove

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

v0.1.1 is the current foundational release. Next:

1. Seal integration with `pack` for immutable manifest bundles
2. Register Airlock proofs in catalog
3. Multiple adapter support beyond OpenAI chat completions
4. Policy inheritance and composition
5. Witness ledger rotation and archival

The implementation-grade detail lives in
[docs/airlock_plan.md](./docs/airlock_plan.md).

## Source of Truth

- **Spec and roadmap:** [docs/airlock_plan.md](./docs/airlock_plan.md)
- **Agent guidance:** [AGENTS.md](./AGENTS.md)

If README and plan disagree, the plan wins.

## License

MIT
