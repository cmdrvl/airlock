# airlock

<div align="center">

[![CI](https://github.com/cmdrvl/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/cmdrvl/airlock/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/v/release/cmdrvl/airlock)](https://github.com/cmdrvl/airlock/releases)

**Prove what crossed the model boundary.**

*Airlock is under active construction. This README describes the product
contract and operator story the repo is being built toward.*

</div>

---

You can tell people "the model never saw the document."

Airlock exists so you can **prove it**.

Airlock is the `cmdrvl` spine tool for **boundary attestation on model
inputs**. If a model interaction happens, Airlock should be able to show:

- the exact prompt payload that crossed
- the exact request payload that crossed
- the exact upstream artifacts that influenced it
- the exact claim level earned
- the exact prompt provenance map showing why each exposed fragment was admitted

That changes the conversation from:

- "trust us, the document never went into the model"

to:

- "inspect the manifest for the exact request that crossed the boundary"

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
- **Proof-carrying prompts**: Airlock does not just emit a prompt. It should
  emit `prompt_provenance.json`, a source map for the model boundary.
- **Honest trust ceilings**: `RAW_DOCUMENT_ABSENT` and
  `STRICT_TELEMETRY_ONLY` are different claims and are not collapsed.
- **Thin adapter boundary**: model-vendor request formatting stays at the edge.
  The proof substrate stays vendor-neutral.
- **Native spine integration**: Airlock artifacts are designed to flow into
  `vacuum -> hash -> lock -> pack -> catalog`, not replace that chain.

## Quick Example (Target v0)

Planned flow:

```bash
airlock assemble \
  --policy airlock_policy.yaml \
  --input strategy_space.json \
  --out prompt_payload.json \
  --provenance-out prompt_provenance.json

airlock verify \
  --policy airlock_policy.yaml \
  --prompt prompt_payload.json \
  --provenance prompt_provenance.json \
  --request request.json \
  --out airlock_manifest.json

airlock explain --manifest airlock_manifest.json
```

Planned human interpretation:

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
```

That is the point of the tool. Not just "the request looked okay," but "here is
the exact claim, the exact blocker, and the exact provenance of what crossed."

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

Boundary mode means:

**when Airlock assembles the prompt, how much filing-derived prose is allowed to
cross the boundary?**

Airlock supports two explicit boundary modes.

### `ANNOTATED`

Structured telemetry plus bounded derived prose.

This is the honest mode when natural-language structural observations still
carry real signal. Claim ceiling: `RAW_DOCUMENT_ABSENT`.

### `TELEMETRY_ONLY`

Structured telemetry only. No filing-derived prose crosses.

This is the stronger trust contract. Claim ceiling:
`STRICT_TELEMETRY_ONLY`.

Boundary mode is not a quality judgment. It is a declared exposure contract.

## Proof-Carrying Prompt

This is the most important Airlock concept after the manifest itself.

Airlock should emit:

- `prompt_payload.json`
- `prompt_provenance.json`
- `airlock_manifest.json`

`prompt_provenance.json` is a deterministic source map for the prompt boundary.
For each emitted prompt field or fragment, it should record:

- where in the prompt it landed
- which upstream artifact produced it
- which source path it came from
- which policy rule admitted it
- which boundary class it belongs to

That gives you something different from `lock` and `pack`.

- `lock` / `pack`: provenance of truth
- `prompt_provenance.json`: provenance of exposure

If an auditor asks "what did the model actually see?", the answer should be in
Airlock artifacts, not in operator memory.

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

Use Airlock when the question is:

**Can we mechanically prove what the model saw, and what it did not see?**

## First Reference Application

The first serious reference workflow for Airlock is the BDC Schedule of
Investments tournament.

That is the right starting point because the tournament already has:

- deterministic harnesses
- frozen gold sets
- zero-regression evaluation
- sealed evidence patterns
- real model-boundary sensitivity

Airlock should start where the trust question is already real.

## Current Repository Status

This repository is currently **spec-first**.

What exists today:

- the implementation-grade plan in [docs/airlock_plan.md](./docs/airlock_plan.md)
- the product and operator framing in this README
- the repo-specific agent guidance in [AGENTS.md](./AGENTS.md)

What is still being built:

- the Rust CLI
- schemas
- fixtures and examples
- CI and release automation
- witness query/runtime implementation

Read this README as the operator-facing contract for the tool being built, not
as a claim that every command below is already released.

## Target CLI Surface (Planned v0)

```bash
airlock assemble \
  --policy airlock_policy.yaml \
  --input strategy_space.json \
  --input heuristic.json \
  --out prompt_payload.json \
  --provenance-out prompt_provenance.json

airlock verify \
  --policy airlock_policy.yaml \
  --prompt prompt_payload.json \
  --provenance prompt_provenance.json \
  --request request.json \
  --out airlock_manifest.json \
  --require-claim RAW_DOCUMENT_ABSENT

airlock explain --manifest airlock_manifest.json

airlock witness query [--json]
airlock witness last [--json]
airlock witness count [--json]
```

Planned common flags:

- `--describe`
- `--schema`
- `--version`
- `--no-witness`

## Planned Artifacts

### `prompt_payload.json`

The deterministic model-facing content before vendor-specific transport wrapping.

### `prompt_provenance.json`

The proof-carrying prompt source map. This should explain why every emitted
fragment exists.

### `airlock_manifest.json`

The primary proof artifact. This should include hashes, claim verdicts,
findings, blocked reasons, upstream artifact inventory, and references to both
the request payload and prompt provenance.

### `airlock_policy.yaml`

The inspectable boundary policy: allow rules, deny rules, derived-text rules,
claim levels, and related settings.

## The Honest Current Public Claim

For the tournament reference workflow, the first credible public statement is
not "telemetry only" unless the manifest actually earns it.

The honest baseline is:

- the model did not receive the raw filing
- the exact request can be inspected
- the current request may still contain derived structural text in
  `ANNOTATED` mode

That is stronger than verbal assurance and weaker than the strongest possible
claim, which is exactly why it is credible.

## What Airlock Is Not

Airlock is not:

- a parser framework
- a benchmark engine
- a model-output scorer
- a replacement for `vacuum`, `hash`, `lock`, or `pack`
- a shell safety tool
- an RL training system

Airlock may eventually become a powerful substrate for downstream learning and
policy optimization, but the first job is to be a trustworthy proof primitive.

## Roadmap

High-level sequence:

1. surface the tournament proof artifacts honestly
2. rewrite the logic as a standalone Rust spine tool
3. add explainability and sealing integration
4. register Airlock proofs in catalog
5. harden dual boundary modes
6. expand to multiple model environments

The implementation-grade detail for that roadmap lives in
[docs/airlock_plan.md](./docs/airlock_plan.md).

## Source of Truth

- **Spec and roadmap:** [docs/airlock_plan.md](./docs/airlock_plan.md)
- **Agent guidance:** [AGENTS.md](./AGENTS.md)

If README and plan disagree, the plan wins.

## License

MIT
