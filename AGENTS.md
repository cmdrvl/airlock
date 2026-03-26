# AGENTS.md — airlock

> Repo-specific guidance for AI coding agents working in `airlock`.

This file adds repo-local instructions on top of the shared `cmdrvl` workspace
rules. In the standalone `airlock` repo, treat this file and
[docs/airlock_plan.md](./docs/airlock_plan.md) as the local source of truth.

---

## airlock — What This Project Does

`airlock` is the epistemic spine's **boundary attestation primitive**.

It exists to prove what crossed the model boundary, what upstream artifacts
influenced that boundary crossing, and what claim level was actually earned.

Pipeline position:

```text
deterministic evidence -> airlock -> model execution -> downstream evaluation / sealing
```

What `airlock` owns:

- boundary policy loading and hashing
- deterministic prompt assembly
- prompt provenance (`prompt_provenance.json`)
- request verification against policy
- claim-level verdicts and blocked reasons
- boundary manifests and explain surface
- local witness receipt logging

What `airlock` does not own:

- document parsing or family routing
- extraction correctness scoring
- model-response scoring
- decision policy classification
- evidence sealing
- shell or execution guardrails
- RL training features in v0

Related tools:

- `fingerprint` selects parser families
- `benchmark` scores fact correctness
- `assess` classifies downstream action bands
- `lock` pins identity and provenance
- `pack` seals final evidence bundles

---

## Current Repository State

The repository is currently **spec-first and docs-heavy**.

At the moment:

- [docs/airlock_plan.md](./docs/airlock_plan.md) is the implementation-grade spec
- [README.md](./README.md) is the operator-facing contract and vision
- the Rust CLI is not yet fully implemented

Implications for new work:

- do not invent architecture beyond the plan
- do not imply released functionality that does not exist yet
- keep docs honest about what is planned vs. landed
- when implementation starts, preserve the repo's standalone spine-tool shape

---

## Quick Reference

Current docs-first verification:

```bash
git diff --check
ubs --diff
```

When Rust code lands, default quality gates become:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Planned operator surface:

```bash
airlock assemble --policy airlock_policy.yaml --input strategy_space.json --out prompt_payload.json --provenance-out prompt_provenance.json
airlock verify --policy airlock_policy.yaml --prompt prompt_payload.json --provenance prompt_provenance.json --request request.json --out airlock_manifest.json
airlock explain --manifest airlock_manifest.json
airlock witness <query|last|count> [--json]
airlock --describe
airlock --schema
airlock --version
```

---

## Source of Truth

- **Spec:** [docs/airlock_plan.md](./docs/airlock_plan.md)
- **Operator framing:** [README.md](./README.md)

If code, README, and plan disagree, the plan wins.

Do not introduce behavior because it "sounds useful" if the plan does not say
to do it. Extend the plan first or get explicit user direction.

---

## Planned File Map

Expected repo shape:

| Path | Purpose |
|------|---------|
| `Cargo.toml` | package metadata and pinned dependency versions |
| `operator.json` | compiled operator manifest emitted by `--describe` |
| `src/main.rs` | thin binary entrypoint only |
| `src/lib.rs` | top-level dispatch and command wiring |
| `src/cli/` | clap structs, exit-code model, command routing |
| `src/policy/` | policy parsing, schema types, hashing |
| `src/assembler/` | prompt assembly and prompt provenance emission |
| `src/scanner/` | boundary scanning and claim derivation |
| `src/manifest/` | manifest types and canonical JSON emission |
| `src/adapter/` | thin transport adapters only |
| `src/refusal/` | refusal envelopes and refusal codes |
| `src/witness/` | witness append and query surface |
| `src/output/` | schema/describe/version rendering and shared output helpers |
| `schemas/` | policy, manifest, and output schemas |
| `fixtures/` | good/bad payloads, requests, manifests, provenance examples |
| `tests/` | CLI, schema, determinism, witness, refusal, provenance coverage |
| `docs/airlock_plan.md` | implementation-grade spec |

Structural rules:

- `main.rs` stays thin
- policy parsing stays separate from scanning
- prompt assembly and prompt provenance evolve together
- adapters only map prompt payload into vendor request envelopes
- witness stays local and non-authoritative

---

## Output Contract (Critical)

Planned command family:

- `airlock assemble --policy <POLICY> --input <FILE>... --out <PROMPT> --provenance-out <PROVENANCE>`
- `airlock verify --policy <POLICY> --prompt <PROMPT> --provenance <PROVENANCE> --request <REQUEST> --out <MANIFEST> [--require-claim <LEVEL>]`
- `airlock explain --manifest <MANIFEST>`
- `airlock witness <query|last|count> [--json]`
- `airlock --describe`
- `airlock --schema`
- `airlock --version`

Domain outcomes:

| Exit | Outcome | Meaning |
|------|---------|---------|
| `0` | `VERIFY_PASS` | verification completed and caller requirement was met |
| `1` | `VERIFY_PARTIAL` | verification completed but achieved claim fell below caller requirement or boundary-mode ceiling |
| `2` | `REFUSAL` | Airlock could not proceed safely |

Critical output rules:

- `assemble` emits deterministic JSON artifacts only
- `verify` emits a manifest even for `BOUNDARY_FAILED`
- refusal envelopes are structured JSON on stdout for exit `2`
- witness query subcommands may support human output and `--json`
- stderr is for process diagnostics only

Do not replace refusal envelopes with ad hoc text.

---

## Core Invariants (Do Not Break)

### 1. Airlock proves the boundary, not the world

Airlock proves what crossed the model boundary.

It does not prove document truth, extraction quality, model correctness, or
business correctness.

### 2. No hidden inputs

Every semantic input that influenced the assembled prompt must be visible in the
manifest or in a referenced hashed artifact. That includes the system prompt.

### 3. Prompt provenance is first-class

`prompt_provenance.json` is not a debug extra.

Every emitted prompt field or message fragment must have provenance coverage:

- source artifact hash
- source path
- policy rule linkage
- boundary classification

No prompt bytes without provenance.

### 4. Boundary-mode honesty is mandatory

`ANNOTATED` and `TELEMETRY_ONLY` are different exposure contracts.

Do not imply `STRICT_TELEMETRY_ONLY` when derived prose still crosses.

### 5. Claim levels stay explicit

Do not collapse all outcomes into generic pass/fail language.

The tool must preserve the difference between:

- `BOUNDARY_FAILED`
- `RAW_DOCUMENT_ABSENT`
- `STRICT_TELEMETRY_ONLY`

### 6. Transport adapters stay thin

Adapters may reshape envelopes.

Adapters may not inject semantic content that lacks provenance coverage.

### 7. Witness stays local

`witness` is a local receipt log only.

Do not make witness portable evidence and do not let it outrank manifest,
lockfile, or pack artifacts.

### 8. Airlock is not the RL layer

Airlock may eventually produce excellent offline-learning data.

That is downstream value. Do not build RL-specific features into v0 unless the
user explicitly changes scope.

---

## Boundary Model

The two most important concepts in this repo are:

- **boundary mode**: how much filing-derived prose is allowed to cross during
  prompt assembly
- **prompt provenance**: why each exposed fragment exists

The mental model:

- `lock` / `pack`: provenance of truth
- `airlock`: provenance of exposure

Any code or docs change that weakens that distinction is suspect.

---

## Witness Rules

Airlock should follow the mature spine witness protocol:

- ambient recording on eligible commands by default
- `--no-witness` opt-out
- ledger path from `EPISTEMIC_WITNESS` or `~/.epistemic/witness.jsonl`
- append failures must not change domain exit semantics
- query subcommands: `query`, `last`, `count`

Expected v0 recording policy:

- record `assemble`
- record `verify`
- do not record metadata surfaces (`--describe`, `--schema`, `--version`)
- do not record witness queries
- `explain` may remain non-recording in v0

---

## Release and CI Expectations

Keep release posture aligned with the mature spine repos:

- `ci.yml`
- `release.yml`
- five-target build matrix:
  `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`,
  `x86_64-apple-darwin`,
  `aarch64-apple-darwin`,
  `x86_64-pc-windows-msvc`
- packaged archives containing binary + `README.md` + `LICENSE`
- `SHA256SUMS`
- signing / attestation
- SBOM artifact
- Homebrew tap update

Do not let docs and release automation drift apart.

---

## Testing Expectations

Once implementation begins, treat these as required:

- CLI precedence tests for `--describe`, `--schema`, and `--version`
- refusal path coverage
- witness append / `--no-witness` / query coverage
- witness failure preserves domain outcome
- deterministic assembly tests
- deterministic prompt provenance tests
- schema validation tests for payloads, manifests, provenance, and refusals
- golden fixtures for clean, degraded, and forbidden boundary cases

If code changes are substantive and tests cannot be run, say so explicitly.

---

## Work Guidance for Agents

- Keep the repo standalone. Do not turn this into a monorepo slice.
- Keep docs honest about current state. The repo is still transitioning from
  spec to implementation.
- When behavior changes, update `docs/airlock_plan.md` and `README.md`
  together.
- Preserve canonical JSON ordering and hash determinism.
- Prefer explicit schema-backed types over dynamic maps.
- Do not add execution guardrails, parser logic, benchmark scoring, or RL
  control logic here just because they feel adjacent.

When in doubt, choose the narrower primitive.

Airlock is valuable because it is precise.
