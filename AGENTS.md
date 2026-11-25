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

The repository is currently a **foundational implemented Rust CLI** with
spec-backed fixtures and tests.

At the moment:

- [docs/airlock_plan.md](./docs/airlock_plan.md) is the implementation-grade spec
- [README.md](./README.md) is the operator-facing contract and vision
- the Rust CLI implements the core assemble / verify / explain / witness /
  doctor surfaces for the v0 boundary proof contract

Implications for new work:

- do not invent architecture beyond the plan
- keep released behavior, README, and plan aligned
- keep docs honest about what is planned vs. landed
- preserve the repo's standalone spine-tool shape

---

## Quick Reference

Docs-only verification:

```bash
git diff --check
ubs --diff
```

For Rust changes, run the targeted test for the changed behavior and these checks:

```bash
cargo fmt --check
cargo test --locked --test <integration_test>
cargo test --locked <test_filter>
ubs <changed-files>
```

CI also runs `cargo clippy --locked --all-targets -- -D warnings`,
`ast-grep scan`, the full `cargo test --locked` suite, and
`cargo build --locked --release`. Do not run the full suite for each bead;
run it only when the user or orchestrator asks. Before a Cargo build or test,
check for another active compile with:

```bash
ps -Ao pid,etime,state,command | rg '[c]argo (test|build|check|clippy)'
```

Wait for it to finish. Never run `cargo clean` in this shared workspace.

Planned operator surface:

```bash
airlock assemble --policy airlock_policy.yaml --input strategy_space.json --out prompt_payload.json --provenance-out prompt_provenance.json
airlock verify --policy airlock_policy.yaml --prompt prompt_payload.json --provenance prompt_provenance.json --request request.json --out airlock_manifest.json
airlock explain --manifest airlock_manifest.json [--json]
airlock witness <query|last|count> [--json]
airlock --robot-triage
airlock capabilities --json
airlock robot-docs guide
airlock --describe
airlock --schema
airlock --version
```

---

## Source of Truth

- **Spec:** [docs/airlock_plan.md](./docs/airlock_plan.md)
- **Operator framing:** [README.md](./README.md)
- **Harness notes:** [CLAUDE.md](./CLAUDE.md), [GEMINI.md](./GEMINI.md),
  [CODEX.md](./CODEX.md)

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
- `airlock explain --manifest <MANIFEST> [--json]`
- `airlock witness <query|last|count> [--json]`
- `airlock --robot-triage`
- `airlock capabilities --json`
- `airlock robot-docs guide`
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
- `explain --json` emits deterministic machine-readable manifest summaries
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
- ledger path from `EPISTEMIC_WITNESS` or `~/.cmdrvl/state/witness/witness.jsonl`
- copy-only first-run migration from `~/.epistemic/witness.jsonl` or
  `.epistemic/witness.jsonl`; never delete legacy ledgers or record contents in
  migration notices
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

CI accumulates these coverage requirements across the project. For one code
change, run only the specific test file or filter that covers the change; do
not run the full suite per bead.

Once implementation begins, treat these as required coverage:

- CLI precedence tests for `--describe`, `--schema`, and `--version`
- agent-discovery tests for `--robot-triage`, `capabilities --json`,
  `robot-docs guide`, and `explain --json`
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

---

## Safety Rules

### RULE 0 — User instructions take precedence

Follow the user's explicit request when it conflicts with defaults in this
file. If a requirement cannot be followed safely or is blocked by a dependency,
report the specific blocker and continue with independent ready work.

### RULE 1 — Never delete a file without explicit user authorization

Do not remove or overwrite user or agent work. Inspect `git status --short` and
`git diff --stat` before editing. Treat unexpected dirty files as another
agent's work: leave them untouched and do not stop to ask about them.

Irreversible actions require a deliberate protocol:

1. Identify the exact paths and effects before acting.
2. Check for a reversible alternative and prefer it.
3. Never infer authorization to delete, reset, clean, or discard work.
4. Ask the user only when the requested outcome actually requires an
   irreversible action and authorization is not already explicit.
5. Record the authorized action and result in the relevant bead or handoff.

Never run `git reset --hard`, `git clean`, `git stash`, `git checkout --`, or
`git restore` on shared work. Never amend commits, force-push, or create a
worktree for this workflow. Do not use bulk scripts to rewrite documentation;
make focused patches and inspect the resulting diff.

### File ownership and repository boundaries

- Keep Airlock a standalone Rust spine tool. The plan is the behavior source of
  truth; README and code describe what has landed.
- Change only the files required by the bead. Do not add placeholder files,
  compatibility shims, or parallel guidance documents that duplicate
  `AGENTS.md`.
- Do not move parser, benchmark, downstream decision, evidence-sealing, or
  shell-guard behavior into Airlock. See the ownership list above.
- Do not add `unsafe` code. The current Rust source contains no unsafe blocks;
  the illustrative entry point in the plan is not a compiler-enforced lint.

## Rust Toolchain and CI

- Package: `airlock` 0.3.0, Rust edition 2024, MSRV 1.85. CI installs stable
  Rust with `rustfmt` and `clippy`; runtime dependency versions are exact-pinned
  in `Cargo.toml`, and `Cargo.lock` records resolved versions including dev
  dependencies.
- `clap` defines the CLI, `serde` / `serde_json` / `serde_yaml` handle typed
  artifacts and policies, `blake3` hashes provenance, `regex` scans policy
  patterns, and `chrono` timestamps manifests and witness receipts.
- Release builds use size optimization, LTO, one codegen unit, abort-on-panic,
  and symbol stripping as configured in `Cargo.toml`.

| Goal | Command | Use |
|------|---------|-----|
| Format check | `cargo fmt --check` | Every Rust change |
| One integration test | `cargo test --locked --test <test_file>` | Focused behavior coverage |
| One test/filter | `cargo test --locked <filter>` | Focused unit or integration coverage |
| Clippy | `cargo clippy --locked --all-targets -- -D warnings` | CI gate or when requested |
| Local binary | `cargo build --locked --bin airlock` | Verify the CLI builds |
| Full suite | `cargo test --locked` | CI or explicit request only |
| Release binary | `cargo build --locked --release` | Matches the CI release build |
| Static rules | `ast-grep scan` | CI static analysis |

CI runs on pushes to `main` and pull requests. Its blocking Rust job checks
formatting, Clippy, AST rules, all tests, and a release build. Tagged releases
build Linux, macOS, and Windows targets, package the binary with README and
LICENSE, generate SHA256 sums, sign them, emit an SPDX SBOM, and update the
Homebrew tap when its token is configured. Targets are
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`, and
`x86_64-pc-windows-msvc`. There is no coverage threshold in the current
workflow. If a local CI command fails, read the first compiler or lint
diagnostic, reproduce with that same command, and check active Cargo processes
before retrying.

## Beads and Agent Mail

Use one bead as the unit of work:

1. Read the repo instructions, then run `git status --short` and
   `git diff --stat`. Preserve existing work.
2. Pick from `br ready --limit 0` (never use bare `br ready`), claim with
   `br update <id> --status in_progress --assignee <agent>`, and read the full
   acceptance criteria with `br show <id>` before editing. Reclaim an assigned
   bead only when it is explicitly in your assignment and its agent is dead.
3. Register once per session with Agent Mail `macro_start_session`, using this
   repository's absolute path as the project. Set your contact policy to
   `open` once for yourself.
4. Reserve every exact file path before editing it, with an exclusive lease
   and a reasonable TTL. Do not reserve directories or broad globs. Release
   the paths when editing is complete.
5. Use the bead ID as Agent Mail `thread_id` and begin subjects with
   `[<bead-id>]`. Send relevant progress and handoff notes to the owner or
   orchestrator. If Agent Mail is unavailable, use
   `ntm lock <session> <exact-path> --ttl 2h` and record coordination in bead
   comments.
6. Run `br dep cycles` after bead metadata is synced; the output must report
   no dependency cycles.

Useful Beads commands:

```bash
br ready --limit 0
br show <id>
br update <id> --status in_progress --assignee <agent>
br comments add <id> "<evidence: command, result, commit sha, remaining work>"
br dep cycles
```

Do not close beads. The orchestrator verifies acceptance and closes them. If a
bead is blocked, notify its owner or orchestrator once, comment on the blocker,
and move to the next ready bead. Do not wait idle for dependencies.

## Search and Agent Tools

- Use `rg` / `rg --files` for exact text and file inventory, for example
  `rg -n "policy_hash" src tests` or `rg --files -g '*.yaml' fixtures`.
- Use `ast-grep` for Rust syntax patterns or structural edits, for example
  `ast-grep run --lang Rust --pattern '$X.unwrap()' src/`. Review every match
  before changing it. Use `ast-grep scan` for the same static rules CI runs.
- Run `ubs <changed-files>` before every commit. Fix critical findings; review
  warnings in context instead of mechanically changing unrelated code. For a
  docs-only diff, run `ubs --diff`; it may report no supported language and no
  scanner. Record that limitation and use `git diff --check` for whitespace.
- Use `cass search "<topic>" --workspace "$PWD" --limit 10 --json` to search
  prior agent sessions. Use the `cass-memory` skill's
  `cm context "<task>" --json` when available. Treat both as historical
  context and verify decisions against current code,
  `docs/airlock_plan.md`, and the active bead.
- Use `bv --robot-triage --format json` or `bv --robot-next --format json` for
  dependency-aware suggestions. These are triage aids; confirm claimability
  with `br ready --limit 0` and `br show <id>` before claiming work.

## Landing the Plane

Work is not complete until the bead evidence is recorded and the commit is
pushed.

1. Finish the acceptance criteria or document exactly what remains and why.
2. Run the targeted test only for code changes, plus `cargo fmt --check` and
   `ubs <changed-files>`. For docs-only changes run `git diff --check` and
   `ubs --diff`; report when UBS has no Markdown scanner.
3. Review `git diff --check`, `git status --short`, and the exact file list.
   Never stage all files; another pane's changes are not yours.
4. Stage only your paths with `git add <paths>` and commit with an explicit
   pathspec: `git commit -m "<message>" -- <paths>`. The Beads hook may stage
   `.beads/issues.jsonl`; that metadata is expected.
5. Run `git pull --no-rebase`, then `git push`. Do not amend or force-push.
6. Add a `br comments add` entry with exact test/check commands, results,
   commit SHA, and remaining work. Send the orchestrator a matching Agent Mail
   handoff, then release your reservations.
7. Verify `git status --short` and `git status -sb`. Leave other agents'
   changes untouched. Move to the next ready bead unless the orchestrator has
   explicitly ended the assignment.

Keep this file aligned with `Cargo.toml`, `.github/workflows/ci.yml`,
`.github/workflows/release.yml`, the CLI, and `docs/airlock_plan.md` whenever
those contracts change.
