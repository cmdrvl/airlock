# airlock agent ergonomics pass 1 playbook

Mode: full.

Architecture summary:

- `src/main.rs` is intentionally thin and delegates to `airlock::run()`.
- `src/cli/mod.rs` owns clap parsing, subcommands, flags, and enum parsers.
- `src/lib.rs` handles global introspection precedence, parse-error hints, and command dispatch.
- `src/commands/assemble.rs` loads policy/input/system prompt files, emits canonical prompt/provenance JSON, and appends witness records.
- `src/commands/verify.rs` validates prompt/provenance/request consistency, runs the scanner, writes the manifest, and records witness outcomes.
- `src/commands/explain.rs` renders existing manifests without re-running verification.
- `src/commands/doctor.rs` owns read-only health, capabilities, robot docs, and robot triage.
- `src/witness.rs` and `src/paths.rs` implement the spine witness protocol and copy-only legacy path migration.

Applied recommendations:

1. `R-001`: bare `airlock` now succeeds with useful help and agent entrypoints.
2. `R-002`: `airlock --robot-triage` exposes a top-level read-only mega-command.
3. `R-003`: `airlock capabilities --json` exposes the machine command/config/side-effect contract.
4. `R-004`: `airlock robot-docs guide` exposes paste-ready in-tool agent docs.
5. `R-005`: `airlock explain --json` avoids text scraping for manifest explanations.
6. `R-006`: JSON typos and witness timestamp mistakes now include copyable correction breadcrumbs.

Deferred:

- No destructive or mutating commands were added.
- No policy/scanner semantics were changed.
- No top-level `--json` was added because it would be ambiguous; `--robot-triage` is the explicit machine summary.
