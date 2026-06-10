# airlock handoff - agent ergonomics pass 1

Status: complete for this pass.

What changed:

- Added top-level `--robot-triage`, `capabilities --json`, and `robot-docs guide` read-only agent-discovery surfaces.
- Added `explain --json` with deterministic `airlock.explain.v1` output.
- Made bare `airlock` print useful help and exit successfully.
- Improved parse/refusal breadcrumbs for common `--json` typos and bad witness timestamps.
- Updated README, AGENTS, implementation plan, and `operator.json`.
- Moved Cargo metadata to Rust 2024 / rust-version 1.85 per shared spine rules.

Validation to rerun:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
for test in agent_ergonomics_audit/audit/regression_tests/*.test.sh; do bash "$test"; done
bash /Users/zac/.codex/skills/agent-ergonomics-and-intuitiveness-maximization-for-cli-tools/scripts/validate_pass.sh agent_ergonomics_audit
```

Known caveat:

- The skill preflight hard-requires `flock`; this macOS environment does not provide it. The pass was run serially without installing system utilities.
