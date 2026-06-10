# airlock agent ergonomics scorecard - pass 1

Inventoried surfaces: 76.
Scored focus surfaces: 8.
Mode: full.

Median uplift estimate: 170 points across changed surfaces.

Strong surfaces after pass:

- `airlock --robot-triage`: parseable read-only mega-command.
- `airlock capabilities --json`: standard machine discovery surface.
- `airlock robot-docs guide`: in-tool agent handbook.
- `airlock explain --manifest <MANIFEST> --json`: parseable manifest explanation.

Largest risks reduced:

- Bare invocation no longer looks like a failed command.
- Agents no longer need to know the `doctor` namespace before discovery.
- `explain` no longer requires scraping human text.
- Common `--json` typos and invalid witness timestamps teach the corrected command.

Verification:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `agent_ergonomics_audit/audit/regression_tests/*.test.sh`
