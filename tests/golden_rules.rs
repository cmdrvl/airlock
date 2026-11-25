//! spine-rules family contract for airlock (`operator.v1`, `cmdrvl.doctor.v1`,
//! exit-code dictionary, flag dictionary, ANSI-free piped output).
//!
//! Opted in: `fixture_refusal_args` (a real refusal run: R-001 `version` in the
//! refusal envelope, plus the ANSI-free check on the refusal path).
//!
//! Also opted in: `fixture_timestamped_args` (`SOURCE_DATE_EPOCH`): a real `verify`
//! run whose manifest stdout must be identical across runs under one epoch. The
//! manifest is written under `CARGO_TARGET_TMPDIR` because `--out` writes atomically
//! next to the destination; only that one generated test uses the path.
//!
//! Also opted in: `fixture_empty_query_args` (`family_empty_query_exits_zero`, al-4u3):
//! a real `witness query` that must exit 0 and print exactly `[]`. The macro passes
//! static arguments and no environment, so the run reads whatever ledger the machine
//! has. `--since 2999-01-01T00:00:00Z` matches no record in any ledger, which keeps the
//! result empty on every machine without depending on `~/.cmdrvl` contents. The query
//! is read-only. The per-ledger-state coverage (absent, empty, corrupt, non-matching
//! filter) and `last`/`count` live in `tests/cli_tests.rs` against temp ledgers.
//!
//! Not opted in, and why:
//! - `fixture_success_args` (R-001 resolved / R-008 / R-017): airlock's success
//!   commands write their artifacts to `--out` paths and the macro takes static
//!   argument slices, so parallel generated tests would share one output path.
//!   `--no-witness` suppression and witness-failure non-fatality are covered by
//!   `tests/cli_tests.rs` against per-test temp dirs.

use spine_rules::golden_rules_suite;

golden_rules_suite! {
    binary: env!("CARGO_BIN_EXE_airlock"),
    operator_json: include_str!("../operator.json"),
    source_files: &["src/refusal/mod.rs"],
    fixture_refusal_args: &[
        "verify",
        "--no-sign",
        "--policy", "does-not-exist/policy.yaml",
        "--prompt", "does-not-exist/prompt_payload.json",
        "--provenance", "does-not-exist/prompt_provenance.json",
        "--request", "does-not-exist/request.json",
        "--out", "does-not-exist/airlock_manifest.json",
        "--no-witness",
    ],
    fixture_timestamped_args: &[
        "verify",
        "--no-sign",
        "--policy", "fixtures/clean_telemetry_only/policy.yaml",
        "--prompt", "fixtures/clean_telemetry_only/expected_prompt_payload.json",
        "--provenance", "fixtures/clean_telemetry_only/expected_prompt_provenance.json",
        "--request", "fixtures/clean_telemetry_only/request.json",
        "--out", concat!(env!("CARGO_TARGET_TMPDIR"), "/golden_rules_manifest.json"),
        "--no-witness",
    ],
    fixture_empty_query_args: &[
        "witness", "query",
        "--since", "2999-01-01T00:00:00Z",
        "--json",
    ],
}
