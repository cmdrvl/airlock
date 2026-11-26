# FINOS CALM `AIR-OP-028` + AIGF `MI-20` Executable Wire Proof

![FINOS CALM AIR-OP-028 + airlock terminal demo](finos-calm-airlock-demo.gif)

*(Full MP4 video: [`finos-calm-airlock-demo.mp4`](finos-calm-airlock-demo.mp4) — 71s, 897 KB)*

---

## Why this demo exists

In upstream **FINOS CALM** (`finos/architecture-as-code@92b032b527`), AI governance controls like [`AIR-OP-028` (Multi-Agent Trust Boundary Violations)](finos-upstream/013-air-op-028-multi-agent-trust-boundary-violations.json) ship with `"configurations": []`, and [`calm/draft/2026-03/meta/evidence.json`](finos-upstream/calm-evidence.schema.json) defines only a 3-field pointer stub (`unique-id`, `evidence-paths`, `control-config-url`) without a concrete cryptographic proof format.

This self-contained, zero-account demo fills both slots with shipped open-source Rust binaries from the `cmdrvl` toolkit:

1. **Deterministic assembly & negative inventory (`airlock assemble` / `airlock verify`):** Strips raw client fields (`client_ssn`, `raw_document`, `raw_ledger_rows`), records only cryptographic value hashes in `not_crossed.json` (0 raw bytes written), and Ed25519-signs an `airlock.v0.3` `STRICT_TELEMETRY_ONLY` manifest.
2. **Live egress proxy (`airlock gate --mode policy-proxy`):** Enforces `policy/air-op-028-boundary.yaml` in front of an upstream LLM/MCP endpoint:
   - Clean redacted telemetry → `HTTP 200 ALLOWED`
   - Direct US SSN → `HTTP 403 BLOCKED` (**0 bytes** reach upstream)
   - Raw confidential HTML table → `HTTP 403 BLOCKED` (**0 bytes** reach upstream)
   - **Base64-encoded CSV exfiltration** (with **zero** base64 regexes in the policy) → `HTTP 403 BLOCKED` via recursive `boundary-detectors` (**0 bytes** reach upstream)
3. **Schema-valid CALM `evidence.json` + sealed pack (`vacuum` → `hashbytes` → `lock` → `pack seal`):** Emits `out/evidence.json` conforming to `https://calm.finos.org/draft/2026-03/meta/evidence.json`, SHA-256 locks all 10 artifacts, and seals a reproducible Evidence Pack.
4. **Offline auditor verification + 1-byte tamper test:** Independently verifies the Ed25519 manifest signature (`airlock verify-manifest`), SHA-256 lockfile (`lock verify`), and sealed pack (`pack verify`) offline (`exit 0`), then flips 1 claim field to demonstrate immediate cryptographic rejection (`exit 2`).

## Honest scope boundary

- **Enforced deterministically at the wire:** Inter-agent/egress payload validation, raw-document/PII blocking, recursive smuggling detection (`AIR-OP-028` req #3, `AIGF MI-20`), negative hash inventory, and Ed25519 + SHA-256 offline verification.
- **Explicitly `documented_only`:** Process controls such as annual access recertification and incident response drills are never claimed as automated.

## Run locally

Install the open-source binaries via Homebrew:

```bash
brew install cmdrvl/tap/airlock cmdrvl/tap/vacuum cmdrvl/tap/cmdrvl-hash cmdrvl/tap/lock cmdrvl/tap/pack
```

Run the full 5-step proof locally (no API keys, no external network calls):

```bash
cd examples/finos-calm-air-op-028
./run_demo.py all
```

Re-render the terminal recording (optional, requires `brew install vhs`):

```bash
vhs demo.tape
```
