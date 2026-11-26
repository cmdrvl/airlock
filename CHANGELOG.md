# Changelog

## 0.4.0

The release that turns a manifest into something you can check without trusting
the tool that wrote it, and adds the gate that forwards a request only when a
verified manifest covers its exact bytes. The detail for each item is in
[README.md](./README.md); the commands are listed in `airlock --help`.

### Read this before upgrading from 0.3.0

- **`airlock verify` signs by default.** It loads the key `airlock keygen`
  created before it reads any input, and with no usable key it refuses
  (`E_BAD_INPUT`, `next_command: airlock keygen`) instead of writing an
  unsigned manifest. Run `airlock keygen` once, or pass `--no-sign` (for CI
  without a key).
- **`verify` binds the request to the assembled prompt.** Any missing, added,
  reordered or altered message, or an undeclared top-level request field, is a
  `REQUEST_UNBOUND` finding and the claim is `BOUNDARY_FAILED`.
- **Manifests are `airlock.v0.3`** (and `airlock.v0.4` for a chained turn), and
  their payload hashes are `blake3` over RFC 8785 canonical JSON. Manifests
  written by 0.3.0 and earlier (`airlock.v0`) used a private serialization;
  `airlock gate` and `airlock chain verify` refuse them as an unsupported
  manifest version. Run `airlock verify` again to get a new one.
- `assemble` encodes structured OpenAI Chat Completions content as a string, a
  wire-format fix.
- `airlock witness query`, `last` and `count` exit 0 on an empty result.

### Added

- **`airlock gate`**, a localhost egress gate (loopback only; the listener is
  plain HTTP), in two modes. `strict-manifest` forwards a request only if its
  canonical hash equals the `request_payload_hash` of a verified manifest it
  loaded from `--manifest-dir`, and refuses everything else with `E_GATE_DENIED`.
  `policy-proxy` screens each request against a policy and detector packs.
  Options: `--require-claim`, `--max-request-bytes`, `--timeout-seconds`,
  `--pubkey` (check a signed manifest's signature), `--witness-lookup` (find
  manifests through the witness ledger, by exact output hash), and
  `--upstream-proxy` (the gate ignores `HTTP_PROXY` and similar variables; a
  proxy is an explicit opt-in). `GET /airlock/health` answers without writing a
  receipt. Forwarded and refused requests are recorded in an `airlock.gate.v1`
  receipt, which `airlock explain` describes. A response is relayed as it
  arrives, so a streamed reply is not held until it ends, and an HTTP/1.1
  client is told at once when the upstream cuts a response short.
- **Chained turns.** A later prompt can carry an earlier model reply
  (`MODEL_OUTPUT`) and tool results (`TOOL_RESULT`) under a receipt anchor. The
  manifest for such a turn is `airlock.v0.4` and names the manifest the gate's
  receipt matched. `airlock chain verify` walks the chain back to turn 0 and
  checks every link. A strict gate forwards a chained turn only if it forwarded
  the reply that turn follows.
- **`airlock send`**: verify, then transmit, in one process, and record the
  bytes actually sent in a `transmission` member. A transport failure is an
  `E_TRANSPORT` refusal that says whether the body may have reached the
  endpoint. `airlock explain` shows what was sent.
- **Signed, richer manifests (`airlock.v0.3`)**: `bytes_crossed`,
  `attestation`, `transmission`, an optional `not_crossed` inventory of the
  fields left out of the request (`verify --not-crossed`, from
  `assemble --not-crossed-out`), and an Ed25519 `signature`. New commands
  `airlock keygen` and `airlock verify-manifest`.
- **Witness ledger chain.** Each entry carries `prev_hash`, written under a
  ledger lock, and `airlock witness verify` checks the chain. It is a tamper
  hint, not a proof: see the README for what it cannot catch.
- **Transport adapters** for OpenAI Responses, Anthropic Messages and Gemini
  `generateContent`, plus a declared `generic_json`, selected by shape or by
  `verify --transport`.
- **Opt-in detector packs** (the policy's `detectors` list) and inherited
  policies (`extends`).
- **A tamper matrix**: `docs/tamper-matrix.md` is generated from the real
  binary (54 cells, in both boundary modes) and CI fails if it drifts.
- **Egress deployment recipes** in `docs/deploy/egress-firewall.md`, with the
  macOS Seatbelt recipe run against the real gate by a test.
- RFC 8785 canonical JSON with published vectors and a cross-implementation
  check (`docs/canonicalization.md`); `SOURCE_DATE_EPOCH` pins the manifest
  timestamp; `--output` is an alias for `--out`.
- Witness recording is on by default for `assemble` and `verify`, and
  `--no-witness` turns it off; both are now tested through the real binary.

### Not proven

These are limits of what was checked, not promises that they hold.

- **Egress enforcement is proven on one platform only.** Only the macOS
  Seatbelt recipe in `docs/deploy/egress-firewall.md` has been run by a test,
  on macOS, for network egress only. The Linux nftables rules and the macOS
  `pf` rules are examples that no Airlock test runs. A Linux Landlock
  (network rules, kernel 6.7 or later) or network-namespace sandbox is named
  as the intended mechanism, but no recipe is given because none has been
  run.
- **No run against a real provider endpoint yet.** The gate and `send` are
  tested against local origins and mock servers. A run against a real
  endpoint is still to do.
- **Gate receipts are unsigned.** Anyone who can write the receipt directory
  can alter a receipt. The `gated` attestation value is reserved and is not
  written yet.
- **The gate trusts what it is pointed at.** A manifest directory, and (with
  `--witness-lookup`) the witness ledger together with the files it names, are
  trusted inputs: whoever can write them can add a manifest. The gate does not
  check the ledger's `prev_hash` chain.
- **The gate listens on loopback over plain HTTP.** There is no TLS listener
  and no remote listener (there is no `--allow-remote` option); that is
  deliberate, because the loopback-only listener is a security boundary.
- **The gate never verifies a request itself.** A strict-manifest request with
  no matching verified manifest is refused (`E_GATE_DENIED`); there is no
  `gate.allow_unbound` policy field and no inline `verify` fallback, because
  that would lower what a forwarded request proves.
- **The gate runs on `tiny_http` and `ureq`, one thread per request, with at
  most 32 in flight.** A planned rebuild on `asupersync` was not done.
- **The firewall recipes constrain one host.** They do not stop anything
  running as the gate's own account or as root, and say nothing about other
  machines or a proxy the agent account can already reach.
- **An in-place upgrade from 0.3.0 was not tested.** Output of 0.3.0
  `assemble` and `verify` was not fed to 0.4.0 commands. Run `assemble` and
  `verify` again with 0.4.0.
- **An HTTP/1.0 client** still waits until its own timeout when the upstream
  cuts a response short, and gets the whole response only at the end.
- The witness `prev_hash` chain does not detect removal of the newest entries
  or a whole ledger rewritten with recomputed links, unless you hold the
  expected head.
