# airlock — Boundary Attestation for Model Inputs

## One-line promise

**Prove what crossed the model boundary.**

If a model interaction occurs, Airlock should be able to show the exact prompt
payload, the exact upstream artifacts used to build it, and the exact claim
level achieved.

Second promise: **Make model-boundary trust an inspectable artifact, not a
verbal assurance.**

---

## Problem (clearly understood)

Teams can describe clean-room boundaries verbally:

- "the document never goes into the model"
- "the model only sees metadata"
- "we keep the sensitive content outside the AI system"

That language does not travel well with stakeholders, buyers, auditors, or
internal reviewers. It sounds like a policy claim, not a mechanical one.

What they actually need is:

- a deterministic account of what crossed the boundary
- a machine verdict on whether forbidden material was present
- a replayable artifact they can inspect without trusting the operator

Today the broader `cmdrvl` spine proves many things:

- what was scanned
- what was hashed
- what was routed
- what was benchmarked
- what passed policy
- what was sealed and packed

But it does not yet make model-boundary cleanliness a first-class proof object.

That gap is what Airlock fills.

---

## Why This Matters

Airlock is not a sidecar safety feature. It is a missing primitive in the
epistemic spine.

Without Airlock:

- model-boundary claims remain informal
- sensitive-document workflows remain hard to socialize
- downstream evidence packs cannot prove input cleanliness
- "AI on telemetry, not on documents" remains rhetoric

With Airlock:

- the model boundary becomes inspectable
- boundary claims become stratified and auditable
- proof artifacts can be sealed, packed, and cataloged
- regulated or trust-sensitive workflows become legible

This is especially important for systems like the tournament, where the core
innovation is not "send the filing to the model," but "keep the filing in a
deterministic harness and let the model operate only on bounded telemetry."

---

## Working Name

**`Airlock` is the right working name.**

Why:

- it implies a controlled boundary, not an aspirational policy
- it is short and easy to say in conversation
- it matches the clean-room mental model directly
- it works equally well for local tools, manifests, and catalog artifacts

Recommended open-source repo form (matching spine convention):

- GitHub: `cmdrvl/airlock`
- Crate / binary: `airlock`

Recommended artifact names:

- `airlock_manifest.json`
- `airlock_policy.yaml`

The eventual product umbrella can still change. For now, `Airlock` is strong
enough to build around.

---

## Relationship To The Spine

Airlock should be a native `cmdrvl` extension, not a generic wrapper around
Claude, Codex, or OpenAI APIs.

The existing spine already covers:

```text
deterministic parse / route / shape / canon
  → verify / benchmark / assess
  → vacuum / hash / lock / pack
  → evidence archive / catalog / foundry
```

What is missing as a first-class primitive:

```text
deterministic artifacts
  → airlock policy + assembly + verification + attestation
  → model request (Airlock proves what crossed here)
  → model response (outside Airlock scope — evaluated by downstream tools)
  → downstream evaluation / sealing / catalog
```

Airlock fills the proof gap between deterministic evidence and model execution.
It proves the input boundary only. The model response is persisted for
traceability but its correctness is evaluated by downstream spine tools
(benchmark, verify, assess), not by Airlock.

---

## Non-goals (explicit)

Airlock is NOT:

- A parser framework
- A benchmark engine
- A policy engine for extraction quality
- A replacement for `vacuum`, `hash`, `lock`, or `pack`
- A model vendor abstraction layer as the primary product
- A shell safety tool or execution guard (see Resolved Questions)

---

## Product Thesis

Open source the proof substrate.

That means:

- the boundary policy is inspectable
- the allowlist and denylist are inspectable
- the request assembler is inspectable
- the manifest schema is inspectable
- the scanner and verdict logic are inspectable

The open-source layer is the trust wedge.

It is not the full economic moat by itself. The deeper value sits in:

- cataloged evidence networks
- domain-specific evaluation harnesses
- sealed provenance pipelines
- managed decisioning and enterprise workflows
- compounding domain packs and reusable proofs

Open source should lower trust friction and adoption friction. The long-term
system value comes from what flows through the proof layer and becomes
operational capital.

---

## Design Invariants

Airlock should preserve the following invariants:

1. **Deterministic assembly**
   Same approved inputs must produce the same prompt payload. The prompt payload
   is the deterministic core. The request payload wraps it in a transport
   envelope (model ID, temperature, response format) that may vary across
   adapter versions or vendor API changes. The manifest hashes both separately:
   `prompt_payload_hash` (blake3) for the deterministic content,
   `request_payload_hash` (blake3) for the full transport artifact. Replay and re-verification use the prompt
   payload hash.

2. **No hidden inputs**
   Everything that materially influenced the request must appear in the manifest
   or in an upstream hashed artifact referenced by the manifest. This includes
   the system prompt. The system prompt is part of the model boundary — it
   shapes model behavior and may itself contain domain-specific instructions
   derived from the workflow. The manifest must record `system_prompt_hash`
   (blake3) as a first-class field. If the system prompt is templated, the
   template and its
   inputs are upstream artifacts. If the system prompt changes between runs,
   the manifest hash changes — making the difference visible.

3. **Claim levels are explicit**
   Airlock should not collapse all passes into one undifferentiated "safe"
   verdict. It must say exactly which claim level was achieved.

4. **Fail closed on forbidden classes**
   If forbidden artifacts or fields are present, the boundary claim degrades to
   `BOUNDARY_FAILED`. Airlock always produces a manifest — it does not silently
   block or silently pass. The manifest is the record regardless of verdict.
   Whether a `BOUNDARY_FAILED` manifest prevents the model call from being sent
   is an integration decision, not an Airlock decision. In gated integrations,
   the caller checks the verdict before sending. In audit integrations, the
   manifest is generated alongside or after the call. Both are valid. Airlock's
   job is to produce an honest verdict, not to own the call/no-call decision.

5. **Transport adapters are thin**
   Vendor-specific request formatting should sit at the edge, not define the
   core abstraction.

6. **Proofs can be sealed**
   Airlock artifacts must fit cleanly into `vacuum → hash → lock → pack` and
   later into catalog registration.

7. **Replayability over rhetoric**
   A third party should be able to inspect the manifest and reconstruct what was
   sent, without needing a narrative explanation from the operator.

8. **Replay is self-contained**
   The manifest must reference everything needed to answer four questions without
   operator assistance:
   - What exact bytes crossed? → `request_payload_hash` resolves to the
     persisted request artifact (e.g., `round-01.request.json`)
   - What upstream artifacts influenced them? → `upstream_artifact_inventory`
     lists each artifact with its content hash; hashes can be verified against
     the originals in the evidence pack or lockfile
   - What policy was in force? → `policy_hash` resolves to the persisted
     policy file; the manifest includes the full allowlist and denylist inline
     so the verdict can be re-derived without the policy file
   - Why did stronger claims fail? → `findings` and `blocked_reasons` are
     machine-readable and include offending key paths and sample values

   The manifest does NOT need to embed the full request payload (that would
   double storage). It must include the hash and a co-located path or pack
   member reference so the payload can be retrieved and hash-verified.

---

## Threat Model

Airlock exists to guard against boundary leakage from deterministic document
zones into model zones.

The primary leakage classes are:

- raw filing HTML
- PDF files or paths
- page images
- SEC archive URLs or primary document URLs
- section HTML
- row-level document extracts
- verbatim filing spans beyond allowed limits
- freeform filing-derived text when strict telemetry mode is required
- hidden adapter-side enrichments not represented in the manifest

Airlock does not guarantee:

- that the source document itself is correct
- that the model output is correct
- that a downstream operator will make a good decision
- that command execution is safe unless a separate execution guard is active

It proves boundary cleanliness claims. Other spine tools prove other things.

### Fingerprint router interaction

Airlock operates downstream of fingerprint routing. The fingerprint router
dispatches documents to parser families based on structural assertions
(`.fp.yaml` rules). By the time Airlock runs, the document has already been
parsed, benchmarked, and reduced to telemetry. Airlock does not need to be
fingerprint-aware — it validates whatever crosses the model boundary regardless
of which parser family produced the upstream artifacts. The manifest records
upstream artifact hashes, which trace back through the evidence chain to the
fingerprint that selected the parser.

### Multi-model boundary crossings

When a workflow involves multiple model calls (e.g., mutator → model A, then
evaluator → model B), each boundary crossing gets its own manifest. There is no
composite manifest. Each manifest is independently verifiable. Downstream
correlation (which manifests belong to the same workflow run) is handled by the
evidence pack, not by Airlock itself.

### Manifest storage at scale

The manifest itself is small (typically < 10 KB). The co-located request
payload is larger but bounded by prompt size. At tournament scale (hundreds of
rounds across dozens of families), total storage is modest. At production scale
with high-frequency model calls, request payload persistence should be
configurable: always persist (default for audit-sensitive workflows), persist
to external blob store with hash reference (for high-volume workflows where
co-location is impractical), or persist hash only (for high-volume
low-sensitivity calls where the claim verdict matters but replay does not).
Hash-only mode sacrifices Invariant #8: the manifest records what claim was
achieved, but a third party cannot verify the content without the payload.
Workflows that need third-party replay must persist the payload. The manifest
always persists — it is the proof object.

---

## Core Claims

Airlock supports three claim levels in a strict hierarchy:

```text
BOUNDARY_FAILED < RAW_DOCUMENT_ABSENT < STRICT_TELEMETRY_ONLY
```

### `BOUNDARY_FAILED`

Forbidden material was detected in the request boundary. The manifest records
what was found (`findings`, `blocked_reasons`) but makes no positive claim
about boundary cleanliness. This is the verdict when the denylist fires.

### `RAW_DOCUMENT_ABSENT`

Proves that the request boundary did not contain:

- raw filing HTML
- PDF bytes or PDF paths
- page images
- SEC archive URLs
- section HTML
- row-level document extracts

This is the first credible public claim for the tournament workflow.

### `STRICT_TELEMETRY_ONLY`

Proves:

- `RAW_DOCUMENT_ABSENT`
- no freeform filing-derived text crossed either

This stronger claim should be explicit, harder to earn, and never implied when
the request still carries descriptive filing-derived text.

### Important current-state distinction

These claims are not interchangeable.

Airlock can honestly support a workflow where:

- `RAW_DOCUMENT_ABSENT = true`
- `STRICT_TELEMETRY_ONLY = false`

That is not a failure of the system. It is a more precise statement of what the
system currently proves.

---

## Boundary Modes

Boundary mode means: **when Airlock assembles the prompt, how much
filing-derived prose is allowed to cross the boundary?**

The prompt assembler supports two explicit boundary modes. The mode is recorded in the
manifest. There is no implicit fallback — the operator chooses a boundary mode
at prompt assembly time, and the claim ceiling follows mechanically.

Where the mode is declared is an open design question (see Open Questions). The
two options are: mode in the policy file (simpler, one file defines
everything) or mode as an invocation flag on `airlock assemble` / `airlock
verify` (cleaner for A/B comparison of the same policy in both modes, since
changing mode doesn't change the policy hash). Either way, the manifest records
both `boundary_mode` and `policy_hash` independently.

### `ANNOTATED` mode

The assembler includes derived prose fields alongside structured telemetry:

- `mutator_context.challenge_observation` (natural language structural summary)
- `mutator_context.challenge_profile.header_surfaces[]` (column name strings)
- `mutator_context.challenge_profile.layout_notes[]` (layout observations)

**Claim ceiling: `RAW_DOCUMENT_ABSENT`.**

The manifest records `boundary_mode: "ANNOTATED"` and flags each derived
prose field in `findings.derived_text_field_hits`. The claim is honest: no raw
document crossed, but filing-derived descriptive text did. This is the right
mode when:

- the mutator needs structural context that has not yet been encoded into
  telemetry fields
- a new parser family is being onboarded and the structured profile is
  incomplete
- the workflow is exploratory and the prose fields carry signal that structured
  counterparts do not yet capture

### `TELEMETRY_ONLY` mode

The assembler strips all derived prose fields before prompt assembly. The prompt
payload contains only structured telemetry:

- `benchmark_summary` (numeric scores, field-level pass/fail)
- `unresolved_failure_fields` (field names, not content)
- `allowed_toggles` (configuration keys and types)
- `recent_lineage_rows` (round IDs, scores, toggle deltas)
- `heuristic_reference` (policy rules, proposal templates)
- `mutator_context.challenge_profile.page_count`
- `mutator_context.challenge_profile.dominant_column_count`
- `mutator_context.challenge_profile.parsing_shape_id`
- `mutator_context.challenge_profile.behavior_traits`
- `mutator_context.challenge_profile.canonical_roles`
- `mutator_context.challenge_fixture_id`

**Claim ceiling: `STRICT_TELEMETRY_ONLY`.**

The manifest records `boundary_mode: "TELEMETRY_ONLY"` and
`derived_text_field_hits` is empty. If derived prose fields somehow survive
assembly (bug or misconfiguration), the scanner catches them and the claim
degrades to `RAW_DOCUMENT_ABSENT` — fail-safe, not fail-silent.

### Boundary mode selection is a policy decision, not a quality judgment

`ANNOTATED` is not a lesser mode. It is a different trust contract with a
different claim ceiling. Some workflows will stay in `ANNOTATED` mode
permanently because the prose carries genuine signal. The system is honest
about this rather than forcing everything toward `TELEMETRY_ONLY` at the cost
of mutation quality.

The migration path from `ANNOTATED` to `TELEMETRY_ONLY` for a given workflow
is:

1. Run both modes on the same inputs
2. Compare mutation proposal quality (are proposals materially worse without
   the prose?)
3. If quality holds, switch the workflow to `TELEMETRY_ONLY`
4. If quality degrades, either enrich the structured telemetry fields to
   capture what the prose was providing, or keep `ANNOTATED` with its honest
   claim ceiling

---

## Operating Model

Airlock should formalize the clean-room pattern:

```text
document zone
  → deterministic extraction / routing / benchmark / verify / assess
  → bounded telemetry artifacts
  → airlock assemble (deterministic prompt assembly)
  → airlock verify (produce manifest with claim verdict)
  → caller decides: send or abort based on verdict
  → model request / model response
  → deterministic evaluation and promotion
  → seal / pack / catalog (manifest included)
```

Airlock produces the verdict. The caller acts on it. In the tournament today,
verify runs post-hoc alongside the call (audit mode). In a stricter
integration, verify runs pre-request and a `BOUNDARY_FAILED` verdict blocks
the call (gated mode). Both patterns produce the same manifest artifact.

The key separation is:

- the deterministic harness sees the document
- the model sees only what the airlock allows across the boundary

The core stakeholder sentence depends on the boundary mode:

- `TELEMETRY_ONLY`: **"AI on telemetry, not on documents."**
- `ANNOTATED`: **"AI on telemetry and bounded annotations, not on documents."**

The stronger sentence is only earned when the manifest shows
`STRICT_TELEMETRY_ONLY`. Using the unqualified version when the workflow is in
`ANNOTATED` mode would overstate the claim — which is exactly the kind of
verbal-assurance-masquerading-as-proof that Airlock exists to prevent.

---

## First Reference Application

The BDC Schedule of Investments tournament should be the first serious Airlock
reference application.

Why:

- it already has deterministic harnesses
- it already has frozen gold sets
- it already has zero-regression evaluation
- it already has sealed evidence patterns
- it already has model-boundary sensitivity
- it already has real stakeholder trust pressure

This is important strategically. Airlock should not start as an abstract SDK
with toy examples. It should start in a workflow where the value of the
boundary proof is obvious.

The tournament already demonstrates the shape:

- allowlist / denylist scanning
- claim-level verdicts
- saved request artifacts
- generated airlock manifests

It is the seed, not the final product.

---

## Current Proof State In The Tournament

The current tournament implementation gives us an honest baseline:

- it can persist the exact request prepared for the mutator
- it can generate an `airlock_manifest.json`
- it can prove that raw document artifacts did not cross
- it can show when strict telemetry-only mode has NOT yet been achieved

That distinction matters. The right first public statement is:

- the model did not receive the raw filing
- the exact request can be inspected
- the current request may still contain derived structural text

This is stronger than a verbal assurance and weaker than a full
telemetry-only claim, which is exactly why it is credible.

---

## Why This Approach Compounds

Airlock matters more when attached to a compounding system than when attached
to one-off model calls.

In the tournament, value compounds in two ways:

- **quality compounding**: each sealed improvement raises the floor and prevents
  regression
- **coverage compounding**: each absorbed family or layout pattern unlocks more
  filings at lower marginal effort

Airlock compounds alongside that system:

- each validated boundary policy becomes reusable
- each sealed manifest becomes a proof precedent
- each cataloged evidence pack makes future stakeholder conversations cheaper

The long-term effect is not just "we can prove one call was clean." It is "we
can accumulate reusable, sealed proof that this workflow class stays inside its
declared boundary."

---

## Bounded-Truth Positioning

Airlock should be described consistently with the broader tournament truth
model.

We should not claim:

- universal perfection
- universal safety
- future-proof guarantee across every unseen workflow

We should claim:

- bounded, inspectable proofs on specific interactions
- stronger claims only when the manifest earns them
- family-by-family and workflow-by-workflow expansion outward

This mirrors the tournament's quality stance:

- 100% quality is credible on bounded scopes with reviewed truth and sealed
  evidence
- not as a universal claim across all future documents forever

Airlock is the input-boundary analogue of that same philosophy.

---

## Core Components

### 1. Policy

Defines:

- allowed input classes
- forbidden artifact classes
- key-path rules
- value-pattern rules
- claim levels
- sampling / evidence rules for findings

Examples (from current tournament policy):

- allow `family_id`, `current_strategy`, `allowed_toggles`, `max_proposals`
- allow `benchmark_summary`, `unresolved_failure_fields`
- allow `recent_lineage_rows`, `heuristic_reference`
- allow `mutator_context` (with sub-field rules)
- forbid `html_path`, `section_html`, `pdf_path`
- forbid raw HTML markup (regex pattern match)
- forbid SEC archive URLs
- mark `mutator_context.challenge_observation` as derived text (disqualifies
  `STRICT_TELEMETRY_ONLY` but permitted in `ANNOTATED` mode)

**Policy versioning.** Policies are content-addressed: the manifest records the
blake3 hash of the policy file that was in force (using the spine's standard
`blake3:{hex}` format). A policy change (new denylist
entry, tightened pattern) produces a new hash. Old manifests remain valid
records of what was proven under the old policy — they do not retroactively
fail. If a reviewer needs to know whether an old manifest would pass under a
newer policy, `airlock verify` can re-evaluate a persisted request against a
different policy file and emit a new manifest with both `policy_hash` and
`evaluated_against_policy_hash`. This separates "what was true at the time"
from "what would be true under current rules" — consistent with PR-001
(time is first-class).

### 2. Prompt Assembler

Deterministically turns approved telemetry into a prompt payload.

The assembler's output is a structured JSON object containing the system prompt
and user prompt content — the model-facing payload before transport wrapping.
In v0, this means selecting and filtering fields from the input artifacts per
the policy's allowlist, then assembling them into the prompt structure (system
message template + user message payload). The adapter (or the caller, if no
adapter is used) wraps this into a vendor-specific request.

The assembler does NOT build the full API request. That separation is
deliberate: the prompt payload is the deterministic, policy-governed artifact.
The request payload adds transport-layer fields (model ID, temperature, API
format) that are adapter concerns.

Properties:

- same inputs → same prompt payload (deterministic core; see Invariant #1)
- no hidden data sources
- policy-aware and boundary-mode-aware
- system prompt is an explicit input, not embedded in the assembler
- explicit versioning

### 3. Scanner / Verifier

Checks system prompts, prompt payloads, request payloads, and referenced
upstream artifacts against policy.

Outputs:

- pass / fail
- claim level achieved
- blocked-by reasons
- offending paths and samples
- summary counts by artifact class

### 4. Manifest

Writes an `airlock_manifest.json`. See Artifact Model for the full field
inventory. The manifest is the primary proof object — everything else
(assemble, verify, explain) exists to produce or consume it.

### 5. Explain Surface

Airlock should make the result legible to humans as well as machines.

That means:

- one machine artifact: `airlock_manifest.json`
- one concise explanation path: `airlock explain`

Stakeholders should be able to read the proof without wading through raw JSON.

### 6. Sealing Integration

Airlock artifacts should feed the existing proof chain:

```text
airlock manifest
  → vacuum
  → hash
  → lock
  → pack
```

### 7. Catalog Integration

Airlock proofs should become first-class catalog objects, linked to:

- the model interaction
- the evidence pack
- the downstream decision
- the promoted outcome

This is where proof becomes durable infrastructure rather than a local file.

### 8. Adapters

Thin transport adapters targeting API formats, not environments:

- OpenAI Chat Completions API (covers ChatGPT, Codex CLI, Azure OpenAI)
- Anthropic Messages API (covers Claude Code, direct API)
- Additional vendor APIs as needed

Adapters should not define the policy model. They should only map assembled
prompt payloads into vendor-specific request shapes. An adapter is a function
from `(prompt_payload, transport_config) → request_payload`, nothing more.

---

## Artifact Model

The proof object should be an input bill of materials for the model boundary.

Minimum fields:

- manifest version
- boundary mode
- policy id / hash
- claim levels evaluated
- achieved claim level
- upstream artifact inventory
- system prompt hash
- prompt payload hash
- prompt provenance hash
- request payload hash
- model id and adapter
- findings
- blocked reasons
- `raw_document_present`
- `filing_derived_text_present`
- prompt provenance reference: co-located path or pack member ID for the
  persisted `prompt_provenance.json`, verifiable against
  `prompt_provenance_hash`
- replay reference: co-located path or pack member ID for the persisted
  request payload, verifiable against `request_payload_hash`

The manifest must make it easy to answer:

- What exact bytes crossed?
- What exact artifacts influenced them?
- What claim level was achieved?
- Why did stronger claims fail?

---

## Prompt Provenance (Proof-Carrying Prompt)

Airlock should emit a second first-class artifact beside the prompt payload:
`prompt_provenance.json`.

This artifact is a deterministic source map for the model boundary. It does not
just say what request was sent. It says, for every emitted prompt field or
message fragment, **what upstream artifact produced it, what policy rule
admitted it, and what boundary class it belongs to**.

That is the difference between:

- a request scanner
- a proof-carrying prompt assembler

### What it proves

`lock` and `pack` prove where facts came from in the document and how they were
sealed into evidence.

`prompt_provenance.json` proves something different:

- what the model was exposed to
- where each exposed fragment came from
- why it was allowed across the boundary
- why a stronger claim was or was not earned

In other words:

- `lock` / `pack`: provenance of truth
- `prompt_provenance.json`: provenance of exposure

### Artifact shape

`prompt_provenance.json` should contain one record per emitted prompt field or
message fragment. Minimum fields per record:

- `prompt_path` or message-fragment locator (for example:
  `messages[1].content.challenge_profile.page_count`)
- `emitted_value_hash`
- `source_artifact_hash`
- `source_path`
- `transformation_kind`
- `policy_rule_id`
- `boundary_class`
- `admitted_boundary_modes`

Recommended enums:

- `transformation_kind`: `COPY`, `NORMALIZE`, `AGGREGATE`, `TEMPLATE`,
  `DERIVED_ANNOTATION`
- `boundary_class`: `TELEMETRY`, `DERIVED_TEXT`, `FORBIDDEN`

The artifact may additionally include a small redacted sample value or length
metadata when useful for explainability, but the core contract should rely on
hashes and paths, not on embedding more text than necessary.

### Invariants

Prompt provenance should obey four hard rules:

1. No prompt bytes without provenance.
   If a field or fragment appears in the assembled prompt payload, it must have
   at least one provenance record.
2. No hidden adapter enrichment.
   Transport adapters may reshape the request envelope, but they may not inject
   semantic content that lacks provenance coverage.
3. Policy linkage is first-class.
   Every emitted fragment must point to the allow rule or derivation rule that
   admitted it.
4. Claim degradation is explainable.
   If `STRICT_TELEMETRY_ONLY` fails, provenance should identify exactly which
   emitted fragments were classified as `DERIVED_TEXT` and where they came from.

### Why this matters

This is the most leveraged addition Airlock can make because it turns the
system from "we scanned the final request and found no forbidden classes" into
"we can account for why every emitted fragment exists."

That enables:

- precise explanation of why a run earned only `RAW_DOCUMENT_ABSENT`
- deterministic migration from `ANNOTATED` to `TELEMETRY_ONLY`
- stronger detection of hidden enrichments and accidental prompt drift
- catalog queries like "show the exact derived-text fragments that blocked strict telemetry"

### Manifest integration

The manifest should record:

- `prompt_provenance_hash`
- `prompt_provenance_ref`

That makes prompt provenance part of the sealed replay story, not an optional
debug artifact.

---

## CLI Shape (v0)

```bash
# Core subcommands
airlock assemble --policy policy.yaml --input strategy_space.json [--input heuristic.json ...] --out prompt_payload.json --provenance-out prompt_provenance.json
airlock verify  --policy policy.yaml --prompt prompt_payload.json --provenance prompt_provenance.json --request request.json --out airlock_manifest.json [--require-claim RAW_DOCUMENT_ABSENT]
airlock explain --manifest airlock_manifest.json
airlock witness query [--tool airlock] [--since <iso8601>] [--until <iso8601>] [--outcome <ASSEMBLED|VERIFIED|VERIFY_PARTIAL|REFUSAL>] [--input-hash <substring>] [--limit <n>] [--json]
airlock witness last [--json]
airlock witness count [--tool airlock] [--since <iso8601>] [--until <iso8601>] [--outcome <ASSEMBLED|VERIFIED|VERIFY_PARTIAL|REFUSAL>] [--input-hash <substring>] [--json]

# Spine-standard introspection flags
airlock --describe          # Emit operator.json (pipeline metadata)
airlock --schema            # Emit output JSON schema
airlock --version           # Emit version string
```

Common flags (all subcommands):

- `--describe`: print compiled `operator.json` and exit 0 before normal validation
- `--schema`: print the output schema and exit 0 before normal validation
- `--version`: print `airlock <semver>` and exit 0
- `--no-witness`: suppress ambient witness ledger recording for eligible runs

`assemble` accepts multiple `--input` files. Each input file becomes an entry in
the manifest's `upstream_artifact_inventory` with its content hash. This keeps
assembly inside Airlock's proof boundary — if an input is added or removed, the
manifest reflects it. Passing a single pre-assembled JSON is also valid but the
assembler then sits outside the proof boundary; the manifest records only the
assembled file's hash, not its constituents.

`assemble` should also emit `prompt_provenance.json`, which records one
deterministic provenance entry for each emitted prompt field or message
fragment.

Likely later:

```bash
airlock diff --before old_manifest.json --after new_manifest.json
airlock adapter openai --prompt prompt_payload.json --out request.json
```

`verify` defaults to audit behavior: it always emits a manifest, even when the
achieved claim is `BOUNDARY_FAILED`. `--require-claim` enables gated behavior:
if the achieved claim is below the requested threshold, `verify` exits non-zero
after writing the manifest.

`witness` follows the standard spine ledger surface. Query subcommands do not
append witness records themselves.

Sealing is NOT an Airlock subcommand. Airlock produces artifacts; the existing
spine tools seal them: `vacuum` scans the evidence directory, `hash` adds
content hashes, `lock` pins them, `pack` bundles the result. Airlock should not
re-implement or wrap that chain.

Repo layout (matching spine convention):

```text
Cargo.toml
README.md
LICENSE
operator.json
.github/
└── workflows/
    ├── ci.yml
    └── release.yml
src/
├── main.rs                    # Thin: lib::run() → ExitCode
├── lib.rs                     # Orchestration: assemble, verify, explain
├── cli/
│   ├── mod.rs                 # clap derive structs, subcommands
│   └── exit.rs                # Exit code constants
├── policy/
│   ├── mod.rs                 # Policy YAML parsing (serde_yaml)
│   └── types.rs               # AirlockPolicy, AllowRule, DenyRule structs
├── assembler/
│   └── mod.rs                 # Prompt assembly, field selection, mode filtering
├── scanner/
│   └── mod.rs                 # Verify payload against policy, produce findings
├── manifest/
│   └── mod.rs                 # AirlockManifest struct, canonical JSON emission
├── adapter/
│   └── mod.rs                 # Transport adapters (OpenAI, Anthropic)
├── refusal/
│   └── mod.rs                 # RefusalEnvelope, RefusalCode enum
├── witness/
│   └── mod.rs                 # witness append + query surface
└── output/
    └── mod.rs                 # JSONL, sorted JSON, --describe, --schema
tests/
fixtures/
schemas/
├── airlock_policy.schema.json
├── airlock_manifest.schema.json
└── airlock.v0.schema.json     # Output schema (embedded via include_str!)
rules/                          # Example / reference policy files
examples/                       # Canonical demo payloads + manifests
docs/
```

---

## Implementation Conventions

Airlock is a spine tool. It follows the same Rust conventions as vacuum, hash,
lock, pack, fingerprint, and canon.

### Hashing

All content hashes use blake3 with the spine's prefixed format:
`blake3:{hex}`. This applies to policy hashes, prompt payload hashes, request
payload hashes, system prompt hashes, and upstream artifact hashes. SHA-256 is
available as a fallback (`sha256:{hex}`) but blake3 is the default.

Hashes are computed over canonical JSON (sorted keys at all nesting levels) to
ensure determinism. The `sort_value()` pattern from lock is the reference
implementation.

### Canonical JSON

All JSON output — manifests, JSONL records, refusal envelopes — uses
recursively sorted keys. This is required for deterministic hashing and
reproducible output. The pattern:

```rust
fn sort_value(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: Map<String, Value> = map.into_iter()
                .sorted_by(|(a, _), (b, _)| a.cmp(b))
                .map(|(k, v)| (k, sort_value(v)))
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_value).collect()),
        other => other,
    }
}
```

### Exit codes

```text
0  VERIFY_PASS       Assembly and verification succeeded; claim earned
1  VERIFY_PARTIAL    Verification completed but achieved claim fell below caller
                     requirement or selected boundary mode ceiling
2  REFUSAL           Bad input, missing policy, or unrecoverable error
```

`BOUNDARY_FAILED` is exit code 0, not 1 — the tool ran correctly and produced
an honest manifest. The verdict happens to be negative. Exit code 1 is reserved
for cases where the achieved claim is lower than the caller's declared minimum
(`--require-claim`) or lower than the boundary mode's ceiling (an anomaly
worth investigating).

### Error handling

Custom `RefusalEnvelope` structs, not `anyhow` or `thiserror`. Refusals are
structured JSON on stdout with exit code 2:

```json
{
  "version": "airlock.v0",
  "outcome": "REFUSAL",
  "refusal": {
    "code": "E_BAD_POLICY",
    "message": "policy file failed schema validation",
    "detail": { "path": "policy.yaml", "error": "..." },
    "next_command": "airlock --schema"
  }
}
```

### Witness ledger

Airlock should follow the spine witness protocol:

- default: append one `witness.v0` record per eligible invocation
- opt-out: `--no-witness`
- path: `EPISTEMIC_WITNESS` or `~/.epistemic/witness.jsonl`
- append failure never changes domain exit semantics

Recording policy in v0:

- record for `assemble` and `verify`
- do not record for `witness` query subcommands
- do not record for `--describe`, `--schema`, or `--version`
- `explain` may remain non-recording in v0 to avoid ledger noise from purely
  local render passes

Witness outcome mapping in v0:

- `assemble`: `ASSEMBLED` or `REFUSAL`
- `verify`: `VERIFIED`, `VERIFY_PARTIAL`, or `REFUSAL`

The witness record includes: tool name, command, timestamp, outcome, exit code,
input paths with hashes, params, stdout hash, and stdout byte count.

Airlock should also expose the standard ledger query surface:

- `airlock witness query [filters] [--json]`
- `airlock witness last [--json]`
- `airlock witness count [filters] [--json]`

Query runtime semantics should match the mature spine tools:

- exit `0`: successful query with matches
- exit `1`: successful query with no matches
- exit `2`: ledger error or refusal

### Embedded metadata

`operator.json` and output schemas are embedded at build time via
`include_str!()` and emitted via `--describe` (operator metadata) and
`--schema` (output JSON schema) flags. These are present on every spine tool
and used by pipeline orchestrators to discover tool capabilities.

The compiled `operator.json` should be richer than a name/version stub. It
should include:

- invocation usage strings
- output mode and output schema
- common flags (`--describe`, `--schema`, `--version`, `--no-witness`)
- subcommands (`assemble`, `verify`, `explain`, `witness`)
- exit semantics
- refusal map
- witness capabilities
- pipeline position (`upstream` / `downstream`)

### Release And Distribution

Airlock should ship with the same release posture as the mature spine tools:

- `ci.yml` for locked, repeatable build/test checks
- `release.yml` with a five-target matrix:
  `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`,
  `x86_64-apple-darwin`,
  `aarch64-apple-darwin`,
  `x86_64-pc-windows-msvc`
- packaged archives containing binary + `README.md` + `LICENSE`
- generated `SHA256SUMS`
- keyless signing / attestation for release checksums
- published SBOM artifact
- Homebrew tap update in `cmdrvl/homebrew-tap`

The release workflow should validate that the requested release version matches
`Cargo.toml` before publishing immutable artifacts.

### Testing Conventions

Airlock should carry the same spine testing posture:

- CLI precedence tests for `--describe`, `--schema`, and `--version`
- witness append / `--no-witness` / query behavior on synthetic ledgers
- witness append failure preserves domain exit semantics
- deterministic assembly tests: same inputs, same prompt payload hash
- schema validation tests for prompt payloads, manifests, and refusal envelopes
- golden fixtures for known clean, degraded, and forbidden boundary cases

### Entry point

```rust
#![forbid(unsafe_code)]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(airlock::run())
}
```

`lib::run()` handles CLI parsing, dispatch, witness append, and returns `u8`.

### Policy types

Policy files are YAML, parsed with `serde_yaml` into strongly typed Rust
structs (following the fingerprint `FingerprintDefinition` pattern):

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AirlockPolicy {
    pub policy_id: String,
    pub version: String,
    pub allowed_keys: Vec<AllowRule>,
    pub forbidden_keys: Vec<String>,
    pub forbidden_patterns: Vec<ForbiddenPattern>,
    pub derived_text_paths: Vec<String>,
    pub claim_levels: Vec<String>,
}
```

### Dependencies (pinned, matching spine)

```toml
clap = { version = "=4.5.60", features = ["derive"] }
serde = { version = "=1.0.225", features = ["derive"] }
serde_json = "=1.0.143"
serde_yaml = "=0.9.34"
blake3 = "=1.8.2"
sha2 = "=0.10"
chrono = "=0.4.41"
regex = "=1.11"
```

### Build profile

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

---

## Success Criteria

Airlock v0 (Phases 1–2) is successful if we can do all of the following:

1. deterministically assemble a prompt payload and `prompt_provenance.json`
   from approved telemetry
2. produce a manifest with honest claim verdicts (including `BOUNDARY_FAILED`
   when forbidden material is present)
3. produce a machine-readable manifest with boundary mode, claim levels,
   system prompt hash, upstream artifact inventory, and prompt provenance refs
4. prove, for each emitted prompt fragment, what upstream artifact and policy
   rule admitted it
5. demonstrate the full flow in a real workflow, not a toy example

Airlock v1 (Phases 3–4) adds:

6. a concise human explanation of the verdict (`airlock explain`)
7. sealed manifests in the existing proof chain (`vacuum → hash → lock → pack`)
8. catalog-registered proof artifacts linked to evidence packs and outcomes

Airlock becomes genuinely important when a third party can inspect a sealed
manifest and verify, without operator narration, that a declared claim is true.

---

## Implementation Sequence

### Phase 1 — Tournament Proof Surface

1. Emit `airlock_manifest.json` beside mutator request artifacts
2. Persist exact prompt, prompt provenance, and request payloads for replay
3. Define the first allowlist and denylist
4. Define `RAW_DOCUMENT_ABSENT` and `STRICT_TELEMETRY_ONLY`
5. Record `boundary_mode` in manifests from day one (current tournament
   manifests are `ANNOTATED` — label them honestly rather than retroactively
   adding the field in Phase 5)
6. Establish one or two canonical demos for stakeholder review

### Phase 2 — Rewrite As Spine Tool

Phase 1 artifacts are Python, in-process, tournament-specific
(`mutator_airlock.py`, `propose_family_mutations.py`). Phase 2 is not
extraction — it is a rewrite into a Rust CLI with file-based I/O, matching the
spine convention. The tournament integration changes from in-process Python
calls to writing intermediate JSON files and invoking the CLI.

7. Rewrite policy, scanner, prompt provenance, and manifest logic in Rust at
   `cmdrvl/airlock`
8. Add JSON schemas, fixtures, and tests for known good / known bad payloads
9. Add a thin OpenAI Chat Completions adapter
10. Add deterministic prompt assembly and prompt provenance contracts
11. Migrate tournament scripts to invoke the CLI instead of in-process Python

### Phase 3 — Explainability And Sealing

12. Add `airlock explain`
13. Feed manifests into `vacuum / hash / lock / pack`
14. Attach airlock artifacts to evidence packs
15. Make airlock claims visible in proof summaries

### Phase 4 — Catalog Integration

16. Register airlock proof artifacts in catalog
17. Link manifests to evidence packs, decisions, and promoted outcomes
18. Define query patterns for "show me the boundary proof for this result"

### Phase 5 — Dual Boundary Modes

19. Complete first-class dual-mode support in the Rust prompt assembler
20. Reach `STRICT_TELEMETRY_ONLY` for workflows where structured telemetry is
    sufficient
21. Retain `ANNOTATED` mode for workflows that genuinely need derived prose,
    with its claim ceiling clearly labeled

See "Boundary Modes" section for design details.

### Phase 6 — Cross-Environment Ecosystem

22. Add adapters for multiple model APIs
23. Publish reference patterns for regulated and sensitive document workflows

---

## Immediate Next Steps

1. Keep `Airlock` as the working name.
2. Treat the BDC tournament as the first reference application.
3. Promote the existing tournament airlock artifacts into canonical examples.
4. Decide the first public claim precisely:
   - `RAW_DOCUMENT_ABSENT`
   - not `STRICT_TELEMETRY_ONLY` until the manifest earns it
5. Create the initial `cmdrvl/airlock` repo skeleton:
   - `docs/`
   - `schemas/`
   - `examples/`
   - `adapters/`
6. Draft the first policy file, manifest schema, and prompt provenance schema
   as repo-native artifacts.

---

## Open Questions

- Should `Airlock` stay the end-user name, or become a lower-level capability
  under a broader `cmdrvl` product surface?
- How strict should the public semantics be before we call a workflow
  "telemetry only"?
- What is the first non-tournament reference workflow after BDC SOI?
- Should boundary mode live in the policy file or be an invocation flag?
  If in the policy, switching boundary modes changes the policy hash and
  requires separate policy files for A/B comparison. If an invocation flag, the
  same policy can be tested in both boundary modes without hash divergence.
  Tradeoff:
  policy-embedded is simpler to reason about; flag-based is cleaner for
  migration testing.

## Resolved Questions

### Standalone repo, not monorepo

The spine tools (vacuum 0.2.1, hash 0.3.1, lock 0.3.1, pack 0.2.2,
fingerprint 0.5.1, canon 0.2.2) are all standalone Rust repos at
`cmdrvl/{tool}`, independently versioned via `Cargo.toml`, distributed through
`cmdrvl/homebrew-tap` with multi-platform release automation (macOS arm64/x64,
Linux arm64/x64, Windows x64), SHA256SUMS with cosign signatures, and SPDX
SBOMs.

Airlock follows the same pattern:

- Repo: `cmdrvl/airlock`
- Binary: `airlock`
- Formula: `tap/Formula/airlock.rb`
- Versioning: independent semver via `Cargo.toml`
- Interop: `operator.json` declaring pipeline position
- CI: `.github/workflows/release.yml` matching existing spine release template

### Execution guardrails live outside this repo

Runtime command protection (destructive command interception, shell policy
enforcement, sandbox restrictions) is adjacent to boundary attestation. If a
`dcg`-style execution guard is built, it should be a separate spine tool that
Airlock can reference in its manifest (e.g., `execution_guard_policy_hash`)
but does not own. See Non-goals.

---

## Summary

`cmdrvl` already proves output quality, artifact identity, and sealed
provenance. Airlock should prove input cleanliness at the model boundary.

That is the missing primitive.

If we get this right, the stakeholder conversation changes from:

- "trust us, the document never went into the model"

to:

- "inspect the manifest for the exact request that crossed the boundary"

That shift is the point.
