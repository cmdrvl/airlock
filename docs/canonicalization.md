# Canonical JSON and payload hashes

Every hash airlock writes into a manifest for a JSON document is

```
blake3( RFC 8785 JCS( document ) )   written as "blake3:<64 hex digits>"
```

so an auditor can recompute `prompt_payload_hash`, `request_payload_hash` and
`prompt_provenance_hash` from the files named in the manifest with any conforming JCS library
and any BLAKE3 implementation, without airlock. Manifests with `manifest_version`
`airlock.v0.2` and later use this algorithm. Manifests with `airlock.v0`, written by every
release through 0.3.0, used a private serialization (see
[Differences from airlock.v0](#differences-from-airlockv0)).

## The algorithm

[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) section 3.2, in short:

- no whitespace between tokens;
- object members sorted recursively by member name, compared as arrays of **UTF-16 code
  units** (not UTF-8 bytes and not code points: a name containing U+1F600 sorts before one
  containing U+FB33);
- strings escape only `"`, `\` and U+0000 to U+001F (`\b \t \n \f \r`, otherwise lowercase
  `\u00xx`); every other character, including U+007F, is written as is, in UTF-8;
- numbers are the ECMAScript `Number::toString` form of the IEEE 754 double: shortest
  round-trip digits, plain decimal from `1e-6` up to (not including) `1e21`, otherwise
  exponent form with an explicit sign (`1e+21`, `5e-324`), and `-0` is written `0`. So `1`,
  `1.0` and `1e0` are the same number and hash identically.

The implementation is `src/hash/jcs.rs`; `airlock::hash::jcs_blake3_hash(&value)` is the hash
above.

## Recompute a hash yourself

This is the check that was run against `fixtures/clean_telemetry_only`,
`fixtures/annotated_mode` and `fixtures/boundary_failed` (all nine payload, request and
provenance hashes in their `expected_manifest.json` files matched), using PyPI `jcs` 0.3.0 and
`blake3` 1.0.11 and no airlock code:

```python
import json, jcs, blake3

def airlock_hash(path):
    with open(path) as handle:
        document = json.load(handle)
    return "blake3:" + blake3.blake3(jcs.canonicalize(document)).hexdigest()

manifest = json.load(open("expected_manifest.json"))
assert airlock_hash("request.json") == manifest["request_payload_hash"]
assert airlock_hash("prompt_payload.json") == manifest["prompt_payload_hash"]
assert airlock_hash("prompt_provenance.json") == manifest["prompt_provenance_hash"]
```

The paths are the ones in the manifest: `replay_ref` is the request, `prompt_provenance_ref` is
the provenance, and the prompt payload is the file `airlock verify --prompt` was given.

`jcs` on PyPI is a third-party package (author titusz), not written by the RFC authors. It
reproduces every RFC 8785 vector in `fixtures/jcs` (the six reference pairs and the 24
Appendix B rows), but any library that passes those vectors works equally well. Python's
`json` module parses floats correctly rounded, as airlock does with `float_roundtrip`, and
`jcs` refuses an integer that is not exactly representable as a double (next section).

## Integers beyond 2^53

RFC 8785 writes every number as a double, so `9007199254740993` and `9007199254740992` both
become `9007199254740992`, and a library that reads numbers as doubles cannot reproduce the
exact value. RFC 8785 Appendix D says such values must be carried as JSON strings.

For the two documents a third party must recompute, airlock refuses instead of hashing:

- `airlock verify` refuses a prompt payload with `E_BAD_PROMPT` and a request payload with
  `E_BAD_REQUEST` when either contains an integer whose magnitude exceeds 2^53 (9007199254740992);
- `airlock assemble` refuses with `E_BAD_INPUT` when an input artifact puts such an integer into
  the prompt payload, before any output is written.

The refusal `detail` carries the RFC 6901 `pointer` to the number, the `number` as written,
`max_integer_magnitude`, and the `rule`. The fix is on the producer's side: write the value as a
string (for example a large `seed` or an identifier). Integers up to and including 2^53 and all
finite floats are accepted.

Airlock's own documents (provenance, manifest, policy hash input) go through the same
serializer in a total mode that writes integers beyond 2^53 as exact digits instead of
refusing. For any document without such an integer the two modes are byte-identical; the total
mode exists so that internal hashing never fails and never makes two different integers equal.

One gap to know about: an integer literal beyond `u64::MAX` (18446744073709551615) is read by
serde_json as a double, indistinguishable from a float literal, so airlock accepts it and
serializes that double (`18446744073709551616` and `18446744073709551617` both become
`18446744073709552000`). A library that keeps integer literals exact, such as Python's `json`
with `jcs`, refuses such a document instead. Keep integers within 2^53, or use strings.

## Parsing, and why `float_roundtrip` is enabled

Canonicalization starts from the parsed value, so a wrong parse is a wrong hash. serde_json
1.0.143's default float parser is not correctly rounded. Compared with Rust's `str::parse::<f64>`
(which is), on deterministic pseudo-random inputs it gave a different double for:

| Input text | Default features | With `float_roundtrip` |
| --- | --- | --- |
| shortest round-trip text of random finite doubles | 593,089 of 1,999,014 | 0 |
| 17 to 25 significant digits, random exponent | 348,427 of 1,000,000 | 0 |
| plain decimals such as `0.987654321` | 0 of 1,000,000 | 0 |

Short everyday numbers (`0.98`, `0.0`) were never affected; full-precision doubles are, by one
ULP, and a one-ULP difference changes the canonical text and therefore the hash. `Cargo.toml`
enables `float_roundtrip` on serde_json, and
`tests/jcs_conformance.rs::full_precision_floats_parse_correctly_rounded` fails if the feature
is removed. serde_json's parser also rejects `NaN`, `Infinity`, numbers that overflow a double,
and lone surrogates, which RFC 8785 requires to be errors.

## Test vectors

All under `fixtures/jcs`, with provenance and pinned BLAKE3 hashes in `SOURCES.json` (a test
checks every pinned hash, so a vector file cannot be edited to make a test pass):

| Source | What it covers | Test |
| --- | --- | --- |
| RFC 8785 sections 3.2.2 to 3.2.4 | the worked example and its byte dump | `tests/jcs_conformance.rs` |
| RFC 8785 section 3.2.3 | the UTF-16 member-sorting sample | `tests/jcs_conformance.rs` |
| RFC 8785 Appendix B | the 24-row IEEE 754 to text table, NaN and Infinity refused | `tests/jcs_conformance.rs` |
| cyberphone/json-canonicalization `testdata` (Apache-2.0, commit `32a48195`) | six published input/output pairs | `tests/jcs_conformance.rs` |
| the same repository's 100-million-line ES6 number file | `double bits,expected text` | a 140-line sample in the default run; the full file with `--ignored` |
| `golden_hashes.json` | hash stability: canonical text and BLAKE3 for four documents, computed with PyPI `jcs` and `blake3`, not airlock | `tests/jcs_conformance.rs` |
| `tests/jcs_reference.py` | an independent standard-library Python implementation, validated against the published vectors above, compared with the Rust serializer on 200,000 random doubles and 20,000 random documents (non-ASCII and astral keys, escapes, integers at the 2^53 boundary) | `tests/jcs_crosscheck.rs` |

`tests/jcs_crosscheck.rs` needs `python3`. Without it the tests print `SKIPPED` locally and fail
when the `CI` environment variable is set. Set `AIRLOCK_PYTHON` to pick another interpreter.

To run the full published number file (about 2 GB gzipped) without storing it decompressed:

```
mkfifo /tmp/es6.fifo
gzip -dc es6testfile100m.txt.gz > /tmp/es6.fifo &
AIRLOCK_JCS_ES6_FILE=/tmp/es6.fifo cargo test --release --test jcs_conformance \
    es6_published_file_matches_in_full -- --ignored --nocapture
```

## Differences from airlock.v0

Manifests through release 0.3.0 (`airlock.v0`) hashed `serde_json::to_string` of a key-sorted
value, as did the unreleased `airlock.v0.2` work before the JCS change. Strings, `null`,
booleans, integers and objects whose keys are all in the Basic Multilingual Plane below U+E000
serialize identically, so none of the committed fixture hashes changed when JCS replaced it.
The cases that differ:

- a float with an integral value: `1.0` was written `1.0`, now `1`; `-0.0` was `-0.0`, now `0`;
- floats whose exponent form differed from ECMAScript's: `1e21` was `1e21`, now `1e+21`; `1e16`
  was `1e16`, now `10000000000000000`; `0.000001` was `1e-6`, now `0.000001`;
- keys containing characters above U+FFFF alongside characters in U+E000 to U+FFFF are ordered
  by UTF-16 code units, not UTF-8;
- floats with 17 or more significant digits parse correctly rounded (`float_roundtrip`);
- payloads with integers beyond 2^53 are refused instead of hashed.

A verifier must choose the algorithm from `manifest_version`: JCS for `airlock.v0.2` and later,
the private serialization above for `airlock.v0`.
