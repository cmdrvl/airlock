# `airlock send` Real-Endpoint Proof (`al-331`)

Five real `airlock send` calls against `https://api.anthropic.com/v1/messages` (`claude-haiku-4-5-20251001`) over synthetic redacted spine receipts, plus one negative run blocked before transmission (`BOUNDARY_FAILED`, `sent: false`).

Verify any manifest offline:

```bash
airlock verify-manifest examples/real-send-proof/receipts/run_01_shape.manifest.json --pubkey examples/real-send-proof/signer.pub
```

## Positive run (`run_01_shape` — `STRICT_TELEMETRY_ONLY`, transmitted)

```text
AIRLOCK

Claim achieved: STRICT_TELEMETRY_ONLY
Boundary mode: TELEMETRY_ONLY

Raw document artifacts: absent
Derived filing text: absent

Bytes crossed: 431
Attestation: transmitted
Transmission: SENT to api.anthropic.com
  At: 2026-11-26T02:10:56.087Z (849 ms to the end)
  Request: 431 bytes blake3:47f32ea245712db975075cda1223956ced13c68d90f8afa7da6ad37e29176553
  Response: HTTP 200, 659 bytes blake3:b1b2527447faeda17538a5d952d481db8b2ea70dd4b64127964ac0ea3ab84bff
Signature: ed25519 by blake3:4f9206532320ec28dbb4dce25dddf21e12ab8422eecc86e4ed546f81bb416d74 (explain does not check it; run airlock verify-manifest)
Left out of the request: 1 field (values are never stored):
  - raw_document [FORBIDDEN_KEY] blake3:6725049f27d07186e826c01800c1680c1da6997b8a53321ba9e26e3265c25965

Prompt provenance:
  - 10 prompt fragments emitted
  - 10 TELEMETRY

Policy: spine_receipt_summary_v1 (blake3:1fc0e049a14b5720090c024539af2063dc155073c35131c77aad642bc0f819c3)
Manifest hash: blake3:2d2702b35eb66ad895451c6fd5cbce5041465b4799cfaa89d9aff0593fb79c1a
```

## Negative run (`run_negative_leak` — `BOUNDARY_FAILED`, not sent)

```text
AIRLOCK

Claim achieved: BOUNDARY_FAILED
Boundary mode: TELEMETRY_ONLY

Raw document artifacts: present
Derived filing text: absent

Bytes crossed: 466
Attestation: self_attested (written by airlock verify, not by a send or gate receipt)
Transmission: NOT SENT to airlock-negative-guard.invalid (CLAIM_BELOW_REQUIRED); no request body was written to a connection
  Request: 466 bytes blake3:0bb9197e4ae3cd10ea5c60a3e056427375e5a0c04d730421b62836374e344a92
Signature: ed25519 by blake3:4f9206532320ec28dbb4dce25dddf21e12ab8422eecc86e4ed546f81bb416d74 (explain does not check it; run airlock verify-manifest)
Left out of the request: not recorded (verify was not given a not-crossed inventory)

Boundary violation detected:
  - messages[1].content.matched_rule [canary_secret via forbidden_patterns[0]] sample=leaked_CANARY_SECRET_9941_ssn_123-45-6789
  - messages[0].content[0].text [canary_secret via forbidden_patterns[0]] sample={"decision_band":"ESCALATE","matched_rule":"leaked_CANARY_SECRET_9941_ssn_123-45-6789","outcome":"ES

Why strict telemetry-only was not earned:
  - messages[0].content[0].text
  - messages[1].content.matched_rule

Prompt provenance:
  - 8 prompt fragments emitted
  - 8 TELEMETRY

Policy: spine_receipt_summary_v1 (blake3:1fc0e049a14b5720090c024539af2063dc155073c35131c77aad642bc0f819c3)
Manifest hash: blake3:ba43d91cc080d12cf6f472c4df9cc14145a17196c3013cc67fa15458fcdcce45
```
