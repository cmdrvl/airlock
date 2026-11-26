#!/usr/bin/env python3
"""Run 5 real `airlock send` proofs + 1 negative blocked run for al-331.

Reads ANTHROPIC_API_KEY from the environment — never prints, logs, or
writes the credential to disk. Uses repo-relative paths so committed
manifests contain portable `replay_ref` and `prompt_provenance_ref` paths.
"""
import json
import os
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
os.chdir(REPO_ROOT)

ROOT = "examples/real-send-proof"
INPUTS_DIR = f"{ROOT}/inputs"
RECEIPTS_DIR = f"{ROOT}/receipts"
os.makedirs(INPUTS_DIR, exist_ok=True)
os.makedirs(RECEIPTS_DIR, exist_ok=True)

SYNTHETIC_INPUTS = {
    "run_01_shape": {
        "tool": "shape",
        "outcome": "COMPATIBLE",
        "summary": {"columns_common": 11, "overlap_ratio": 1.0, "rows_old": 7, "rows_new": 7, "key_overlap": 6},
        "raw_document": "STRIPPED_BY_AIRLOCK: private loan schedule never crosses",
    },
    "run_02_rvl": {
        "tool": "rvl",
        "outcome": "REAL_CHANGE",
        "summary": {"numeric_cells_checked": 18, "numeric_cells_changed": 6, "top_2_share": 0.996},
        "raw_rows": ["STRIPPED_BY_AIRLOCK: raw rows stay local"],
    },
    "run_03_verify": {
        "tool": "verify",
        "outcome": "FAIL",
        "summary": {"total_rules": 3, "passed_rules": 2, "failed_rules": 1, "severity_band": "ERROR_PRESENT"},
        "raw_document": "STRIPPED_BY_AIRLOCK: failing borrower details stay local",
    },
    "run_04_assess": {
        "tool": "assess",
        "outcome": "ESCALATE",
        "decision_band": "ESCALATE",
        "matched_rule": "verify_fail_escalate",
        "risk_factors": [{"code": "VERIFY_FAIL"}],
    },
    "run_05_redline": {
        "tool": "redline",
        "outcome": "CHANGES_FOUND",
        "summary": {"total_hunks": 6, "semantic_hunks": 4, "formatting_only_hunks": 2, "numeric_changed_hunks": 2},
        "raw_document": "STRIPPED_BY_AIRLOCK: full filing html stays local",
    },
}

NEGATIVE_INPUT = {
    "tool": "assess",
    "outcome": "ESCALATE",
    "decision_band": "ESCALATE",
    "matched_rule": "leaked_CANARY_SECRET_9941_ssn_123-45-6789",
    "risk_factors": [{"code": "VERIFY_FAIL"}],
}

for name, payload in SYNTHETIC_INPUTS.items():
    with open(os.path.join(INPUTS_DIR, f"{name}.json"), "w") as f:
        json.dump(payload, f, indent=2)
with open(os.path.join(INPUTS_DIR, "run_negative_leak.json"), "w") as f:
    json.dump(NEGATIVE_INPUT, f, indent=2)

env = os.environ.copy()
if not env.get("ANTHROPIC_API_KEY"):
    sys.exit("ANTHROPIC_API_KEY must be set in the environment")

# Ensure Ed25519 signing key exists in ~/.cmdrvl/secrets/airlock/ (never overwrites existing)
pub_path = os.path.expanduser("~/.cmdrvl/secrets/airlock/ed25519.pub")
if not os.path.exists(pub_path):
    kg = subprocess.run(["/opt/homebrew/bin/airlock", "keygen"], env=env, capture_output=True, text=True)
    if kg.returncode != 0:
        sys.exit(f"airlock keygen failed: {kg.stdout} {kg.stderr}")
    print("keygen:", kg.stdout.strip())
shutil.copyfile(pub_path, os.path.join(ROOT, "signer.pub"))

policy = os.path.join(ROOT, "policy.yaml")
sys_prompt = os.path.join(ROOT, "system_prompt.txt")
transport = os.path.join(ROOT, "transport.json")

# Run 5 positive real airlock send calls (witness enabled by default!)
for name in sorted(SYNTHETIC_INPUTS.keys()):
    inp = os.path.join(INPUTS_DIR, f"{name}.json")
    prompt_out = os.path.join(RECEIPTS_DIR, f"{name}.prompt.json")
    prov_out = os.path.join(RECEIPTS_DIR, f"{name}.provenance.json")
    nc_out = os.path.join(RECEIPTS_DIR, f"{name}.not_crossed.json")
    req_out = os.path.join(RECEIPTS_DIR, f"{name}.request.json")
    resp_out = os.path.join(RECEIPTS_DIR, f"{name}.response.json")
    man_out = os.path.join(RECEIPTS_DIR, f"{name}.manifest.json")

    asm = subprocess.run(
        [
            "/opt/homebrew/bin/airlock", "assemble",
            "--policy", policy,
            "--input", inp,
            "--system-prompt", sys_prompt,
            "--boundary-mode", "TELEMETRY_ONLY",
            "--out", prompt_out,
            "--provenance-out", prov_out,
            "--not-crossed-out", nc_out,
        ],
        env=env, capture_output=True, text=True,
    )
    if asm.returncode != 0:
        sys.exit(f"assemble {name} failed ({asm.returncode}): {asm.stdout} {asm.stderr}")

    snd = subprocess.run(
        [
            "/opt/homebrew/bin/airlock", "send",
            "--policy", policy,
            "--prompt", prompt_out,
            "--provenance", prov_out,
            "--transport", transport,
            "--not-crossed", nc_out,
            "--require-claim", "STRICT_TELEMETRY_ONLY",
            "--request-out", req_out,
            "--response-out", resp_out,
            "--out", man_out,
        ],
        env=env, capture_output=True, text=True,
    )
    if snd.returncode != 0:
        sys.exit(f"send {name} failed ({snd.returncode}): {snd.stdout} {snd.stderr}")

    m = json.load(open(man_out))
    tx = m.get("transmission") or {}
    vm = subprocess.run(
        ["/opt/homebrew/bin/airlock", "verify-manifest", man_out, "--pubkey", os.path.join(ROOT, "signer.pub")],
        env=env, capture_output=True, text=True,
    )
    if vm.returncode != 0:
        sys.exit(f"verify-manifest {name} failed: {vm.stdout} {vm.stderr}")
    print(
        f"[PASS {name}] attestation={m.get('attestation')} claim={m.get('achieved_claim')} "
        f"sent={tx.get('sent')} status={tx.get('response_status')} latency_ms={tx.get('latency_ms')} sig=OK"
    )

# Run 1 negative run (forbidden canary + SSN inside allowed field -> BOUNDARY_FAILED, sent=false, exit 1)
neg_name = "run_negative_leak"
neg_inp = os.path.join(INPUTS_DIR, f"{neg_name}.json")
neg_prompt = os.path.join(RECEIPTS_DIR, f"{neg_name}.prompt.json")
neg_prov = os.path.join(RECEIPTS_DIR, f"{neg_name}.provenance.json")
neg_req = os.path.join(RECEIPTS_DIR, f"{neg_name}.request.json")
neg_man = os.path.join(RECEIPTS_DIR, f"{neg_name}.manifest.json")

# Point negative run at .invalid host as defense-in-depth so even a hypothetical bug could never transmit
neg_transport = os.path.join(ROOT, "transport_negative.json")
t_obj = json.load(open(transport))
t_obj["url"] = "https://airlock-negative-guard.invalid/v1/messages"
with open(neg_transport, "w") as f:
    json.dump(t_obj, f, indent=2)

subprocess.check_call(
    [
        "/opt/homebrew/bin/airlock", "assemble",
        "--policy", policy,
        "--input", neg_inp,
        "--system-prompt", sys_prompt,
        "--boundary-mode", "TELEMETRY_ONLY",
        "--out", neg_prompt,
        "--provenance-out", neg_prov,
    ],
    env=env, stdout=subprocess.DEVNULL,
)
neg_snd = subprocess.run(
    [
        "/opt/homebrew/bin/airlock", "send",
        "--policy", policy,
        "--prompt", neg_prompt,
        "--provenance", neg_prov,
        "--transport", neg_transport,
        "--require-claim", "RAW_DOCUMENT_ABSENT",
        "--request-out", neg_req,
        "--out", neg_man,
    ],
    env=env, capture_output=True, text=True,
)
nm = json.load(open(neg_man))
ntx = nm.get("transmission") or {}
nvm = subprocess.run(
    ["/opt/homebrew/bin/airlock", "verify-manifest", neg_man, "--pubkey", os.path.join(ROOT, "signer.pub")],
    env=env, capture_output=True, text=True,
)
print(
    f"[NEG  {neg_name}] exit={neg_snd.returncode} claim={nm.get('achieved_claim')} "
    f"sent={ntx.get('sent')} error={ntx.get('error')} sig_exit={nvm.returncode}"
)
assert neg_snd.returncode == 1 and nm.get("achieved_claim") == "BOUNDARY_FAILED" and ntx.get("sent") is False

# Capture plain `airlock explain --manifest` + JSON output
exp_txt = subprocess.check_output(
    ["/opt/homebrew/bin/airlock", "explain", "--manifest", os.path.join(RECEIPTS_DIR, "run_01_shape.manifest.json")],
    env=env, text=True,
)
exp_neg = subprocess.check_output(
    ["/opt/homebrew/bin/airlock", "explain", "--manifest", neg_man],
    env=env, text=True,
)
with open(os.path.join(ROOT, "EXPLAIN.md"), "w") as f:
    f.write("# `airlock send` Real-Endpoint Proof (`al-331`)\n\n")
    f.write("Five real `airlock send` calls against `https://api.anthropic.com/v1/messages` (`claude-haiku-4-5-20251001`) over synthetic redacted spine receipts, plus one negative run blocked before transmission (`BOUNDARY_FAILED`, `sent: false`).\n\n")
    f.write("Verify any manifest offline:\n\n```bash\n")
    f.write("airlock verify-manifest examples/real-send-proof/receipts/run_01_shape.manifest.json --pubkey examples/real-send-proof/signer.pub\n")
    f.write("```\n\n")
    f.write("## Positive run (`run_01_shape` — `STRICT_TELEMETRY_ONLY`, transmitted)\n\n```text\n")
    f.write(exp_txt.strip() + "\n```\n\n")
    f.write("## Negative run (`run_negative_leak` — `BOUNDARY_FAILED`, not sent)\n\n```text\n")
    f.write(exp_neg.strip() + "\n```\n")

# Verify witness ledger recorded the airlock entries
wit = subprocess.check_output(
    ["/opt/homebrew/bin/airlock", "witness", "query", "--tool", "airlock", "--limit", "10", "--json"],
    env=env, text=True,
)
wit_recs = json.loads(wit)
print(f"[WITNESS] airlock witness query returned {len(wit_recs)} recent records")
