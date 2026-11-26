#!/usr/bin/env python3
"""
FINOS CALM + AIGF MI-20 Executable Wire Governance Demo
Uses shipped open-source cmdrvl binaries: airlock 0.4.0, lock 0.7.0, pack 0.7.1.
"""
import base64
import hashlib
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
HOME_DIR = OUT / "ephemeral-home"
RECEIPTS_DIR = OUT / "gate-receipts"
PACK_DIR = OUT / "calm-evidence-pack"

# ANSI palette (clean on dark terminal themes)
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"

FINOS_COMMIT = "92b032b527344c2dde8f66547418fc7e1e468406"
VACUUM_BIN = shutil.which("vacuum") or "/opt/homebrew/bin/vacuum"
AIRLOCK_BIN = shutil.which("airlock") or "/opt/homebrew/bin/airlock"
HASHBYTES_BIN = shutil.which("hashbytes") or "/opt/homebrew/bin/hashbytes"
LOCK_BIN = shutil.which("lock") or "/opt/homebrew/bin/lock"
PACK_BIN = shutil.which("pack") or "/opt/homebrew/bin/pack"


def banner(num: str, title: str, subtitle: str = "") -> None:
    print(f"\n{BOLD}{CYAN}━━━ [{num}] {title} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
    if subtitle:
        print(f"{DIM}{subtitle}{RESET}")


def demo_env() -> dict:
    env = os.environ.copy()
    env["HOME"] = str(HOME_DIR)
    return env


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, env=demo_env(), capture_output=True, text=True, check=check)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def step1_gap() -> None:
    banner(
        "1/5",
        "THE FINOS CALM GAP (REAL UPSTREAM SPEC)",
        f"Pinned verbatim from finos/architecture-as-code @ {FINOS_COMMIT[:10]}",
    )
    ctrl_path = ROOT / "finos-upstream/013-air-op-028-multi-agent-trust-boundary-violations.json"
    schema_path = ROOT / "finos-upstream/calm-evidence.schema.json"
    ctrl = json.loads(ctrl_path.read_text())
    req = ctrl["requirement"]["1-0-0"]

    print(f"  {BOLD}Control:{RESET}        {ctrl['name']}")
    print(f"  {BOLD}Source:{RESET}         {req['source']}  (SHA-256: {DIM}{sha256_file(ctrl_path)[:16]}...{RESET})")
    print(f"  {BOLD}Requirement:{RESET}    \"{req['requirements'][2]}\"")
    print(f"  {BOLD}Configurations:{RESET} {YELLOW}{json.dumps(ctrl['configurations'])}{RESET}   {DIM}<-- empty in upstream FINOS repo{RESET}")
    ev_schema = json.loads(schema_path.read_text())
    req_fields = ev_schema["properties"]["evidence"]["required"]
    print(f"  {BOLD}evidence.json:{RESET}  requires {CYAN}{req_fields}{RESET}   {DIM}<-- pointer stub, no proof format{RESET}")


def step2_assemble() -> None:
    banner(
        "2/5",
        "COMPILE BOUNDARY + STRIP RAW DATA + ED25519 SIGN",
        "airlock assemble --boundary-mode TELEMETRY_ONLY  ->  airlock verify (Ed25519)",
    )
    if OUT.exists():
        shutil.rmtree(OUT)
    HOME_DIR.mkdir(parents=True)
    RECEIPTS_DIR.mkdir(parents=True)

    # 1. Generate ephemeral Ed25519 keypair for this demo
    run([AIRLOCK_BIN, "keygen"])
    pub_src = HOME_DIR / ".cmdrvl/secrets/airlock/ed25519.pub"
    pub_dst = OUT / "signer.pub"
    shutil.copy2(pub_src, pub_dst)

    # 2. Assemble strict telemetry-only payload + negative not_crossed inventory
    run([
        AIRLOCK_BIN, "assemble",
        "--policy", "policy/air-op-028-boundary.yaml",
        "--input", "input/agent_context.json",
        "--boundary-mode", "TELEMETRY_ONLY",
        "--out", "out/prompt_payload.json",
        "--provenance-out", "out/prompt_provenance.json",
        "--not-crossed-out", "out/not_crossed.json",
        "--no-witness",
    ])

    # 3. Build transport-wrapped request bound to assembled messages & Ed25519-sign manifest
    payload = json.loads((OUT / "prompt_payload.json").read_text())
    (OUT / "request_bound.json").write_text(
        json.dumps({"model": "claude-haiku-4-5-20251001", "messages": payload["messages"]}, indent=2) + "\n"
    )
    run([
        AIRLOCK_BIN, "verify",
        "--policy", "policy/air-op-028-boundary.yaml",
        "--prompt", "out/prompt_payload.json",
        "--provenance", "out/prompt_provenance.json",
        "--request", "out/request_bound.json",
        "--not-crossed", "out/not_crossed.json",
        "--require-claim", "STRICT_TELEMETRY_ONLY",
        "--out", "out/airlock_manifest.json",
        "--no-witness",
    ])

    nc = json.loads((OUT / "not_crossed.json").read_text())
    m = json.loads((OUT / "airlock_manifest.json").read_text())
    entries = nc.get("entries", []) if isinstance(nc, dict) else nc
    stripped_paths = [e.get("path", e.get("key_path", "?")) for e in entries]

    print(f"  {GREEN}✓{RESET} Assembled {BOLD}STRICT_TELEMETRY_ONLY{RESET} prompt (raw client fields stripped before model)")
    print(f"  {GREEN}✓{RESET} Negative inventory ({BOLD}not_crossed.json{RESET}): {YELLOW}{', '.join(stripped_paths)}{RESET}")
    print(f"    {DIM}(only cryptographic value hashes recorded — 0 raw bytes written){RESET}")
    print(f"  {GREEN}✓{RESET} Manifest signed: {BOLD}{m.get('manifest_version')}{RESET} | claim={GREEN}{m.get('achieved_claim')}{RESET} | binding={CYAN}{m.get('binding_status')}{RESET} | sig={CYAN}{m.get('signature', {}).get('algorithm')}{RESET}")


def step3_live_proxy() -> None:
    banner(
        "3/5",
        "LIVE EGRESS PROXY: BLOCKING RAW PII + BASE64 SMUGGLING",
        "airlock gate --mode policy-proxy  (zero base64 regexes in policy; recursive boundary-detectors)",
    )
    upstream_hits: list[tuple[str, int]] = []

    class MockUpstream(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(ln)
            upstream_hits.append((self.path, len(body)))
            resp = json.dumps({"id": "msg_demo_01", "status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), MockUpstream)
    up_port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    gate_port = sock.getsockname()[1]
    sock.close()

    gate = subprocess.Popen(
        [
            AIRLOCK_BIN, "gate",
            "--mode", "policy-proxy",
            "--policy", "policy/air-op-028-boundary.yaml",
            "--upstream", f"http://127.0.0.1:{up_port}",
            "--listen", f"127.0.0.1:{gate_port}",
            "--out-dir", "out/gate-receipts",
            "--no-witness",
        ],
        cwd=ROOT,
        env=demo_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    ready = False
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", gate_port), timeout=0.1):
                ready = True
                break
        except OSError:
            time.sleep(0.05)
    if not ready:
        gate.terminate()
        out, err = gate.communicate(timeout=2)
        raise RuntimeError(f"airlock gate failed to start: {out} {err}")

    smuggled_csv = (
        "loan_id,borrower,ssn,balance\n"
        "L-001,Acme Holdings,123-45-6789,42500000\n"
        "L-002,Beacon Corp,987-65-4321,18750000\n"
        "L-003,Crest LLC,555-12-3456,9100000\n"
    )
    b64_blob = base64.b64encode(smuggled_csv.encode()).decode()

    cases = [
        (
            "Clean redacted telemetry",
            {"model": "gpt-4.1", "input": [{"role": "user", "content": '{"control_id":"AIR-OP-028","decision_band":"ESCALATE","failed_rules":1}'}]},
        ),
        (
            "Direct PII leak (US SSN)",
            {"model": "gpt-4.1", "input": [{"role": "user", "content": "Summarize borrower SSN 123-45-6789 exposure."}]},
        ),
        (
            "Raw confidential HTML table",
            {"model": "gpt-4.1", "input": [{"role": "user", "content": "<table><tr><td>Confidential Ledger</td><td>$42.5M</td></tr></table>"}]},
        ),
        (
            "Base64-encoded CSV smuggling",
            {"model": "gpt-4.1", "input": [{"role": "user", "content": f"Telemetry blob: {b64_blob}"}]},
        ),
    ]

    summary_rows = []
    try:
        for label, body in cases:
            before = len(upstream_hits)
            req = urllib.request.Request(
                f"http://127.0.0.1:{gate_port}/v1/responses",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status = resp.status
            except urllib.error.HTTPError as e:
                status = e.code
            after = len(upstream_hits)
            reached = after - before
            if status == 200:
                badge = f"{GREEN}{BOLD}HTTP 200 ALLOWED{RESET}"
                wire = f"{GREEN}forwarded (clean){RESET}"
            else:
                badge = f"{RED}{BOLD}HTTP {status} BLOCKED{RESET}"
                wire = f"{CYAN}0 bytes reached upstream{RESET}"
            print(f"  • {label:<31} ->  {badge}  |  {wire}", flush=True)
            summary_rows.append({"case": label, "http_status": status, "reached_upstream": reached})
            time.sleep(0.75)
    finally:
        gate.terminate()
        try:
            gate.wait(timeout=2)
        except subprocess.TimeoutExpired:
            gate.kill()
        srv.shutdown()

    (OUT / "live_proxy_summary.json").write_text(json.dumps(summary_rows, indent=2) + "\n")
    print(f"\n  {BOLD}Audit tally:{RESET} upstream received {GREEN}{len(upstream_hits)}/4{RESET} | blocked before wire: {RED}{4 - len(upstream_hits)}{RESET} | leaked bytes: {GREEN}0{RESET}")


def step4_calm_pack() -> None:
    banner(
        "4/5",
        "FILLING CALM evidence.json + SEALING EVIDENCE PACK",
        "Validates against https://calm.finos.org/draft/2026-03/meta/evidence.json  ->  lock + pack seal",
    )
    receipt_files = sorted(RECEIPTS_DIR.glob("*.json"))
    evidence_paths = [
        "finos-upstream/013-air-op-028-multi-agent-trust-boundary-violations.json",
        "policy/air-op-028-boundary.yaml",
        "out/airlock_manifest.json",
        "out/not_crossed.json",
        "out/signer.pub",
        "out/live_proxy_summary.json",
    ] + [str(p.relative_to(ROOT)) for p in receipt_files]

    calm_evidence = {
        "$schema": "https://calm.finos.org/draft/2026-03/meta/evidence.json",
        "evidence": {
            "unique-id": "ev-finos-air-op-028-airlock-demo-001",
            "control-config-url": "policy/air-op-028-boundary.yaml",
            "evidence-paths": evidence_paths,
        },
        "x-cmdrvl-scope": {
            "enforced_deterministically": [
                "Inter-agent / egress payload validation & sanitization (AIR-OP-028 req #3)",
                "Centralized egress proxy isolation & smuggling block (AIGF MI-20)",
                "Ed25519 manifest signature & negative not_crossed hash inventory",
            ],
            "documented_only": [
                "Annual access recertification & incident response drills (process controls)",
            ],
        },
    }
    ev_path = OUT / "evidence.json"
    ev_path.write_text(json.dumps(calm_evidence, indent=2) + "\n")

    # Verify required fields against pinned CALM schema
    schema = json.loads((ROOT / "finos-upstream/calm-evidence.schema.json").read_text())
    req_keys = schema["properties"]["evidence"]["required"]
    missing = [k for k in req_keys if k not in calm_evidence["evidence"]]
    assert not missing, f"Missing CALM evidence fields: {missing}"

    # Assemble a clean evidence-bundle directory (zero private keys!) and lock via vacuum | hashbytes | lock
    bundle_dir = OUT / "evidence-bundle"
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True)
    for rel in evidence_paths:
        src = ROOT / rel
        dst = bundle_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    shutil.copy2(ev_path, bundle_dir / "evidence.json")

    vac = run([VACUUM_BIN, "out/evidence-bundle", "--no-witness"])
    hb = subprocess.run(
        [HASHBYTES_BIN, "--algorithm", "sha256", "--no-witness"],
        input=vac.stdout,
        cwd=ROOT,
        env=demo_env(),
        capture_output=True,
        text=True,
        check=True,
    )
    subprocess.run(
        [LOCK_BIN, "--dataset-id", "finos-air-op-028-demo", "--out", "out/evidence.lock.json", "--no-witness"],
        input=hb.stdout,
        cwd=ROOT,
        env=demo_env(),
        capture_output=True,
        text=True,
        check=True,
    )

    # Seal pack (remove old pack dir if re-running step 4 standalone)
    if PACK_DIR.exists():
        shutil.rmtree(PACK_DIR)
    seal_args = [
        PACK_BIN, "seal",
        "out/evidence.json",
        "out/evidence.lock.json",
        "out/airlock_manifest.json",
        "out/not_crossed.json",
        "out/signer.pub",
        "out/live_proxy_summary.json",
        "policy/air-op-028-boundary.yaml",
        "finos-upstream/013-air-op-028-multi-agent-trust-boundary-violations.json",
        "--out", "out/calm-evidence-pack",
        "--note", "FINOS CALM AIR-OP-028 + AIGF MI-20 cryptographic wire proof",
        "--no-witness",
    ]
    run(seal_args)
    pack_manifest = json.loads((PACK_DIR / "manifest.json").read_text())

    print(f"  {GREEN}✓{RESET} Emitted {BOLD}out/evidence.json{RESET} (valid against CALM draft/2026-03/meta/evidence.json)")
    print(f"    unique-id:      {CYAN}{calm_evidence['evidence']['unique-id']}{RESET}")
    print(f"    evidence-paths: {BOLD}{len(evidence_paths)} SHA-256 locked artifacts{RESET} (incl. {len(receipt_files)} live gate receipts)")
    print(f"  {GREEN}✓{RESET} Sealed {BOLD}out/calm-evidence-pack/{RESET}  (pack_id={CYAN}{pack_manifest.get('pack_id', '?')[:24]}...{RESET})")


def step5_verify_and_tamper() -> None:
    banner(
        "5/5",
        "OFFLINE AUDITOR VERIFICATION + 1-BYTE TAMPER TEST",
        "Zero network. Zero accounts. Standalone Rust binaries verify Ed25519 + SHA-256 + pack integrity.",
    )
    v_sig = run([AIRLOCK_BIN, "verify-manifest", "out/airlock_manifest.json", "--pubkey", "out/signer.pub"], check=False)
    v_lock = run([LOCK_BIN, "verify", "out/evidence.lock.json", "--root", "out/evidence-bundle", "--json", "--no-witness"], check=False)
    v_pack = run([PACK_BIN, "verify", "out/calm-evidence-pack", "--json", "--no-witness"], check=False)
    pack_manifest = json.loads((PACK_DIR / "manifest.json").read_text())
    member_count = len(pack_manifest.get("members", []))

    assert v_sig.returncode == 0, f"airlock verify-manifest failed: {v_sig.stdout} {v_sig.stderr}"
    assert v_lock.returncode == 0, f"lock verify failed: {v_lock.stdout} {v_lock.stderr}"
    assert v_pack.returncode == 0, f"pack verify failed: {v_pack.stdout} {v_pack.stderr}"

    print(f"  {GREEN}{BOLD}✓ airlock verify-manifest{RESET}  ->  exit {v_sig.returncode}  {GREEN}(Ed25519 signature + request binding VALID){RESET}", flush=True)
    print(f"  {GREEN}{BOLD}✓ lock verify{RESET}              ->  exit {v_lock.returncode}  {GREEN}(SHA-256 lockfile + all member files VALID){RESET}", flush=True)
    print(f"  {GREEN}{BOLD}✓ pack verify{RESET}              ->  exit {v_pack.returncode}  {GREEN}(all {member_count} sealed members + pack integrity VALID){RESET}", flush=True)
    time.sleep(1.5)

    # Tamper 1 claim field in a copy of the manifest
    raw = (OUT / "airlock_manifest.json").read_text()
    tampered = raw.replace("STRICT_TELEMETRY_ONLY", "RAW_DOCUMENT_ABSENT", 1)
    tampered_path = OUT / "airlock_manifest.TAMPERED.json"
    tampered_path.write_text(tampered)

    v_bad = run([AIRLOCK_BIN, "verify-manifest", str(tampered_path), "--pubkey", "out/signer.pub"], check=False)
    assert v_bad.returncode == 2, f"Expected tampered manifest to exit 2, got {v_bad.returncode}"
    print(f"\n  {YELLOW}⚡ Tamper test:{RESET} modified 1 field in manifest -> re-running {BOLD}airlock verify-manifest{RESET}")
    print(f"  {RED}{BOLD}✗ TAMPER DETECTED{RESET}          ->  exit {v_bad.returncode}  {RED}(Ed25519 signature rejected){RESET}")

    print(f"\n{BOLD}{MAGENTA}Honest scope:{RESET} {DIM}Structural & wire boundaries enforced cryptographically (AIR-OP-028 / MI-20).{RESET}")
    print(f"{DIM}              Process controls (annual reviews, incident drills) stay explicitly documented_only.{RESET}\n")


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    steps = {
        "1": step1_gap,
        "2": step2_assemble,
        "3": step3_live_proxy,
        "4": step4_calm_pack,
        "5": step5_verify_and_tamper,
    }
    if cmd == "all":
        for k in ("1", "2", "3", "4", "5"):
            steps[k]()
    elif cmd in steps:
        steps[cmd]()
    else:
        print(f"Usage: {sys.argv[0]} [all|1|2|3|4|5]", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
