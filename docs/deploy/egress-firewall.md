# Egress firewall: make the gate the only route

`airlock gate` attests what it forwards. A host firewall turns that into
enforcement: model-provider traffic can leave the machine **only** through the
gate, so nothing reaches the provider without passing a manifest match (or the
policy screen).

This page gives example rules. Airlock does not install, load or manage any
firewall rule, and nothing here is automated. Read the rules, adapt the account
names and port, syntax-check them (`nft -c -f FILE` on Linux, `pfctl -nf FILE`
on macOS) and load them yourself.

## The model

Three roles, identified by operating-system account:

| Role | Account | What it may do |
| ---- | ------- | -------------- |
| Agent | `agent` | Run the SDK or coding agent. May reach the gate on loopback and nothing else off the box. |
| Gate | `airlock-gate` (`_airlockgate` on macOS) | Run `airlock gate`. May open outbound TLS to the provider. |
| Everyone else | any | Unconstrained in the narrow profile; blocked from port 443 in the host-wide profile. |

Firewalls match the **account that owns the socket**, not the program. So "only
from the gate binary" means "only from the account that runs the gate binary".
Anything that can run as that account, and root, can open a provider connection
without the gate. Keep the gate account non-login and free of other duties.

## 1. Run the gate as its own account

```sh
# Linux example; on macOS create a role account such as _airlockgate instead.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin airlock-gate
```

Start the gate as that account. The gate only ever binds loopback (it refuses a
non-loopback `--listen`) and writes its receipts and witness records as the
account that runs it, so give that account a writable `--out-dir`.

```bash
airlock gate --mode strict-manifest \
  --manifest-dir /var/lib/airlock/manifests \
  --upstream https://api.openai.com \
  --listen 127.0.0.1:8787 \
  --out-dir /var/lib/airlock/gate
```

```bash
airlock gate --mode policy-proxy \
  --policy /etc/airlock/policy.yaml \
  --upstream https://api.anthropic.com \
  --listen 127.0.0.1:8787 \
  --out-dir /var/lib/airlock/gate
```

Strict-manifest mode can also require a minimum claim and cap the request body.
`--require-claim` takes `RAW_DOCUMENT_ABSENT` or `STRICT_TELEMETRY_ONLY`; a
request whose manifest claims less is denied. `--max-request-bytes` defaults to
33554432 (32 MiB) in strict-manifest mode. Policy-proxy mode keeps its 4194304
byte scan limit as the default and refuses a larger value at startup. Each
in-flight request holds its body, and its canonical copy, in memory, so size the
cap against up to 32 concurrent requests.

```bash
airlock gate --mode strict-manifest \
  --manifest-dir /var/lib/airlock/manifests \
  --require-claim STRICT_TELEMETRY_ONLY \
  --max-request-bytes 8388608 \
  --upstream https://api.openai.com \
  --listen 127.0.0.1:8787 \
  --out-dir /var/lib/airlock/gate
```

`--upstream` is an origin only (scheme and host, no path). The gate appends the
request path it receives, so SDK base URLs keep their API prefix:

```sh
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
```

Use the literal `127.0.0.1`, not `localhost`: `localhost` may resolve to `::1`
first, and the rules below name the IPv4 address the gate listens on.

### Proxy environment variables

The gate's upstream client reads `ALL_PROXY`, `HTTPS_PROXY` and `NO_PROXY` from
**its own environment**. If any of them is set for the gate account, the gate
sends upstream traffic to that proxy, not to the provider, and the firewall must
allow the proxy instead. Start the gate with those variables unset unless you
mean to chain it behind a proxy.

## 2a. Narrow profile (recommended): confine the agent account

The agent may reach the gate and nothing else outside the process. Every other
account is untouched.

### Linux (nftables)

```nft
table inet airlock_egress {
    chain output {
        type filter hook output priority 0; policy accept;

        # Only the agent account is constrained.
        meta skuid != "agent" accept

        # The agent may talk to the gate on loopback.
        ip daddr 127.0.0.1 tcp dport 8787 accept

        # Everything else the agent sends is dropped (TCP, UDP/QUIC, DNS, IPv6).
        counter drop
    }
}
```

### macOS (pf)

Save as `/etc/pf.anchors/airlock`:

```pf
agent_user = "agent"

pass out quick on lo0 proto tcp from any to 127.0.0.1 port 8787 user $agent_user
block drop out quick all user $agent_user
```

Reference the anchor from `/etc/pf.conf`, then check and enable:

```pf
anchor "airlock"
load anchor "airlock" from "/etc/pf.anchors/airlock"
```

```sh
sudo pfctl -nf /etc/pf.conf   # syntax check only
sudo pfctl -ef /etc/pf.conf   # load and enable
```

## 2b. Host-wide profile: only the gate account may open outbound 443

This is the strict form: no account except the gate may make an outbound TLS
connection on 443, including root's other jobs (package updates, other tools).
Expect to add exceptions.

### Linux (nftables)

```nft
table inet airlock_egress_all {
    chain output {
        type filter hook output priority 0; policy accept;

        oifname "lo" accept
        meta skuid "airlock-gate" accept

        tcp dport 443 drop
        udp dport 443 drop   # QUIC / HTTP/3
    }
}
```

### macOS (pf)

```pf
gate_user = "_airlockgate"

pass out quick on lo0 all
pass out quick proto tcp from any to any port 443 user $gate_user
block drop out quick proto { tcp, udp } from any to any port 443
```

## 3. Check it from the agent account

Run these as the `agent` account. The first must fail; the others must reach the
gate.

```sh
# Direct provider connection: must time out or be refused, never print a status.
sudo -u agent curl -m 5 -sS -o /dev/null -w '%{http_code}\n' https://api.openai.com/

# Through the gate, strict-manifest mode, body whose hash has no manifest: HTTP 403.
sudo -u agent curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'content-type: application/json' -d '{"messages":[]}' \
  http://127.0.0.1:8787/v1/chat/completions

# The gate accepts POST only: any other method gets 405.
sudo -u agent curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/v1/models

# Liveness: HTTP 200 with the mode and what the gate is enforcing.
sudo -u agent curl -sS http://127.0.0.1:8787/airlock/health
```

`GET /airlock/health` is answered by the gate itself: it contacts no upstream
and writes no receipt or witness record, so a supervisor can poll it. The path
is reserved for every method; a POST to it is a 405 and is never forwarded.

A request denied by the gate leaves a receipt in `--out-dir` and a witness
record; a request forwarded to the provider leaves a receipt with the response
hash and upstream status.

## 4. Read the refusals and receipts

A refused request gets a JSON body (`airlock.gate_refusal.v1`) whose `code` says
why:

| Code | HTTP | Meaning |
| ---- | ---- | ------- |
| `E_GATE_DENIED` | 403 | Strict-manifest mode did not forward the request: no bound manifest matches its canonical hash, the manifest claims less than `--require-claim`, the body is unreadable, malformed or over `--max-request-bytes`, or the request target is invalid. |
| `BOUNDARY_FAILED` | 403 | Policy-proxy mode found something in the request, or could not screen it. |
| `UPSTREAM_UNAVAILABLE` | 502 | The gate admitted the request but the upstream could not be reached or did not answer within `--timeout-seconds`. |
| `GATE_BUSY` | 503 | The gate already has 32 requests in flight. |

Each proxied request leaves an `airlock.gate.v1` receipt in `--out-dir`: the
request and response byte counts and hashes, the matched manifest, and, when a
configured limit stopped the request, a `limit` object naming
`max_request_bytes` or `timeout_seconds` with the configured value. Authorization
and provider key headers are forwarded to the provider but never written to a
receipt or witness record. To read a receipt:

```sh
airlock explain --manifest /var/lib/airlock/gate/RECEIPT.json
```

## What this does not give you

- It does not stop anything running as the gate account, or as root.
- It constrains outbound traffic from this host only; it says nothing about
  other machines, containers with their own network namespace, or a VPN or
  proxy that the agent account can already reach on an allowed address.
- A request the gate forwards is attested by its receipt; the firewall only
  guarantees that forwarded requests are the only ones that left.
- If the upstream ends a response early, the receipt carries a
  `GATE_STREAM_INTERRUPTED` finding, but the gate does not close the client's
  connection: the client waits until its own timeout (known gap, tracked on
  al-3pz as G14). Set a timeout in the agent's SDK.
