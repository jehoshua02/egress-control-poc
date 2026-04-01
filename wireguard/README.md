# Container Egress Control PoC — WireGuard Mode

Transparent egress firewall for Docker containers. The app container has **zero proxy awareness** — no `HTTP_PROXY`, no code changes, no special SDK. All outbound traffic is routed through a WireGuard VPN tunnel to mitmproxy, which enforces a block-all/allow-explicit policy.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│  internal_net (172.30.0.0/24, no internet)              │
│                                                         │
│  ┌───────────┐    WireGuard tunnel    ┌──────────────┐  │
│  │    app     │ ─────────────────────▶│    proxy      │  │
│  │ (no proxy  │   all traffic routed  │ (mitmproxy +  │──┼──▶ internet
│  │  awareness)│   via wg0 interface   │  WireGuard)   │  │    (external_net)
│  └───────────┘                        └──────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

1. **Proxy** runs mitmproxy in WireGuard mode (`--mode wireguard@51820`), listening for VPN connections on the internal network.
2. **Config-init** (one-shot container) waits for mitmproxy to generate its WireGuard keys, then produces a client config file (`wg0.conf`).
3. **App** starts after config-init completes, sets up a WireGuard interface using the generated config, and routes all traffic through the tunnel. iptables rules on the app block non-HTTP/HTTPS ports on the tunnel interface.

The proxy intercepts all HTTP and HTTPS traffic and enforces policy via three layers.

## Enforcement Layers

| Layer | What it checks | Decryption needed? | Example |
|-------|---------------|-------------------|---------|
| **Layer 1 — SNI** | TLS ClientHello SNI field | No | Block `google.com` before TLS handshake |
| **Layer 2 — Domain/IP** | Host header, destination IP | HTTPS: yes | Block `1.1.1.1`, allow `httpbin.org` |
| **Layer 3 — URL path** | Request path after domain match | HTTPS: yes | Allow `/repos/` but block `/admin` on `api.github.com` |

TLS interception uses mitmproxy's auto-generated CA certificate, which is installed in the app container at startup.

## Policy Configuration

Edit [`proxy/scripts/enforcer.py`](proxy/scripts/enforcer.py) — the `ALLOWED_RULES` list. Default policy is **block all, allow explicit**.

Rule types:

```python
# Domain (exact or suffix match)
{"type": "domain", "value": "httpbin.org"}

# Domain with path restrictions
{"type": "domain", "value": "api.github.com",
 "paths": ["/repos/", "/users/"],
 "paths_blocked": ["/admin"]}

# Wildcard suffix (all subdomains)
{"type": "suffix", "value": ".googleapis.com"}

# IP, prefix, or CIDR
{"type": "ip",        "value": "93.184.216.34"}
{"type": "ip_prefix", "value": "140.82."}
{"type": "cidr",      "value": "10.0.0.0/8"}

# Port restriction (on any rule)
{"type": "domain", "value": "example.com", "ports": [443]}

# Regex path patterns
{"type": "domain", "value": "api.example.com",
 "paths": ["regex:^/v[0-9]+/public/"]}
```

## Prerequisites

- Docker Desktop (tested on Windows with WSL2)
- Docker Compose v2

## Quick Start

```bash
cd wireguard

# Build and start
docker compose up -d

# Watch proxy logs
docker compose logs -f proxy

# Run the test suite (24 tests)
docker exec app /bin/sh /test.sh

# Open an interactive shell in the app
docker exec -it app /bin/sh

# Try some requests from the app
curl http://httpbin.org/get          # allowed
curl https://httpbin.org/get         # allowed (TLS intercepted)
curl http://google.com/              # blocked (403)
curl https://google.com/             # blocked (SNI)
curl https://api.github.com/users/torvalds  # allowed (path rule)
curl https://api.github.com/gists    # blocked (path not in allowlist)

# View traffic in the mitmproxy web UI
# http://localhost:8081

# Tear down
docker compose down -v
```

## Test Coverage

The test suite (`app/test.sh`) runs 24 strict tests. "Blocked" means the proxy returned a `403` with `blocked_by_policy` (or killed the TLS handshake). "Allowed" means a `200` with expected content. Any other result is a FAIL.

| # | Category | Test | Expects |
|---|----------|------|---------|
| 1 | HTTP allowlist | Allowed domain (httpbin.org) | 200 |
| 2 | HTTP allowlist | Blocked domain (google.com) | 403 blocked_by_policy |
| 3 | HTTP allowlist | Blocked direct IP (1.1.1.1) | 403 blocked_by_policy |
| 4 | HTTPS allow | Allowed domain with TLS intercept | 200 |
| 5 | SNI blocking | Blocked domain (google.com) | Connection kill or 403 |
| 6 | SNI blocking | Blocked domain (twitter.com) | Connection kill or 403 |
| 7 | Path rules | Allowed path `/repos/` | 200 |
| 8 | Path rules | Blocked path `/admin` | 403 blocked_by_policy |
| 9 | Path rules | Unlisted path `/gists` | 403 blocked_by_policy |
| 10 | Path rules | Allowed path `/users/` | 200 |
| 11 | HTTP paths | All-paths-open domain | 200 |
| 12 | Port blocking | Non-HTTP port (22) | iptables DROP (timeout) |
| 13 | DNS | Resolution works | Resolves to expected IP |
| 14 | IP rules | Allowed IP (93.184.216.34) | Not blocked by policy |
| 15 | IP rules | Blocked IP (8.8.8.8) | 403 blocked_by_policy |
| 16 | IP rules | Blocked IP over HTTPS | 403 blocked_by_policy |
| 17 | Non-standard ports | HTTPS on port 8443 | iptables DROP |
| 18 | Non-standard ports | HTTP on port 8080 | iptables DROP |
| 19 | DNS behavior | Blocked domain resolves | Documents DNS-layer behavior |
| 20 | Security | Host header spoofing | 403 (DNS verification) |
| 21 | Security | Path traversal (`../`) | 403 (path normalization) |
| 22 | Security | HTTPS to raw IP (no SNI) | 403 blocked_by_policy |
| 23 | Security | Double Host header | 403 or rejected |
| 24 | Security | URL-encoded traversal (`%2e%2e`) | 403 (decoded before check) |

## Security Hardening

The enforcer includes protections against common bypass techniques:

- **Host header spoofing** — DNS-verified: the proxy resolves the Host header hostname and checks if the actual packet destination IP is in the result set. Mismatches are blocked.
- **Path traversal** — Paths are URL-decoded (`%2e%2e` -> `..`) and normalized (`posixpath.normpath`) before policy evaluation.
- **Non-HTTP port bypass** — iptables on the app's WireGuard interface only allows TCP 80, 443, and DNS (53). All other ports are dropped.
- **Non-standard HTTP ports** — Blocked at the iptables level before reaching the proxy.
- **Raw IP with no SNI** — Falls through to Layer 2, which checks against IP rules and blocks unmatched IPs.

## File Structure

```
wireguard/
├── docker-compose.yml          # Three services: proxy, config-init, app
├── proxy/
│   ├── Dockerfile              # mitmproxy + cryptography
│   ├── gen-client-conf.py      # Generates WireGuard client config from mitmproxy keys
│   └── scripts/
│       └── enforcer.py         # Policy engine (3-layer enforcement)
└── app/
    ├── Dockerfile              # Alpine + curl, wireguard-tools, iptables
    └── test.sh                 # 24-test suite
```

## Architecture Decisions

**Why WireGuard instead of iptables PREROUTING?** — Docker Desktop for Windows (WSL2) doesn't support iptables PREROUTING/REDIRECT for forwarded traffic in container network namespaces. Packets routed through a gateway container never enter the gateway's iptables PREROUTING chain. WireGuard mode sidesteps this entirely by operating at the VPN layer.

**Why `connection_strategy=lazy`?** — mitmproxy defers the upstream connection until the request is fully parsed. This allows the enforcer to inspect and block requests before any connection is made to the destination, reducing information leakage.

**Why manual WireGuard setup instead of `wg-quick`?** — `wg-quick` writes to `/proc/sys` which is read-only in Docker containers. The `sysctls` directive in docker-compose.yml sets `net.ipv4.conf.all.src_valid_mark=1` at container creation, and the entrypoint script sets up the interface and routing manually.
