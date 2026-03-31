# Container Firewall PoC — Docker (Fully Transparent, TLS Aware)

**The application has zero proxy awareness.** No `HTTP_PROXY`, no code changes.
The app makes completely normal requests. The firewall transparently intercepts
everything and enforces a block-all, allow-explicit policy with three layers
of enforcement including HTTPS path-level inspection.

---

## Three Enforcement Layers

```
App makes a request
        │
        ▼
┌─────────────────────────────────┐
│ LAYER 1 — TLS/SNI Blocking     │   No decryption needed.
│                                 │   Reads the SNI field from
│ Is the domain in the allowlist? │   the TLS ClientHello.
│                                 │
│ ❌ NO  → kill connection        │   Connection dies before
│ ✅ YES → continue               │   TLS handshake completes.
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│ LAYER 2 — Domain/IP Allowlist   │   HTTP: always visible.
│                                 │   HTTPS: visible after TLS
│ Is destination allowed?         │   interception (CA cert).
│ (domain, IP, CIDR, port)        │
│                                 │
│ ❌ NO  → return 403             │
│ ✅ YES → continue               │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│ LAYER 3 — Path Rules            │   Only for rules that have
│                                 │   paths or paths_blocked.
│ Is the URL path allowed?        │   Requires TLS interception
│                                 │   for HTTPS.
│ ❌ NO  → return 403             │
│ ✅ YES → forward request        │
└─────────────────────────────────┘
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Host                                                          │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  internal_net (Docker: internal=true, gateway=proxy)      │  │
│  │                                                          │  │
│  │  ┌──────────────────┐       ┌─────────────────────────┐  │  │
│  │  │ app              │──────▶│ proxy (gateway)         │  │  │
│  │  │                  │ normal│                         │  │  │
│  │  │ • No HTTP_PROXY  │  TCP  │ Layer 1: SNI check      │  │  │
│  │  │ • No code changes│       │ Layer 2: domain/IP      │  │  │
│  │  │ • CA cert in     │       │ Layer 3: URL path       │  │  │
│  │  │   trust store    │       │                         │  │  │
│  │  │   (container     │       │ iptables: transparent   │  │  │
│  │  │    config, not   │       │   redirect :80→:8080    │  │  │
│  │  │    app config)   │       │   redirect :443→:8443   │──┼──▶
│  │  └──────────────────┘       └─────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  mitmproxy Web UI: http://localhost:8081                        │
└────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
docker compose up -d --build

# Watch proxy logs
docker compose logs -f proxy

# Open Web UI
open http://localhost:8081

# Run tests
docker cp scripts/test.sh app:/test.sh
docker exec -it app /bin/sh /test.sh

# Interactive shell
docker exec -it app /bin/sh
```

## HTTPS: Two Modes

### Mode 1: SNI-only (no CA cert needed)

Set `TLS_INTERCEPT = False` in `proxy/scripts/enforcer.py`.

The proxy reads the domain from the TLS SNI field and blocks/allows at the
connection level. No decryption occurs. The app doesn't need any CA cert.

**You can:** block/allow by domain name on HTTPS.
**You cannot:** see URL paths, headers, or body on HTTPS.

### Mode 2: Full TLS interception (default)

Set `TLS_INTERCEPT = True` in `proxy/scripts/enforcer.py`.

The proxy performs a man-in-the-middle on TLS connections. It terminates TLS
from the app, inspects the full HTTP request (path, headers, body), then
opens a new TLS connection to the real destination.

The app needs to trust mitmproxy's CA cert. This is handled automatically
by the `cert-init` service — the CA cert is copied to a shared volume
and installed into the app's system trust store on startup.

**You can:** block/allow by domain, IP, AND URL path on HTTPS.
**The app's code does not change.** Only the container's trust store is configured.

## Policy Configuration

Edit `proxy/scripts/enforcer.py`:

```python
ALLOWED_RULES = [
    # Allow all paths on a domain
    {"type": "domain", "value": "httpbin.org"},

    # Allow a domain with path restrictions
    {
        "type": "domain",
        "value": "api.github.com",
        "paths": ["/repos/", "/users/"],         # only these paths
        "paths_blocked": ["/admin", "/settings"], # deny these first
    },

    # Path with regex
    {
        "type": "domain",
        "value": "api.example.com",
        "paths": ["regex:^/v[0-9]+/public/"],
    },

    # Port-restricted
    {"type": "domain", "value": "internal.example.com", "ports": [443]},

    # IP-based
    {"type": "ip",        "value": "93.184.216.34"},
    {"type": "cidr",      "value": "10.0.0.0/8"},
    {"type": "ip_prefix", "value": "140.82."},
    {"type": "suffix",    "value": ".amazonaws.com"},
]
```

Path evaluation order:
1. `paths_blocked` patterns are checked first — deny takes priority
2. `paths` patterns are checked — request must match at least one
3. If neither field is present, all paths are allowed

Restart proxy after changes: `docker compose restart proxy`

## File Structure

```
container-firewall/
├── docker-compose.yml              # Networks, proxy, cert-init, app
├── proxy/
│   ├── Dockerfile                  # mitmproxy + iptables + dnsmasq
│   ├── entrypoint.sh               # Transparent redirect setup
│   ├── dnsmasq.conf                # DNS forwarder
│   └── scripts/
│       └── enforcer.py             # v2: SNI + domain/IP + path rules
├── scripts/
│   └── test.sh                     # Full test suite (HTTP + HTTPS)
└── README.md
```

## Adding Your Own App Container

Replace the `app` service image. The cert-init + shared volume handles
CA cert distribution automatically:

```yaml
  app:
    image: your-image:tag
    networks:
      internal_net:
        ipv4_address: 172.30.0.20
    dns:
      - 172.30.0.10
    depends_on:
      cert-init:
        condition: service_completed_successfully
    volumes:
      - shared-certs:/shared-certs:ro
    command:
      - /bin/sh
      - -c
      - |
        # Install CA cert (adjust for your base image's cert system)
        # Alpine:
        cp /shared-certs/ca.crt /usr/local/share/ca-certificates/mitmproxy.crt
        update-ca-certificates 2>/dev/null
        # Debian/Ubuntu: same path, same command
        # RHEL/Fedora: cp to /etc/pki/ca-trust/source/anchors/ && update-ca-trust

        exec your-actual-entrypoint
```

No `HTTP_PROXY`. No code changes. Just the CA cert in the system trust store.
