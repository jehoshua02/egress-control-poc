"""
Container Firewall — Transparent Enforcer (v2)

Three enforcement layers:

  LAYER 1 — TLS ClientHello / SNI (no decryption needed)
    Blocks HTTPS connections by domain BEFORE TLS handshake completes.
    Works without CA cert injection. Cannot see URL paths.

  LAYER 2 — Domain / IP allowlist (HTTP and decrypted HTTPS)
    Blocks by domain, IP, CIDR, suffix. Works on HTTP always.
    On HTTPS, requires TLS interception (CA cert in app container).

  LAYER 3 — Path rules (HTTP and decrypted HTTPS)
    Allows or blocks specific URL paths within an allowed domain.
    e.g., allow api.github.com/repos/* but block api.github.com/admin/*
    Requires TLS interception for HTTPS.

The app has no knowledge of this proxy.
"""

import mitmproxy.http
from mitmproxy import ctx, tls
import json
import re
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# TLS INTERCEPTION MODE
# ═══════════════════════════════════════════════════════════════
# True  = decrypt HTTPS for full L7 inspection (path, headers, body)
#         Requires CA cert installed in the app container.
# False = SNI-only blocking — no decryption, no CA cert needed,
#         but can only see the domain name, not path/body.
# ═══════════════════════════════════════════════════════════════
TLS_INTERCEPT = True

# ═══════════════════════════════════════════════════════════════
# ALLOWLIST RULES
# ═══════════════════════════════════════════════════════════════
# DEFAULT: BLOCK ALL. Only matching rules are permitted.
#
# Rule types:
#   domain   — exact or suffix match on hostname
#   suffix   — wildcard suffix (e.g. ".amazonaws.com")
#   ip       — exact IP match
#   ip_prefix— IP prefix match
#   cidr     — CIDR range match
#
# Optional fields on any rule:
#   ports         — list of allowed ports (default: all)
#   paths         — list of allowed path patterns (prefix or regex:)
#                   If set, ONLY these paths are allowed on this domain.
#                   If not set, all paths are allowed.
#   paths_blocked — list of path patterns to DENY (checked first)
# ═══════════════════════════════════════════════════════════════

ALLOWED_RULES = [
    # ── Basic domain allow (all paths, all ports) ──
    {
        "type": "domain",
        "value": "httpbin.org",
    },
    {
        "type": "domain",
        "value": "example.com",
    },
    {
        "type": "domain",
        "value": "dl-cdn.alpinelinux.org",
    },

    # ── Domain with path restrictions ──
    # Allow api.github.com but only specific path prefixes
    # (path enforcement requires TLS_INTERCEPT = True for HTTPS)
    {
        "type": "domain",
        "value": "api.github.com",
        "paths": [
            "/repos/",
            "/users/",
            "/orgs/",
        ],
        "paths_blocked": [
            "/admin",
            "/settings",
        ],
    },

    # ── Domain restricted to specific ports ──
    # {"type": "domain", "value": "internal-api.example.com", "ports": [443]},

    # ── Suffix match (all subdomains) ──
    # {"type": "suffix", "value": ".googleapis.com"},

    # ── IP-based rules ──
    # {"type": "ip",        "value": "93.184.216.34"},
    # {"type": "ip_prefix", "value": "140.82."},
    # {"type": "cidr",      "value": "93.184.216.0/24"},

    # ── Path with regex ──
    # {
    #     "type": "domain",
    #     "value": "api.example.com",
    #     "paths": ["regex:^/v[0-9]+/public/"],
    #     "paths_blocked": ["regex:^/v[0-9]+/admin/"],
    # },
]


# ═══════════════════════════════════════════════════════════════
# IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════

def _ip_in_cidr(ip_str, cidr_str):
    try:
        network, prefix_len = cidr_str.split("/")
        prefix_len = int(prefix_len)
        def ip_to_int(ip):
            p = ip.split(".")
            return (int(p[0]) << 24) + (int(p[1]) << 16) + (int(p[2]) << 8) + int(p[3])
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        return (ip_to_int(ip_str) & mask) == (ip_to_int(network) & mask)
    except Exception:
        return False


def _match_domain(host, rule):
    rtype = rule["type"]
    value = rule["value"]
    if rtype == "domain":
        return host == value or host.endswith("." + value)
    elif rtype == "suffix":
        return host.endswith(value)
    return False


def _match_ip(ip_address, rule):
    if not ip_address or ip_address == "unresolved":
        return False
    rtype = rule["type"]
    value = rule["value"]
    if rtype == "ip":
        return ip_address == value
    elif rtype == "ip_prefix":
        return ip_address.startswith(value)
    elif rtype == "cidr":
        return _ip_in_cidr(ip_address, value)
    return False


def _match_host_or_ip(host, ip_address, rule):
    rtype = rule["type"]
    if rtype in ("domain", "suffix"):
        return _match_domain(host, rule)
    elif rtype in ("ip", "ip_prefix", "cidr"):
        return _match_ip(ip_address, rule)
    return False


def _check_path(path, rule):
    """Check path restrictions. Returns (allowed, reason)."""
    if "paths" not in rule and "paths_blocked" not in rule:
        return True, "all paths"

    # Blocked paths take priority
    for pattern in rule.get("paths_blocked", []):
        if pattern.startswith("regex:"):
            if re.search(pattern[6:], path):
                return False, f"path blocked (regex: {pattern[6:]})"
        else:
            if path == pattern or path.startswith(pattern):
                return False, f"path blocked ({pattern})"

    # Check allowed paths
    if "paths" in rule:
        for pattern in rule["paths"]:
            if pattern.startswith("regex:"):
                if re.search(pattern[6:], path):
                    return True, f"path match (regex: {pattern[6:]})"
            else:
                if path == pattern or path.startswith(pattern):
                    return True, f"path match ({pattern})"
        return False, "path not in allowlist"

    # Only paths_blocked was defined, and we passed it
    return True, "path not blocked"


def _check_allowed(host, ip_address, port, path=None):
    """Full check: destination + port + path. Returns (allowed, reason)."""
    for rule in ALLOWED_RULES:
        if "ports" in rule and port not in rule["ports"]:
            continue
        if not _match_host_or_ip(host, ip_address, rule):
            continue

        # Destination matches — check path
        if path is not None and ("paths" in rule or "paths_blocked" in rule):
            path_ok, path_reason = _check_path(path, rule)
            if path_ok:
                return True, f"{rule['type']}:{rule['value']} ({path_reason})"
            else:
                return False, f"{rule['type']}:{rule['value']} ({path_reason})"

        return True, f"{rule['type']}:{rule['value']}"

    return False, "no matching rule"


def _check_sni_allowed(sni):
    """SNI-only check (Layer 1). Domain rules only, no IP/path."""
    for rule in ALLOWED_RULES:
        if rule["type"] in ("domain", "suffix"):
            if _match_domain(sni, rule):
                return True, f"{rule['type']}:{rule['value']}"
    return False, "no matching domain rule"


class TransparentEnforcer:
    def __init__(self):
        path_rules = sum(1 for r in ALLOWED_RULES if "paths" in r or "paths_blocked" in r)
        ctx.log.info("╔══════════════════════════════════════════════════╗")
        ctx.log.info("║  Transparent Enforcer v2                         ║")
        ctx.log.info("║  Policy: BLOCK ALL — allow explicit only         ║")
        ctx.log.info(f"║  Rules: {len(ALLOWED_RULES)} destination, {path_rules} with path filters    ║")
        tls_status = "ON — full L7" if TLS_INTERCEPT else "OFF — SNI only"
        ctx.log.info(f"║  TLS interception: {tls_status:<29s}║")
        ctx.log.info("╚══════════════════════════════════════════════════╝")

    # ─────────────────────────────────────────────
    # LAYER 1: TLS ClientHello — SNI-based blocking
    # Fires BEFORE TLS handshake. No decryption needed.
    # ─────────────────────────────────────────────
    def tls_clienthello(self, data: tls.ClientHelloData):
        sni = data.context.client.sni
        ts = datetime.now().strftime("%H:%M:%S")

        if not sni:
            ctx.log.info(f"⚠️  [{ts}] TLS no SNI — deferring to L2")
            return

        allowed, reason = _check_sni_allowed(sni)

        if not allowed:
            ctx.log.warn(f"🚫 [{ts}] TLS/SNI BLOCK  {sni}  ({reason})")
            # Refuse to establish TLS — kills the connection
            data.ignore_connection = False
            data.establish_server_tls = False
            data.context.client.error = f"Blocked by SNI policy: {sni}"
            return

        ctx.log.info(f"🔒 [{ts}] TLS/SNI pass   {sni}  ({reason})")

        if not TLS_INTERCEPT:
            # SNI-only mode: verified domain is allowed, pass through
            # without intercepting/decrypting the TLS connection
            data.ignore_connection = True

    # ─────────────────────────────────────────────
    # LAYER 2+3: HTTP request — domain/IP + path
    # Fires for all HTTP and (when TLS_INTERCEPT=True) HTTPS.
    # ─────────────────────────────────────────────
    def request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        port = flow.request.port
        method = flow.request.method
        path = flow.request.path
        scheme = flow.request.scheme
        ts = datetime.now().strftime("%H:%M:%S")

        ip_address = (
            flow.server_conn.ip_address[0]
            if flow.server_conn and flow.server_conn.ip_address
            else "unresolved"
        )

        allowed, reason = _check_allowed(host, ip_address, port, path)

        if allowed:
            ctx.log.info(
                f"✅ [{ts}] ALLOW  {scheme.upper()} {method} "
                f"{host}:{port}{path}  (ip={ip_address}, {reason})"
            )
        else:
            ctx.log.warn(
                f"🚫 [{ts}] BLOCK  {scheme.upper()} {method} "
                f"{host}:{port}{path}  (ip={ip_address}, {reason})"
            )
            flow.response = mitmproxy.http.Response.make(
                403,
                json.dumps({
                    "error": "blocked_by_policy",
                    "host": host,
                    "ip": ip_address,
                    "port": port,
                    "path": path,
                    "scheme": scheme,
                    "reason": reason,
                    "message": "Outbound request blocked by container firewall.",
                }, indent=2),
                {"Content-Type": "application/json"},
            )

    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        if flow.response:
            ts = datetime.now().strftime("%H:%M:%S")
            host = flow.request.pretty_host
            status = flow.response.status_code
            size = len(flow.response.content) if flow.response.content else 0
            ctx.log.info(f"   ↳ [{ts}] {status} ({size}B) from {host}")


addons = [TransparentEnforcer()]
