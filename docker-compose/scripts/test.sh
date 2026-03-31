#!/bin/sh
# =============================================================================
# Container Firewall v2 — Test Suite
# =============================================================================
# Tests all three enforcement layers:
#   Layer 1: TLS/SNI blocking (domain, no decryption)
#   Layer 2: Domain/IP allowlist (HTTP + decrypted HTTPS)
#   Layer 3: Path-level rules (HTTP + decrypted HTTPS)
#
# Run:  docker exec -it app /bin/sh /test.sh
# =============================================================================

echo "╔════════════════════════════════════════════════════════╗"
echo "║  Container Firewall v2 — Full Test Suite               ║"
echo "║  App has ZERO proxy awareness. Normal requests only.   ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# ── Verify no proxy env vars ──
echo "── Environment ──"
echo "  HTTP_PROXY:  ${HTTP_PROXY:-(not set) ✅}"
echo "  HTTPS_PROXY: ${HTTPS_PROXY:-(not set) ✅}"

# ── Verify CA cert is installed ──
if [ -f /usr/local/share/ca-certificates/mitmproxy.crt ]; then
    echo "  CA cert:     installed ✅ (TLS interception enabled)"
else
    echo "  CA cert:     not found ⚠️  (HTTPS path tests will fail)"
fi
echo ""

apk add --no-cache curl 2>/dev/null | tail -1
echo ""

# ═════════════════════════════════════════════
# LAYER 2: HTTP domain/IP tests
# ═════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════"
echo "  LAYER 2 — HTTP Domain/IP Allowlist"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "── TEST 1: HTTP allowed domain ──"
echo "   curl http://httpbin.org/get"
R=$(curl -s --max-time 10 http://httpbin.org/get 2>&1)
if echo "$R" | grep -q '"origin"'; then
    echo "   ✅ ALLOWED"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

echo "── TEST 2: HTTP blocked domain ──"
echo "   curl http://google.com/"
R=$(curl -s --max-time 10 http://google.com/ 2>&1)
if echo "$R" | grep -q "blocked"; then
    echo "   🚫 BLOCKED"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

echo "── TEST 3: HTTP blocked direct IP ──"
echo "   curl http://1.1.1.1/"
R=$(curl -s --max-time 5 http://1.1.1.1/ 2>&1)
if echo "$R" | grep -q "blocked"; then
    echo "   🚫 BLOCKED — direct IP caught by transparent proxy"
elif [ -z "$R" ]; then
    echo "   🚫 BLOCKED — connection dropped"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

# ═════════════════════════════════════════════
# LAYER 1: TLS/SNI blocking (no decryption)
# ═════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════"
echo "  LAYER 1 — TLS/SNI Domain Blocking"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "── TEST 4: HTTPS allowed domain (SNI passes) ──"
echo "   curl https://httpbin.org/get"
R=$(curl -s --max-time 10 https://httpbin.org/get 2>&1)
if echo "$R" | grep -q '"origin"'; then
    echo "   ✅ ALLOWED — SNI allowed, TLS intercepted, response received"
elif echo "$R" | grep -q "url"; then
    echo "   ✅ ALLOWED"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

echo "── TEST 5: HTTPS blocked domain (SNI blocked) ──"
echo "   curl https://google.com/"
R=$(curl -s --max-time 5 https://google.com/ 2>&1)
if echo "$R" | grep -q "blocked"; then
    echo "   🚫 BLOCKED at TLS/SNI level — connection killed before handshake"
elif echo "$R" | grep -qi "error\|reset\|refused\|closed\|SSL"; then
    echo "   🚫 BLOCKED at TLS/SNI level — connection refused"
elif [ -z "$R" ]; then
    echo "   🚫 BLOCKED — no response"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

echo "── TEST 6: HTTPS blocked domain (twitter.com) ──"
echo "   curl https://twitter.com/"
R=$(curl -s --max-time 5 https://twitter.com/ 2>&1)
if echo "$R" | grep -q "blocked"; then
    echo "   🚫 BLOCKED at TLS/SNI"
elif echo "$R" | grep -qi "error\|reset\|refused\|closed\|SSL"; then
    echo "   🚫 BLOCKED at TLS/SNI — connection killed"
elif [ -z "$R" ]; then
    echo "   🚫 BLOCKED"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

# ═════════════════════════════════════════════
# LAYER 3: Path-level rules (requires TLS interception)
# ═════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════"
echo "  LAYER 3 — Path-Level Rules (HTTPS with TLS intercept)"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "── TEST 7: HTTPS allowed domain + allowed path ──"
echo "   curl https://api.github.com/repos/torvalds/linux"
R=$(curl -s --max-time 10 https://api.github.com/repos/torvalds/linux 2>&1)
if echo "$R" | grep -q "blocked"; then
    echo "   🚫 BLOCKED (unexpected)"
    echo "   $(echo "$R" | head -3)"
elif echo "$R" | grep -qi "full_name\|id\|torvalds"; then
    echo "   ✅ ALLOWED — path /repos/ is in the allowlist"
elif echo "$R" | grep -qi "rate limit"; then
    echo "   ✅ ALLOWED (hit GitHub rate limit, but request went through)"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

echo "── TEST 8: HTTPS allowed domain + blocked path ──"
echo "   curl https://api.github.com/admin/something"
R=$(curl -s --max-time 10 https://api.github.com/admin/something 2>&1)
if echo "$R" | grep -q "blocked_by_policy"; then
    echo "   🚫 BLOCKED — path /admin is explicitly blocked"
    echo "   $(echo "$R" | grep reason | head -1)"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

echo "── TEST 9: HTTPS allowed domain + unlisted path ──"
echo "   curl https://api.github.com/gists"
R=$(curl -s --max-time 10 https://api.github.com/gists 2>&1)
if echo "$R" | grep -q "blocked_by_policy"; then
    echo "   🚫 BLOCKED — path /gists not in path allowlist"
    echo "   $(echo "$R" | grep reason | head -1)"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

echo "── TEST 10: HTTPS allowed domain + allowed path (users) ──"
echo "   curl https://api.github.com/users/torvalds"
R=$(curl -s --max-time 10 https://api.github.com/users/torvalds 2>&1)
if echo "$R" | grep -q "blocked"; then
    echo "   🚫 BLOCKED (unexpected)"
elif echo "$R" | grep -qi "login\|torvalds\|id"; then
    echo "   ✅ ALLOWED — path /users/ is in the allowlist"
elif echo "$R" | grep -qi "rate limit"; then
    echo "   ✅ ALLOWED (rate limited, but request went through)"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

# ═════════════════════════════════════════════
# HTTP path tests (same rules, no TLS needed)
# ═════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════"
echo "  LAYER 3 — Path-Level Rules (HTTP, no TLS needed)"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "── TEST 11: HTTP allowed domain, all paths open ──"
echo "   curl http://httpbin.org/anything/secret/data"
R=$(curl -s --max-time 10 http://httpbin.org/anything/secret/data 2>&1)
if echo "$R" | grep -q "secret"; then
    echo "   ✅ ALLOWED — httpbin.org has no path restrictions"
else
    echo "   Result: $(echo "$R" | head -3)"
fi
echo ""

# ═════════════════════════════════════════════
# Bypass / edge cases
# ═════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════"
echo "  BYPASS ATTEMPTS"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "── TEST 12: Non-HTTP port ──"
echo "   nc -w 3 1.1.1.1 22"
timeout 5 sh -c 'echo test | nc -w 3 1.1.1.1 22' 2>&1 && \
    echo "   ⚠️  Connection succeeded (unexpected)" || \
    echo "   🚫 BLOCKED — non-HTTP port dropped"
echo ""

echo "── TEST 13: DNS resolution works ──"
nslookup example.com 2>&1 | head -5
echo ""

echo "╔════════════════════════════════════════════════════════╗"
echo "║  Tests complete!                                       ║"
echo "║                                                        ║"
echo "║  Summary:                                              ║"
echo "║    Layer 1 (SNI):  Block HTTPS by domain, no decrypt   ║"
echo "║    Layer 2 (Host): Block by domain/IP, HTTP + HTTPS    ║"
echo "║    Layer 3 (Path): Block by URL path, HTTP + HTTPS     ║"
echo "║                                                        ║"
echo "║  View all traffic: http://localhost:8081                ║"
echo "╚════════════════════════════════════════════════════════╝"
