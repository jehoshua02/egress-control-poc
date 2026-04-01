#!/bin/sh
# =============================================================================
# Container Firewall v2 — Test Suite
# =============================================================================
# Strict tests: "blocked" means we got a 403 with "blocked_by_policy" from the
# proxy (or a TLS/connection kill for SNI blocks). "Allowed" means we got the
# expected real response. Anything else is a FAIL.
# =============================================================================

PASS=0
FAIL=0

pass() { echo "   PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "   FAIL: $1"; FAIL=$((FAIL+1)); }

echo ""
echo "═══ Environment ═══"
echo "  HTTP_PROXY:  ${HTTP_PROXY:-(not set)}"
echo "  HTTPS_PROXY: ${HTTPS_PROXY:-(not set)}"
[ -f /usr/local/share/ca-certificates/mitmproxy.crt ] \
    && echo "  CA cert:     installed" \
    || echo "  CA cert:     NOT FOUND"
echo ""

# ─── TEST 1: HTTP allowed domain ───
echo "── TEST 1: HTTP allowed domain (httpbin.org) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 http://httpbin.org/get 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "200" ] && echo "$BODY" | grep -q '"origin"'; then
    pass "got 200 with expected JSON body"
else
    fail "expected 200 with origin field, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 2: HTTP blocked domain ───
echo "── TEST 2: HTTP blocked domain (google.com) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 http://google.com/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy from proxy"
else
    fail "expected 403 blocked_by_policy, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 3: HTTP blocked direct IP ───
echo "── TEST 3: HTTP blocked direct IP (1.1.1.1) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 http://1.1.1.1/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy from proxy"
else
    fail "expected 403 blocked_by_policy, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 4: HTTPS allowed domain ───
echo "── TEST 4: HTTPS allowed domain (httpbin.org) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 https://httpbin.org/get 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "200" ] && echo "$BODY" | grep -q '"origin"'; then
    pass "got 200 with expected JSON body (TLS intercepted)"
else
    fail "expected 200 with origin field, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 5: HTTPS blocked domain (SNI) ───
# SNI blocks kill the TLS handshake — curl gets a connection error, not a 403.
# We verify: (a) curl fails, AND (b) we do NOT get a valid HTTP response.
echo "── TEST 5: HTTPS blocked domain / SNI block (google.com) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 5 https://google.com/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "000" ] || [ "$CODE" = "" ]; then
    # curl got no HTTP response — connection was killed (SNI block)
    pass "connection killed before HTTP response (SNI block working)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    # Proxy returned 403 — also acceptable (blocked at L2 after TLS)
    pass "got 403 blocked_by_policy"
else
    fail "expected connection kill or 403, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 6: HTTPS blocked domain (SNI) ───
echo "── TEST 6: HTTPS blocked domain / SNI block (twitter.com) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 5 https://twitter.com/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "000" ] || [ "$CODE" = "" ]; then
    pass "connection killed before HTTP response (SNI block working)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy"
else
    fail "expected connection kill or 403, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 7: HTTPS allowed domain + allowed path ───
echo "── TEST 7: HTTPS allowed path (api.github.com/repos/) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 https://api.github.com/repos/torvalds/linux 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "200" ] && echo "$BODY" | grep -q "torvalds/linux"; then
    pass "got 200 with expected repo data"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "rate limit"; then
    pass "got 403 rate limit from GitHub (request reached origin = allowed)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    fail "blocked by proxy policy (should be allowed)"
    echo "   body: $(echo "$BODY" | head -2)"
else
    fail "unexpected HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 8: HTTPS allowed domain + blocked path ───
echo "── TEST 8: HTTPS blocked path (api.github.com/admin/) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 https://api.github.com/admin/something 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy (path /admin blocked)"
else
    fail "expected 403 blocked_by_policy, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 9: HTTPS allowed domain + unlisted path ───
echo "── TEST 9: HTTPS unlisted path (api.github.com/gists) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 https://api.github.com/gists 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy (path /gists not in allowlist)"
else
    fail "expected 403 blocked_by_policy, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 10: HTTPS allowed domain + allowed path ───
echo "── TEST 10: HTTPS allowed path (api.github.com/users/) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 https://api.github.com/users/torvalds 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "200" ] && echo "$BODY" | grep -q "torvalds"; then
    pass "got 200 with expected user data"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "rate limit"; then
    pass "got 403 rate limit from GitHub (request reached origin = allowed)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    fail "blocked by proxy policy (should be allowed)"
    echo "   body: $(echo "$BODY" | head -2)"
else
    fail "unexpected HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 11: HTTP allowed domain, all paths open ───
echo "── TEST 11: HTTP all paths open (httpbin.org) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 http://httpbin.org/anything/secret/data 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "200" ] && echo "$BODY" | grep -q "secret"; then
    pass "got 200 with reflected path"
else
    fail "expected 200 with 'secret' in body, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 12: Non-HTTP port blocked ───
# iptables on wg0 drops non-80/443/53 traffic.
# We verify nc fails AND that allowed ports still work (test 1-4 prove that).
echo "── TEST 12: Non-HTTP port blocked (1.1.1.1:22) ──"
# Use timeout + nc. We need to distinguish "iptables dropped it" from "remote refused".
# With iptables DROP, nc will hang until timeout (no RST, no response).
R=$(timeout 5 sh -c 'echo test | nc -w 3 1.1.1.1 22 2>&1')
NC_EXIT=$?
if [ $NC_EXIT -ne 0 ] && [ -z "$R" ]; then
    pass "nc timed out with no response (iptables DROP)"
elif [ $NC_EXIT -ne 0 ]; then
    pass "nc failed (exit $NC_EXIT) — port blocked"
else
    fail "nc succeeded — port 22 was NOT blocked"
    echo "   response: $(echo "$R" | head -1)"
fi
echo ""

# ─── TEST 13: DNS resolution works ───
echo "── TEST 13: DNS resolution ──"
R=$(nslookup example.com 2>&1)
if echo "$R" | grep -qi "address.*93\.184"; then
    pass "resolved example.com to expected IP"
elif echo "$R" | grep -qi "name:.*example.com"; then
    pass "resolved example.com"
else
    fail "DNS resolution failed"
    echo "   $(echo "$R" | head -3)"
fi
echo ""

# ─── Summary ───
TOTAL=$((PASS+FAIL))
echo "═══════════════════════════════════════"
echo "  Results: $PASS/$TOTAL passed, $FAIL failed"
echo "═══════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
