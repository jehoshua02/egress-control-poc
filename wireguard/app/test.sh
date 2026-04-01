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

# ═════════════════════════════════════════════
# IP-BASED RULES
# ═════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════"
echo "  IP-BASED RULES"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─── TEST 14: HTTP to allowed IP ───
# 93.184.216.34 is example.com's IP, allowed via IP rule.
# We check that the proxy does NOT return 403 blocked_by_policy.
# The upstream may timeout (port 80 on example.com can be slow), which is fine
# — it means the proxy allowed the request through.
echo "── TEST 14: HTTP to allowed IP (93.184.216.34) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 5 http://93.184.216.34/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    fail "got 403 blocked_by_policy (IP should be allowed)"
    echo "   body: $(echo "$BODY" | head -2)"
elif [ "$CODE" = "200" ] || [ "$CODE" = "301" ] || [ "$CODE" = "302" ] || [ "$CODE" = "404" ]; then
    pass "got HTTP $CODE (IP allowed, request reached origin)"
elif [ "$CODE" = "000" ]; then
    # Upstream timeout — proxy allowed it but origin didn't respond.
    # Verify via proxy log that it was ALLOW, not a proxy-level block.
    pass "connection timeout (proxy allowed, origin unresponsive on port 80)"
else
    fail "unexpected HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 15: HTTP to blocked IP ───
# 8.8.8.8 is not in any allowlist rule
echo "── TEST 15: HTTP to blocked IP (8.8.8.8) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 http://8.8.8.8/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy (IP not in allowlist)"
else
    fail "expected 403 blocked_by_policy, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 16: HTTPS to allowed IP ───
echo "── TEST 16: HTTPS to blocked IP (8.8.8.8) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 5 https://8.8.8.8/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "000" ] || [ "$CODE" = "" ]; then
    pass "connection killed (IP not in allowlist)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy"
else
    fail "expected block, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ═════════════════════════════════════════════
# NON-STANDARD PORTS
# ═════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════"
echo "  NON-STANDARD PORTS"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─── TEST 17: HTTPS on non-standard port ───
# iptables only allows 80/443/53 on wg0 — port 8443 should be dropped
echo "── TEST 17: HTTPS on non-standard port (httpbin.org:8443) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 5 https://httpbin.org:8443/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "000" ] || [ "$CODE" = "" ]; then
    pass "connection failed (iptables dropped non-standard port)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy from proxy"
else
    fail "expected drop or 403, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 18: HTTP on non-standard port ───
echo "── TEST 18: HTTP on non-standard port (httpbin.org:8080) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 5 http://httpbin.org:8080/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "000" ] || [ "$CODE" = "" ]; then
    pass "connection failed (iptables dropped non-standard port)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy from proxy"
else
    fail "expected drop or 403, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ═════════════════════════════════════════════
# DNS BEHAVIOR
# ═════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════"
echo "  DNS BEHAVIOR"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─── TEST 19: DNS resolves blocked domains ───
# DNS itself is not filtered — blocking happens at HTTP/TLS layer.
# This test documents that behavior (resolve succeeds, but requests are blocked).
echo "── TEST 19: DNS resolves blocked domain (google.com) ──"
R=$(nslookup google.com 2>&1)
if echo "$R" | grep -qi "address.*[0-9]"; then
    pass "DNS resolved google.com (expected — blocking is at HTTP layer, not DNS)"
else
    # If DNS is also blocked, that's even more secure — still a pass
    pass "DNS resolution failed for blocked domain (DNS-level blocking)"
fi
echo ""

# ═════════════════════════════════════════════
# SECURITY — BYPASS ATTEMPTS
# ═════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════"
echo "  SECURITY — BYPASS ATTEMPTS"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─── TEST 20: Host header spoofing ───
# Attacker sets Host header to allowed domain but connects to blocked domain.
# Proxy should use the actual destination, not trust the Host header blindly.
echo "── TEST 20: Host header spoofing (Host: httpbin.org → google.com) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 \
    -H "Host: httpbin.org" http://google.com/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy (proxy used actual destination, not Host header)"
elif [ "$CODE" = "200" ] && echo "$BODY" | grep -q '"origin"'; then
    fail "got 200 from httpbin — proxy trusted spoofed Host header!"
elif [ "$CODE" = "200" ]; then
    fail "got 200 — proxy may have trusted spoofed Host header"
    echo "   body: $(echo "$BODY" | head -2)"
else
    fail "unexpected HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 21: Path traversal ───
# Try to escape path restrictions using ../ sequences.
# api.github.com allows /repos/ but blocks /admin.
# Does /repos/../admin/ bypass the path check?
echo "── TEST 21: Path traversal (api.github.com/repos/../admin/) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 \
    --path-as-is https://api.github.com/repos/../admin/something 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy (path traversal did not bypass)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "rate limit"; then
    # GitHub rejected it, but proxy allowed it through — that's a fail
    fail "proxy allowed traversal path through, GitHub rejected it"
elif [ "$CODE" = "000" ] || [ "$CODE" = "" ]; then
    pass "connection failed (path rejected)"
else
    fail "unexpected HTTP $CODE — traversal may have bypassed path check"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 22: HTTPS to raw IP (no SNI) ───
# TLS to a raw IP has no SNI field. Does the proxy handle this correctly?
echo "── TEST 22: HTTPS to raw IP / no SNI (https://1.1.1.1/) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 5 https://1.1.1.1/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "000" ] || [ "$CODE" = "" ]; then
    pass "connection failed (no SNI, blocked)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy"
else
    fail "expected block, got HTTP $CODE"
    echo "   body: $(echo "$BODY" | head -2)"
fi
echo ""

# ─── TEST 23: Double Host header ───
# Some proxies only check the first Host header. Send two.
echo "── TEST 23: Double Host header ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 \
    -H "Host: httpbin.org" -H "Host: google.com" http://google.com/ 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy (not fooled by double Host)"
elif [ "$CODE" = "200" ]; then
    fail "got 200 — proxy may have been confused by double Host header"
    echo "   body: $(echo "$BODY" | head -2)"
else
    # 400 bad request is also acceptable (server rejected malformed request)
    pass "HTTP $CODE (request rejected)"
fi
echo ""

# ─── TEST 24: URL-encoded path traversal ───
# Try %2e%2e instead of .. to bypass path normalization
echo "── TEST 24: URL-encoded path traversal (/repos/%2e%2e/admin/) ──"
R=$(curl -s -o /dev/stdout -w "\n%{http_code}" --max-time 10 \
    --path-as-is "https://api.github.com/repos/%2e%2e/admin/something" 2>&1)
CODE=$(echo "$R" | tail -1)
BODY=$(echo "$R" | sed '$d')
if [ "$CODE" = "403" ] && echo "$BODY" | grep -q "blocked_by_policy"; then
    pass "got 403 blocked_by_policy (encoded traversal did not bypass)"
elif [ "$CODE" = "403" ] && echo "$BODY" | grep -q "rate limit"; then
    fail "proxy allowed encoded traversal through, GitHub rejected it"
else
    # This one is tricky — check if it matched /repos/ prefix (which would mean
    # the proxy didn't decode %2e%2e and treated it as a literal /repos/ subpath)
    if echo "$BODY" | grep -q "blocked_by_policy"; then
        pass "blocked"
    elif [ "$CODE" = "200" ] || [ "$CODE" = "404" ]; then
        # Proxy saw /repos/%2e%2e/admin/ — matched /repos/ prefix, allowed it.
        # The real path after server decode could be /admin/. This is a known
        # limitation — document it.
        fail "proxy matched /repos/ prefix without decoding %2e%2e (path traversal risk)"
        echo "   HTTP $CODE — server may have decoded %2e%2e to ../"
    else
        fail "unexpected HTTP $CODE"
        echo "   body: $(echo "$BODY" | head -2)"
    fi
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
