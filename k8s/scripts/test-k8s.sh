#!/bin/sh
# =============================================================================
# Container Firewall — K8s Transparent Test Suite
# =============================================================================
# The app has NO proxy env vars. These are completely normal requests.
# =============================================================================

echo "╔══════════════════════════════════════════════════════╗"
echo "║  K8s Transparent Firewall — Test Suite               ║"
echo "║  App has ZERO proxy awareness. Normal requests only. ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

echo "── Environment check ──"
echo "  HTTP_PROXY:  ${HTTP_PROXY:-(not set) ✅}"
echo "  HTTPS_PROXY: ${HTTPS_PROXY:-(not set) ✅}"
echo ""

apk add --no-cache curl 2>/dev/null | tail -1
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 1: Allowed domain — curl http://httpbin.org/get"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
R=$(curl -s --max-time 10 http://httpbin.org/get 2>&1)
if echo "$R" | grep -q '"origin"'; then
    echo "  ✅ ALLOWED"
    echo "$R" | head -5
else
    echo "  $R" | head -5
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 2: Blocked domain — curl http://google.com/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
R=$(curl -s --max-time 10 http://google.com/ 2>&1)
if echo "$R" | grep -q "blocked"; then
    echo "  🚫 BLOCKED"
else
    echo "  $R" | head -3
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 3: Allowed domain — curl http://example.com/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
R=$(curl -s --max-time 10 http://example.com/ 2>&1)
if echo "$R" | grep -q "Example Domain"; then
    echo "  ✅ ALLOWED"
else
    echo "  $R" | head -3
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 4: Blocked direct IP — curl http://1.1.1.1/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
R=$(curl -s --max-time 5 http://1.1.1.1/ 2>&1)
if echo "$R" | grep -q "blocked"; then
    echo "  🚫 BLOCKED — direct IP caught"
elif [ -z "$R" ]; then
    echo "  🚫 BLOCKED — no response"
else
    echo "  $R" | head -3
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 5: Blocked direct IP — curl http://8.8.8.8/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
R=$(curl -s --max-time 5 http://8.8.8.8/ 2>&1)
if echo "$R" | grep -q "blocked"; then
    echo "  🚫 BLOCKED"
elif [ -z "$R" ]; then
    echo "  🚫 BLOCKED — dropped"
else
    echo "  $R" | head -3
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 6: Non-HTTP port (should be dropped)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
timeout 5 sh -c 'echo test | nc -w 3 1.1.1.1 22 2>&1' && \
    echo "  ⚠️  Unexpected success" || \
    echo "  🚫 BLOCKED — non-HTTP dropped by iptables OUTPUT chain"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 7: iptables bypass attempt (should fail)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
iptables -F 2>&1 && \
    echo "  ⚠️  iptables flush succeeded (unexpected)" || \
    echo "  ✅ Cannot modify iptables — NET_ADMIN dropped"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 8: DNS works (via proxy dnsmasq)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
nslookup example.com 2>&1 | head -5
echo ""

echo "╔══════════════════════════════════════════════════════╗"
echo "║  Done. App used plain curl — no proxy flags.         ║"
echo "║  View traffic: kubectl port-forward                  ║"
echo "║    svc/proxy-webui -n sandboxed 8081:8081            ║"
echo "╚══════════════════════════════════════════════════════╝"
