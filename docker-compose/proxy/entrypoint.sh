#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════╗"
echo "║  Container Firewall — Transparent Gateway        ║"
echo "║  App has ZERO knowledge of this proxy            ║"
echo "╚══════════════════════════════════════════════════╝"

# ─────────────────────────────────────────────
# 1. Identify network interfaces
# ─────────────────────────────────────────────
# eth0 = internal_net (172.30.0.0/24) — app-facing
# eth1 = external_net — internet-facing
# The proxy is the default gateway for the internal network.

INTERNAL_IF="eth0"
INTERNAL_SUBNET="172.30.0.0/24"
PROXY_IP="172.30.0.10"

echo "[+] Internal interface: $INTERNAL_IF ($INTERNAL_SUBNET)"
echo "[+] Proxy IP: $PROXY_IP"
echo ""

# ─────────────────────────────────────────────
# 2. Enable IP forwarding (already set via sysctl in compose,
#    but ensure it's on)
# ─────────────────────────────────────────────
echo "[+] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# ─────────────────────────────────────────────
# 3. Flush existing rules
# ─────────────────────────────────────────────
iptables -t nat -F
iptables -t filter -F FORWARD 2>/dev/null || true

# ─────────────────────────────────────────────
# 4. NAT + Transparent redirect
# ─────────────────────────────────────────────
# The app thinks it's talking directly to the destination.
# iptables intercepts the packets and redirects them to
# mitmproxy's transparent mode ports.
#
# PREROUTING: catch packets BEFORE routing decision
#   - Port 80  → mitmproxy transparent HTTP  (8080)
#   - Port 443 → mitmproxy transparent HTTPS (8443)
#
# The app never sees mitmproxy. It just makes a normal
# request to any domain or IP, and mitmproxy intercepts it.
# ─────────────────────────────────────────────

echo "[+] Setting up transparent redirect rules..."

# HTTP: redirect to mitmproxy transparent mode
iptables -t nat -A PREROUTING \
    -s "$INTERNAL_SUBNET" \
    -p tcp --dport 80 \
    -j REDIRECT --to-port 8080

# HTTPS: redirect to mitmproxy transparent mode
iptables -t nat -A PREROUTING \
    -s "$INTERNAL_SUBNET" \
    -p tcp --dport 443 \
    -j REDIRECT --to-port 8443

# Additional common ports — redirect to HTTP transparent
for port in 8080 8443 3000 5000 8000 8888 9090; do
    iptables -t nat -A PREROUTING \
        -s "$INTERNAL_SUBNET" \
        -p tcp --dport "$port" \
        -j REDIRECT --to-port 8080
done

# ─────────────────────────────────────────────
# 5. MASQUERADE outbound traffic from mitmproxy
# ─────────────────────────────────────────────
# When mitmproxy makes the actual outbound connection on behalf
# of the app, NAT it so return traffic comes back correctly.
iptables -t nat -A POSTROUTING \
    ! -o "$INTERNAL_IF" \
    -s "$INTERNAL_SUBNET" \
    -j MASQUERADE

# ─────────────────────────────────────────────
# 6. FORWARD chain: drop everything not handled by mitmproxy
# ─────────────────────────────────────────────
# Any traffic from the internal subnet that isn't HTTP/HTTPS
# (and thus wasn't redirected to mitmproxy) gets DROPPED.
# This prevents raw TCP, UDP, ICMP, etc. from bypassing the proxy.

# Allow established/related connections (return traffic)
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop all other forwarded traffic from internal subnet
iptables -A FORWARD -s "$INTERNAL_SUBNET" -j DROP

echo ""
echo "[+] iptables NAT rules:"
iptables -t nat -L -n -v
echo ""
echo "[+] iptables FORWARD rules:"
iptables -L FORWARD -n -v
echo ""

# ─────────────────────────────────────────────
# 7. Start DNS forwarder
# ─────────────────────────────────────────────
echo "[+] Starting dnsmasq..."
dnsmasq

# ─────────────────────────────────────────────
# 8. Start mitmproxy in transparent-only mode
# ─────────────────────────────────────────────
echo "[+] Starting mitmproxy (transparent mode)..."
echo ""
echo "    Mode:         TRANSPARENT (app is unaware)"
echo "    HTTP  intercept: *:80  → :8080"
echo "    HTTPS intercept: *:443 → :8443"
echo "    Web UI:       http://localhost:8081"
echo "    Policy:       block-all, allow-explicit"
echo ""
echo "    The app makes normal requests."
echo "    This proxy silently intercepts everything."
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Ready. All app traffic flows through here.      ║"
echo "╚══════════════════════════════════════════════════╝"

exec mitmweb \
    --mode transparent@8080 \
    --mode transparent@8443 \
    --web-host 0.0.0.0 \
    --web-port 8081 \
    --set ssl_insecure=true \
    --set block_global=false \
    --set connection_strategy=lazy \
    -s /home/mitmproxy/scripts/enforcer.py
