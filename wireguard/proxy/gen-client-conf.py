"""Generate WireGuard client config from mitmproxy's wireguard.conf."""
import json, base64, sys, time, os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

CONF_PATH = "/root/.mitmproxy/wireguard.conf"
OUT_PATH = "/wg-config/wg0.conf"
ENDPOINT = "172.30.0.10:51820"

# Wait for mitmproxy to generate config
for _ in range(30):
    if os.path.exists(CONF_PATH):
        break
    time.sleep(1)
else:
    print("ERROR: wireguard.conf not found", file=sys.stderr)
    sys.exit(1)

with open(CONF_PATH) as f:
    conf = json.load(f)

# Derive server public key from server private key
server_privkey_bytes = base64.b64decode(conf["server_key"])
server_privkey = X25519PrivateKey.from_private_bytes(server_privkey_bytes)
server_pubkey = base64.b64encode(
    server_privkey.public_key().public_bytes_raw()
).decode()

client_config = f"""[Interface]
PrivateKey = {conf["client_key"]}
Address = 10.0.0.1/32
DNS = 10.0.0.53

[Peer]
PublicKey = {server_pubkey}
Endpoint = {ENDPOINT}
AllowedIPs = 0.0.0.0/0
"""

os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
with open(OUT_PATH, "w") as f:
    f.write(client_config)

print(f"WireGuard client config written to {OUT_PATH}")
print(client_config)
