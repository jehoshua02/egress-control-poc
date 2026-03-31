# Outbound Traffic Enforcement for Untrusted Containers

## Requirements

1. Application runs containerized (untrusted code)
2. Enforcement is external to the app container
3. App container cannot bypass enforcement
4. Full visibility and control over all outbound requests
5. Works for domain names AND direct IP connections
6. Proof-of-concept scope

---

## Solution Comparison

| Criteria                          | A: Isolated Network + Proxy Gateway            | B: Host iptables/nftables                        | C: eBPF (Cilium/Tetragon)                        | D: VM-level Isolation                            |
|-----------------------------------|------------------------------------------------|--------------------------------------------------|--------------------------------------------------|--------------------------------------------------|
| **How it works**                  | App container on internal-only Docker network. Only route out is via a proxy container (mitmproxy) that has external access. | Host firewall rules restrict container's veth/subnet. All traffic forced through proxy or dropped. | Kernel-level hooks intercept packets from the container's cgroup/namespace. Policy enforced before packets leave. | Container runs inside a micro-VM (Firecracker/Kata). VM's virtual NIC routes through inspection layer. |
| **Catches domain connections**    | ✅ Yes — all traffic must traverse the proxy    | ✅ Yes — DNAT/redirect rules catch all outbound   | ✅ Yes — intercepts at socket/packet level         | ✅ Yes — VM has no other network path              |
| **Catches direct IP connections** | ✅ Yes — no route exists except through proxy    | ✅ Yes — rules apply regardless of destination     | ✅ Yes — operates below DNS layer                  | ✅ Yes — VM NIC is the only exit                   |
| **Non-bypassable by app**         | ✅ No route to bypass (no default gateway)       | ✅ Host kernel enforces (container can't modify)   | ✅ Kernel-level, outside container namespace        | ✅✅ Strongest — separate kernel boundary           |
| **L7 inspection (HTTP headers, body)** | ✅ Full — mitmproxy sees everything (with TLS intercept) | ⚠️ Partial — need to chain to a proxy for L7     | ⚠️ Partial — L7 possible but complex config       | ✅ Full — if proxy sits at VM network boundary     |
| **TLS inspection**                | ✅ Yes — proxy terminates TLS (CA cert needed)   | ❌ Not by itself — needs proxy chain               | ⚠️ Limited — can see SNI, not decrypted body      | ✅ Yes — with proxy at VM boundary                 |
| **Allowlist/blocklist control**   | ✅ Proxy rules (domain, IP, path, method)        | ✅ IP/port level; domain needs DNS resolution      | ✅ IP/port/CIDR; L7 with extra config              | ✅ Whatever you put at the boundary                |
| **Web UI for inspection**         | ✅ mitmproxy has built-in web UI                 | ❌ No — CLI/log only                               | ⚠️ Hubble UI (Cilium) — network-level only        | Depends on proxy choice                          |
| **Setup complexity**              | 🟢 Low — Docker Compose + 2 containers          | 🟡 Medium — manual iptables + proxy config        | 🔴 High — kernel version requirements, CRDs       | 🔴 High — VM runtime + networking plumbing        |
| **PoC friendliness**              | ⭐⭐⭐⭐⭐                                        | ⭐⭐⭐                                              | ⭐⭐                                                | ⭐⭐                                                |
| **Production path**               | Good — add policy engine, harden proxy          | Good — battle-tested Linux primitives             | Excellent — Cilium is production-grade            | Excellent — strongest isolation guarantees        |

---

## Recommendation for PoC

**Solution A (Isolated Network + Proxy Gateway)** is the clear winner for a proof of concept:

- Lowest complexity: just Docker Compose with two containers and one internal network
- Strongest L7 visibility out of the box (mitmproxy gives you full request/response inspection including TLS)
- Structurally non-bypassable: the app container's network literally has no route to the internet
- Covers both domain and IP-based connections by design — there is no path *around* the proxy
- Built-in web UI for real-time inspection
- Clean upgrade path to production (add policy enforcement, swap proxy, add logging pipeline)

### How Solution A enforces IP-based connections

The key insight: the app container is on a Docker network with **no default gateway to the internet**. It can only talk to other containers on that internal network. The proxy container has **two network interfaces** — one on the internal network (reachable by the app) and one with external access. Whether the app tries to reach a domain or a raw IP, the packet has nowhere to go except through the proxy.

---

## Architecture Diagram (Solution A)

```
┌─────────────────────────────────────────────────────┐
│  Host Machine                                       │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │  internal_network (no external access)       │    │
│  │                                              │    │
│  │  ┌──────────────┐     ┌──────────────────┐   │    │
│  │  │  App Container│────▶│  Proxy Container │   │    │
│  │  │  (untrusted)  │     │  (mitmproxy)     │   │    │
│  │  │              │     │                  │   │    │
│  │  │  - No default │     │  - 2 NICs:       │   │    │
│  │  │    gateway    │     │    internal +     │   │    │
│  │  │  - No DNS     │     │    external      │   │    │
│  │  │  - HTTP_PROXY │     │  - Inspects all  │   │    │
│  │  │    points to  │     │    traffic       │   │    │
│  │  │    proxy      │     │  - Allowlist/    │   │    │
│  │  │              │     │    blocklist     │   │    │
│  │  └──────────────┘     │  - Web UI :8081  │   │    │
│  │                        └────────┬─────────┘   │    │
│  └─────────────────────────────────┼─────────────┘    │
│                                    │                  │
│  ┌─────────────────────────────────┼─────────────┐    │
│  │  external_network               │              │    │
│  │  (has internet access)          │              │    │
│  └─────────────────────────────────┼─────────────┘    │
│                                    │                  │
└────────────────────────────────────┼──────────────────┘
                                     │
                                     ▼
                                 Internet
```
