# Container Firewall PoC — Kubernetes (Fully Transparent, TLS Aware)

**The app has zero proxy awareness.** No `HTTP_PROXY`, no code changes.
Three enforcement layers including HTTPS path-level inspection.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Namespace: sandboxed                                            │
│  NetworkPolicy: deny-all-egress                                  │
│                                                                  │
│  App Pod                              Proxy Pod                  │
│  ┌──────────────────────────┐         ┌────────────────────────┐ │
│  │ init: fetch-ca-cert      │         │ mitmproxy (transparent)│ │
│  │   downloads CA from proxy│         │   :8080 HTTP           │ │
│  │                          │         │   :8443 HTTPS          │ │
│  │ init: iptables-init      │         │   :8081 Web UI         │ │
│  │   DNAT :80→proxy:8080    │         │                        │ │
│  │   DNAT :443→proxy:8443   │         │ Layer 1: SNI block     │ │
│  │   DROP all other egress  │         │ Layer 2: domain/IP     │ │
│  │                          │         │ Layer 3: URL path      │ │
│  │ app: alpine              │  DNAT   │                        │ │
│  │   CA cert in trust store │────────▶│ dnsmasq :53            │ │
│  │   no HTTP_PROXY          │         │                        │ │
│  │   no NET_ADMIN           │         │ → Internet (allowed    │─▶
│  │   can't undo iptables    │         │   destinations only)   │ │
│  └──────────────────────────┘         └────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh

# Web UI
kubectl port-forward svc/proxy-webui -n sandboxed 8081:8081

# Shell into app — try normal requests
kubectl exec -it deploy/app -n sandboxed -- /bin/sh
# curl http://httpbin.org/get                          → ✅
# curl https://httpbin.org/get                         → ✅
# curl https://api.github.com/repos/torvalds/linux     → ✅
# curl https://api.github.com/admin/something          → 🚫 path blocked
# curl https://google.com                              → 🚫 SNI blocked
# curl http://1.1.1.1                                  → 🚫 IP blocked
```

## Prerequisites

- Kubernetes cluster with NetworkPolicy-capable CNI (Calico, Cilium)
- `minikube start --cni=calico` for local testing

## Policy

Edit `proxy/configmaps.yaml` → `ALLOWED_RULES`. Same rule format as Docker PoC.

## Files

```
container-firewall-k8s/
├── base/namespace.yaml
├── network-policies/policies.yaml
├── proxy/
│   ├── configmaps.yaml         # enforcer v2 + dnsmasq
│   └── deployment.yaml         # mitmproxy + services
├── app/
│   └── deployment.yaml         # init containers + app
└── scripts/
    ├── deploy.sh
    └── test-k8s.sh
```
