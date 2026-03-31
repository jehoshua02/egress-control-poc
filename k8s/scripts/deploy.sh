#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║  Container Firewall — K8s PoC (Fully Transparent)    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

NAMESPACE="sandboxed"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Prerequisites ──
echo "[1/5] Checking prerequisites..."
if ! command -v kubectl &>/dev/null; then
    echo "  ❌ kubectl not found"
    exit 1
fi
echo "  ⚠️  Requires a CNI with NetworkPolicy support (Calico, Cilium)"
echo "     minikube: minikube start --cni=calico"
echo ""

# ── Namespace + Network Policies ──
echo "[2/5] Creating namespace and network policies..."
kubectl apply -f "$ROOT_DIR/base/namespace.yaml"
kubectl apply -f "$ROOT_DIR/network-policies/policies.yaml"
echo "  ✅ Namespace and policies applied"

# ── Deploy Proxy ──
echo ""
echo "[3/5] Deploying proxy..."
kubectl apply -f "$ROOT_DIR/proxy/configmaps.yaml"
kubectl apply -f "$ROOT_DIR/proxy/deployment.yaml"
kubectl rollout status deployment/proxy -n "$NAMESPACE" --timeout=120s
echo "  ✅ Proxy running"

# ── Discover Proxy ClusterIP ──
echo ""
echo "[4/5] Discovering proxy ClusterIP and deploying app..."
PROXY_IP=$(kubectl get svc proxy-svc -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
echo "  Proxy ClusterIP: $PROXY_IP"

# Patch placeholder in app deployment and apply
sed "s/PROXY_SVC_IP_PLACEHOLDER/$PROXY_IP/g" "$ROOT_DIR/app/deployment.yaml" \
    | kubectl apply -f -

kubectl rollout status deployment/app -n "$NAMESPACE" --timeout=120s
echo "  ✅ App running"

# ── Status ──
echo ""
echo "[5/5] Deployment complete!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
kubectl get pods -n "$NAMESPACE" -o wide
echo ""
kubectl get svc -n "$NAMESPACE"
echo ""
kubectl get networkpolicies -n "$NAMESPACE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  # Web UI"
echo "  kubectl port-forward svc/proxy-webui -n $NAMESPACE 8081:8081"
echo "  open http://localhost:8081"
echo ""
echo "  # Shell into app"
echo "  kubectl exec -it deploy/app -n $NAMESPACE -- /bin/sh"
echo ""
echo "  # Proxy logs"
echo "  kubectl logs -f deploy/proxy -n $NAMESPACE -c mitmproxy"
echo ""
echo "  # Run tests"
APP_POD=\$(kubectl get pod -n $NAMESPACE -l role=app -o jsonpath='{.items[0].metadata.name}')
echo "  kubectl cp scripts/test-k8s.sh $NAMESPACE/\$APP_POD:/test.sh"
echo "  kubectl exec -it \$APP_POD -n $NAMESPACE -- /bin/sh /test.sh"
echo ""
echo "  # Tear down"
echo "  kubectl delete namespace $NAMESPACE"
echo ""
