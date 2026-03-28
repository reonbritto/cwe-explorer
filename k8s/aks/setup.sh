#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
#  PureSecure CVE Explorer — AKS Deployment Script
#  Domain: reondev.top  |  Ingress: Traefik  |  TLS: Let's Encrypt
# ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN="reondev.top"

# ── Colours ──────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}==> $1${NC}"; }
warn()  { echo -e "${YELLOW}⚠  $1${NC}"; }
error() { echo -e "${RED}✖  $1${NC}"; exit 1; }

# ── Pre-flight checks ───────────────────────────────────
info "Checking prerequisites..."
command -v kubectl >/dev/null 2>&1 || error "kubectl is not installed"
command -v helm >/dev/null 2>&1    || error "helm is not installed"
command -v az >/dev/null 2>&1      || error "Azure CLI (az) is not installed"

kubectl cluster-info >/dev/null 2>&1 || error "Cannot connect to Kubernetes cluster. Run: az aks get-credentials --resource-group <RG> --name <CLUSTER>"

# ── Validate required environment variables ──────────────
SERVICE_API_KEY="${SERVICE_API_KEY:?ERROR: SERVICE_API_KEY environment variable is required}"
GF_ADMIN_PASSWORD="${GF_ADMIN_PASSWORD:?ERROR: GF_ADMIN_PASSWORD environment variable is required}"

# ── Step 1: Install Traefik Ingress Controller ───────────
info "Installing Traefik ingress controller..."
helm repo add traefik https://traefik.github.io/charts 2>/dev/null || true
helm repo update

if helm status traefik -n traefik >/dev/null 2>&1; then
    warn "Traefik already installed — upgrading..."
    helm upgrade traefik traefik/traefik \
        --namespace traefik \
        --set ports.web.port=8000 \
        --set ports.web.exposedPort=80 \
        --set ports.websecure.port=8443 \
        --set ports.websecure.exposedPort=443 \
        --set service.type=LoadBalancer \
        --set ingressRoute.dashboard.enabled=false \
        --wait
else
    kubectl create namespace traefik 2>/dev/null || true
    helm install traefik traefik/traefik \
        --namespace traefik \
        --set ports.web.port=8000 \
        --set ports.web.exposedPort=80 \
        --set ports.websecure.port=8443 \
        --set ports.websecure.exposedPort=443 \
        --set service.type=LoadBalancer \
        --set ingressRoute.dashboard.enabled=false \
        --wait
fi

# ── Step 2: Install cert-manager for TLS ─────────────────
info "Installing cert-manager..."
if helm status cert-manager -n cert-manager >/dev/null 2>&1; then
    warn "cert-manager already installed — skipping"
else
    kubectl create namespace cert-manager 2>/dev/null || true
    helm repo add jetstack https://charts.jetstack.io 2>/dev/null || true
    helm repo update
    helm install cert-manager jetstack/cert-manager \
        --namespace cert-manager \
        --set crds.install=true \
        --wait
fi

# ── Step 3: Create namespace ─────────────────────────────
info "Creating namespace..."
kubectl apply -f "$SCRIPT_DIR/namespace.yaml"

# ── Step 4: Create secrets ───────────────────────────────
info "Creating secrets..."
kubectl create secret generic app-secrets \
    --namespace=puresecure \
    --from-literal=SERVICE_API_KEY="$SERVICE_API_KEY" \
    --from-literal=GF_ADMIN_PASSWORD="$GF_ADMIN_PASSWORD" \
    --dry-run=client -o yaml | kubectl apply -f -

# ── Step 5: Deploy cert-manager issuers & certificates ───
info "Deploying TLS certificates (Let's Encrypt)..."
kubectl apply -f "$SCRIPT_DIR/cert-manager/"

# ── Step 6: Deploy application ───────────────────────────
info "Deploying application..."
kubectl apply -f "$SCRIPT_DIR/app/"

# ── Step 7: Deploy monitoring ────────────────────────────
info "Deploying Prometheus..."
kubectl apply -f "$SCRIPT_DIR/prometheus/"

info "Deploying Grafana..."
kubectl apply -f "$SCRIPT_DIR/grafana/"

# ── Step 8: Deploy load testing ──────────────────────────
info "Deploying Locust..."
kubectl apply -f "$SCRIPT_DIR/locust/"

# ── Step 9: Deploy Traefik IngressRoutes ─────────────────
info "Deploying Traefik ingress routes..."
kubectl apply -f "$SCRIPT_DIR/traefik/"

# ── Step 10: Wait for rollouts ───────────────────────────
info "Waiting for deployments to roll out..."
kubectl rollout status deployment/cwe-explorer -n puresecure --timeout=300s
kubectl rollout status deployment/prometheus -n puresecure --timeout=120s
kubectl rollout status deployment/grafana -n puresecure --timeout=120s
kubectl rollout status deployment/locust -n puresecure --timeout=120s

# ── Step 11: Get LoadBalancer IP ─────────────────────────
info "Retrieving Traefik LoadBalancer IP..."
echo ""
echo "Waiting for external IP (this may take 1-2 minutes)..."

LB_IP=""
for i in $(seq 1 30); do
    LB_IP=$(kubectl get svc traefik -n traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
    if [ -n "$LB_IP" ]; then
        break
    fi
    sleep 5
done

# ── Print access info ────────────────────────────────────
echo ""
echo "============================================="
echo "  AKS Deployment Complete!"
echo "============================================="
echo ""

if [ -n "$LB_IP" ]; then
    echo "  Load Balancer IP: $LB_IP"
    echo ""
    echo "  ── DNS Records (add to your DNS provider) ──"
    echo ""
    echo "    reondev.top          → A record → $LB_IP"
    echo "    grafana.reondev.top  → A record → $LB_IP"
    echo "    prometheus.reondev.top → A record → $LB_IP"
    echo ""
else
    warn "External IP not yet assigned. Check later with:"
    echo "    kubectl get svc traefik -n traefik"
    echo ""
fi

echo "  ── Service URLs ──"
echo ""
echo "    App:         https://$DOMAIN"
echo "    Grafana:     https://grafana.$DOMAIN  (admin / \$GF_ADMIN_PASSWORD)"
echo "    Prometheus:  https://prometheus.$DOMAIN"
echo "    Locust:      kubectl port-forward svc/locust 8089:8089 -n puresecure"
echo ""
echo "  ── Azure AD Setup ──"
echo ""
echo "    Register this redirect URI in Azure Portal:"
echo "    https://$DOMAIN"
echo ""
echo "  ── Verify TLS certificates ──"
echo ""
echo "    kubectl get certificates -n puresecure"
echo "    kubectl describe certificate reondev-top-tls -n puresecure"
echo ""
