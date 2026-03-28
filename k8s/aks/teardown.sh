#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
#  PureSecure CVE Explorer — AKS Teardown Script
# ─────────────────────────────────────────────────────────

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}==> $1${NC}"; }
warn() { echo -e "${YELLOW}⚠  $1${NC}"; }

echo ""
echo "This will remove ALL PureSecure resources from AKS."
echo "Press Ctrl+C to cancel, or Enter to continue..."
read -r

info "Deleting puresecure namespace (all app resources)..."
kubectl delete namespace puresecure --ignore-not-found

info "Uninstalling Traefik..."
helm uninstall traefik -n traefik 2>/dev/null || warn "Traefik not found"
kubectl delete namespace traefik --ignore-not-found 2>/dev/null || true

info "Uninstalling cert-manager..."
helm uninstall cert-manager -n cert-manager 2>/dev/null || warn "cert-manager not found"
kubectl delete namespace cert-manager --ignore-not-found 2>/dev/null || true

echo ""
echo "============================================="
echo "  Teardown complete."
echo "============================================="
echo ""
echo "  To delete the AKS cluster entirely:"
echo "    az aks delete --resource-group <RG> --name <CLUSTER> --yes"
echo ""
