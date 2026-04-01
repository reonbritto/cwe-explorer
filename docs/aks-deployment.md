# AKS Deployment Guide — PureSecure CVE Explorer

For local development, see [kubernetes-deployment.md](kubernetes-deployment.md). For the full dev workflow, see [developer-guide.md](developer-guide.md).

Deploy on **AKS** with **Traefik** ingress, **Let's Encrypt** TLS, domain **`reondev.top`**.

---

## Architecture

```
        Internet
           |
     [ Azure Load Balancer ]  <-- Public IP (reondev.top)
           |
     [ Traefik Ingress ]      <-- TLS termination + routing
         /       \
   web:8000   grafana:3000        <-- puresecure namespace
      |           |
      |     (Azure AD OAuth)
      |
   prometheus:9090   (internal only, port-forward)
   locust:8089       (internal only, port-forward)
```

| URL | Service | Auth |
|-----|---------|------|
| `https://reondev.top` | Main app (FastAPI) | Microsoft Entra ID (MSAL.js) |
| `https://grafana.reondev.top` | Grafana dashboards | Microsoft Entra ID (OAuth) |
| `localhost:9090` (port-forward) | Prometheus metrics | Internal only |
| `localhost:8089` (port-forward) | Locust load testing | Internal only |

---

## Step 1: Create AKS Cluster

```bash
# Create resource group
az group create --name rg-puresecure --location uksouth

# Create AKS cluster (Free tier, 1 node)
# IMPORTANT: Use an x86/AMD64 VM (not ARM). The "p" in VM names means ARM.
az aks create \
    --resource-group rg-puresecure \
    --name aks-puresecure \
    --tier free \
    --node-count 1 \
    --node-vm-size Standard_D2lds_v6 \
    --enable-managed-identity \
    --generate-ssh-keys \
    --network-plugin azure \
    --enable-cluster-autoscaler \
    --min-count 1 \
    --max-count 2

# Get credentials
az aks get-credentials --resource-group rg-puresecure --name aks-puresecure

# Verify
kubectl get nodes
```

> **Warning:** Do NOT use ARM-based VMs (e.g. `Standard_D2pls_v6` — the "p" means ARM/Ampere). The Docker image is built for AMD64 (x86). Using ARM nodes causes `exec format error`.

---

## Step 2: Docker Image

The CI/CD pipeline automatically builds and pushes the Docker image to Docker Hub when you push to `main`. No manual build or push needed.

The deployment pulls `reonbritto/puresecure-cve-explorer:latest` from Docker Hub.

---

## Step 3: Install Traefik (Ingress Controller)

```bash
helm repo add traefik https://traefik.github.io/charts
helm repo update
kubectl create namespace traefik

helm install traefik traefik/traefik \
    --namespace traefik \
    --set ports.web.port=8000 \
    --set ports.web.exposedPort=80 \
    --set ports.websecure.port=8443 \
    --set ports.websecure.exposedPort=443 \
    --set service.type=LoadBalancer \
    --set ingressRoute.dashboard.enabled=false \
    --wait
```

**Get the Load Balancer IP:**

```bash
kubectl get svc traefik -n traefik
```

Write down the `EXTERNAL-IP` — you need it for DNS. - 20.49.147.111

---

## Step 4: Install cert-manager (HTTPS/TLS)

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update
kubectl create namespace cert-manager

helm install cert-manager jetstack/cert-manager \
    --namespace cert-manager \
    --set installCRDs=true \
    --wait
```

---

## Step 5: Configure Secrets

### 5a. Edit the ConfigMap

Edit `k8s/aks/app/configmap.yaml` — fill in your Azure AD values.

Find these in **Azure Portal > App registrations > your app (`cwe-explorer`) > Overview**:

```yaml
AZURE_TENANT_ID: "your-tenant-id"       # Directory (tenant) ID
AZURE_CLIENT_ID: "your-client-id"       # Application (client) ID
```

### 5b. Edit Grafana Auth ConfigMap

Edit `k8s/aks/grafana/configmap-auth.yaml` — set the same client ID from Step 5a:

```yaml
GF_AUTH_AZUREAD_CLIENT_ID: "your-client-id"   # Same Application (client) ID as above
```

> All values come from the **same Azure AD app registration**. Grafana and the main app share one app registration. The auth and token URLs use the `common` endpoint to support both organizational and personal Microsoft accounts — do not change these.

### 5c. Set secret environment variables

```bash
export SERVICE_API_KEY="your-api-key"
export GF_ADMIN_PASSWORD="your-grafana-password"
export GF_AUTH_AZUREAD_CLIENT_SECRET="your-azure-client-secret"
```

---

## Step 6: Deploy Everything

Run these one by one:

```bash
# 1. Create namespace
kubectl apply -f k8s/aks/namespace.yaml
```

```bash
# 2. Deploy cert-manager issuers and certificates
kubectl apply -f k8s/aks/cert-manager/
```

```bash
# 3. Deploy the main app
kubectl apply -f k8s/aks/app/
```

```bash
# 4. Create secrets (AFTER deploying app, so placeholder doesn't overwrite)
kubectl create secret generic app-secrets \
    --namespace=puresecure \
    --from-literal=SERVICE_API_KEY="$SERVICE_API_KEY" \
    --from-literal=GF_ADMIN_PASSWORD="$GF_ADMIN_PASSWORD" \
    --from-literal=GF_AUTH_AZUREAD_CLIENT_SECRET="$GF_AUTH_AZUREAD_CLIENT_SECRET" \
    --dry-run=client -o yaml | kubectl apply -f -
```

```bash
# 5. Deploy Prometheus
kubectl apply -f k8s/aks/prometheus/
```

```bash
# 6. Deploy Grafana
kubectl apply -f k8s/aks/grafana/
```

```bash
# 7. Deploy Locust
kubectl apply -f k8s/aks/locust/
```

```bash
# 8. Deploy Traefik ingress routes
kubectl apply -f k8s/aks/traefik/
```

**Watch pods start:**

```bash
kubectl get pods -n puresecure -w
```

Wait until all pods show `Running` (press Ctrl+C to stop watching).

---

## Step 7: Configure DNS

Add these **A records** in your DNS provider:

| Type | Name | Value |
|------|------|-------|
| A | `@` | `<LOAD_BALANCER_IP>` |
| A | `grafana` | `<LOAD_BALANCER_IP>` |

---

## Step 8: Configure Azure AD for Grafana OAuth

### 8a. Create a Client Secret

1. Go to **Azure Portal > App registrations > your app > Certificates & secrets**
2. Click **New client secret**, add a description (e.g. "Grafana OAuth"), set expiry
3. **Copy the Value** (not the Secret ID) — this is your `GF_AUTH_AZUREAD_CLIENT_SECRET` used in Step 5c

### 8b. Register Redirect URIs

Go to **Azure Portal > App registrations > your app > Authentication > Redirect URI configuration**:

1. Click **Add a platform > Web** (must be **Web**, not SPA)
2. Add these redirect URIs:

```
https://reondev.top
https://grafana.reondev.top/login/azuread
```

> **Important:** Grafana redirect URIs must be registered as **Web** platform, not **Single-page application (SPA)**. SPA uses PKCE (no client secret), but Grafana requires the standard authorization code flow with a client secret. Using SPA will cause "Failed to get token from provider" errors.

### 8c. Supported Account Types

Under **Authentication > Supported accounts**, ensure it is set to:

**Accounts in any organizational directory and personal Microsoft accounts**

This allows personal Microsoft accounts (e.g. `@outlook.com`) to sign in.

### 8d. Restart Grafana

```bash
kubectl rollout restart deployment/grafana -n puresecure
```

---

## Step 9: Verify

```bash
# Check TLS certificate
kubectl get certificates -n puresecure

# Check all pods
kubectl get pods -n puresecure
```

Test in browser:

1. `https://reondev.top` — App login with Microsoft
2. `https://grafana.reondev.top` — Click "Sign in with Microsoft"

---

## Access Internal Services (port-forward)

Prometheus and Locust are not exposed to the internet:

```bash
# Prometheus
kubectl port-forward svc/prometheus 9090:9090 -n puresecure
# Open: http://localhost:9090

# Locust
kubectl port-forward svc/locust 8089:8089 -n puresecure
# Open: http://localhost:8089
```

---

## Sign Out

Clicking **Sign Out** in the main app redirects to the login page (`/login.html`).

---

## Troubleshooting

### `exec format error` on cwe-explorer

The Docker image is built for AMD64 (x86) but the AKS node is ARM64. This happens when using ARM-based VMs like `Standard_D2pls_v6` (the **"p"** = ARM/Ampere).

**Fix:** Recreate the cluster with an AMD64 VM size like `Standard_D2lds_v6`.

### Prometheus `permission denied` / `Unable to create mmap-ed active query log`

The Prometheus data directory has wrong ownership. The init container fixes this, but the command order matters — `mkdir` must run before `chown`:

```yaml
command: ["sh", "-c", "mkdir -p /prometheus/data && chown -R 65534:65534 /prometheus"]
```

If Prometheus is still failing after a fix, the old pod may be holding a lock on the PVC. Scale to zero first:

```bash
kubectl scale deployment prometheus -n puresecure --replicas=0
# Wait a few seconds
kubectl scale deployment prometheus -n puresecure --replicas=1
```

### Prometheus `lock DB directory: resource temporarily unavailable`

Two Prometheus pods are trying to use the same PVC simultaneously (e.g. during a rolling update). Scale down and back up:

```bash
kubectl scale deployment prometheus -n puresecure --replicas=0
kubectl scale deployment prometheus -n puresecure --replicas=1
```

### Grafana `Permission denied` on `/var/lib/grafana`

Same pattern — the init container fixes permissions. If the PVC is corrupted from a failed run:

```bash
kubectl scale deployment grafana -n puresecure --replicas=0
kubectl delete pvc grafana-data-pvc -n puresecure
kubectl apply -f k8s/aks/grafana/pvc.yaml
kubectl scale deployment grafana -n puresecure --replicas=1
```

### `CreateContainerConfigError`

The `app-secrets` secret is missing or incomplete. Recreate with all 3 keys:

```bash
kubectl create secret generic app-secrets --namespace=puresecure \
    --from-literal=SERVICE_API_KEY="$SERVICE_API_KEY" \
    --from-literal=GF_ADMIN_PASSWORD="$GF_ADMIN_PASSWORD" \
    --from-literal=GF_AUTH_AZUREAD_CLIENT_SECRET="$GF_AUTH_AZUREAD_CLIENT_SECRET" \
    --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment -n puresecure
```

### TLS certificate not issuing

```bash
kubectl get certificates -n puresecure
kubectl describe certificate reondev-top-tls -n puresecure
kubectl logs -l app=cert-manager -n cert-manager
```

Ensure DNS A records are pointing to the Traefik Load Balancer IP before requesting certificates.

---

## Quick Reference

```bash
# All pods
kubectl get pods -n puresecure

# App logs
kubectl logs -f deployment/cwe-explorer -n puresecure

# Restart app (after pushing new image)
kubectl rollout restart deployment/cwe-explorer -n puresecure

# Shell into app
kubectl exec -it deployment/cwe-explorer -n puresecure -- /bin/sh

# Traefik IP
kubectl get svc traefik -n traefik

# TLS certificates
kubectl get certificates -n puresecure

# Scale down/up (fix lock issues)
kubectl scale deployment prometheus -n puresecure --replicas=0
kubectl scale deployment prometheus -n puresecure --replicas=1
```

---

## Tear Down

```bash
# Delete app resources
kubectl delete namespace puresecure
helm uninstall traefik -n traefik
helm uninstall cert-manager -n cert-manager
kubectl delete namespace traefik cert-manager

# Delete AKS cluster
az aks delete --resource-group rg-puresecure --name aks-puresecure --yes

# Delete resource group
az group delete --name rg-puresecure --yes

# Stop cluster (save money, keep data)
az aks stop --resource-group rg-puresecure --name aks-puresecure

# Start again
az aks start --resource-group rg-puresecure --name aks-puresecure
```

---

## Cost (AKS Free Tier)

| Resource | Monthly |
|----------|---------|
| AKS control plane | $0 (Free tier) |
| VM (1x Standard_D2lds_v6) | ~$55 |
| Managed disks (3x PVC) | ~$3-5 |
| Load Balancer | ~$18 |
| **Total** | **~$75-80/month** |

Stop the cluster when not in use to save on VM costs.
