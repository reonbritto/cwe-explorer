# Developer Guide — PureSecure CVE Explorer

Guide for new developers: from local setup to production deployment on AKS.

---

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Python 3.12+ | Backend development | python.org |
| Docker Desktop | Containerization | docs.docker.com |
| Git | Version control | git-scm.com |
| Azure CLI | AKS management | docs.microsoft.com |
| kubectl | Kubernetes CLI | Bundled with Docker Desktop or az aks install-cli |
| Helm | Package manager for Kubernetes | helm.sh |

---

## Stage 1: Local Development

```bash
# Clone the repo
git clone <repository-url>
cd cve-new-bri

# Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS/Linux

# Install dependencies
pip install -r requirements-dev.txt

# Set environment variables
cp .env.example .env
# Edit .env with your Azure Entra ID values

# Start the server
uvicorn app.main:app --reload

# Open: http://localhost:8000
```

### Run Tests
```bash
pytest tests/ -v --tb=short --cov=app
flake8 app/ tests/ --max-line-length=100
bandit -r app/ -ll
```

---

## Stage 2: Docker Compose Verification

Before pushing to GitHub, verify everything works in Docker Compose (this matches the production setup).

```bash
# Build and start all services
docker compose up --build

# Verify all 4 services are running:
# - Web app: http://localhost:8000
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000 (admin / from .env)
# - Locust: http://localhost:8089

# Check health
curl http://localhost:8000/api/health

# Stop
docker compose down
```

### What Docker Compose Runs
| Service | Image | Port |
|---------|-------|------|
| web | Built from Dockerfile (multi-stage) | 8000 |
| prometheus | prom/prometheus:v2.51.2 | 9090 |
| grafana | grafana/grafana:10.4.2 | 3000 |
| locust | locustio/locust:2.24.1 | 8089 |

### Grafana Microsoft Login (Optional for Local)

Docker Compose includes Grafana Azure AD OAuth support. To enable "Sign in with Microsoft" locally:

1. **Create a client secret** in Azure Portal > App registrations > your app > Certificates & secrets
2. **Add redirect URI** in Azure Portal > App registrations > Authentication:
   - Click **Add a platform > Web** (must be **Web**, not SPA)
   - Add: `http://localhost:3000/login/azuread`
3. **Supported account types** must be set to "Any Entra ID Tenant + Personal Microsoft accounts"
4. **Update `.env`**:
   ```
   GF_AUTH_AZUREAD_ENABLED=true
   GF_AUTH_AZUREAD_CLIENT_SECRET=paste-your-secret-value-here
   ```
5. Restart: `docker compose down && docker compose up`

> **Note:** If you see "Failed to get token from provider", the redirect URI is likely registered as **SPA** instead of **Web**. Grafana requires the standard authorization code flow with a client secret, which only works with Web platform redirect URIs.

---

## Stage 3: Push to GitHub

```bash
git add -A
git commit -m "your commit message"
git push origin main
```

---

## Stage 4: CI/CD Pipeline (Automatic)

When you push to `main` or `master`, the GitHub Actions pipeline runs automatically.

### Pipeline Stages (9 stages)

| Stage | Tool | What It Does |
|-------|------|--------------|
| 1. Lint | Flake8 | Code quality checks |
| 2. SAST | CodeQL | Static security analysis (Python + JS) |
| 3. SCA | Snyk | Dependency vulnerability scanning |
| 4. Secrets | Gitleaks | Detect committed secrets |
| 5. SBOM | CycloneDX | Generate Software Bill of Materials |
| 6. Test | pytest | Unit & integration tests with coverage |
| 7. Docker Build | Buildx | Build container image |
| 8. Trivy Scan | Trivy | Container vulnerability scanning |
| 9. Docker Push | Docker Hub | Push image (latest + commit SHA tag) |

Stages 1-6 run in **parallel**. Stages 7-9 run **sequentially** after all pass.

### Required GitHub Secrets

Go to your repository **Settings > Secrets and variables > Actions** and add:

| Secret | Description |
|--------|-------------|
| `DOCKERHUB_USERNAME` | Your Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub access token |
| `SNYK_TOKEN` | Snyk API token (for SCA) |

### Verify Pipeline

Check the pipeline at: `https://github.com/<your-org>/cve-new-bri/actions`

After Stage 9 completes, the image is available at:
```
docker pull reonbritto/puresecure-cve-explorer:latest
```

---

## Stage 5: Create AKS Cluster

Only needed once (first-time setup). After the cluster exists, skip to Stage 6.

```bash
# Login to Azure
az login

# Create resource group
az group create --name rg-puresecure --location uksouth

# Create AKS cluster (Free tier, 1 node)
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
    --max-count 3

# Get credentials
az aks get-credentials --resource-group rg-puresecure --name aks-puresecure

# Verify
kubectl get nodes
```

> You can also create the cluster via Azure Portal if preferred.

> **Warning:** Do NOT use ARM-based VMs (e.g. `Standard_D2pls_v6` — the "p" means ARM/Ampere). The Docker image is built for AMD64 (x86). Using ARM nodes causes `exec format error`. Use `Standard_D2lds_v6` or similar x86 VM sizes.

---

## Stage 6: Deploy to AKS

Follow the full guide: **[aks-deployment.md](aks-deployment.md)**

### Quick Summary

```bash
# 1. Install Traefik ingress controller
helm repo add traefik https://traefik.github.io/charts && helm repo update
kubectl create namespace traefik
helm install traefik traefik/traefik --namespace traefik \
    --set ports.web.port=8000 --set ports.web.exposedPort=80 \
    --set ports.websecure.port=8443 --set ports.websecure.exposedPort=443 \
    --set service.type=LoadBalancer --set ingressRoute.dashboard.enabled=false --wait

# 2. Install cert-manager
helm repo add jetstack https://charts.jetstack.io && helm repo update
kubectl create namespace cert-manager
helm install cert-manager jetstack/cert-manager --namespace cert-manager --set installCRDs=true --wait

# 3. Set secrets
export SERVICE_API_KEY="your-api-key"
export GF_ADMIN_PASSWORD="your-grafana-password"
export GF_AUTH_AZUREAD_CLIENT_SECRET="your-azure-client-secret"

# 4. Deploy all K8s manifests
kubectl apply -f k8s/aks/namespace.yaml
kubectl apply -f k8s/aks/cert-manager/
kubectl apply -f k8s/aks/app/
kubectl create secret generic app-secrets --namespace=puresecure \
    --from-literal=SERVICE_API_KEY="$SERVICE_API_KEY" \
    --from-literal=GF_ADMIN_PASSWORD="$GF_ADMIN_PASSWORD" \
    --from-literal=GF_AUTH_AZUREAD_CLIENT_SECRET="$GF_AUTH_AZUREAD_CLIENT_SECRET" \
    --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f k8s/aks/prometheus/
kubectl apply -f k8s/aks/grafana/
kubectl apply -f k8s/aks/locust/
kubectl apply -f k8s/aks/traefik/

# 5. Verify
kubectl get pods -n puresecure
```

### Configure DNS

Add A records pointing to the Traefik Load Balancer IP:

| Type | Name | Value |
|------|------|-------|
| A | @ | `<LOAD_BALANCER_IP>` |
| A | grafana | `<LOAD_BALANCER_IP>` |

Get the IP: `kubectl get svc traefik -n traefik`

### Register Azure AD Redirect URIs

In Azure Portal > App registrations > your app > Authentication:

1. Click **Add a platform > Web** (must be **Web**, not SPA)
2. Add these redirect URIs:
   - `https://reondev.top`
   - `https://grafana.reondev.top/login/azuread`
3. Under **Supported accounts**, set to "Any Entra ID Tenant + Personal Microsoft accounts"
4. Create a **Client secret** under Certificates & secrets (value goes in `GF_AUTH_AZUREAD_CLIENT_SECRET`)

---

## Stage 7: Update Production (After Code Changes)

After making code changes and pushing to GitHub:

```bash
# 1. Push to GitHub (triggers CI/CD)
git add -A && git commit -m "your changes" && git push origin main

# 2. Wait for CI/CD to complete (check GitHub Actions)

# 3. Restart the deployment to pull the new image
kubectl rollout restart deployment/cwe-explorer -n puresecure

# 4. Watch the rollout
kubectl rollout status deployment/cwe-explorer -n puresecure
```

---

## Project Structure

```
cve-new-bri/
├── app/                    # FastAPI application source code
│   ├── main.py             # API routes, middleware, lifespan
│   ├── auth.py             # Microsoft Entra ID JWT validation
│   ├── models.py           # Pydantic models
│   ├── nvd_client.py       # NVD API 2.0 client
│   ├── cwe_parser.py       # MITRE CWE XML parser
│   ├── cache.py            # SQLite cache layer
│   ├── analytics.py        # Risk scoring, top CWEs
│   ├── security.py         # Input validation
│   ├── metrics.py          # Prometheus middleware
│   ├── attack_parser.py    # MITRE ATT&CK mapping
│   └── static/             # Frontend (HTML, JS, CSS)
├── monitoring/             # Prometheus & Grafana configs
├── locust/                 # Load testing scenarios
├── tests/                  # pytest test suite
├── k8s/aks/                # AKS deployment manifests
│   ├── app/                # App deployment, service, configmap, PVC
│   ├── cert-manager/       # TLS certificates (Let's Encrypt)
│   ├── grafana/            # Grafana with Azure AD OAuth
│   ├── locust/             # Load testing
│   ├── prometheus/         # Metrics collection
│   └── traefik/            # Ingress routes, middleware
├── docs/                   # Documentation
├── .github/workflows/      # CI/CD pipeline
├── Dockerfile              # Multi-stage build (Python 3.12-slim)
├── docker-compose.yml      # Local full-stack development
├── requirements.txt        # Production dependencies
└── requirements-dev.txt    # Dev dependencies (pytest, flake8, etc.)
```

---

## Useful Commands

```bash
# --- Local Development ---
uvicorn app.main:app --reload                    # Start dev server
pytest tests/ -v --tb=short --cov=app            # Run tests
docker compose up --build                         # Full local stack

# --- AKS Management ---
az aks get-credentials --resource-group rg-puresecure --name aks-puresecure
kubectl get pods -n puresecure                    # Check pod status
kubectl logs -f deployment/cwe-explorer -n puresecure  # App logs
kubectl rollout restart deployment/cwe-explorer -n puresecure  # Deploy new image
kubectl port-forward svc/prometheus 9090:9090 -n puresecure    # Access Prometheus
kubectl port-forward svc/locust 8089:8089 -n puresecure        # Access Locust

# --- Cluster Cost Management ---
az aks stop --resource-group rg-puresecure --name aks-puresecure   # Stop (save money)
az aks start --resource-group rg-puresecure --name aks-puresecure  # Start again
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `exec format error` on cwe-explorer | AKS node is ARM but image is AMD64 — use `Standard_D2lds_v6` (x86), not `Standard_D2pls_v6` (ARM). The **"p"** in VM name = ARM |
| Pod in `CrashLoopBackOff` | Check logs: `kubectl logs -l app=cwe-explorer -n puresecure --previous` |
| `CreateContainerConfigError` | Secret missing — recreate `app-secrets` with all 3 keys |
| Prometheus `permission denied` | Init container command order: `mkdir -p` first, then `chown -R`. Already fixed in deployment manifest |
| Prometheus `lock DB directory` | Two pods sharing PVC — scale to 0 then back to 1: `kubectl scale deployment prometheus -n puresecure --replicas=0` then `--replicas=1` |
| Grafana `Permission denied` | Delete and recreate the PVC: scale to 0, delete PVC, apply PVC yaml, scale to 1 |
| TLS certificate not issuing | Check cert-manager logs: `kubectl logs -l app=cert-manager -n cert-manager`. Ensure DNS A records point to Traefik LB IP |
| Grafana "Failed to get token from provider" | Redirect URI is registered as SPA instead of Web — remove it and re-add under **Web** platform |
| Grafana "User account does not exist in tenant" | Auth URLs must use `common` endpoint, and Supported account types must include personal Microsoft accounts |
| Infinite page refresh after login | Clear browser Local Storage, verify redirect URI is registered in Azure AD |
| Pipeline failing | Check GitHub Actions logs, ensure all secrets are configured |
