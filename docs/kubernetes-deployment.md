# Kubernetes Deployment Guide — PureSecure CVE Explorer

Deploy the PureSecure CVE Explorer on **Docker Desktop Kubernetes** for local development and testing.

---

## Prerequisites

| Tool | Install |
|------|---------|
| **Docker Desktop** | <https://docs.docker.com/desktop/install/windows-install/> |
| **kubectl** | Bundled with Docker Desktop |

Enable Kubernetes in Docker Desktop: **Settings > Kubernetes > Enable Kubernetes > Apply & Restart**.

Verify:

```bash
docker --version
kubectl version --client
kubectl get nodes
```

Expected node output:

```
NAME             STATUS   ROLES           AGE   VERSION
docker-desktop   Ready    control-plane   ...   v1.x.x
```

---

## Architecture Overview

The application deploys 3 services into a `puresecure` namespace:

```
                        ┌─────────────────────────────────┐
                        │         puresecure namespace     │
                        │                                  │
  User ──► localhost ─► │  ┌──────────┐                   │
         (port-forward) │  │   web     │ ◄── FastAPI app   │
                        │  │  :8000    │     (port 8000)   │
                        │  └────┬─────┘                    │
                        │       │ /metrics                 │
                        │  ┌────▼──────┐                   │
                        │  │prometheus │ ◄── Metrics store  │
                        │  │  :9090    │     (port 9090)   │
                        │  └────┬──────┘                   │
                        │       │                          │
                        │  ┌────▼──────┐                   │
                        │  │  grafana  │ ◄── Dashboards    │
                        │  │  :3000    │     (port 3000)   │
                        │  └───────────┘                   │
                        └─────────────────────────────────┘
```

| Component | Image | Purpose |
|-----------|-------|---------|
| **web** | `reonbritto/puresecure-cve-explorer:latest` | FastAPI application |
| **prometheus** | `prom/prometheus:v2.51.2` | Metrics collection |
| **grafana** | `grafana/grafana:10.4.2` | Monitoring dashboards |

---

## Quick Start

```bash
chmod +x k8s/setup.sh
./k8s/setup.sh
```

The script will:
1. Create the `puresecure` namespace
2. Create secrets
3. Deploy all services (app, Prometheus, Grafana)
4. Deploy NGINX ingress
5. Wait for pods to be ready
6. Print access URLs

---

## Step-by-Step Deployment

### 1. Enable Kubernetes

Open Docker Desktop > **Settings > Kubernetes > Enable Kubernetes** > Apply & Restart.

Wait for the Kubernetes status icon (bottom-left) to turn green.

### 2. Build or Load the Docker Image

**Option A: Pull from Docker Hub**

No action needed. The deployment pulls `reonbritto/puresecure-cve-explorer:latest` automatically.

**Option B: Build locally**

```bash
docker build -t reonbritto/puresecure-cve-explorer:latest .
```

Since Docker Desktop Kubernetes shares the Docker daemon, locally built images are immediately available — no extra loading step required.

### 3. Create the Namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

### 4. Create Secrets

```bash
kubectl create secret generic app-secrets \
  --namespace=puresecure \
  --from-literal=SERVICE_API_KEY="puresecure-locust-key-2026" \
  --from-literal=GF_ADMIN_PASSWORD="admin" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Or from your `.env` file:

```bash
export $(grep -v '^#' .env | xargs)

kubectl create secret generic app-secrets \
  --namespace=puresecure \
  --from-literal=SERVICE_API_KEY="$SERVICE_API_KEY" \
  --from-literal=GF_ADMIN_PASSWORD="$GF_ADMIN_PASSWORD" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 5. Deploy All Services

```bash
kubectl apply -f k8s/app/ -f k8s/prometheus/ -f k8s/grafana/ -f k8s/ingress.yaml
```

### 6. Verify the Deployment

```bash
kubectl rollout status deployment/cwe-explorer -n puresecure --timeout=300s
kubectl rollout status deployment/prometheus -n puresecure --timeout=60s
kubectl rollout status deployment/grafana -n puresecure --timeout=60s
```

Check pods:

```bash
kubectl get pods -n puresecure
```

Expected:

```
NAME                            READY   STATUS    RESTARTS   AGE
cwe-explorer-xxxxxxxxxx-xxxxx   1/1     Running   0          1m
prometheus-xxxxxxxxxx-xxxxx     1/1     Running   0          1m
grafana-xxxxxxxxxx-xxxxx        1/1     Running   0          1m
```

### 7. Access the Application

**Port Forwarding (recommended):**

```bash
# Terminal 1 — Web app
kubectl port-forward svc/web 8000:8000 -n puresecure

# Terminal 2 — Grafana
kubectl port-forward svc/grafana 3000:3000 -n puresecure

# Terminal 3 — Prometheus
kubectl port-forward svc/prometheus 9090:9090 -n puresecure
```

| Service | URL |
|---------|-----|
| **App** | <http://localhost:8000> |
| **Grafana** | <http://localhost:3000> (admin / admin) |
| **Prometheus** | <http://localhost:9090> |

**Ingress (optional):**

Install the NGINX ingress controller:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.1/deploy/static/provider/cloud/deploy.yaml
```

Add to `C:\Windows\System32\drivers\etc\hosts` (run Notepad as Admin):

```
127.0.0.1  puresecure.local grafana.puresecure.local prometheus.puresecure.local
```

Then access via <http://puresecure.local>.

---

## Useful Commands

```bash
# View logs
kubectl logs -f deployment/cwe-explorer -n puresecure
kubectl logs -f deployment/prometheus -n puresecure

# Get all resources
kubectl get all -n puresecure

# Describe a pod
kubectl describe pod -l app=cwe-explorer -n puresecure

# Check PVCs
kubectl get pvc -n puresecure

# Shell into the app container
kubectl exec -it deployment/cwe-explorer -n puresecure -- /bin/sh

# Restart the app
kubectl rollout restart deployment/cwe-explorer -n puresecure

# Scale (web app must stay at 1 due to SQLite)
kubectl scale deployment/grafana --replicas=0 -n puresecure
```

---

## Troubleshooting

### Pod stuck in `CrashLoopBackOff`

```bash
kubectl describe pod -l app=cwe-explorer -n puresecure
kubectl logs -l app=cwe-explorer -n puresecure --previous
```

Common causes:
- Missing secret (`app-secrets`) or `GF_ADMIN_PASSWORD` key — recreate using step 4
- Insufficient memory — increase Docker Desktop resources: **Settings > Resources > Memory**

### Pod stuck in `Pending`

```bash
kubectl describe pod -l app=cwe-explorer -n puresecure
```

Common causes:
- PVC not bound — check StorageClass: `kubectl get sc`
- Insufficient resources — increase Docker Desktop CPU/Memory in Settings

### Ingress not working

```bash
kubectl get ingress -n puresecure
kubectl get pods -n ingress-nginx
```

If ingress controller isn't installed, use port-forwarding instead.

### Image pull errors

Since Docker Desktop shares its daemon with Kubernetes, build locally:

```bash
docker build -t reonbritto/puresecure-cve-explorer:latest .

kubectl patch deployment cwe-explorer -n puresecure \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"cwe-explorer","imagePullPolicy":"Never"}]}}}}'
```

---

## Tearing Down

Remove all resources:

```bash
kubectl delete namespace puresecure
```

Disable Kubernetes: Docker Desktop > **Settings > Kubernetes > uncheck Enable Kubernetes**.

---

## AKS Migration Notes

When moving to Azure Kubernetes Service:

### 1. Container Registry

```bash
az acr create -n puresecureacr -g rg-puresecure --sku Basic
az acr login -n puresecureacr

docker tag reonbritto/puresecure-cve-explorer \
  puresecureacr.azurecr.io/puresecure-cve-explorer:latest

docker push puresecureacr.azurecr.io/puresecure-cve-explorer:latest

az aks update -n aks-puresecure -g rg-puresecure --attach-acr puresecureacr
```

Update `k8s/app/deployment.yaml` image to `puresecureacr.azurecr.io/puresecure-cve-explorer:latest`.

### 2. Storage Class

Update PVCs (`k8s/app/pvc.yaml`, `k8s/grafana/pvc.yaml`):

```yaml
spec:
  storageClassName: managed-csi
```

### 3. Secrets

Use Azure Key Vault:

```bash
az keyvault create -n puresecure-kv -g rg-puresecure
az keyvault secret set --vault-name puresecure-kv --name SERVICE-API-KEY --value "your-key"
```

### 4. Ingress

Replace NGINX with Azure Application Gateway:

```yaml
spec:
  ingressClassName: azure-application-gateway
```

### 5. TLS

```yaml
spec:
  tls:
    - hosts:
        - puresecure.yourdomain.com
      secretName: puresecure-tls
```
