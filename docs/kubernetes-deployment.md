# Local Kubernetes Guide (Docker Desktop) — PureSecure CVE Explorer

> **For production AKS deployment, see [aks-deployment.md](aks-deployment.md).**

This guide covers running the PureSecure CVE Explorer locally using Docker Desktop for development and testing.

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

The local stack runs 4 services via Docker Compose:

| Component | Image | Purpose |
|-----------|-------|---------|
| **web** | `reonbritto/puresecure-cve-explorer:latest` | FastAPI application |
| **prometheus** | `prom/prometheus:v2.51.2` | Metrics collection |
| **grafana** | `grafana/grafana:10.4.2` | Monitoring dashboards |
| **locust** | `locustio/locust:2.24.1` | Load testing UI |

---

## Quick Start

The local Kubernetes manifests have been removed. For local development and testing, use Docker Compose instead:

```bash
# 1. Copy and configure environment variables
cp .env.example .env
# Edit .env with your actual Azure, API key, and Grafana values

# 2. Build the Docker image locally
docker build -t reonbritto/puresecure-cve-explorer:latest .

# 3. Start the full local stack
docker compose up
```

This brings up the web app, Prometheus, Grafana, and Locust in a single command.

---

## Access URLs

| Service | URL |
|---------|-----|
| **App** | <http://localhost:8000> |
| **Grafana** | <http://localhost:3000> (admin / admin) |
| **Prometheus** | <http://localhost:9090> |
| **Locust** | <http://localhost:8089> |

---

## Environment Variables

Environment variables are configured in `docker-compose.yml` and `.env.example`. Copy `.env.example` to `.env` and set your values:

| Variable | Default | Description |
|----------|---------|-------------|
| `AZURE_TENANT_ID` | *(required)* | Microsoft Entra ID tenant |
| `AZURE_CLIENT_ID` | *(required)* | App registration client ID |
| `SERVICE_API_KEY` | *(required)* | API key for Locust/monitoring auth |
| `GF_ADMIN_PASSWORD` | *(required)* | Grafana admin password |
| `CORS_ORIGINS` | `http://localhost:8000,http://127.0.0.1:8000` | Comma-separated allowed origins for CORS |
| `GRAFANA_URL` | `http://localhost:3000` | Grafana dashboard URL for nav links |
| `PROMETHEUS_URL` | `http://localhost:9090` | Prometheus URL for nav links |
| `LOCUST_URL` | `http://localhost:8089` | Locust URL for nav links (empty to hide) |

---

## Useful Commands

```bash
# View logs for a specific service
docker compose logs -f web
docker compose logs -f prometheus

# Rebuild after code changes
docker compose up --build

# Stop all services
docker compose down

# Stop and remove volumes
docker compose down -v
```

---

## Troubleshooting

### Containers failing to start

```bash
docker compose logs <service-name>
```

Common causes:
- Missing environment variables — ensure `.env` contains all required values (`SERVICE_API_KEY`, `GF_ADMIN_PASSWORD`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`)
- Port conflicts — ensure ports 8000, 3000, 9090, and 8089 are not in use by other applications
- Insufficient memory — increase Docker Desktop resources: **Settings > Resources > Memory**

### Infinite page refresh after login

If the page keeps refreshing after signing in with Microsoft:

1. **Check Azure AD redirect URI** — ensure `http://localhost:8000` is registered as a redirect URI in your Azure AD app registration (Azure Portal > App registrations > Authentication).

2. **Clear browser storage** — open DevTools > Application > Local Storage and clear all entries for the site, then try logging in again.

3. **Check container logs** for 401 errors:
   ```bash
   docker compose logs -f web
   ```

### Grafana "Failed to get token from provider"

The Grafana Microsoft login redirect URI must be registered as **Web** platform (not SPA) in Azure Portal > App registrations > Authentication. SPA uses PKCE without a client secret, which doesn't work with Grafana's authorization code flow.

### Grafana "User account does not exist in tenant"

The auth URLs in `docker-compose.yml` use the `common` endpoint to support personal Microsoft accounts. Ensure **Supported account types** is set to "Any Entra ID Tenant + Personal Microsoft accounts" in Azure Portal > App registrations > Authentication.

### Image build errors

```bash
docker build -t reonbritto/puresecure-cve-explorer:latest .
```

If the build fails, check that all required files (e.g., `requirements.txt`, application source) are present and not excluded by `.dockerignore`.

---

## Tearing Down

Stop and remove all containers:

```bash
docker compose down
```

To also remove volumes (databases, metrics data):

```bash
docker compose down -v
```

Disable Kubernetes (if enabled): Docker Desktop > **Settings > Kubernetes > uncheck Enable Kubernetes**.
