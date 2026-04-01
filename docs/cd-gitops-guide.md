# PureSecure CVE Explorer — CD, GitOps, Helm & Azure Key Vault Guide

Complete end-to-end guide for implementing Continuous Deployment with ArgoCD, Helm charts, automated image tag updates, and Azure Key Vault secret management.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites & Tool Installation](#2-prerequisites--tool-installation)
3. [Phase 1: Azure Resource Group & AKS Cluster](#3-phase-1-azure-resource-group--aks-cluster)
4. [Phase 2: Azure AD App Registration](#4-phase-2-azure-ad-app-registration)
5. [Phase 3: Install Traefik Ingress Controller](#5-phase-3-install-traefik-ingress-controller)
6. [Phase 4: Install cert-manager for TLS](#6-phase-4-install-cert-manager-for-tls)
7. [Phase 5: DNS Configuration](#7-phase-5-dns-configuration)
8. [Phase 6: GitHub & DockerHub Secrets](#8-phase-6-github--dockerhub-secrets)
9. [Phase 7: Azure Key Vault Setup](#9-phase-7-azure-key-vault-setup)
10. [Phase 8: AKS Workload Identity Configuration](#10-phase-8-aks-workload-identity-configuration)
11. [Phase 9: Install External Secrets Operator](#11-phase-9-install-external-secrets-operator)
12. [Phase 10: Helm Chart Structure](#12-phase-10-helm-chart-structure)
13. [Phase 11: Install ArgoCD](#13-phase-11-install-argocd)
14. [Phase 12: Configure ArgoCD](#14-phase-12-configure-argocd)
15. [Phase 13: CI Pipeline Changes](#15-phase-13-ci-pipeline-changes)
16. [Phase 14: Migration from Raw Manifests](#16-phase-14-migration-from-raw-manifests)
17. [Verification & Testing](#17-verification--testing)
18. [Troubleshooting](#18-troubleshooting)
19. [Day-2 Operations](#19-day-2-operations)

---

## 1. Architecture Overview

### GitOps Flow

```
Developer pushes code to main
        │
        ▼
GitHub Actions CI (Stages 1–9)
  Lint → SAST → SCA → Secrets Scan → SBOM → Tests → Docker Build → Trivy → Docker Push
        │
        ▼
Stage 10: update-manifest job
  • yq updates helm/puresecure/values.yaml with new SHA tag
  • git commit + push to main
        │
        ▼
ArgoCD detects values.yaml change (webhook or 3-min poll)
        │
        ▼
ArgoCD runs: helm template → kubectl apply (server-side)
  • Deployment gets new image tag → rolling update
  • ESO ExternalSecret unchanged → secrets stay synced from Key Vault
        │
        ▼
App pods roll out with new image
Secrets pulled from Azure Key Vault via External Secrets Operator
```

### Component Overview

| Component | Purpose | Namespace |
|-----------|---------|-----------|
| **ArgoCD** | GitOps CD — watches Git, syncs Helm chart to AKS | `argocd` |
| **External Secrets Operator** | Syncs secrets from Azure Key Vault to K8s Secrets | `external-secrets` |
| **Helm Chart** | Parameterized K8s manifests for all resources | `puresecure` |
| **GitHub Actions** | CI pipeline (security, build, push, tag update) | N/A |
| **Azure Key Vault** | Centralized secrets storage | Azure (cloud) |
| **Traefik** | Ingress controller with TLS | `traefik` |
| **cert-manager** | TLS certificate automation (Let's Encrypt) | `cert-manager` |

---

## 2. Prerequisites & Tool Installation

### 2.1 Required Tools

Install all the following tools before proceeding:

```bash
# ── Azure CLI ──────────────────────────────────────────────
# macOS
brew install azure-cli

# Linux (Ubuntu/Debian)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Windows (PowerShell)
winget install Microsoft.AzureCLI

# Verify
az --version          # >= 2.50.0
```

```bash
# ── kubectl (Kubernetes CLI) ───────────────────────────────
# macOS
brew install kubectl

# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Windows (via Azure CLI — installs automatically)
az aks install-cli

# Verify
kubectl version --client      # >= 1.28
```

```bash
# ── Helm ───────────────────────────────────────────────────
# macOS
brew install helm

# Linux
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Windows
winget install Helm.Helm

# Verify
helm version          # >= 3.12
```

```bash
# ── ArgoCD CLI (optional but recommended) ──────────────────
# macOS
brew install argocd

# Linux
curl -sSL -o argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
chmod +x argocd && sudo mv argocd /usr/local/bin/

# Verify
argocd version --client       # >= 2.9
```

```bash
# ── yq (YAML processor — used by CI) ──────────────────────
# macOS
brew install yq

# Linux
sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
sudo chmod +x /usr/local/bin/yq

# Verify
yq --version          # >= 4.30
```

### 2.2 Required Accounts & Access

| Account | Purpose | Signup |
|---------|---------|--------|
| **Azure Subscription** | AKS, Key Vault, Managed Identity | [portal.azure.com](https://portal.azure.com) |
| **GitHub Account** | Source code, CI/CD pipeline | [github.com](https://github.com) |
| **DockerHub Account** | Container image registry | [hub.docker.com](https://hub.docker.com) |
| **Domain Name** | DNS for app, Grafana, ArgoCD | Any registrar (e.g., Cloudflare, Namecheap) |

### 2.3 Authenticate to Azure

```bash
# Login to Azure (opens browser)
az login

# Set the subscription (if you have multiple)
az account set --subscription "<YOUR_SUBSCRIPTION_NAME_OR_ID>"

# Verify
az account show --output table
```

---

## 3. Phase 1: Azure Resource Group & AKS Cluster

### 3.1 Create the Resource Group

```bash
az group create \
  --name rg-puresecure \
  --location uksouth
```

### 3.2 Register Required Azure Resource Providers

Azure subscriptions must have resource providers registered before you can use their services. Register all providers needed for this project:

```bash
# Register all required providers (run all at once)
az provider register --namespace Microsoft.ContainerService    # AKS
az provider register --namespace Microsoft.KeyVault            # Azure Key Vault
az provider register --namespace Microsoft.ManagedIdentity     # Workload Identity
az provider register --namespace Microsoft.Network             # Virtual Network, Load Balancer
az provider register --namespace Microsoft.Compute             # Virtual Machine Scale Sets (nodes)
az provider register --namespace Microsoft.Storage             # Persistent Volumes (managed disks)
az provider register --namespace Microsoft.OperationsManagement  # Container Insights (optional)
```

Wait for all providers to reach `Registered` state:

```bash
# Check registration status (run until all show "Registered")
az provider show --namespace Microsoft.ContainerService --query "registrationState" -o tsv
az provider show --namespace Microsoft.KeyVault --query "registrationState" -o tsv
az provider show --namespace Microsoft.ManagedIdentity --query "registrationState" -o tsv
az provider show --namespace Microsoft.Network --query "registrationState" -o tsv
az provider show --namespace Microsoft.Compute --query "registrationState" -o tsv
az provider show --namespace Microsoft.Storage --query "registrationState" -o tsv
```

> **Note**: Registration typically takes 1–3 minutes per provider. You can proceed once `Microsoft.ContainerService` is registered and come back to verify the rest before Phase 7 (Key Vault).

### 3.3 Create the AKS Cluster

```bash
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
```

> **Note**: This creates a Free-tier AKS cluster with 1 node (Standard_D2lds_v6: 2 vCPU, 4 GiB RAM) and cluster autoscaler enabled (scales 1–2 nodes). The `--enable-managed-identity` flag is required for Workload Identity in later steps.

This command takes 3–5 minutes to complete.

### 3.4 Connect kubectl to the Cluster

```bash
az aks get-credentials \
  --resource-group rg-puresecure \
  --name aks-puresecure \
  --overwrite-existing
```

### 3.5 Verify Cluster Connection

```bash
kubectl cluster-info
kubectl get nodes
```

Expected output:
```
NAME                                STATUS   ROLES    AGE   VERSION
aks-nodepool1-xxxxxxxx-vmssxxxxxx   Ready    <none>   5m    v1.29.x
```

### 3.6 Verify Cluster Capabilities

```bash
# Check available storage classes (managed-csi should be present)
kubectl get storageclass

# Check Kubernetes version
kubectl version --short
```

---

## 4. Phase 2: Azure AD App Registration

The application uses Microsoft Entra ID (Azure AD) for user authentication. You need to register an application in Azure AD.

### 4.1 Register the Application

1. Go to [Azure Portal](https://portal.azure.com) → **Microsoft Entra ID** → **App registrations** → **New registration**
2. Fill in:
   - **Name**: `PureSecure CVE Explorer`
   - **Supported account types**: Accounts in any organizational directory and personal Microsoft accounts
   - **Redirect URI (Web)**: `https://reondev.top`
3. Click **Register**

### 4.2 Note the Application IDs

After registration, note these values from the **Overview** page:
- **Application (client) ID** — this is `AZURE_CLIENT_ID` in the Helm values
- **Directory (tenant) ID** — this is `AZURE_TENANT_ID` in the Helm values

### 4.3 Add Redirect URIs

Go to **Authentication** → **Add a platform** → **Web** and add:
```
https://reondev.top
https://grafana.reondev.top/login/azuread
```

### 4.4 Create a Client Secret (for Grafana OAuth)

1. Go to **Certificates & secrets** → **New client secret**
2. **Description**: `grafana-oauth`
3. **Expires**: 24 months (or your preference)
4. Click **Add**
5. **Copy the secret value immediately** — you will need it for Azure Key Vault (`gf-auth-azuread-client-secret`)

### 4.5 Configure API Permissions

Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**:
- `openid`
- `profile`
- `email`
- `User.Read`

Click **Grant admin consent** if you have admin access.

### 4.6 Store Azure AD IDs in Key Vault

These IDs are stored in Azure Key Vault and pulled into the cluster via External Secrets Operator. You will add them in Phase 7 (Key Vault Setup):

```bash
# Store in Azure Key Vault (done in Phase 7)
az keyvault secret set --vault-name kv-puresecure-prod --name azure-tenant-id --value "<YOUR_DIRECTORY_TENANT_ID>"
az keyvault secret set --vault-name kv-puresecure-prod --name azure-client-id --value "<YOUR_APPLICATION_CLIENT_ID>"
```

> **Note**: `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` are no longer hardcoded in `values.yaml`. They are pulled from Key Vault via the `app-secrets` ExternalSecret and injected as environment variables into both the app and Grafana pods.

---

## 5. Phase 3: Install Traefik Ingress Controller

Traefik handles all incoming HTTP/HTTPS traffic and routes it to the correct services.

### 5.1 Add the Traefik Helm Repository

```bash
helm repo add traefik https://traefik.github.io/charts
helm repo update
```

### 5.2 Install Traefik

```bash
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

### 5.3 Get the LoadBalancer External IP

```bash
# Wait for the external IP to be assigned (1–2 minutes)
kubectl get svc traefik -n traefik --watch
```

Once assigned:
```bash
export LB_IP=$(kubectl get svc traefik -n traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "LoadBalancer IP: $LB_IP"
```

> **Save this IP** — ExternalDNS will use it automatically in Phase 5, but you may need it for verification.

### 5.4 Verify Traefik

```bash
kubectl get pods -n traefik
kubectl get svc -n traefik
```

---

## 6. Phase 4: Install cert-manager for TLS

cert-manager automates TLS certificate provisioning from Let's Encrypt.

### 6.1 Add the Jetstack Helm Repository

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update
```

### 6.2 Install cert-manager

```bash
kubectl create namespace cert-manager

helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --set installCRDs=true \
  --wait
```

### 6.3 Verify Installation

```bash
kubectl get pods -n cert-manager
```

Expected output:
```
NAME                                       READY   STATUS    RESTARTS   AGE
cert-manager-xxxxxxxxx-xxxxx               1/1     Running   0          1m
cert-manager-cainjector-xxxxxxxxx-xxxxx    1/1     Running   0          1m
cert-manager-webhook-xxxxxxxxx-xxxxx       1/1     Running   0          1m
```

> **Note**: The ClusterIssuer and Certificate resources are part of the Helm chart and will be created automatically when ArgoCD syncs.

---

## 7. Phase 5: Automated DNS Configuration (ExternalDNS)

Instead of manually updating A records at your domain registrar, we use **ExternalDNS** with Azure Workload Identity to automatically map the Traefik LoadBalancer IP to our Azure DNS Zone. 

### 7.1 Setup Azure Identity for ExternalDNS

Execute this from your terminal to create the Identity and grant it permissions to modify your DNS Zone.

```bash
# Set your variables
# DNS_RG is the resource group where your Azure DNS Zone lives
# AKS_RG is the resource group where your AKS cluster lives
export DNS_RG="sa"
export AKS_RG="rg-puresecure"
export DNS_ZONE="reondev.top"
export AKS_NAME="aks-puresecure"

# 1. Create User-Assigned Managed Identity (in the DNS resource group)
az identity create --name external-dns-id --resource-group $DNS_RG

export EXT_DNS_CLIENT_ID=$(az identity show --name external-dns-id --resource-group $DNS_RG --query clientId -o tsv)
export EXT_DNS_PRINCIPAL_ID=$(az identity show --name external-dns-id --resource-group $DNS_RG --query principalId -o tsv)

echo "ExternalDNS Client ID: $EXT_DNS_CLIENT_ID"   # Save this — needed for helm/external-dns-values.yaml

# 2. Grant 'DNS Zone Contributor' to the Identity
export DNS_ZONE_ID=$(az network dns zone show --name $DNS_ZONE --resource-group $DNS_RG --query id -o tsv)

az role assignment create \
  --role "DNS Zone Contributor" \
  --assignee $EXT_DNS_PRINCIPAL_ID \
  --scope $DNS_ZONE_ID

# 3. Create Workload Identity Federation (Linking to K8s ServiceAccount)
export AKS_OIDC_ISSUER="$(az aks show -n $AKS_NAME -g $AKS_RG --query "oidcIssuerProfile.issuerUrl" -otsv)"

az identity federated-credential create \
  --name external-dns-federation \
  --identity-name external-dns-id \
  --resource-group $DNS_RG \
  --issuer $AKS_OIDC_ISSUER \
  --subject system:serviceaccount:external-dns:external-dns-sa \
  --audience api://AzureADTokenExchange
```

### 7.2 Configure and Install ExternalDNS

The `helm/external-dns-values.yaml` file is already populated by Terraform outputs. Review it to confirm the values look correct, then install:

```bash
# Install ExternalDNS
helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/
helm repo update

helm upgrade --install external-dns external-dns/external-dns \
  -n external-dns --create-namespace \
  -f helm/external-dns-values.yaml
```

### 7.3 Annotate the Traefik Service

> **Important**: ExternalDNS uses the **`service` source**, not the `traefik-proxy` source. The `traefik-proxy` source does not auto-discover the LoadBalancer IP — it requires manually annotating every IngressRoute with the IP, which is fragile. Instead, we annotate the **Traefik LoadBalancer Service** with all hostnames. ExternalDNS reads the real IP from the Service and creates A records for each hostname automatically.

After Traefik is installed and has an external IP, run this **once**:

```bash
# Get the LoadBalancer IP first
export LB_IP=$(kubectl get svc traefik -n traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "Traefik LB IP: $LB_IP"

# Annotate the Traefik Service with all hostnames
# ExternalDNS will create A records pointing each hostname to $LB_IP
kubectl annotate service traefik -n traefik \
  "external-dns.alpha.kubernetes.io/hostname=reondev.top,grafana.reondev.top,argocd.reondev.top" \
  --overwrite
```

This annotation is persistent. If the LoadBalancer IP ever changes (e.g. after a Traefik reinstall), ExternalDNS will automatically update all three A records.

### 7.4 Verify DNS Propagation

```bash
# Watch ExternalDNS logs — you should see A records being created
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns -f
# Expected: "Desired change: CREATE reondev.top A [<LB_IP>]" etc.

# Wait 1–2 minutes, then verify DNS resolution
nslookup reondev.top
nslookup grafana.reondev.top
nslookup argocd.reondev.top
```

All three should resolve to the same Traefik LoadBalancer IP.

> **Note**: TLS certificates (Let's Encrypt) will only be issued once DNS is resolving correctly. If the site shows a certificate error initially, wait approximately 5 minutes for cert-manager.

---

## 8. Phase 6: GitHub & DockerHub Secrets

The CI pipeline needs credentials to push Docker images and run security scans.

### 8.1 Create a DockerHub Access Token

1. Go to [hub.docker.com](https://hub.docker.com) → **Account Settings** → **Security** → **New Access Token**
2. **Description**: `github-actions-puresecure`
3. **Access permissions**: Read & Write
4. Click **Generate** and copy the token

### 8.2 Get a Snyk API Token (for SCA)

1. Go to [snyk.io](https://snyk.io) → **Account Settings** → **API Token**
2. Copy the token

### 8.3 Add Secrets to GitHub Repository

Go to your GitHub repo → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

Add these secrets:

| Secret Name | Value | Used By |
|-------------|-------|---------|
| `DOCKERHUB_USERNAME` | Your DockerHub username | Docker Push (Stage 9) |
| `DOCKERHUB_TOKEN` | DockerHub access token (from 8.1) | Docker Push (Stage 9) |
| `SNYK_TOKEN` | Snyk API token (from 8.2) | SCA scan (Stage 3) |

### 8.4 Verify GitHub Secrets

Go to **Settings** → **Secrets and variables** → **Actions**. You should see all three secrets listed (values are hidden).

---

## 9. Phase 7: Azure Key Vault Setup

### 9.1 Create the Key Vault

```bash
az keyvault create \
  --name kv-puresecure-prod \
  --resource-group rg-puresecure \
  --location uksouth \
  --enable-rbac-authorization true
```

### 9.2 Store Secrets in Key Vault

```bash
# Azure AD Application IDs (used by the app and Grafana OAuth)
az keyvault secret set \
  --vault-name kv-puresecure-prod \
  --name azure-tenant-id \
  --value "<YOUR_DIRECTORY_TENANT_ID>"

az keyvault secret set \
  --vault-name kv-puresecure-prod \
  --name azure-client-id \
  --value "<YOUR_APPLICATION_CLIENT_ID>"

# Application API key (for Locust, monitoring, internal tools)
az keyvault secret set \
  --vault-name kv-puresecure-prod \
  --name service-api-key \
  --value "<GENERATE_A_STRONG_RANDOM_KEY>"

# Grafana admin password
az keyvault secret set \
  --vault-name kv-puresecure-prod \
  --name gf-admin-password \
  --value "<CHOOSE_A_STRONG_PASSWORD>"

# Grafana Azure AD client secret (from Phase 2, step 4.4)
az keyvault secret set \
  --vault-name kv-puresecure-prod \
  --name gf-auth-azuread-client-secret \
  --value "<YOUR_AZURE_AD_CLIENT_SECRET>"
```

> **Important**: Never commit real secret values to Git. The placeholder values above must be replaced with your actual secrets.

### 9.3 Verify Secrets

```bash
az keyvault secret list --vault-name kv-puresecure-prod --output table
```

Expected output:
```
Name                              ContentType    Enabled
--------------------------------  -------------  ---------
azure-tenant-id                                  True
azure-client-id                                  True
service-api-key                                  True
gf-admin-password                                True
gf-auth-azuread-client-secret                    True
```

---

## 10. Phase 8: AKS Workload Identity Configuration

Workload Identity allows pods to authenticate to Azure Key Vault without storing credentials in the cluster.

### 10.1 Enable OIDC Issuer and Workload Identity on AKS

```bash
az aks update \
  --resource-group rg-puresecure \
  --name aks-puresecure \
  --enable-oidc-issuer \
  --enable-workload-identity
```

### 10.2 Get the OIDC Issuer URL

```bash
export AKS_OIDC_ISSUER=$(az aks show \
  --name aks-puresecure \
  --resource-group rg-puresecure \
  --query "oidcIssuerProfile.issuerUrl" \
  --output tsv)

echo "OIDC Issuer: $AKS_OIDC_ISSUER"
```

### 10.3 Create a User-Assigned Managed Identity

```bash
az identity create \
  --name id-puresecure-eso \
  --resource-group rg-puresecure \
  --location uksouth
```

### 10.4 Get the Managed Identity Client ID

```bash
export MI_CLIENT_ID=$(az identity show \
  --name id-puresecure-eso \
  --resource-group rg-puresecure \
  --query clientId \
  --output tsv)

echo "Managed Identity Client ID: $MI_CLIENT_ID"
```

> **Important**: Save this `MI_CLIENT_ID` value. You will need it in `values.yaml` under `externalSecrets.managedIdentityClientId`.
### 10.5 Grant Key Vault Access to the Managed Identity

```bash
export SUBSCRIPTION_ID=$(az account show --query id --output tsv)

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee $MI_CLIENT_ID \
  --scope /subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-puresecure/providers/Microsoft.KeyVault/vaults/kv-puresecure-prod
```

### 10.6 Create Federated Credential

This links the Managed Identity to the Kubernetes Service Account that ESO will use.

```bash
az identity federated-credential create \
  --name fc-puresecure-eso \
  --identity-name id-puresecure-eso \
  --resource-group rg-puresecure \
  --issuer $AKS_OIDC_ISSUER \
  --subject system:serviceaccount:puresecure:eso-service-account \
  --audiences api://AzureADTokenExchange
```

### 10.7 Update Helm Values

Update `helm/puresecure/values.yaml` with the Managed Identity Client ID:

```yaml
externalSecrets:
  enabled: true
  managedIdentityClientId: "<MI_CLIENT_ID from step 10.4>"
```

---

## 11. Phase 9: Install External Secrets Operator

### 11.1 Add the Helm Repository

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
```

### 11.2 Install ESO

```bash
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set installCRDs=true \
  --wait
```

### 11.3 Verify Installation

```bash
kubectl get pods -n external-secrets
```

Expected output:
```
NAME                                                READY   STATUS    RESTARTS   AGE
external-secrets-xxxxxxxxx-xxxxx                    1/1     Running   0          1m
external-secrets-cert-controller-xxxxxxxxx-xxxxx    1/1     Running   0          1m
external-secrets-webhook-xxxxxxxxx-xxxxx            1/1     Running   0          1m
```

---

## 12. Phase 10: Helm Chart Structure

The Helm chart is located at `helm/puresecure/` and contains all Kubernetes resources.

### Directory Structure

```
helm/puresecure/
├── Chart.yaml                              # Chart metadata
├── values.yaml                             # All configurable values (CI updates image.tag)
└── templates/
    ├── _helpers.tpl                         # Common label templates
    ├── namespace.yaml                       # Namespace
    ├── app/
    │   ├── deployment.yaml                  # FastAPI application
    │   ├── service.yaml                     # ClusterIP service (port 8000)
    │   ├── configmap.yaml                   # App configuration
    │   └── pvc.yaml                         # CWE data storage (2Gi)
    ├── prometheus/
    │   ├── deployment.yaml                  # Prometheus v2.51.2
    │   ├── service.yaml                     # ClusterIP service (port 9090)
    │   ├── configmap.yaml                   # Scrape configs, recording & alerting rules
    │   └── pvc.yaml                         # TSDB storage (5Gi)
    ├── grafana/
    │   ├── deployment.yaml                  # Grafana 10.4.2 with init container
    │   ├── service.yaml                     # ClusterIP service (port 3000)
    │   ├── configmap-auth.yaml              # Azure AD OAuth configuration
    │   ├── configmap-provisioning.yaml      # Datasource & dashboard provisioning
    │   ├── configmap-dashboard.yaml         # Dashboard JSON (18 panels)
    │   └── pvc.yaml                         # Grafana data storage (2Gi)
    ├── locust/
    │   ├── deployment.yaml                  # Locust 2.24.1 load testing
    │   ├── service.yaml                     # ClusterIP service (port 8089)
    │   └── configmap.yaml                   # Python load test script
    ├── traefik/
    │   ├── ingressroute.yaml                # HTTP→HTTPS redirect, app & Grafana routes
    │   └── middleware.yaml                  # Security headers, rate limiting
    ├── cert-manager/
    │   ├── certificates.yaml                # TLS cert for reondev.top domains
    │   └── clusterissuer.yaml               # Let's Encrypt prod & staging issuers
    └── secrets/
        ├── secret-store.yaml                # ESO SecretStore + ServiceAccount
        └── external-secret.yaml             # Maps Azure KV secrets → K8s Secret
```

### Key Configuration in values.yaml

| Path | Purpose | CI Updates? |
|------|---------|-------------|
| `app.image.tag` | Docker image tag | **Yes** — auto-updated by Stage 10 |
| `app.config.*` | Non-sensitive environment variables | No |
| `externalSecrets.secrets[]` | Secret mappings (Azure KV → K8s) | As needed |
| `externalSecrets.managedIdentityClientId` | Azure Managed Identity for ESO | Set once |
| `ingress.hosts.*` | Domain names | No |

> **Note**: Sensitive values (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `SERVICE_API_KEY`, Grafana secrets) are stored in Azure Key Vault and pulled via ExternalSecrets — they are **not** in `values.yaml`.

### Validate the Chart Locally

```bash
# Lint the chart
helm lint helm/puresecure/

# Render templates (dry run)
helm template puresecure helm/puresecure/

# Dry-run install
helm install puresecure helm/puresecure/ --dry-run --debug
```

---

## 13. Phase 11: Install ArgoCD

### 13.1 Create the ArgoCD Namespace

```bash
kubectl create namespace argocd
```

### 13.2 Install ArgoCD

```bash
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

### 13.3 Wait for ArgoCD to be Ready

```bash
kubectl wait --for=condition=available deployment/argocd-server -n argocd --timeout=300s
```

### 13.4 Get the Initial Admin Password

```bash
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
echo
```

> **Important**: Change this password after first login.

### 13.5 Configure ArgoCD to Disable TLS (Traefik handles TLS)

ArgoCD server runs with its own TLS by default. Since Traefik terminates TLS, we need to tell ArgoCD to run in insecure mode behind the reverse proxy:

```bash
kubectl patch configmap argocd-cmd-params-cm -n argocd \
  --type merge \
  -p '{"data":{"server.insecure":"true"}}'

# Restart ArgoCD server to pick up the change
kubectl rollout restart deployment/argocd-server -n argocd
kubectl wait --for=condition=available deployment/argocd-server -n argocd --timeout=120s
```

### 13.6 Expose ArgoCD via Traefik IngressRoute

Apply the ArgoCD ingress and certificate:

```bash
kubectl apply -f argocd/certificate.yaml
kubectl apply -f argocd/ingressroute.yaml
```

### 13.7 Access ArgoCD UI

Navigate to `https://argocd.reondev.top` and log in with:
- **Username**: `admin`
- **Password**: (from step 13.4)

> **Note**: DNS must be configured (Phase 5) and the TLS certificate must be issued before HTTPS works. If DNS is not yet propagated, use port-forward temporarily:
> ```bash
> kubectl port-forward svc/argocd-server -n argocd 8080:80
> # Then access: http://localhost:8080
> ```

### 13.8 Change the Admin Password

```bash
argocd login argocd.reondev.top --username admin --password <initial-password>
argocd account update-password
```

### 13.9 Install ArgoCD CLI (Optional)

```bash
# Linux / macOS
curl -sSL -o argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
chmod +x argocd
sudo mv argocd /usr/local/bin/

# Windows (Git Bash)
curl -sSL -o argocd.exe https://github.com/argoproj/argo-cd/releases/latest/download/argocd-windows-amd64.exe

# Login (use --grpc-web when behind Traefik to avoid 404 gRPC errors)
argocd login argocd.reondev.top --username admin --password <password> --grpc-web
# On Windows, use: ./argocd.exe login ...
```

---

## 14. Phase 12: Configure ArgoCD

### 14.1 Apply the ArgoCD Project

```bash
kubectl apply -f argocd/project.yaml
```

This creates an AppProject that restricts the application to:
- Only the `https://github.com/reonbritto/test-proj.git` monorepo
- Only the `puresecure` namespace
- Allowlisted cluster-scoped resources (ClusterIssuer for cert-manager, Namespace)

### 14.2 Apply the ArgoCD Application

```bash
kubectl apply -f argocd/application.yaml
```

This creates an Application that:
- Watches `helm/puresecure/` in the `main` branch
- Auto-syncs when changes are detected
- Prunes resources deleted from Git
- Self-heals if someone manually changes resources in the cluster
- Uses `ServerSideApply` to handle large ConfigMaps (Grafana dashboard)

### 14.3 Verify Sync Status

```bash
# Via CLI
argocd app get puresecure

# Via kubectl
kubectl get application puresecure -n argocd -o yaml
```

### 14.4 Configure Webhook (Optional — Faster Deployments)

For instant deployments instead of waiting for the 3-minute poll:

1. Go to GitHub repo → Settings → Webhooks → Add webhook
2. **Payload URL**: `https://argocd.reondev.top/api/webhook`
3. **Content type**: `application/json`
4. **Events**: Just the push event
5. **Active**: Yes

---

## 15. Phase 13: CI Pipeline Changes

### What Changed in `.github/workflows/ci-cd.yml`

#### 1. Added `paths-ignore` (safety net to prevent infinite loops)

```yaml
on:
  push:
    branches: [main, master]
    paths-ignore:
      - 'helm/puresecure/values.yaml'
```

#### 2. Added Stage 10: `update-manifest` Job

After Docker Push (Stage 9), a new job:

1. Checks out the code
2. Computes the short Git SHA (same format as Docker image tag)
3. Uses `yq` to update `app.image.tag` in `helm/puresecure/values.yaml`
4. Commits and pushes with `github-actions[bot]`

#### Why This Doesn't Create an Infinite Loop

Two layers of protection:

1. **`GITHUB_TOKEN`**: Events triggered by `GITHUB_TOKEN` do not trigger new workflow runs (GitHub built-in behavior)
2. **`paths-ignore`**: Changes to `helm/puresecure/values.yaml` are ignored by the trigger
3. **`[skip ci]`**: Commit message includes `[skip ci]` as an additional safety net

---

## 16. Phase 14: Migration from Raw Manifests

If you have existing resources deployed from `k8s/aks/`, follow these steps for a zero-downtime migration.

### 16.1 Annotate Existing Resources for ArgoCD Adoption

ArgoCD needs to "adopt" existing resources instead of trying to create them (which would fail).

```bash
# App resources
kubectl annotate deployment/cwe-explorer -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate service/web -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate configmap/app-config -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate pvc/cwe-data-pvc -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite

# Prometheus resources
kubectl annotate deployment/prometheus -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate service/prometheus -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate configmap/prometheus-config -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate pvc/prometheus-data-pvc -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite

# Grafana resources
kubectl annotate deployment/grafana -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate service/grafana -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate configmap/grafana-auth-config -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate configmap/grafana-provisioning -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate configmap/grafana-dashboard -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate pvc/grafana-data-pvc -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite

# Locust resources
kubectl annotate deployment/locust -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate service/locust -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate configmap/locust-script -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite

# Traefik IngressRoutes & Middleware
kubectl annotate ingressroute/web-http-redirect -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate ingressroute/web-https -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate ingressroute/grafana-https -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate middleware/security-headers -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate middleware/redirect-https -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
kubectl annotate middleware/rate-limit -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite

# cert-manager resources
kubectl annotate certificate/reondev-top-tls -n puresecure argocd.argoproj.io/managed-by=argocd --overwrite
```

### 16.2 Delete the Old Manual Secret

Once ESO is running and has created the `app-secrets` Secret:

```bash
# First verify ESO has created the secret
kubectl get externalsecret app-secrets -n puresecure
kubectl get secret app-secrets -n puresecure

# If both show as ready, the old manual secret has been replaced
```

### 16.3 Apply ArgoCD Application

```bash
kubectl apply -f argocd/project.yaml
kubectl apply -f argocd/application.yaml
```

### 16.4 Verify Sync

```bash
argocd app get puresecure
# Should show "Synced" and "Healthy"
```

### 16.5 Delete Old Manifests

After verifying everything works:

```bash
# Remove the old k8s/aks/ directory from Git
git rm -r k8s/aks/
git commit -m "chore: remove old k8s manifests (replaced by Helm chart + ArgoCD)"
git push
```

---

## 17. Verification & Testing

### 17.1 End-to-End Test

1. Make a small code change (e.g., update a docstring)
2. Push to `main`:
   ```bash
   git add .
   git commit -m "test: verify gitops pipeline"
   git push
   ```
3. Watch CI pipeline in GitHub Actions (should complete stages 1–10)
4. Check that `values.yaml` was updated:
   ```bash
   git pull
   grep "tag:" helm/puresecure/values.yaml
   ```
5. Check ArgoCD sync:
   ```bash
   argocd app get puresecure
   ```
6. Verify new pods are running:
   ```bash
   kubectl get pods -n puresecure
   kubectl describe deployment cwe-explorer -n puresecure | grep Image
   ```

### 17.2 Verify Secrets

```bash
# Check ExternalSecret status
kubectl get externalsecret app-secrets -n puresecure -o yaml

# Verify the K8s Secret was created with correct keys
kubectl get secret app-secrets -n puresecure -o jsonpath='{.data}' | python -c "
import sys, json, base64
data = json.load(sys.stdin)
for k, v in data.items():
    print(f'{k}: {base64.b64decode(v).decode()[:5]}...')
"
```

### 17.3 Verify ArgoCD Health

```bash
# Check application health
argocd app get puresecure --show-operation

# Check resource tree
argocd app resources puresecure
```

### 17.4 Verify TLS

```bash
# Check certificate status
kubectl get certificate -n puresecure
kubectl get certificate -n argocd

# Test HTTPS
curl -I https://reondev.top/api/health
curl -I https://grafana.reondev.top/api/health
curl -I https://argocd.reondev.top
```

---

## 18. Troubleshooting

### ArgoCD Sync Issues

**(1) General Sync Commands**
```bash
# View sync details
argocd app get puresecure --show-operation

# Force sync
argocd app sync puresecure

# Hard refresh (re-read Git)
argocd app get puresecure --hard-refresh

# View diff
argocd app diff puresecure
```

**(2) Error: `resource :Namespace is not permitted`**
- **Cause**: The `AppProject` blocks cluster-scoped resources by default.
- **Fix**: Edit `argocd/project.yaml` and add `- group: ""` and `kind: Namespace` to the `clusterResourceWhitelist`.

**(2.5) Error: `The Kubernetes API could not find external-secrets.io/ExternalSecret... Make sure the CRD is installed`**
- **Cause**: The `puresecure` application requires the External Secrets Operator which has not been installed yet.
- **Fix**: Make sure you have completed the Helm installation for the External Secrets Operator in Phase 9.

**(3) ExternalSecret shows `OutOfSync` but Health is `Healthy`**
- **Cause**: The External Secrets Operator injects default fields (e.g. `conversionStrategy`) into K8s, making the Live manifest differ from your Git code.
- **Fix**: This is harmless. To silence it, configure `ignoreDifferences` in your `argocd/application.yaml`.

### ESO / Key Vault Issues

```bash
# Check ESO controller logs
kubectl logs -n external-secrets deployment/external-secrets -f

# Check SecretStore status
kubectl describe secretstore azure-keyvault -n puresecure

# Check ExternalSecret status
kubectl describe externalsecret app-secrets -n puresecure

# Common issues:
# 1. "WorkloadIdentityFailed" → Check federated credential config
# 2. "SecretNotFound" → Verify secret names in Azure Key Vault
# 3. "Unauthorized" → Check role assignment for Managed Identity
# 4. "missing tenantID in store config" → The v1 API requires `tenantId: <your-tenant>` under the `azurekv` provider in your `secret-store.yaml`. Make sure it's explicitly defined.
# 5. "AADSTS700016: Application with identifier ... was not found" → You updated `helm/puresecure/values.yaml` locally with your new Managed Identity Client ID but forgot to commit and push it to GitHub, so ArgoCD is syncing an old identity ID.
```

### Helm Template Issues

```bash
# Render and inspect templates
helm template puresecure helm/puresecure/ > rendered.yaml
cat rendered.yaml

# Lint for errors
helm lint helm/puresecure/ --strict
```

### CI Pipeline Issues

```bash
# Check if values.yaml was updated
git log --oneline -5
# Should see: "ci: update image tag to <sha>"

# Check if image exists in DockerHub
docker pull reonbritto/puresecure-cve-explorer:<sha>
```

### AKS Cluster Issues

```bash
# Check cluster status
az aks show --resource-group rg-puresecure --name aks-puresecure --query "provisioningState" -o tsv

# Check node status
kubectl get nodes -o wide

# Check node resource usage
kubectl top nodes

# If nodes are NotReady, check kubelet logs
kubectl describe node <node-name>

# Scale cluster manually if autoscaler isn't responding
az aks scale --resource-group rg-puresecure --name aks-puresecure --node-count 2
```

### Traefik Ingress Issues

```bash
# Check Traefik is running
kubectl get pods -n traefik
kubectl get svc -n traefik

# Check IngressRoutes are detected
kubectl get ingressroute -n puresecure

# Check Traefik logs for routing errors
kubectl logs -n traefik deployment/traefik -f

# Verify LoadBalancer has an IP
kubectl get svc traefik -n traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}'

# Common issues:
# 1. "503 Service Unavailable" → Target service/pod is not running
# 2. "404 Not Found" → IngressRoute match rule doesn't match the request Host header
# 3. "404 Not Found" (ArgoCD CLI) → The ArgoCD CLI uses gRPC which Traefik drops. Always use the `--grpc-web` flag with CLI commands!
# 4. No external IP → Cloud provider LoadBalancer quota reached
```

### ExternalDNS Issues

```bash
# Check ExternalDNS pods
kubectl get pods -n external-dns

# Check ExternalDNS logs for Azure authentication or DNS update errors
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns -f

# Common issues:
# 1. "ImagePullBackOff" on Bitnami chart → The Bitnami chart is deprecated/paywalled. Ensure you are using the `kubernetes-sigs` chart as specified in Phase 5.
# 2. "Azure Error: AuthorizationFailed" → The Managed Identity does not have the "DNS Zone Contributor" role on the correct Azure DNS Zone.
# 3. "Failed to get credentials" / "open /etc/kubernetes/azure.json: no such file" → You did not use the `secretConfiguration` config block in `helm/external-dns-values.yaml` mapping the `azure.json` Workload Identity config. Ensure you strictly followed the Phase 5 YAML snippet.
```

### TLS Certificate Issues

```bash
# Check certificate status
kubectl get certificate -A
kubectl describe certificate reondev-top-tls -n puresecure

# Check certificate request
kubectl get certificaterequest -n puresecure

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager -f

# Check challenge status (Let's Encrypt HTTP-01)
kubectl get challenge -A

# Common issues:
# 1. "ACME challenge failed" → DNS not pointing to LoadBalancer IP yet
# 2. "rate limited" → Too many cert requests to Let's Encrypt; use staging issuer to test
# 3. "invalid configuration" → Check ClusterIssuer email and server URL
```

### Pod Issues

```bash
# View pod logs
kubectl logs -f deployment/cwe-explorer -n puresecure

# Check events
kubectl get events -n puresecure --sort-by='.lastTimestamp'

# Describe pod for errors
kubectl describe pod -l app=cwe-explorer -n puresecure

# Check resource usage
kubectl top pods -n puresecure

# Common issues:
# 1. "ImagePullBackOff" → Docker image tag doesn't exist in DockerHub
# 2. "CrashLoopBackOff" → App is crashing; check logs for Python errors
# 3. "Pending" → Not enough cluster resources; check node capacity
# 4. "CreateContainerConfigError" → Secret or ConfigMap not found
```

---

## 19. Day-2 Operations

### Adding a New Secret

1. **Store in Azure Key Vault**:
   ```bash
   az keyvault secret set --vault-name kv-puresecure-prod --name my-new-secret --value "secret-value"
   ```

2. **Update `values.yaml`**:
   ```yaml
   externalSecrets:
     secrets:
       - kubeSecretKey: SERVICE_API_KEY
         remoteRef: service-api-key
       - kubeSecretKey: MY_NEW_SECRET        # Add this
         remoteRef: my-new-secret            # Add this
   ```

3. **Commit and push** — ArgoCD will auto-sync the ExternalSecret, and ESO will pull the new secret.

### Rotating a Secret

1. Update the secret value in Azure Key Vault:
   ```bash
   az keyvault secret set --vault-name kv-puresecure-prod --name service-api-key --value "new-value"
   ```

2. ESO will automatically sync the new value within the `refreshInterval` (default: 1 hour).

3. To force immediate sync:
   ```bash
   kubectl annotate externalsecret app-secrets -n puresecure force-sync=$(date +%s) --overwrite
   ```

4. Restart pods to pick up the new secret:
   ```bash
   kubectl rollout restart deployment/cwe-explorer -n puresecure
   ```

### Rolling Back a Deployment

```bash
# View sync history
argocd app history puresecure

# Rollback to a previous version
argocd app rollback puresecure <HISTORY_ID>

# Or revert the values.yaml change in Git and let ArgoCD re-sync
git revert HEAD
git push
```

### Updating Configuration (Non-Secret)

Update the relevant field in `helm/puresecure/values.yaml`, commit, and push. ArgoCD will auto-sync.

Example — update CORS origins:
```yaml
app:
  config:
    CORS_ORIGINS: "https://reondev.top,https://new-domain.com"
```

### Scaling

Update `replicas` in `values.yaml`:
```yaml
app:
  replicas: 3
```

Commit and push — ArgoCD scales the deployment automatically.

### Disabling Components

Set `enabled: false` in `values.yaml`:
```yaml
locust:
  enabled: false    # Disables Locust in production
```

---

## Quick Reference

### URLs

| Service | URL |
|---------|-----|
| Application | `https://reondev.top` |
| Grafana | `https://grafana.reondev.top` |
| ArgoCD | `https://argocd.reondev.top` |
| Prometheus | `kubectl port-forward svc/prometheus 9090:9090 -n puresecure` |
| Locust | `kubectl port-forward svc/locust 8089:8089 -n puresecure` |

### Key Files

| File | Purpose |
|------|---------|
| `helm/puresecure/values.yaml` | Central configuration (CI auto-updates image tag) |
| `helm/puresecure/Chart.yaml` | Helm chart metadata |
| `argocd/application.yaml` | ArgoCD Application (what to deploy, where) |
| `argocd/project.yaml` | ArgoCD Project (permissions) |
| `.github/workflows/ci-cd.yml` | CI/CD pipeline (10 stages) |

### Secrets in Azure Key Vault (`kv-puresecure-prod`)

| Key Vault Secret Name | K8s Secret Key | Used By |
|------------------------|----------------|---------|
| `azure-tenant-id` | `AZURE_TENANT_ID` | cwe-explorer (auth) |
| `azure-client-id` | `AZURE_CLIENT_ID` | cwe-explorer (auth), grafana (OAuth) |
| `service-api-key` | `SERVICE_API_KEY` | cwe-explorer, locust |
| `gf-admin-password` | `GF_ADMIN_PASSWORD` | grafana |
| `gf-auth-azuread-client-secret` | `GF_AUTH_AZUREAD_CLIENT_SECRET` | grafana |

### Common Commands

```bash
# Check ArgoCD status
argocd app get puresecure

# Force sync
argocd app sync puresecure

# View all resources managed by ArgoCD
argocd app resources puresecure

# Check secrets
kubectl get externalsecret -n puresecure
kubectl get secret app-secrets -n puresecure

# Check pods
kubectl get pods -n puresecure

# View current image tag
kubectl get deployment cwe-explorer -n puresecure -o jsonpath='{.spec.template.spec.containers[0].image}'
```

---

## Teardown / Cleanup

If you need to tear down the entire environment:

```bash
# ── Step 1: Remove ArgoCD Application (stops managing resources) ──
kubectl delete application puresecure -n argocd
kubectl delete appproject puresecure -n argocd

# ── Step 2: Delete application namespace (removes all app resources) ──
kubectl delete namespace puresecure

# ── Step 3: Uninstall ArgoCD ──
kubectl delete -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl delete namespace argocd

# ── Step 4: Uninstall External Secrets Operator ──
helm uninstall external-secrets -n external-secrets
kubectl delete namespace external-secrets

# ── Step 4.5: Uninstall ExternalDNS ──
helm uninstall external-dns -n external-dns
kubectl delete namespace external-dns

# ── Step 5: Uninstall cert-manager ──
helm uninstall cert-manager -n cert-manager
kubectl delete namespace cert-manager

# ── Step 6: Uninstall Traefik ──
helm uninstall traefik -n traefik
kubectl delete namespace traefik

# ── Step 7: Delete Azure resources ──
az keyvault delete --name kv-puresecure-prod --resource-group rg-puresecure
az keyvault purge --name kv-puresecure-prod    # If soft-delete is enabled
az identity delete --name id-puresecure-eso --resource-group rg-puresecure
az identity delete --name external-dns-id --resource-group sa
az aks delete --name aks-puresecure --resource-group rg-puresecure --yes --no-wait
az group delete --name rg-puresecure --yes --no-wait
```

> **Warning**: This is destructive and cannot be undone. All data (PVCs, secrets, configs) will be permanently deleted.

---

## Quick Setup Checklist

Complete order of operations for a fresh deployment:

- [ ] **Phase 1**: Create Resource Group and AKS cluster (`az group create`, `az aks create`)
- [ ] **Phase 2**: Register Azure AD app, note Client ID and Tenant ID, create client secret
- [ ] **Phase 3**: Install Traefik ingress controller (`helm install traefik`)
- [ ] **Phase 4**: Install cert-manager (`helm install cert-manager`)
- [ ] **Phase 5**: Install ExternalDNS with Azure Workload Identity (auto-manages DNS A records)
- [ ] **Phase 6**: Add DOCKERHUB_USERNAME, DOCKERHUB_TOKEN, SNYK_TOKEN to GitHub Secrets
- [ ] **Phase 7**: Create Azure Key Vault, store 3 secrets
- [ ] **Phase 8**: Enable Workload Identity on AKS, create Managed Identity, federate credential
- [ ] **Phase 9**: Install External Secrets Operator (`helm install external-secrets`)
- [ ] **Phase 10**: Update `values.yaml` with Managed Identity Client ID (Azure AD IDs are in Key Vault)
- [ ] **Phase 11**: Install ArgoCD, configure insecure mode, apply IngressRoute
- [ ] **Phase 12**: Apply ArgoCD Project and Application manifests
- [ ] **Phase 13**: CI pipeline is already configured (Stage 10 auto-updates image tag)
- [ ] **Phase 14**: If migrating — annotate existing resources, verify, delete old manifests
- [ ] **Verify**: Push code, confirm CI → DockerHub → values.yaml update → ArgoCD sync → pods updated
