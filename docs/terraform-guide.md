# PureSecure CVE Explorer — Terraform Infrastructure Guide

Provision all Azure infrastructure for PureSecure using Terraform. This replaces the manual `az` CLI commands from Phases 1, 3.1–3.3, 7, and 8 in the [CD/GitOps guide](cd-gitops-guide.md).

---

## Table of Contents

1. [What Terraform Creates](#1-what-terraform-creates)
2. [Prerequisites](#2-prerequisites)
3. [Project Structure](#3-project-structure)
4. [Configuration](#4-configuration)
5. [Deploy Infrastructure](#5-deploy-infrastructure)
6. [Post-Terraform Steps](#6-post-terraform-steps)
7. [Day-2 Operations](#7-day-2-operations)
8. [Teardown](#8-teardown)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. What Terraform Creates

| Resource | Name | Purpose |
|----------|------|---------|
| Resource Group | `rg-puresecure` | Container for all resources |
| AKS Cluster | `aks-puresecure` | Kubernetes cluster (Free tier, 1-2 nodes, OIDC + Workload Identity enabled) |
| Azure Key Vault | `kv-puresecure-prod` | Centralized secrets storage (RBAC-enabled) |
| Key Vault Secret | `azure-tenant-id` | Azure tenant ID for app auth |
| Key Vault Secret | `azure-client-id` | Azure AD Application client ID |
| Key Vault Secret | `service-api-key` | Auto-generated API key for Locust and internal tools |
| Key Vault Secret | `gf-admin-password` | Auto-generated Grafana admin password |
| Key Vault Secret | `gf-auth-azuread-client-secret` | Grafana Azure AD OAuth client secret |
| Managed Identity | `id-puresecure-eso` | ESO access to Key Vault (with federated credential) |
| Managed Identity | `id-puresecure-external-dns` | ExternalDNS access to DNS zone (with federated credential) |
| Role Assignment | Key Vault Secrets User | ESO identity → Key Vault |
| Role Assignment | DNS Zone Contributor | ExternalDNS identity → existing DNS zone |
| Role Assignment | Key Vault Secrets Officer | Deployer (you) → Key Vault |

**Not created by Terraform** (already exists or installed via Helm):

- DNS Zone `reondev.top` (already in resource group `sa`) — referenced as a data source
- Traefik, cert-manager, ArgoCD, ESO, ExternalDNS — installed via Helm after Terraform

---

## 2. Prerequisites

### 2.1 Required Tools

```bash
# Terraform
# macOS
brew install terraform

# Linux
sudo apt-get update && sudo apt-get install -y terraform

# Windows
winget install HashiCorp.Terraform

# Verify
terraform --version    # >= 1.5.0
```

```bash
# Azure CLI (must be logged in)
az login
az account set --subscription "dfed6615-05cd-434d-b0e0-7dea9e050738"
az account show --output table
```

### 2.2 Azure AD App Registration (Manual Step)

Before running Terraform, you need an Azure AD App Registration. This **cannot** be automated by Terraform without `Microsoft.Graph` API permissions.

1. Go to [Azure Portal](https://portal.azure.com) > **Microsoft Entra ID** > **App registrations** > **New registration**
2. **Name**: `PureSecure CVE Explorer`
3. **Supported account types**: Accounts in any organizational directory and personal Microsoft accounts
4. **Redirect URI (Web)**: `https://reondev.top`
5. Click **Register**

After registration:

- Copy the **Application (client) ID** — you'll need this for `azure_ad_client_id`
- Go to **Authentication** > **Add a platform** > **Web** > add: `https://grafana.reondev.top/login/azuread`
- Go to **Certificates & secrets** > **New client secret** > Copy the secret **value** — you'll need this for `azure_ad_client_secret`
- Go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Delegated**: `openid`, `profile`, `email`, `User.Read` > **Grant admin consent**

### 2.3 Existing DNS Zone

Your DNS zone `reondev.top` must already exist in Azure. Terraform references it as a data source:

```bash
# Verify it exists
az network dns zone show --name reondev.top --resource-group sa --query name -o tsv
```

---

## 3. Project Structure

```
terraform/
├── providers.tf                # Azure provider configuration
├── variables.tf                # Input variable definitions
├── main.tf                     # All resources (RG, AKS, KV, identities, secrets)
├── outputs.tf                  # Output values (IDs, commands, Helm snippets)
├── terraform.tfvars.example    # Example variables file (copy to terraform.tfvars)
└── terraform.tfvars            # Your actual values (git-ignored)
```

---

## 4. Configuration

### 4.1 Create Your Variables File

```bash
cd terraform/
```

### 4.2 Fill In Required Values

Edit `terraform.tfvars`:

```hcl
subscription_id        = "dfed6615-05cd-434d-b0e0-7dea9e050738"
azure_ad_client_id     = "<APPLICATION_CLIENT_ID from step 2.2>"
azure_ad_client_secret = "<CLIENT_SECRET from step 2.2>"
```

All other variables have sensible defaults. Override them only if needed:

| Variable | Default | Description |
|----------|---------|-------------|
| `location` | `uksouth` | Azure region |
| `resource_group_name` | `rg-puresecure` | Resource group name |
| `cluster_name` | `aks-puresecure` | AKS cluster name |
| `node_vm_size` | `Standard_D2lds_v6` | VM size (2 vCPU, 4 GiB) |
| `node_count` | `1` | Initial node count |
| `node_min_count` | `1` | Autoscaler minimum |
| `node_max_count` | `2` | Autoscaler maximum |
| `key_vault_name` | `kv-puresecure-prod` | Key Vault name (globally unique) |
| `dns_zone_name` | `reondev.top` | Existing DNS zone |
| `dns_zone_resource_group` | `sa` | Resource group of DNS zone |
| `app_namespace` | `puresecure` | K8s namespace for the app |

---

## 5. Deploy Infrastructure

### 5.1 Initialize Terraform

```bash
cd terraform/
terraform init
```

Expected output:

```
Terraform has been successfully initialized!
```

### 5.2 Preview Changes

```bash
terraform plan
```

Review the plan carefully. You should see approximately **15 resources** to be created:

- 1 resource group
- 1 AKS cluster
- 1 Key Vault
- 5 Key Vault secrets
- 2 managed identities
- 2 federated credentials
- 3 role assignments

### 5.3 Apply

```bash
terraform apply
```

Type `yes` when prompted. This takes **5–8 minutes** (mostly AKS cluster creation).

### 5.4 Review Outputs

After apply completes, Terraform prints critical values:

```bash
# View all outputs
terraform output

# View the Helm values snippet (copy-paste helper)
terraform output helm_values_snippet

# View sensitive outputs
terraform output -raw service_api_key
terraform output -raw grafana_admin_password
```

### 5.5 Connect kubectl to the Cluster

```bash
# Use the command from Terraform output
$(terraform output -raw kube_config_command)

# Or manually
az aks get-credentials \
  --resource-group rg-puresecure \
  --name aks-puresecure \
  --overwrite-existing

# Verify
kubectl get nodes
```

---

## 6. Post-Terraform Steps

After Terraform creates the infrastructure, the remaining steps are Helm installs and ArgoCD configuration. These are done manually because they operate on the Kubernetes cluster (not Azure resources).

### 6.1 Update Helm Values with Terraform Outputs

Get the values from Terraform and update the Helm files:

```bash
# Print the helper snippet
terraform output helm_values_snippet
```

Update `helm/puresecure/values.yaml`:

```yaml
externalSecrets:
  tenantId: "<tenant_id from output>"
  managedIdentityClientId: "<eso_managed_identity_client_id from output>"
```

Update `helm/external-dns-values.yaml` — copy the values from `terraform output helm_values_snippet` into the `env`, `secretConfiguration`, and `serviceAccount` fields. The file uses the **`service` source** (not `traefik-proxy`) — see [How ExternalDNS DNS works](#how-externaldns-works) below.

After modifying these files, **commit and push them to GitHub** so that ArgoCD can use the new identity values when deploying the application:

```bash
# Return to the root of the project
cd ..

git add helm/puresecure/values.yaml helm/external-dns-values.yaml
git commit -m "chore: update azure ad identity configs from terraform"
git pull --rebase origin main
git push

# Return to terraform directory if you need to continue working there
cd terraform
```

### 6.2 Install Cluster Components (Helm)

Install these in order:

```bash
# 1. Traefik Ingress Controller
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
  --set providers.kubernetesCRD.allowExternalNameServices=true \
  --wait

# Wait for external IP
kubectl get svc traefik -n traefik --watch
```

```bash
# 2. cert-manager
helm repo add jetstack https://charts.jetstack.io
helm repo update

kubectl create namespace cert-manager
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --set installCRDs=true \
  --wait
```

```bash
# 3. ExternalDNS
helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/
helm repo update

helm upgrade --install external-dns external-dns/external-dns \
  -n external-dns --create-namespace \
  -f helm/external-dns-values.yaml
```

```bash
# 3b. Annotate the Traefik Service with all hostnames (run once after Traefik has an external IP)
#
# ExternalDNS uses the "service" source — it reads the LoadBalancer IP from the Traefik
# Service and creates A records for every hostname listed in the annotation below.
# This is intentional: the "traefik-proxy" source does NOT auto-discover the LB IP and
# requires manually annotating every IngressRoute with the IP address instead.
#
kubectl annotate service traefik -n traefik \
  "external-dns.alpha.kubernetes.io/hostname=reondev.top,grafana.reondev.top,argocd.reondev.top" \
  --overwrite

# Verify ExternalDNS picks it up (should log "Desired change: CREATE <hostname> A [<IP>]")
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns --tail=20
```

```bash
# 4. External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set installCRDs=true \
  --wait
```

```bash
# 5. ArgoCD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl wait --for=condition=available deployment/argocd-server -n argocd --timeout=300s

# Disable ArgoCD TLS (Traefik handles TLS termination)
kubectl patch configmap argocd-cmd-params-cm -n argocd \
  --type merge \
  -p '{"data":{"server.insecure":"true"}}'
kubectl rollout restart deployment/argocd-server -n argocd
kubectl wait --for=condition=available deployment/argocd-server -n argocd --timeout=120s

# Apply ArgoCD certificate and IngressRoute
kubectl apply -f argocd/certificate.yaml
kubectl apply -f argocd/ingressroute.yaml

# Get the initial admin password
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath="{.data.password}" | base64 -d && echo
```

### 6.3 Deploy the Application via ArgoCD

```bash
# Apply ArgoCD project and application manifests
kubectl apply -f argocd/project.yaml
kubectl apply -f argocd/application.yaml

# Log in and verify sync (use --grpc-web behind Traefik)
argocd login argocd.reondev.top --username admin --password <initial-password> --grpc-web

# Change the default password immediately
argocd account update-password

# Verify the application is synced and healthy
argocd app get puresecure --grpc-web
```

### 6.4 How ExternalDNS Works

> **Why we annotate the Traefik Service instead of IngressRoutes:**
>
> The `traefik-proxy` source in ExternalDNS only parses hostnames from IngressRoute rules — it does **not** auto-discover the LoadBalancer IP from Traefik. Using it would require adding `external-dns.alpha.kubernetes.io/target: <LB_IP>` to every IngressRoute manually, which breaks whenever the IP changes.
>
> Instead, we use the `service` source and annotate the **Traefik LoadBalancer Service** once with all hostnames. ExternalDNS reads the real external IP from that Service and creates A records for each hostname automatically. When the IP changes, all records update in sync.

```
Traefik Service (LoadBalancer)
  └── annotation: external-dns.alpha.kubernetes.io/hostname=reondev.top,grafana.reondev.top,argocd.reondev.top
        │
        ▼
ExternalDNS (service source)
  reads LB IP → creates/updates A records in Azure DNS zone reondev.top
        │
        ▼
Azure DNS Zone (reondev.top in resource group "sa")
  reondev.top         A  <LB_IP>
  grafana.reondev.top A  <LB_IP>
  argocd.reondev.top  A  <LB_IP>
```

### 6.5 Verification Checklist

```bash
# ExternalDNS is running and creating records
kubectl logs -n external-dns -l app.kubernetes.io/name=external-dns --tail=30
# Look for: "Desired change: CREATE reondev.top A"

# DNS resolves correctly (wait 1-2 min after ExternalDNS logs show changes)
nslookup reondev.top
nslookup grafana.reondev.top
nslookup argocd.reondev.top

# TLS certificates issued
kubectl get certificate -n puresecure
kubectl get certificate -n argocd

# ExternalSecret synced from Key Vault
kubectl get externalsecret app-secrets -n puresecure

# All pods running
kubectl get pods -n puresecure

# App is healthy
curl -s https://reondev.top/api/health | python -m json.tool
```

---

## 7. Day-2 Operations

### Adding a New Secret

1. Add it to `main.tf`:

   ```hcl
   resource "azurerm_key_vault_secret" "my_new_secret" {
     name         = "my-new-secret"
     value        = "secret-value"
     key_vault_id = azurerm_key_vault.main.id
     depends_on   = [azurerm_role_assignment.kv_deployer]
   }
   ```

2. Run `terraform apply`

3. Add mapping in `helm/puresecure/values.yaml`:

   ```yaml
   externalSecrets:
     secrets:
       - kubeSecretKey: MY_NEW_SECRET
         remoteRef: my-new-secret
   ```

4. Commit and push — ArgoCD syncs, ESO pulls the secret.

### Scaling the Cluster

Update `terraform.tfvars`:

```hcl
node_max_count = 3
```

```bash
terraform apply
```

### Rotating Secrets

Update the secret value in `main.tf` or use the CLI:

```bash
az keyvault secret set --vault-name kv-puresecure-prod --name service-api-key --value "new-value"
```

ESO auto-syncs within `refreshInterval` (1 hour). To force:

```bash
kubectl annotate externalsecret app-secrets -n puresecure force-sync=$(date +%s) --overwrite
kubectl rollout restart deployment/cwe-explorer -n puresecure
```

### Importing Existing Resources

If you already created resources via CLI and want Terraform to manage them:

```bash
# Import resource group
terraform import azurerm_resource_group.main /subscriptions/<SUB_ID>/resourceGroups/rg-puresecure

# Import AKS cluster
terraform import azurerm_kubernetes_cluster.main /subscriptions/<SUB_ID>/resourceGroups/rg-puresecure/providers/Microsoft.ContainerService/managedClusters/aks-puresecure

# Import Key Vault
terraform import azurerm_key_vault.main /subscriptions/<SUB_ID>/resourceGroups/rg-puresecure/providers/Microsoft.KeyVault/vaults/kv-puresecure-prod

# Import managed identities
terraform import azurerm_user_assigned_identity.eso /subscriptions/<SUB_ID>/resourceGroups/rg-puresecure/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-puresecure-eso
terraform import azurerm_user_assigned_identity.external_dns /subscriptions/<SUB_ID>/resourceGroups/rg-puresecure/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-puresecure-external-dns
```

After importing, run `terraform plan` to verify no changes are needed.

---

## 8. Teardown

### Destroy All Terraform-Managed Resources

```bash
cd terraform/
terraform destroy
```

Type `yes` when prompted. This removes:

- AKS cluster and all workloads
- Key Vault and all secrets
- Managed identities and role assignments
- Resource group

> **Warning**: This is destructive and permanent. All Kubernetes workloads, persistent volumes, and secrets will be deleted.

**Not destroyed** (managed separately):

- DNS Zone `reondev.top` (in resource group `sa`)
- Azure AD App Registration
- DockerHub images

### Partial Teardown

To remove only specific resources:

```bash
# Remove only the AKS cluster
terraform destroy -target=azurerm_kubernetes_cluster.main

# Remove only Key Vault secrets (keeps the vault)
terraform destroy -target=azurerm_key_vault_secret.service_api_key
```

---

## 9. Troubleshooting

### Terraform Init Fails

```
Error: Failed to install provider
```

- **Fix**: Check internet connectivity and run `terraform init -upgrade`

### Key Vault Name Already Taken

```
Error: Key Vault "kv-puresecure-prod" already exists
```

- Key Vault names are globally unique across Azure
- **Fix**: Change `key_vault_name` in `terraform.tfvars` to a unique name, or import the existing vault

### Key Vault Soft-Delete Recovery

```
Error: A]  vault with the same name already exists but is in a deleted state
```

- **Fix**: Purge or recover:

  ```bash
  az keyvault purge --name kv-puresecure-prod --location uksouth
  # Then re-run terraform apply
  ```

### DNS Zone Not Found

```
Error: DNS Zone "reondev.top" not found in resource group "sa"
```

- **Fix**: Verify the zone exists:

  ```bash
  az network dns zone list --resource-group sa --output table
  ```

### AKS Creation Quota Error

```
Error: OperationNotAllowed ... quota limit
```

- **Fix**: Choose a smaller VM size or request a quota increase:

  ```bash
  az vm list-skus --location uksouth --size Standard_D --output table
  ```

### Permission Denied on Role Assignment

```
Error: AuthorizationFailed ... does not have authorization to perform action
```

- **Fix**: Your Azure account needs `Owner` or `User Access Administrator` role on the subscription:

  ```bash
  az role assignment list --assignee $(az account show --query user.name -o tsv) --output table
  ```

### State Lock Error

```
Error: Error acquiring the state lock
```

- **Fix**: If you're sure no other process is running:

  ```bash
  terraform force-unlock <LOCK_ID>
  ```

### Existing Secret Conflicts (`already exists`)

```text
Error: a resource with the ID "..." already exists - to be managed via Terraform this resource needs to be imported into the State.
```

- **Cause**: Secrets (e.g., `service-api-key`, `gf-admin-password`) were manually created in the Key Vault prior to running Terraform.
- **Fix**: Import those existing resources into your Terraform state so Terraform can track them without attempting recreation:

  ```bash
  terraform import azurerm_key_vault_secret.service_api_key <SECRET_URI_FROM_ERROR>
  # Repeat for any other conflicting secrets listed in the error
  ```

  *> **Note**: To prevent Terraform from overwriting manually set passwords during subsequent applies, ensure your `main.tf` includes a `lifecycle { ignore_changes = [value, tags] }` block for these specific secrets.*

### Key Vault soft_delete_retention_days Error

```text
Error: updating Key Vault (...): once `soft_delete_retention_days` has been configured it cannot be modified
```

- **Cause**: Terraform is attempting to change the soft-delete retention period (e.g., from 90 days down to 7 days) on a Key Vault that already exists. Azure prohibits changing this value after creation.
- **Fix**: Update your `main.tf` to match the exact `soft_delete_retention_days` of the existing Key Vault (which is `90` by default on Azure).

  ```hcl
  # In main.tf
  resource "azurerm_key_vault" "main" {
    # ...
    soft_delete_retention_days = 90
  }
  ```

---

## Quick Reference

### Commands

```bash
# Initialize
cd terraform/ && terraform init

# Preview
terraform plan

# Apply
terraform apply

# View outputs
terraform output
terraform output helm_values_snippet
terraform output -raw service_api_key

# Connect kubectl
$(terraform output -raw kube_config_command)

# Destroy
terraform destroy
```

### File Map

| File | Purpose |
|------|---------|
| `terraform/providers.tf` | Azure provider config (version constraints) |
| `terraform/variables.tf` | Input variable definitions with defaults |
| `terraform/main.tf` | All Azure resources (RG, AKS, KV, identities, secrets, roles) |
| `terraform/outputs.tf` | Output values and Helm values helper snippet |
| `terraform/terraform.tfvars.example` | Example variables (copy to `terraform.tfvars`) |
| `terraform/terraform.tfvars` | Your actual variables (git-ignored) |

### Deployment Order

```
1.  Azure AD App Registration        (manual — Azure Portal)
2.  terraform apply                   (creates AKS, KV, identities, secrets, role assignments)
3.  Update Helm values & commit/push  (from terraform output helm_values_snippet)
4.  helm install traefik              (ingress controller — wait for external IP)
5.  kubectl annotate traefik Service  (tell ExternalDNS about all 3 hostnames — run once)
6.  helm install cert-manager         (TLS automation via Let's Encrypt)
7.  helm install external-dns         (DNS A record automation — service source)
8.  helm install external-secrets     (Key Vault → K8s secret sync)
9.  kubectl apply argocd              (GitOps controller)
10. kubectl apply argocd/             (project.yaml + application.yaml)
11. Push code → CI/CD → ArgoCD       (fully automated from here)
```

> **Step 5 must happen before Step 7** so ExternalDNS has the annotation to act on as soon as it starts.
> **Step 6 (cert-manager) requires DNS to be resolving** before Let's Encrypt issues certificates — DNS propagation happens in Step 7 within 1–2 minutes of ExternalDNS starting.
