# ─────────────────────────────────────────────────────────
#  Data Sources
# ─────────────────────────────────────────────────────────

data "azurerm_client_config" "current" {}

# Reference the existing DNS zone (already created in resource group "sa")
data "azurerm_dns_zone" "main" {
  name                = var.dns_zone_name
  resource_group_name = var.dns_zone_resource_group
}

# ─────────────────────────────────────────────────────────
#  Resource Group
# ─────────────────────────────────────────────────────────

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    project     = "puresecure"
    environment = "production"
    managed_by  = "terraform"
  }
}

# ─────────────────────────────────────────────────────────
#  AKS Cluster
# ─────────────────────────────────────────────────────────

resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = var.cluster_name
  sku_tier            = "Free"

  default_node_pool {
    name                 = "default"
    vm_size              = var.node_vm_size
    node_count           = var.node_count
    auto_scaling_enabled = true
    min_count            = var.node_min_count
    max_count            = var.node_max_count
    os_disk_size_gb      = 30

    upgrade_settings {
      max_surge = "10%"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  # Enable OIDC issuer for Workload Identity
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  network_profile {
    network_plugin = "azure"
  }

  tags = azurerm_resource_group.main.tags
}

# ─────────────────────────────────────────────────────────
#  Azure Key Vault
# ─────────────────────────────────────────────────────────

resource "azurerm_key_vault" "main" {
  name                       = var.key_vault_name
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled  = true
  soft_delete_retention_days = 90
  purge_protection_enabled   = false

  tags = azurerm_resource_group.main.tags
}

# Grant the current user (deployer) "Key Vault Secrets Officer" so Terraform can write secrets
resource "azurerm_role_assignment" "kv_deployer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ─────────────────────────────────────────────────────────
#  Key Vault Secrets
# ─────────────────────────────────────────────────────────

resource "random_password" "service_api_key" {
  length  = 32
  special = true
}

resource "random_password" "grafana_admin_password" {
  length  = 24
  special = true
}

resource "azurerm_key_vault_secret" "azure_tenant_id" {
  name         = "azure-tenant-id"
  value        = data.azurerm_client_config.current.tenant_id
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]
}

resource "azurerm_key_vault_secret" "azure_client_id" {
  name         = "azure-client-id"
  value        = var.azure_ad_client_id
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]
}

resource "azurerm_key_vault_secret" "service_api_key" {
  name         = "service-api-key"
  value        = random_password.service_api_key.result
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  lifecycle {
    ignore_changes = [value, tags]
  }
}

resource "azurerm_key_vault_secret" "gf_admin_password" {
  name         = "gf-admin-password"
  value        = random_password.grafana_admin_password.result
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  lifecycle {
    ignore_changes = [value, tags]
  }
}

resource "azurerm_key_vault_secret" "gf_auth_azuread_client_secret" {
  name         = "gf-auth-azuread-client-secret"
  value        = var.azure_ad_client_secret
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  lifecycle {
    ignore_changes = [value, tags]
  }
}

resource "azurerm_key_vault_secret" "alertmanager_smtp_username" {
  name         = "alertmanager-smtp-username"
  value        = var.alertmanager_smtp_username
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  lifecycle {
    ignore_changes = [value, tags]
  }
}

resource "azurerm_key_vault_secret" "alertmanager_smtp_password" {
  name         = "alertmanager-smtp-password"
  value        = var.alertmanager_smtp_password
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  lifecycle {
    ignore_changes = [value, tags]
  }
}

# ─────────────────────────────────────────────────────────
#  Managed Identity — External Secrets Operator (ESO)
# ─────────────────────────────────────────────────────────

resource "azurerm_user_assigned_identity" "eso" {
  name                = "id-puresecure-eso"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = azurerm_resource_group.main.tags
}

# Grant ESO identity "Key Vault Secrets User" on the Key Vault
resource "azurerm_role_assignment" "eso_kv_reader" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.eso.principal_id
}

# Federated credential: links ESO Managed Identity <-> K8s ServiceAccount
resource "azurerm_federated_identity_credential" "eso" {
  name                      = "fc-puresecure-eso"
  user_assigned_identity_id = azurerm_user_assigned_identity.eso.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer              = azurerm_kubernetes_cluster.main.oidc_issuer_url
  subject             = "system:serviceaccount:${var.app_namespace}:eso-service-account"
}

# ─────────────────────────────────────────────────────────
#  Managed Identity — ExternalDNS
# ─────────────────────────────────────────────────────────

resource "azurerm_user_assigned_identity" "external_dns" {
  name                = "id-puresecure-external-dns"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = azurerm_resource_group.main.tags
}

# Grant ExternalDNS identity "DNS Zone Contributor" on the existing DNS zone
resource "azurerm_role_assignment" "external_dns_zone" {
  scope                = data.azurerm_dns_zone.main.id
  role_definition_name = "DNS Zone Contributor"
  principal_id         = azurerm_user_assigned_identity.external_dns.principal_id
}

# Federated credential: links ExternalDNS Managed Identity <-> K8s ServiceAccount
resource "azurerm_federated_identity_credential" "external_dns" {
  name                      = "fc-puresecure-external-dns"
  user_assigned_identity_id = azurerm_user_assigned_identity.external_dns.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer              = azurerm_kubernetes_cluster.main.oidc_issuer_url
  subject             = "system:serviceaccount:external-dns:external-dns-sa"
}
