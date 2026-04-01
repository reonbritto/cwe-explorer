# ─────────────────────────────────────────────────────────
#  AKS Cluster
# ─────────────────────────────────────────────────────────

output "aks_cluster_name" {
  description = "Name of the AKS cluster"
  value       = azurerm_kubernetes_cluster.main.name
}

output "aks_resource_group" {
  description = "Resource group of the AKS cluster"
  value       = azurerm_resource_group.main.name
}

output "aks_oidc_issuer_url" {
  description = "OIDC issuer URL for Workload Identity"
  value       = azurerm_kubernetes_cluster.main.oidc_issuer_url
}

output "kube_config_command" {
  description = "Command to configure kubectl"
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_kubernetes_cluster.main.name} --overwrite-existing"
}

# ─────────────────────────────────────────────────────────
#  Key Vault
# ─────────────────────────────────────────────────────────

output "key_vault_name" {
  description = "Name of the Azure Key Vault"
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "URI of the Azure Key Vault"
  value       = azurerm_key_vault.main.vault_uri
}

# ─────────────────────────────────────────────────────────
#  Managed Identities
# ─────────────────────────────────────────────────────────

output "eso_managed_identity_client_id" {
  description = "Client ID for ESO Managed Identity — use in values.yaml externalSecrets.managedIdentityClientId"
  value       = azurerm_user_assigned_identity.eso.client_id
}

output "external_dns_managed_identity_client_id" {
  description = "Client ID for ExternalDNS Managed Identity — use in helm/external-dns-values.yaml"
  value       = azurerm_user_assigned_identity.external_dns.client_id
}

# ─────────────────────────────────────────────────────────
#  Tenant Info
# ─────────────────────────────────────────────────────────

output "tenant_id" {
  description = "Azure tenant ID"
  value       = data.azurerm_client_config.current.tenant_id
}

output "subscription_id" {
  description = "Azure subscription ID"
  value       = data.azurerm_client_config.current.subscription_id
}

# ─────────────────────────────────────────────────────────
#  Generated Secrets (sensitive — use `terraform output -raw`)
# ─────────────────────────────────────────────────────────

output "service_api_key" {
  description = "Generated SERVICE_API_KEY — use for Locust and internal tools"
  value       = random_password.service_api_key.result
  sensitive   = true
}

output "grafana_admin_password" {
  description = "Generated Grafana admin password"
  value       = random_password.grafana_admin_password.result
  sensitive   = true
}

# ─────────────────────────────────────────────────────────
#  Helm Values Snippet (copy-paste helper)
# ─────────────────────────────────────────────────────────

output "helm_values_snippet" {
  description = "Values to update in helm/puresecure/values.yaml and helm/external-dns-values.yaml"
  value       = <<-EOT

    ── helm/puresecure/values.yaml ──
    externalSecrets:
      tenantId: "${data.azurerm_client_config.current.tenant_id}"
      managedIdentityClientId: "${azurerm_user_assigned_identity.eso.client_id}"

    ── helm/external-dns-values.yaml ──
    secretConfiguration:
      enabled: true
      mountPath: "/etc/kubernetes"
      data:
        azure.json: |
          {
            "tenantId": "${data.azurerm_client_config.current.tenant_id}",
            "subscriptionId": "${data.azurerm_client_config.current.subscription_id}",
            "resourceGroup": "sa",
            "useWorkloadIdentityExtension": true
          }
    env:
      - name: AZURE_CLIENT_ID
        value: "${azurerm_user_assigned_identity.external_dns.client_id}"
    serviceAccount:
      annotations:
        azure.workload.identity/client-id: "${azurerm_user_assigned_identity.external_dns.client_id}"

  EOT
}
