# ─────────────────────────────────────────────────────────
#  Required Variables
# ─────────────────────────────────────────────────────────

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "azure_ad_client_id" {
  description = "Azure AD Application (client) ID for app authentication (Entra ID)"
  type        = string
  sensitive   = true
}

variable "grafana_admin_password" {
  description = "Grafana admin password"
  type        = string
  sensitive   = true
}

variable "alertmanager_smtp_username" {
  description = "Gmail address used as the SMTP sending account for Alertmanager (e.g. yourname@gmail.com)"
  type        = string
  sensitive   = true
}

variable "alertmanager_smtp_password" {
  description = "Gmail App Password for Alertmanager SMTP — NOT your Gmail account password. Generate at https://myaccount.google.com/apppasswords"
  type        = string
  sensitive   = true
}

# ─────────────────────────────────────────────────────────
#  Optional Variables (with sensible defaults)
# ─────────────────────────────────────────────────────────

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "canadacentral"
}

variable "resource_group_name" {
  description = "Name of the resource group for AKS and Key Vault"
  type        = string
  default     = "rg-puresecure"
}

variable "cluster_name" {
  description = "Name of the AKS cluster"
  type        = string
  default     = "aks-puresecure"
}

variable "node_vm_size" {
  description = "VM size for AKS node pool"
  type        = string
  default     = "Standard_D2as_v5"
}

variable "node_count" {
  description = "Initial node count for the default node pool"
  type        = number
  default     = 1
}

variable "node_min_count" {
  description = "Minimum node count for autoscaler"
  type        = number
  default     = 1
}

variable "node_max_count" {
  description = "Maximum node count for autoscaler"
  type        = number
  default     = 2
}

variable "key_vault_name" {
  description = "Name of the Azure Key Vault"
  type        = string
  default     = "kv-puresecure-prod"
}

variable "dns_zone_name" {
  description = "Existing Azure DNS zone name"
  type        = string
  default     = "reondev.top"
}

variable "dns_zone_resource_group" {
  description = "Resource group where the existing DNS zone lives"
  type        = string
  default     = "sa"
}

variable "app_namespace" {
  description = "Kubernetes namespace for the application"
  type        = string
  default     = "puresecure"
}
