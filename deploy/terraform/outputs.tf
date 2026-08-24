output "resource_group_name" {
  description = "Resource group holding the halden-identity stack."
  value       = azurerm_resource_group.this.name
}

output "container_registry_login_server" {
  description = "Registry the halden-identity image is pushed to."
  value       = azurerm_container_registry.this.login_server
}

output "kubernetes_cluster_name" {
  description = "AKS cluster running halden-identity."
  value       = azurerm_kubernetes_cluster.this.name
}

output "key_vault_name" {
  description = "Key Vault holding the gateway key and the TLS certificate."
  value       = azurerm_key_vault.this.name
}

output "gateway_key_secret_id" {
  description = "Key Vault secret the workload reads HALDEN_GATEWAY_KEY from."
  value       = azurerm_key_vault_secret.gateway_key.versionless_id
}

output "public_ip_address" {
  description = "Public IP of the application gateway. Point the app hostname at this."
  value       = azurerm_public_ip.gateway.ip_address
}
