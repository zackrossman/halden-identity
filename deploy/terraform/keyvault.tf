resource "azurerm_key_vault" "this" {
  name                          = substr(replace("kv-${local.name}", "--", "-"), 0, 24)
  location                      = azurerm_resource_group.this.location
  resource_group_name           = azurerm_resource_group.this.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  enable_rbac_authorization     = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = false
  tags                          = local.tags

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = var.management_cidrs
    virtual_network_subnet_ids = [azurerm_subnet.aks.id]
  }
}

resource "azurerm_key_vault_secret" "internal_token_secret" {
  name         = "halden-internal-token-secret"
  value        = var.internal_token_secret
  key_vault_id = azurerm_key_vault.this.id
  content_type = "text/plain"
  tags         = local.tags
}

# Held only while the platform still signs HS256. Once every service verifies
# RS256, the shared secret above is what gets deleted; this one replaces it.
resource "azurerm_key_vault_secret" "internal_token_private_key" {
  count = var.internal_token_private_key == "" ? 0 : 1

  name         = "halden-internal-token-private-key"
  value        = var.internal_token_private_key
  key_vault_id = azurerm_key_vault.this.id
  content_type = "application/x-pem-file"
  tags         = local.tags
}

resource "azurerm_private_dns_zone" "key_vault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "key_vault" {
  name                  = "link-kv"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.key_vault.name
  virtual_network_id    = azurerm_virtual_network.this.id
  tags                  = local.tags
}

resource "azurerm_private_endpoint" "key_vault" {
  name                = "pe-${local.name}-kv"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  tags                = local.tags

  private_service_connection {
    name                           = "psc-kv"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "kv"
    private_dns_zone_ids = [azurerm_private_dns_zone.key_vault.id]
  }
}

# The pod reads HALDEN_INTERNAL_TOKEN_SECRET through the Key Vault CSI driver, which uses
# the cluster's workload identity rather than a static credential in the manifest.
resource "azurerm_role_assignment" "workload_secrets_reader" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_kubernetes_cluster.this.key_vault_secrets_provider[0].secret_identity[0].object_id
}

resource "azurerm_role_assignment" "gateway_certificate_reader" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.gateway.principal_id
}
