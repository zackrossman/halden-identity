resource "azurerm_user_assigned_identity" "gateway" {
  name                = "id-${local.name}-appgw"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_public_ip" "gateway" {
  name                = "pip-${local.name}-appgw"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  tags                = local.tags
}

locals {
  frontend_ip         = "frontend-public"
  frontend_https_port = "port-443"
  frontend_http_port  = "port-80"
  backend_pool        = "aks-internal-ingress"
  backend_settings    = "backend-https"
  https_listener      = "listener-https"
  http_listener       = "listener-http"
  tls_certificate     = "halden-identity-tls"
  backend_probe       = "probe-healthz"
  redirect_to_https   = "redirect-to-https"
}

# TLS terminates here. The AKS ingress behind it is internal only, so this
# gateway's public IP is the single way into the stack.
resource "azurerm_application_gateway" "this" {
  name                = "agw-${local.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags

  sku {
    name = "WAF_v2"
    tier = "WAF_v2"
  }

  autoscale_configuration {
    min_capacity = 2
    max_capacity = 10
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.gateway.id]
  }

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101S"
  }

  waf_configuration {
    enabled                  = true
    firewall_mode            = "Prevention"
    rule_set_type            = "OWASP"
    rule_set_version         = "3.2"
    request_body_check       = true
    max_request_body_size_kb = 128
    file_upload_limit_mb     = 10
  }

  gateway_ip_configuration {
    name      = "gateway-ip"
    subnet_id = azurerm_subnet.gateway.id
  }

  frontend_ip_configuration {
    name                 = local.frontend_ip
    public_ip_address_id = azurerm_public_ip.gateway.id
  }

  frontend_port {
    name = local.frontend_https_port
    port = 443
  }

  frontend_port {
    name = local.frontend_http_port
    port = 80
  }

  ssl_certificate {
    name                = local.tls_certificate
    key_vault_secret_id = var.tls_certificate_secret_id
  }

  http_listener {
    name                           = local.https_listener
    frontend_ip_configuration_name = local.frontend_ip
    frontend_port_name             = local.frontend_https_port
    protocol                       = "Https"
    ssl_certificate_name           = local.tls_certificate
    host_name                      = var.app_hostname
    require_sni                    = true
  }

  http_listener {
    name                           = local.http_listener
    frontend_ip_configuration_name = local.frontend_ip
    frontend_port_name             = local.frontend_http_port
    protocol                       = "Http"
    host_name                      = var.app_hostname
  }

  backend_address_pool {
    name         = local.backend_pool
    ip_addresses = [var.internal_ingress_ip]
  }

  probe {
    name                                      = local.backend_probe
    protocol                                  = "Https"
    path                                      = "/healthz"
    interval                                  = 15
    timeout                                   = 10
    unhealthy_threshold                       = 3
    pick_host_name_from_backend_http_settings = true
  }

  backend_http_settings {
    name                  = local.backend_settings
    protocol              = "Https"
    port                  = 443
    cookie_based_affinity = "Disabled"
    host_name             = var.app_hostname
    request_timeout       = 30
    probe_name            = local.backend_probe
  }

  request_routing_rule {
    name                       = "route-https"
    priority                   = 100
    rule_type                  = "Basic"
    http_listener_name         = local.https_listener
    backend_address_pool_name  = local.backend_pool
    backend_http_settings_name = local.backend_settings
  }

  # Port 80 exists only to send callers to HTTPS; it never reaches a backend.
  redirect_configuration {
    name                 = local.redirect_to_https
    redirect_type        = "Permanent"
    target_listener_name = local.https_listener
    include_path         = true
    include_query_string = true
  }

  request_routing_rule {
    name                        = "route-http-redirect"
    priority                    = 110
    rule_type                   = "Basic"
    http_listener_name          = local.http_listener
    redirect_configuration_name = local.redirect_to_https
  }

  depends_on = [azurerm_role_assignment.gateway_certificate_reader]
}

resource "azurerm_monitor_diagnostic_setting" "gateway" {
  name                       = "diag-appgw"
  target_resource_id         = azurerm_application_gateway.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "ApplicationGatewayAccessLog"
  }

  enabled_log {
    category = "ApplicationGatewayFirewallLog"
  }

  metric {
    category = "AllMetrics"
  }
}
