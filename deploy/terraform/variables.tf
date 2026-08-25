variable "prefix" {
  description = "Name prefix for every resource in this stack."
  type        = string
  default     = "halden-identity"
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "northeurope"
}

variable "environment" {
  description = "Environment name, used in resource names and tags. This state manages a development deployment."
  type        = string
  default     = "dev"
}

variable "app_hostname" {
  description = "Public hostname customers use to reach halden-identity."
  type        = string
}

variable "tls_certificate_secret_id" {
  description = "Key Vault secret ID of the TLS certificate served by the application gateway."
  type        = string
}

variable "internal_token_secret" {
  description = "Secret used to sign the short-lived tokens halden-identity presents to internal services. Supplied at apply time; never committed."
  type        = string
  sensitive   = true
}

variable "internal_token_private_key" {
  description = "PEM-encoded RSA private key used to sign downstream tokens with RS256, so the verifying service holds only the public half. Empty until the matching public key is deployed to halden-threat-detection; while empty, tokens stay HS256. Supplied at apply time; never committed."
  type        = string
  sensitive   = true
  default     = ""
}

variable "management_cidrs" {
  description = "CIDRs allowed to reach Key Vault and the container registry for administration, e.g. the deployment agent subnet."
  type        = list(string)
  default     = []
}

variable "node_count" {
  description = "Number of nodes in the AKS system pool."
  type        = number
  default     = 3
}

variable "node_vm_size" {
  description = "VM size for AKS nodes."
  type        = string
  default     = "Standard_D4s_v5"
}

variable "internal_ingress_ip" {
  description = "Private IP of the internal ingress controller inside the AKS subnet."
  type        = string
  default     = "10.20.1.240"
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default = {
    service = "halden-identity"
    owner   = "platform-engineering"
  }
}
