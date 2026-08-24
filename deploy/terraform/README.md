# halden-identity infrastructure

Azure infrastructure for `halden-identity`. Traffic enters through an
Application Gateway with WAF that terminates TLS on the only public IP in the
stack; everything behind it is private.

- `main.tf` — resource group and the virtual network with its three subnets.
- `nsg.tf` — network security groups. The AKS subnet accepts traffic only from
  the gateway subnet; both subnets end with an explicit deny-all inbound rule.
- `gateway.tf` — Application Gateway (WAF_v2, Prevention mode, TLS 1.2 policy),
  the HTTPS listener, and the port-80 listener that only redirects to HTTPS.
- `aks.tf` — private AKS cluster with Entra RBAC, local accounts disabled,
  workload identity, Azure network policy, and the Key Vault CSI driver.
- `registry.tf` — private container registry reached over a private endpoint,
  with admin user and anonymous pull disabled.
- `keyvault.tf` — Key Vault holding the gateway key, RBAC-authorised, private
  endpoint only, with the role assignments the workload and the gateway need.

## Applying

`gateway_key`, `app_hostname` and `tls_certificate_secret_id` have no defaults
and must be supplied at apply time. Pass the gateway key from the deployment
pipeline's secret store:

```sh
terraform apply \
  -var "app_hostname=api.halden.example" \
  -var "tls_certificate_secret_id=$TLS_CERT_SECRET_ID" \
  -var "internal_token_secret=$HALDEN_INTERNAL_TOKEN_SECRET"
```

Key Vault and the registry deny public network access. Set `management_cidrs`
to the deployment agent's egress range so the apply can write the secret.
