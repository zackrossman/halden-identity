# halden-identity

The user management service for the Halden platform, and the service customer
traffic arrives through. It validates the caller's Auth0-issued RS256 access
token on every request, then serves the user directory and proxies threat-scan
reads to `halden-threat-detection`.

## Position in the platform

Auth0 is the source of truth for users. `halden-identity` sits at the edge: it
validates access tokens against the Auth0 JWKS endpoint and calls internal
services with the propagated identity headers described in
[docs/platform/internal-service-contract.md](docs/platform/internal-service-contract.md).

Downstream:

| Service | Call |
|---|---|
| `halden-threat-detection` | `GET {THREAT_DETECTION_URL}/v1/scans` |

No other Halden service authenticates end users; validation is centralised here
so that key rotation and Auth0 tenant changes touch one service.

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/healthz` | none | Liveness and readiness probe. |
| GET | `/v1/users/me` | bearer token | The calling user's profile. |
| GET | `/v1/users` | bearer token | Users in the caller's tenant. |
| GET | `/v1/threat-scans` | bearer token | Threat scans for the caller's tenant, read from `halden-threat-detection`. |

Authenticated routes expect `Authorization: Bearer <Auth0 access token>`. The
tenant comes from the `https://halden.io/tenant_id` claim on that token.

## Configuration

All settings come from the environment. See [.env.example](.env.example).

| Variable | Required | Description |
|---|---|---|
| `HALDEN_LISTEN_ADDR` | no | Listen address, default `:8080`. |
| `HALDEN_GATEWAY_KEY` | yes | Service-to-service credential for internal calls. Read from Key Vault in deployed environments. |
| `THREAT_DETECTION_URL` | no | Base URL of `halden-threat-detection`, default `http://halden-threat-detection.halden.svc.cluster.local:8000`. |
| `AUTH0_JWKS_URL` | yes | Auth0 JWKS endpoint. |
| `AUTH0_ISSUER` | yes | Expected `iss` claim. |
| `AUTH0_AUDIENCE` | yes | Expected `aud` claim. |

## Development

```sh
cp .env.example .env      # then fill in the Auth0 settings and gateway key
go build ./...
go test ./...
go run ./cmd/server
```

`./demo/run-local.sh` brings the service up against a local
`halden-threat-detection` and a mock OIDC provider, so no Auth0 tenant is
needed. See [demo/README.md](demo/README.md).

## Container

```sh
docker build -t halden-identity:dev .
```

The image is a distroless static base and runs as a non-root user on port 8080.

## Infrastructure

Azure infrastructure for this service lives in
[deploy/terraform](deploy/terraform): an AKS workload with a private API server,
an Application Gateway with WAF terminating TLS, a private container registry,
a Key Vault holding the gateway key, and a network security group that limits
inbound traffic to the gateway subnet.
