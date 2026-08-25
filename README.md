# halden-identity

The user management service for the Halden platform, and the service customer
traffic arrives through. It validates the caller's Auth0-issued RS256 access
token on every request, then serves the user directory and proxies threat-scan
reads to `halden-threat-detection`.

## Position in the platform

Auth0 is the source of truth for users. `halden-identity` sits at the edge: it
validates access tokens against the Auth0 JWKS endpoint, then calls internal
services with short-lived signed tokens it mints for each call.

The `tenant_id` claim taken from the access token is checked twice before it is
carried anywhere: against `^[a-zA-Z0-9_-]+$` for shape, and against the user
directory for membership. A validated token proves Auth0 issued it; it does not
prove the subject belongs to the tenant it names, and every downstream read is
scoped by that claim. A subject the directory does not list in the claimed
tenant is refused.

The directory is `internal/users.Store`, which is currently seeded in memory.
Until it is backed by a real source, only the subjects it lists can
authenticate. A validated token proves who
issued it, not that the claim is safe to use, and downstream services take that
value as a database filter and as a path segment in their artifact store.

Downstream tokens are signed RS256 with `HALDEN_INTERNAL_TOKEN_PRIVATE_KEY`.
The private key stays in this service; downstream services hold only the
matching public key, so reading their configuration, environment or pods does
not let anyone mint a token. There is no symmetric fallback — a shared secret
would put a minting key in every service that only needs to verify.

Downstream:

| Service | Call |
|---|---|
| `halden-threat-detection` | `GET {THREAT_DETECTION_URL}/v1/scans`, `GET {THREAT_DETECTION_URL}/v1/scans/summary` |

Validation of end-user tokens is centralised here so that key rotation and Auth0
tenant changes touch one service.

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/healthz` | none | Liveness and readiness probe. |
| GET | `/v1/users/me` | bearer token | The calling user's profile. |
| GET | `/v1/users` | bearer token | Users in the caller's tenant. |
| GET | `/v1/threat-scans` | bearer token | Threat scans for the caller's tenant, read from `halden-threat-detection`. |
| GET | `/v1/threat-scans/summary` | bearer token | Threat-scan totals for the caller's tenant, read from `halden-threat-detection`. |

Authenticated routes expect `Authorization: Bearer <Auth0 access token>`. The
tenant comes from the `https://halden.io/tenant_id` claim on that token.

## Configuration

All settings come from the environment. See [.env.example](.env.example).

| Variable | Required | Description |
|---|---|---|
| `HALDEN_LISTEN_ADDR` | no | Listen address, default `:8080`. |
| `HALDEN_INTERNAL_TOKEN_PRIVATE_KEY` | yes | PEM-encoded RSA private key used to sign downstream tokens with RS256. The private half stays here; downstream services hold only the matching public key, so none of them can mint a token. Read from Key Vault in deployed environments. |
| `THREAT_DETECTION_URL` | no | Base URL of `halden-threat-detection`, default `http://halden-threat-detection.halden.svc.cluster.local:8000`. |
| `AUTH0_JWKS_URL` | yes | Auth0 JWKS endpoint. |
| `AUTH0_ISSUER` | yes | Expected `iss` claim. |
| `AUTH0_AUDIENCE` | yes | Expected `aud` claim. |
| `THREAT_DETECTION_TLS_CA_BUNDLE` | no | CA that signs halden-threat-detection's certificate. Required to call it over TLS, since an internally-issued certificate is not in the system roots. |
| `THREAT_DETECTION_CLIENT_CERT` | no | This service's certificate, presented for mutual TLS. Set with the key below. |
| `THREAT_DETECTION_CLIENT_KEY` | no | Key for the certificate above. |
| `JWKS_CACHE_MIN_TTL_SECONDS` | no | Floor on how often the Auth0 JWKS is refetched, and so the ceiling on how long a key Auth0 has already revoked still validates tokens here. Defaults to 300, and is clamped to 900. An unset, zero, negative or unparseable value falls back to the default rather than removing the floor; a value above the ceiling is clamped, so no configuration can make the window worse than the 15 minutes this was hardcoded at before it was tunable. |

## Development

```sh
cp .env.example .env      # then fill in the Auth0 settings and the token secret
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
a Key Vault holding the internal token secret, and a network security group that limits
inbound traffic to the gateway subnet.
