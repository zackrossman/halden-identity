#!/usr/bin/env bash
# Bring up halden-identity and its downstream halden-threat-detection locally.
#
# Requires Docker and this repo's sibling checkout:
#   ~/dev/.../halden-identity        (this repo)
#   ~/dev/.../halden-threat-detection
#
# Credentials are generated per run and never written to disk. Inbound customer
# access tokens are issued by a local mock OIDC provider, so no Auth0 tenant is
# needed. halden-identity signs its own downstream tokens with a shared secret
# that halden-threat-detection verifies.

set -euo pipefail

IDENTITY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THREAT_DIR="$(cd "${IDENTITY_DIR}/../halden-threat-detection" 2>/dev/null && pwd || true)"
NET=halden-demo

if [[ -z "${THREAT_DIR}" ]]; then
  echo "error: halden-threat-detection not found beside this repo." >&2
  echo "       clone it as a sibling directory and re-run." >&2
  exit 1
fi

INTERNAL_TOKEN_SECRET="$(openssl rand -hex 32)"
PG_PASSWORD="$(openssl rand -hex 16)"

echo "==> cleaning up any previous run"
docker rm -f halden-identity halden-threat-detection halden-db halden-mock-auth0 >/dev/null 2>&1 || true
docker network rm "${NET}" >/dev/null 2>&1 || true
docker network create "${NET}" >/dev/null

echo "==> starting postgres"
docker run -d --name halden-db --network "${NET}" \
  -e POSTGRES_USER=halden -e POSTGRES_PASSWORD="${PG_PASSWORD}" -e POSTGRES_DB=halden \
  postgres:16-alpine >/dev/null

echo "==> starting mock OIDC provider (stands in for Auth0)"
docker run -d --name halden-mock-auth0 --network "${NET}" -p 8090:8080 \
  -e JSON_CONFIG="$(cat "${IDENTITY_DIR}/demo/mock-oidc-config.json")" \
  ghcr.io/navikt/mock-oauth2-server:2.1.10 >/dev/null

echo "==> building images"
docker build -q -t halden-threat-detection:local "${THREAT_DIR}" >/dev/null
docker build -q -t halden-identity:local "${IDENTITY_DIR}" >/dev/null

echo "==> starting halden-threat-detection"
docker run -d --name halden-threat-detection --network "${NET}" \
  -e HALDEN_INTERNAL_TOKEN_SECRET="${INTERNAL_TOKEN_SECRET}" \
  -e HALDEN_DATABASE_URL="postgresql+psycopg://halden:${PG_PASSWORD}@halden-db:5432/halden" \
  -e HALDEN_ARTIFACT_DIR=/tmp/halden-artifacts \
  halden-threat-detection:local >/dev/null

echo "==> waiting for postgres, then seeding detections"
for _ in $(seq 1 30); do
  docker exec halden-db pg_isready -U halden >/dev/null 2>&1 && break
  sleep 1
done
docker exec halden-threat-detection python -m scripts.seed

echo "==> starting halden-identity"
docker run -d --name halden-identity --network "${NET}" -p 8080:8080 \
  -e HALDEN_INTERNAL_TOKEN_SECRET="${INTERNAL_TOKEN_SECRET}" \
  -e THREAT_DETECTION_URL="http://halden-threat-detection:8000" \
  -e AUTH0_JWKS_URL="http://halden-mock-auth0:8080/halden/jwks" \
  -e AUTH0_ISSUER="http://localhost:8090/halden" \
  -e AUTH0_AUDIENCE="halden-api" \
  halden-identity:local >/dev/null

for _ in $(seq 1 30); do
  curl -sf http://localhost:8080/healthz >/dev/null 2>&1 && break
  sleep 1
done

mint_token() {
  curl -s -X POST "http://localhost:8090/halden/token" \
    -d grant_type=client_credentials -d client_id=halden-web -d client_secret=unused \
    -d "scope=tenant-$1" | tr -d '\n ' | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

NORTHWIND_TOKEN="$(mint_token northwind)"
CONTOSO_TOKEN="$(mint_token contoso)"

cat <<MSG

Stack is up.

  halden-identity          http://localhost:8080
  mock OIDC provider       http://localhost:8090/halden
  seeded tenants           northwind, contoso

Export tokens into your shell:

  export NORTHWIND_TOKEN=${NORTHWIND_TOKEN}
  export CONTOSO_TOKEN=${CONTOSO_TOKEN}

Then a normal request returns only the caller's tenant:

  curl -s -H "Authorization: Bearer \$NORTHWIND_TOKEN" \\
    http://localhost:8080/v1/threat-scans

Tear down: docker rm -f halden-identity halden-threat-detection halden-db halden-mock-auth0
MSG
