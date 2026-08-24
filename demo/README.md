# Local stack

Runs `halden-identity` together with its downstream `halden-threat-detection`,
a Postgres instance, and a mock OIDC provider that stands in for Auth0 so no
Auth0 tenant is needed.

Clone both repositories as siblings, then:

    ./demo/run-local.sh

The script generates the gateway credential and the database password per run —
nothing is written to disk and no key material lives in this repository. It
prints access tokens for the two seeded tenants when the stack is ready.

Tear down:

    docker rm -f halden-identity halden-threat-detection halden-db halden-mock-auth0
