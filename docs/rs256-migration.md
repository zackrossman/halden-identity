# Moving internal tokens to RS256

Status: in progress · Applies to: `halden-identity`, `halden-threat-detection`

## Why

`halden-identity` used to sign internal tokens with `HALDEN_INTERNAL_TOKEN_SECRET`,
and `halden-threat-detection` verified them with the same value. A symmetric key
signs as well as it verifies, so anyone who read that value — from either
service, from either pod, or from the Kubernetes secret holding it — could mint
a token carrying any `tenant_id`, or the `platform:aggregate` scope that reads
across every tenant.

Deriving a stronger key from the secret does not help. The derived key is still
symmetric, and it is still present in the service that only needs to verify.

Under RS256 the private key stays in `halden-identity`. Every other service
holds the public half, which is not secret and cannot sign. An attacker who
reads everything a downstream service knows still cannot produce a token.

## Order of operations

The steps are not independent. Each one is safe only after the one before it.

**1. Generate the keypair.**

```sh
openssl genrsa -out halden-identity-private.pem 2048
openssl rsa -in halden-identity-private.pem -pubout -out halden-identity-public.pem
```

`openssl genrsa` writes PKCS#1. Both PKCS#1 and PKCS#8 load, so either is fine.
The private key never leaves Key Vault and your terminal; do not commit it, and
do not paste it into a ticket.

**2. Put the public key on the verifier.** `halden-threat-detection` reads it
from `HALDEN_INTERNAL_TOKEN_PUBLIC_KEY`. It is a public key, so it does not need
secret storage.

At this point the verifier accepts RS256 but nothing is signing that way yet.
Traffic is unaffected.

**3. Put the private key here and deploy.** `halden-identity` reads it from
`HALDEN_INTERNAL_TOKEN_PRIVATE_KEY`, sourced from Key Vault. The service refuses
to start without it, so a missing key fails the rollout rather than the requests.

Confirm before continuing. On startup this service logs:

```
downstream token signing configured  algorithm=RS256
```

Internal calls should be succeeding. If they are not, stop and roll back — do
not proceed to step 4.

**4. Drop HS256 from the verifier.** `halden-threat-detection` stops accepting
symmetric tokens and stops reading `HALDEN_INTERNAL_TOKEN_SECRET`.

**This is the step that retires the threat.** Everything before it adds a second
way to sign; only this one takes the old way away.

Doing step 4 before step 3 is deployed refuses every internal call.

**5. Delete the old secret.** Remove `HALDEN_INTERNAL_TOKEN_SECRET` from Key
Vault, from both services' Kubernetes secrets, and from any local `.env` files.
A secret that still exists somewhere is still a secret that can leak.

## Rotating the keypair afterwards

Rotation is the same shape, and the same order: publish the new public key to
every verifier first, then switch this service to the new private key, then
remove the old public key. Verifiers must accept the new key before the signer
starts using it.

## What this does not fix

RS256 stops anyone but `halden-identity` minting tokens. It does not change what
`halden-identity` itself chooses to mint. A handler here that mints a
platform-scoped token on a customer's behalf still hands that customer
estate-wide data, correctly signed. Those are separate bugs, and they belong to
whichever handler makes the choice.
