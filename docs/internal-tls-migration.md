# Encrypting the internal hop

Status: in progress · Applies to: `halden-identity`, `halden-threat-detection`

## Why

`halden-identity` calls `halden-threat-detection` over plain HTTP inside the
cluster, and every one of those calls carries a bearer token in the
`Authorization` header. Anything able to watch pod-to-pod traffic — a
compromised pod, a node with a packet capture, a misconfigured mesh — reads
those tokens, and a captured one works for its whole lifetime.

RS256 signing did not fix this. It changed who can *mint* a token; it did
nothing about one being read off the wire and replayed.

## Order of operations

The listener must be serving TLS before the caller requires it, and the caller
must trust the CA before it connects. Each step is safe only after the one
before.

**1. Issue the certificates.** cert-manager is the expected source. Two things
are needed: a serving certificate for `halden-threat-detection`, with a SAN
covering `halden-threat-detection.halden.svc.cluster.local`; and, for mutual
TLS, a client certificate for `halden-identity`. Both signed by the same
internal CA.

**2. Give the caller the CA, and nothing else.** Set
`THREAT_DETECTION_TLS_CA_BUNDLE` on `halden-identity` and deploy. The URL still
names `http://…:8000`, so nothing changes yet — the client simply knows the CA
it will need.

**3. Switch the listener.** Set `tls_secret_name` in the detection
deployment. The listener moves to 8443, the probes move to HTTPS with it, and
the Service publishes 8443.

**This is the breaking moment.** The caller is still pointed at
`http://…:8000`, which no longer answers. Either take a maintenance window, or
run the blue/green below.

**4. Point the caller at TLS.** Set `THREAT_DETECTION_URL` to
`https://halden-threat-detection.halden.svc.cluster.local:8443` and deploy.
Confirm calls succeed before continuing.

**5. Turn on mutual TLS.** Set `THREAT_DETECTION_CLIENT_CERT` and
`THREAT_DETECTION_CLIENT_KEY` on `halden-identity` and deploy. Only then set
`tls_client_ca_secret_name` on the detection deployment. Doing it in the other
order refuses every call the moment the client CA is mounted, because the
caller is not yet presenting a certificate.

## Avoiding the window in step 3

A single uvicorn process serves one protocol on one port, so the service cannot
answer both 8000 and 8443 at once. To cut over without downtime, run a second
Deployment on the TLS configuration behind its own Service, point
`THREAT_DETECTION_URL` at it, confirm, then retire the plaintext one.

If a short window is acceptable, steps 3 and 4 back to back is simpler, and the
failure mode is loud: connection refused, not silent plaintext.

## What TLS does not fix

It encrypts the hop. It does not stop the two ends disagreeing about what a
token means, and it does not make a token harder to misuse once a legitimate
holder has it. A handler that mints a platform-scoped token for a customer
request is still wrong over TLS, and correctly encrypted.

Replay detection was proposed alongside this and deliberately not built. Tokens
live 60 seconds, and a replay store would put a lookup on every request and make
authentication depend on another service being up. Encrypting the hop removes
the capture the replay depends on, which is the cheaper end of the problem.
