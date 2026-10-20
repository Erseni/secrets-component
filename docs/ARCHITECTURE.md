# Architecture

## Overview

`secrets-component` has two flows: **send** (outbound, one-off share) and **request** (inbound, ask a third party for a secret). Both are zero-knowledge: the server stores ciphertext only.

## Send flow

```
sender browser                                           server                      recipient browser
  |                                                        |                                 |
  | generate AES-256-GCM key K (32 random bytes)           |                                 |
  | nonce N (12 random bytes)                              |                                 |
  | ciphertext C = AES-GCM(K, N, plaintext, aad=id)        |                                 |
  |                                                        |                                 |
  | POST /api/secrets { C, N, expires_at, views_left } --> |                                 |
  |                                   store row, return id |                                 |
  | <----------------------------------------------- {id}  |                                 |
  |                                                        |                                 |
  | build URL: https://host/v/{id}#k=base64url(K)          |                                 |
  | send URL to recipient out-of-band                      |                                 |
  |                                                        |   <-- open URL --               |
  |                                                        |   GET /api/secrets/{id} -->     |
  |                                                        |   atomic DELETE ... RETURNING   |
  |                                                        |   --> {C, N}                    |
  |                                                        |                                 |
  |                                                        |   extract K from fragment       |
  |                                                        |   plaintext = AES-GCM(K,N,C)    |
```

Key points:

- The key `K` never leaves the sender's browser except as part of the URL fragment (`#k=...`), which browsers do not send to servers.
- Retrieval is atomic: the row is deleted in the same transaction as the read, so a second retrieval is impossible.
- `expires_at` is enforced both at retrieval time and by a cleanup cron.

## Request flow

The requester asks a third party (the "filler") for a secret without the filler having an account.

```
requester browser                                        server                      filler browser
  |                                                        |                                 |
  | generate X25519 keypair (priv_r, pub_r)                |                                 |
  |                                                        |                                 |
  | POST /api/secrets/requests { pub_r, expires_at } --->  |                                 |
  |                                   store row, return id |                                 |
  | <----------------------------------------------- {id}  |                                 |
  |                                                        |                                 |
  | filler URL:    https://host/fulfill/{id}#rp=b64url(pub_r)[&l=b64url(label)]              |
  | retrieve URL:  https://host/request/{id}/retrieve#p=b64url(priv_r)  (kept by requester)  |
  | send the filler URL out-of-band                        |                                 |
  |                                                        |   <-- open filler URL --        |
  |                                                        |   GET /api/secrets/requests/{id}|
  |                                                        |   --> {pub_r}                   |
  |                                                        |   compare with rp, abort if not |
  |                                                        |   equal (tampered link)         |
  |                                                        |   generate ephemeral keypair    |
  |                                                        |   (priv_e, pub_e)               |
  |                                                        |   shared = X25519(priv_e, pub_r)|
  |                                                        |   K = HKDF(shared)              |
  |                                                        |   N = random 12 bytes           |
  |                                                        |   C = AES-GCM(K, N, plaintext)  |
  |                                                        |                                 |
  |                                                        |   POST /api/secrets/requests/   |
  |                                                        |   {id}/fulfill { pub_e, N, C }  |
  |                                                        |                                 |
  | POST /api/secrets/requests/{id}/fulfillment/retrieve ->|                                 |
  | atomic DELETE ... RETURNING                            |                                 |
  | <-- {pub_e, N, C}                                      |                                 |
  |                                                        |                                 |
  | extract priv_r from fragment                           |                                 |
  | shared = X25519(priv_r, pub_e)                         |                                 |
  | K = HKDF(shared)                                       |                                 |
  | plaintext = AES-GCM(K, N, C)                           |                                 |
```

Key points:

- Only the requester holds `priv_r`; the server only sees `pub_r`. The filler never receives `priv_r`: the filler link carries the public key `rp` (and optionally a label `l`), the private key stays in the requester's own retrieve link.
- The filler generates an ephemeral keypair per submission; `priv_e` is discarded after encryption.
- The fulfilment row contains only the ephemeral public key, nonce, ciphertext and, optionally, the three opaque attachment blobs. Neither side reveals a long-lived identity.
- Attachments on this flow are opt-in per request. The requester's byte cap is frozen into `max_attachment_bytes` when the request is created; the anonymous fulfil page reads that value from `GET /api/secrets/requests/{id}` and the server re-enforces it from the same row. `0` means attachments are disabled for this request.
- The attachment blobs are written in the same atomic `UPDATE ... WHERE filler_pub IS NULL` as the fulfilment and deleted with it in the same `DELETE ... RETURNING`.

## Agent request flow

The same request flow, driven by a program instead of a browser: `vault-ask` (CLI) and `vault-ask-mcp` (MCP server) in [`cli/`](../cli). They exist so that an AI agent can obtain a secret without the value passing through the conversation.

```
agent machine (vault-ask)                                server                      filler browser
  |                                                        |                                 |
  | generate X25519 keypair (priv_r, pub_r) in memory      |                                 |
  | fix purpose P = {kind, display}                        |                                 |
  |   kind: command | env-file | file                      |                                 |
  |   display: quoted argv or absolute path                |                                 |
  |                                                        |                                 |
  | POST /api/secrets/requests { pub_r, ttl } ------------>|  anonymous: proof of work        |
  |   [Authorization: Bearer <API key>]                    |  API key: host quota instead     |
  | <---------------------------------------------- {id}   |                                 |
  |                                                        |                                 |
  | print only the link:                                   |                                 |
  | https://host/fulfill/{id}#rp=b64url(pub_r)&a=b64url(JSON{v:1,k,c,n:[names]})              |
  |                                                        |   <-- open link --              |
  |                                                        |   show P (k, c) before input,   |
  |                                                        |   one field per name            |
  |                                                        |   bundle = JSON{v:2,k,c,s:{name:value}}
  |                                                        |   encrypt bundle as above       |
  |                                                        |   POST .../fulfill              |
  |                                                        |                                 |
  | wait: status + SSE channel secret-request:{id}         |                                 |
  | POST .../fulfillment/retrieve (atomic delete)          |                                 |
  | decrypt, require bundle.k/c == P and names == n        |                                 |
  | deliver to exactly P, mask values in its output        |                                 |
```

Key points:

- `priv_r` never leaves the memory of the `vault-ask` process. There is no retrieve link.
- The purpose travels in the URL fragment, so the server never sees which command or path a secret is meant for. The filler page encrypts the purpose it displayed together with the values; a link whose fragment was altered shows the altered purpose to the person, and a CLI started for another purpose refuses the answer after decryption.
- `Create`, `CreateRequest` and `RetrieveFulfillment` are CSRF-exempt so that a client without a browser session can call them. `Create` and `CreateRequest` still demand either a proof of work (sent in `X-PoW-*` headers) or an API key (`Authorization` header); both are custom headers a cross-site form cannot set, so the exemption does not open a forgery path for logged-in browsers. `RetrieveFulfillment` is a capability endpoint: whoever holds the token can already call it without a session.
- API keys are a host concept and apply to `Create` and `CreateRequest` alike, through `SecretsApiKeyAccessTrait`. A host implements `SecretsApiKeys` and returns a `SecretsApiKeyAuthenticator`, which resolves a presented key to an account and reserves quota per request (`SecretsApiQuota`). The component only reads the `Authorization: Bearer` header (ignored when `X-Refresh-Signature` marks it as the framework's own refresh token), skips the proof of work when a key is presented, answers `401` for an unknown key and `429` with `Retry-After` when the host denies quota. `SecretsApiKeyService::getAuthenticatedAccountId()` exposes the account for the rest of the request, so host hooks can attribute ownership without a session. Both endpoints reserve from the same host quota, so a sent secret and a request count alike.

## Agent send flow

The other direction: an agent generates a secret for a person, for example a new database password, and hands it over as a one-time link. `vault-ask send` (CLI) and the MCP tool `send_secret` drive the same send flow as the browser page.

```
agent machine (vault-ask send)                           server                      recipient browser
  |                                                        |                                 |
  | value: generated locally (CSPRNG, length, charset)     |                                 |
  |        or read from a file / environment variable      |                                 |
  | K = 32 random bytes, nonce = 12 random bytes           |                                 |
  | ct = AES-256-GCM(K, nonce, JSON{l: label, t: value})   |                                 |
  |                                                        |                                 |
  | POST /api/secrets { ct, nonce, ttl } ----------------->|  anonymous: proof of work        |
  |   [Authorization: Bearer <API key>]                    |  API key: host quota instead     |
  | <---------------------------------------------- {id}   |                                 |
  |                                                        |                                 |
  | optional: write the same value to one destination      |                                 |
  |   (.env file, file 600, or one command, output masked) |                                 |
  | print only the link: https://host/view/{id}#k=b64url(K)|                                 |
  |                                                        |   <-- open link, read once --   |
```

Key points:

- The bundle is the one the browser send page writes (`{l, t}`), so the existing view page opens the link unchanged. `K` exists only in the memory of the `vault-ask` process and in the fragment of the link.
- The value never reaches the agent: the tool result carries the link, its expiry and the length. The destination is written after the secret was created, so a failing server leaves the system unchanged; a failing command is reported together with the link.
- Discoverability without prior knowledge: the MCP server answers `initialize` with `instructions` that map "generate or hand over a secret" to `send_secret` and "need a secret from the user" to `request_secret` / `run_with_secret`, and forbid secrets in the chat. Tool descriptions begin with the same triggers, because a client may load them only on demand.

## Storage schema

Two tables, both minimal:

```sql
CREATE TABLE secrets (
  id            UUID PRIMARY KEY,
  ciphertext    BYTEA NOT NULL,
  nonce         BYTEA NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  views_left    SMALLINT NOT NULL DEFAULT 1,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE secret_requests (
  id            UUID PRIMARY KEY,
  requester_pub BYTEA NOT NULL,
  filler_pub    BYTEA,
  ciphertext    BYTEA,
  nonce         BYTEA,
  attachment_ciphertext BYTEA,
  attachment_nonce      BYTEA,
  attachment_meta       BYTEA,
  max_attachment_bytes  INTEGER NOT NULL DEFAULT 0,
  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

No foreign keys to users, no project IDs, no IP columns. Intentional.

## Client crypto

All client-side crypto uses the native Web Crypto API (`window.crypto.subtle`). No third-party crypto libraries. No inline scripts. Subresource Integrity (SRI) is enforced for the crypto bundle and the core scripts, which are served with `integrity` and `crossorigin` attributes. Web component scripts, third-party libraries and stylesheets carry no hash. Because the hash is produced by the same deploy that ships the code, SRI guards against an asset altered in transit or served from a cache, not against a server that hands out a matching pair; the independent check remains the `build-sha` meta tag verified against the public mirror. Hardening therefore rests on `script-src 'self'` plus a nonce-based CSP alongside SRI, not on SRI alone.

## Observability

Deliberately minimal: no access logs on `/api/secrets/*`, no IP addresses stored, no analytics. Metrics limited to counts (active secrets, active requests, cleanup rate) exposed at a protected `/metrics` endpoint.
