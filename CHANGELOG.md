# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial repository scaffolding (README, licence, security policy, contribution guide).
- Phase 3 trust features: per-IP rate limiting on all state-mutating API endpoints (Redis-backed fixed-window counters, 10/min create/fulfill, 20/min retrieve/get). Returns HTTP 429 with `Retry-After` on exceed.
- Phase 3 `build-sha` meta tag on `/secrets/*` pages so auditors can compare the running commit against the public mirror.
- Phase 3 `/.well-known/security.txt` endpoint pointing to `security@erseni.com` and the public `SECURITY.md`.
- Phase 3 `/secrets/status` public dashboard with active secret, request and fulfilled-but-uncollected counts plus build SHA, deploy timestamp and environment.
- Optional single encrypted file attachment on the send-secret flow. The file is encrypted client-side with the same AES-GCM key as the secret (separate nonce); the filename and MIME type are packed into a separately encrypted metadata blob. The server persists only opaque `bytea` (`attachment_ciphertext`, `attachment_nonce`, `attachment_meta`) and never sees plaintext file bytes, filename or MIME. The attachment is deleted atomically with the secret in the same single-view `DELETE ... RETURNING`. The raw size cap is enforced server-side against `SecretsLimitsInterface::getMaxAttachmentBytes()` (host-project, tier-aware; `0` disables attachments entirely for non-eligible accounts).
- Optional single encrypted file attachment on the request/fulfil flow. The requester opts in when creating the request; the cap is frozen into the request row (`max_attachment_bytes`, `0` = attachments disabled) so the anonymous fulfil page needs no account lookup and reads the limit solely from `GET /api/secrets/requests/{token}`. The filler encrypts the file client-side under the derived request key, and the server persists only opaque `bytea` (`attachment_ciphertext`, `attachment_nonce`, `attachment_meta`) on the request row. The attachment is written in the same atomic `UPDATE ... WHERE filler_pub IS NULL` as the fulfilment and removed in the same single-view `DELETE ... RETURNING`.
- New host hook `SecretsHooksListener::onSecretExpiredUnretrieved()`, dispatched by the cleanup job for every secret that was deleted because its TTL ran out. A secret that was read is deleted by the single-view read itself, so everything the cleanup removes from the secrets table is by definition unretrieved. `CleanupResult` carries the matching tokens in `expiredSecretTokens`. Host projects that implement the listener must add the method.

- `vault-ask` (`cli/`, npm package `@erseni/vault-ask`): requests secrets for AI agents without a browser on the requesting side. It generates the X25519 key pair in memory, solves the proof of work or uses an API key, prints only the fill link, waits on the status stream, decrypts locally and delivers to exactly one destination: an environment variable of one child process (`-- <command>`, default), a `.env` file or a file, both with permissions 600. Output of the child is masked including Base64, URL and hex encodings. Ships with `vault-ask-mcp` (MCP tools `request_secret` and `run_with_secret`) and `vault-ask-guard` (Claude Code PreToolUse hook).
- Purpose binding for program requests: the fill page reads names and purpose from the `a` fragment parameter, shows the purpose before input, renders one field per name and encrypts purpose and values together (bundle format `v: 2`). Clients refuse answers for a different purpose.
- `vault-ask send` and the MCP tool `send_secret`: an agent generates a secret (or takes one from a file or environment variable), encrypts it locally in the bundle format of the send page and returns only a one-time `/view/` link. The same value can also go to a `.env` file, a file or one command, so the system and the link hold the same value. `vault-ask-mcp` answers `initialize` with `instructions` that tell an agent when to send, when to request and never to put a secret into the chat; every tool description starts with the same triggers. `vault-ask-guard` also covers `send_secret`.
- Host hook `SecretsApiKeys` / `SecretsApiKeyAuthenticator`: `POST /api/secrets/requests` accepts `Authorization: Bearer <key>`, skips the proof of work for it, answers `401` for an unknown key and `429` with `Retry-After` when the host denies quota.

### Changed

- The live status tracker now renders the `expires_at` timestamp and is also attached on the request retrieve page, so the recipient sees when the request was created, when it expires and whether the secret has been submitted.
- While the status stream is reconnecting, the tracker now renders a visible "reconnecting" label instead of an empty one; the reconnect window can span several minutes and previously showed nothing at all. Once the status reaches an end state the tracker stops, so the connection label is cleared instead of being left on "reconnecting".
- The live status tracker no longer falls back to HTTP polling when the SSE stream is unavailable. Both status streams (the per-secret tracker and the dashboard status list) now reconnect with exponential backoff, and report the failure once through the host page's error reporter when they give up. The tracker then shows an offline hint asking for a page reload; the report carries only the flow kind and the failure reason, never the secret token or the channel name.
- `POST /api/secrets/requests` and `POST /api/secrets/requests/{token}/fulfillment/retrieve` are CSRF-exempt, so clients without a browser session can call them. Request creation still needs proof-of-work headers or an API key.
- `POST /api/secrets` is CSRF-exempt as well and accepts an API key like request creation, from the same host quota. Without a key it still needs proof-of-work headers.
- Subresource Integrity (SRI) is enforced for the crypto bundle and the core scripts, which now ship with `integrity` and `crossorigin`. Web component scripts, third-party libraries and stylesheets carry no hash. Because hash and code come from the same deploy, SRI does not replace the reproducible-build check against the public mirror; the nonce-based strict CSP and the `build-sha` meta tag remain in place.

### Security

- SECURITY NOTE: Phase 1 had no rate limiting. All endpoints returned `hasAccess(): true`. Phase 3 closes this gap: every state-mutating endpoint now enforces a per-IP fixed-window limit before touching the database. Redis unavailability fails open with a warning log to avoid false lock-outs.

[Unreleased]: https://github.com/Erseni/secrets-component/commits/main
