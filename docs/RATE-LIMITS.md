# Rate Limits

Per-endpoint and global rate limits for the secrets component. Used by Vault and any other host that mounts this component.

## Backing store

`RateLimitService` (`src/esn/core/security/RateLimitService.php`) reads and writes counters through the framework `Cache` interface. The production binding is `ApcCache`, an in-process APCu store. There is no Redis dependency. Counter state is therefore **per FPM worker, not cluster-wide**. With N workers and an attacker that distributes across them, the effective per-IP limit is up to N times the configured number. The global limit has the same per-worker characteristic.

This is a deliberate trade-off: no shared-store outage class, no cross-worker write contention, and the controllers also guard themselves with explicit Postgres atomicity (`DELETE … RETURNING`, single-fulfill `UPDATE … WHERE filler_pub IS NULL`). The rate-limit layer is a coarse abuse brake, not a hard concurrency primitive.

## Failure modes

Two failure paths exist:

- **Cache miss / corrupt entry**: `isRateLimited()` returns `false` (`RateLimitService.php:35-37`). Treated as "not yet observed", caller proceeds. **Fail-open**, intentional. A missing counter means the request is the first one in its window.
- **Lock acquisition timeout**: `acquireLock()` throws `RuntimeException` after retries are exhausted (`RateLimitService.php:135`). The controller `catch (Throwable)` translates this to HTTP 500 via `showErrorMessage('Unable to ...')`. **Fail-closed**: the request is rejected with a 5xx, no business operation runs.

Outright cache backend failure (APCu disabled or OOM) raises an exception inside `Cache::store`, which propagates as HTTP 500 — also fail-closed.

## Per-endpoint policy

All Secrets API controllers `implement RateLimit` and return a `RateLimitConfig`. All current entries set `recordOnlyOnSuccess: false`, `windowSeconds: 60`.

| Endpoint | Method + path | perIp / min | global / min | keyPrefix |
|---|---|---|---|---|
| Create secret | `POST /api/secrets` | 10 | 200 | `secrets:create` |
| Create request | `POST /api/secrets/requests` | 10 | 200 | `secrets:create-request` |
| Fulfill request | `POST /api/secrets/requests/{token}/fulfill` | 10 | 200 | `secrets:fulfill` |
| Retrieve secret | `POST /api/secrets/{token}/retrieve` | 20 | 500 | `secrets:retrieve` |
| Retrieve fulfillment | `POST /api/secrets/requests/{token}/fulfillment/retrieve` | 20 | 500 | `secrets:retrieve-fulfillment` |
| Get request | `GET /api/secrets/requests/{token}` | 20 | 500 | `secrets:get-request` |
| Get secret status | `GET /api/secrets/{token}/status` | 60 | 1000 | `secrets:status` |
| Get request status | `GET /api/secrets/requests/{token}/status` | 60 | 1000 | `secrets:request-status` |

Constants live in `SecretService.php` (`RATE_LIMIT_WRITE_PER_MINUTE`, `RATE_LIMIT_READ_PER_MINUTE`, `RATE_LIMIT_STATUS_PER_MINUTE`, plus global twins and the window). `RateLimitPrefixTest` guarantees prefixes are unique and listed in `SecretService::RATE_LIMIT_KEY_PREFIXES`.

`recordOnlyOnSuccess: false` means failed lookups still count toward the limit. This is deliberate so that token-existence probes (failed retrieves, failed fulfillment retrieves) cannot be amplified for free.

## Secrets and requests created with an API key

`POST /api/secrets` and `POST /api/secrets/requests` accept `Authorization: Bearer <key>` when the host implements `SecretsApiKeys`. A valid key replaces both the proof of work and the per-IP limit of the table above with the quota the host's `SecretsApiKeyAuthenticator::reserveRequestQuota()` grants, one reservation per created secret or request from the same count; an invalid key gets `401` and stays under the per-IP limit. On Erseni Vault the quota is per account:

| Plan | Secrets and requests |
|---|---|
| Free | 50 per UTC day |
| Pro | 500 per UTC day |
| Business | unlimited |
| every plan | at most 60 per minute (technical cap, APCu per worker like the rest of this layer) |

The daily count lives in Postgres (`vault.api_key_usage`, one row per account and day, incremented atomically), so it holds across workers and restarts. Only the current day is needed: the daily vault job `CleanupApiKeyUsage` deletes every row of an earlier UTC day. A denied request answers `429` with `Retry-After` until the next UTC day or the end of the minute window.

## Rationale for write < read < status

- Writes mutate Postgres rows. Cheapest per-IP cap protects DB write throughput and reduces ciphertext disk pressure.
- Reads consume one secret each (DELETE … RETURNING) and can amplify a brute-force token guess. Higher than writes but still capped.
- Status endpoints are read-only counters with no token-state mutation, so a higher cap is acceptable for polling clients.

## What is not rate-limited at the application layer

- Static asset fetches (`/c/<hash>/...`) handled by nginx - not capped anywhere. Neither the production templates under `ansible/roles/nginx/templates/` nor the deployed `/etc/nginx/` contain `limit_req` or `limit_conn` (measured on the production host, 2026-09-04); the only `limit_req_zone` in the repo sits at `http` level in `docker/nginx/nginx.conf:138` and is applied only in the `server` block at `:141-144`, which carries no `server_name` and serves none of the app vhosts.
- Public landing / status / how-it-works / security pages - not capped either, same reason.
- The `/build-manifest.json` endpoint - an `AssetApplication`, so `RateLimit` would never be evaluated. The manifest is cached for 60 seconds instead, which caps the work per hit (per FPM worker, since the backing store is APCu). The **number of requests is not capped**.

The limits in the table above cover `/api/secrets/*`. Everything else is uncapped in PHP unless its own controller implements `RateLimit`, because that is the only thing `ApiApplication::getContent()` checks; other components on the same host bring their own configs. Leaving the public Vault pages uncapped is a deliberate decision, not an oversight: measured on 2026-09-04, the only bursts on production were 404 probe scanners whose per-second peak never exceeded 5 requests and which consumed 13.98 s of upstream time in total, which is 0.12 of the 36 available `pm.max_children`. A cap in the shape of the local one (`docker/nginx/nginx.conf:138`, 5r/s burst=10) would have let them through; an effective cap would have to sit near 1 r/s, below what a single page view with its asset fetches produces. Revisit this if real traffic, not probes, starts saturating the pool.

## When to extend

Add an explicit `implements RateLimit` block to any new API controller in this component before merging. The framework's `ApiApplication::getContent()` short-circuits to HTTP 429 once the configured limit is reached (through `checkAndRecord()`, or through `isRateLimited()` when `recordOnlyOnSuccess` is set), so missing the marker silently bypasses protection. `RateLimitPrefixTest` catches the omission via `class_implements(...)`.
