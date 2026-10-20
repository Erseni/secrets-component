# Threat model

## What we defend against

| Threat | Mitigation |
|---|---|
| Server operator reading plaintext | Keys never reach the server (URL fragment only); server sees only ciphertext |
| Server operator reading an attachment, its filename or MIME | The file is encrypted client-side with the same AES-GCM key as the secret (separate nonce); filename and MIME are packed into a separately encrypted metadata blob. The server stores only opaque `bytea` and never sees plaintext file, filename or MIME |
| Attachment surviving the single view | The attachment columns are returned and removed in the same atomic `DELETE ... RETURNING` as the secret or the fulfilled request; no independent read path exists |
| Anonymous filler bypassing the attachment cap | The cap is frozen into the request row at creation time (`max_attachment_bytes`); the fulfil path enforces it from that row only and never resolves an account or tier. `0` rejects any attachment with `attachment => attachments_not_allowed` |
| Attachment smuggled into a request whose owner never opted in | Attachments are opt-in per request. Without the opt-in the stored cap is `0`, so the fulfil endpoint refuses the three attachment fields outright |
| Database compromise | Same: ciphertext only. Attacker still needs every URL fragment to decrypt |
| Backup leak | Secrets tables are excluded from `pg_dump` |
| Tampering with in-transit ciphertext | AES-GCM authenticated encryption; tamper = decrypt failure |
| Replay of retrieval request | Atomic `DELETE ... RETURNING`: a secret can be read exactly once |
| Stale secrets piling up | Cron-driven purge every minute; hard `expires_at` enforcement at read |
| Token guessing | 128-bit UUIDs + per-IP rate limit on retrieve endpoints |
| Malicious JavaScript injected into client | Strict CSP (`script-src 'self'` + nonce), no inline JS, no third-party scripts, SRI on the crypto bundle and core scripts |
| Compromised CDN | No external CDN. All assets served from the same origin as the HTML |
| Supply-chain attack on a crypto library | Only native Web Crypto API is used; zero third-party crypto dependencies |
| A secret an AI agent generates for the user landing in the chat, the session log or at the model provider | `vault-ask send` and `send_secret` generate the value in the tool process, encrypt it there and return only a one-time link plus the length. The same value can go to one destination (.env file, file with permissions 600, or one command with masked output), so the agent never needs to see it to configure a system. The MCP `instructions` steer an agent to this tool when a user asks it to generate a password, without any memory or project file |
| A secret for an AI agent landing in the chat, the session log or at the model provider | `vault-ask` requests it through the fill page and hands it to one destination: an environment variable of one child process (default), or a file with permissions 600. No destination writes it to stdout; the agent only receives name and length |
| An agent accidentally printing the value through the command it started | `vault-ask` is the parent process and masks the value in stdout and stderr of the child, including Base64, Base64url, URL, form and hex encodings and each line of a multi-line value |
| An agent (for example after a prompt injection) sending the value somewhere else, including over the network | Purpose binding: the command or path is fixed at creation, shown to the filler before input and encrypted together with the values; `vault-ask` refuses an answer whose purpose or names differ from what it was started for. A new purpose needs a new request and a new look from the person |
| A spoofed purpose display (bidirectional or invisible characters) | The displayed command is the shell-quoted argv; every character outside printable ASCII is shown as an escape sequence |
| An agent reading a file that `vault-ask` wrote by accident | The optional `vault-ask-guard` PreToolUse hook denies file tools and shell commands that name a recorded path, match it through a shell glob, or search a directory above it recursively (`grep -r`, `rg`, `ag`, `find -exec`, `find \| xargs`, `tar`, `cp -r`, `rsync`, the Grep tool without a glob that leaves the file out). It reads the command text and does not run it, so a detour it cannot see still reaches the file: a variable holding the path, a script, an interpreter one-liner. It catches accidents; a manipulated agent that aims for the file gets past it, see the same-user row below |
| Cross-site forgery of the CSRF-exempt secret or request creation from a logged-in browser | Creation requires either proof-of-work headers or an `Authorization` header, both custom headers that a cross-site request cannot set without a CORS preflight the server does not grant |
| A stolen API key | Keys are shown once, stored only as SHA-256 hashes, revocable in the account, limited per plan; a key only creates requests and secrets, it cannot read any secret |

## What we do NOT defend against

| Threat | Why out of scope |
|---|---|
| A compromised sender or recipient device | End-point compromise is outside our control; E2E only protects the pipe |
| Coercion of the holder of a URL | The URL fragment IS the key; protect it like a password |
| Traffic analysis at the network layer | Metadata (sizes, timing) can leak to a passive network observer |
| Side channels in the user's browser crypto | We trust the browser vendor; no WebCrypto implementation is perfect |
| Denial of service | Rate-limits reduce abuse but are not a full DoS defence |
| Forgotten secrets in sender's browser history | Users should clear history if pasting sensitive URLs |
| An agent that runs under the same operating system user as `vault-ask` and has a shell | It can read the memory and the environment of processes it started, attach a debugger, or replace the `vault-ask` binary. Masking, purpose binding and the guard catch accidents and make a manipulated agent visible to the person, they do not contain a hostile one. Complete protection needs privilege separation: the secret held by a service under another user, the agent only holding a handle. This is not part of the component |
| Someone reading the one-time link of a sent secret before the recipient opens it | The link is the key. An agent shows it in the conversation, so the conversation log and the model provider hold it until it is opened. Whoever opens it first reads the value; the recipient then finds it used up and knows the value is burnt. Use a short `--ttl` and open the link promptly |
| Output the command writes elsewhere than stdout and stderr | Masking covers the two pipes only. A command that writes the value into a file, a socket or a log is the command's behaviour; the person approved that command |

## Assumptions

- TLS 1.3 is enforced and certificates are issued by a trusted CA.
- The host OS, PHP runtime, and Postgres binaries are patched promptly.
- Deployment uses HSTS, `X-Content-Type-Options: nosniff`, and a strict CSP.
- The operator has verified the deployed commit SHA against this repository.

## Known limitations

- A server operator could, in principle, serve modified JavaScript to a specific user to leak their URL fragment back via a covert channel. This is an inherent limitation of server-delivered client-side crypto. Mitigation: reproducible builds plus a `build-sha` meta tag (implemented in Phase 3) allow an auditor to verify code integrity per page load, but not per user. Subresource Integrity (SRI) is enforced for the crypto bundle and the core scripts, but it does not close this particular gap: the hash is produced by the same deploy that ships the code, so an operator serving modified JavaScript serves a matching hash with it. Web component scripts, third-party libraries and stylesheets carry no hash at all. `script-src 'self'` plus a nonce-based CSP, and the reproducible-build check against the public mirror, remain the defences that matter against a hostile operator.
- A compromised build pipeline could ship malicious code. Mitigation: tagged releases, signed commits on maintainer side, public mirror with history retention.
