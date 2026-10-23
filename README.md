# secrets-component

[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/erseni/secrets-component)
[![Vault Ask MCP server](https://mcprush.com/badge/vault-ask-mcp/card.svg)](https://mcprush.com/to/vault-ask-mcp?ref=badge)

Zero-knowledge, one-time secret sharing. End-to-end encrypted in the browser. The server only ever stores ciphertext. Supports both **sending** and **requesting** secrets without requiring any account.

Part of the [Erseni](https://erseni.com) open-source components.

**Status**: early development. API and on-disk format may change until the first tagged release.

> Primary development happens in Erseni's internal monorepo. This repository is a public mirror, kept in sync via Jenkins after every successful production deploy. Issues and merge requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Features

- **Send a secret**: create a one-time link, recipient decrypts in the browser, secret self-destructs after viewing.
- **Request a secret**: create an inbound link, send it to a third party (customer, colleague) who submits a secret without an account. You retrieve it once with your private key.
- **End-to-end encryption**: AES-GCM 256 for sending, X25519 + ECIES for requesting. All crypto in the browser via the native Web Crypto API. The server never sees plaintext.
- **No accounts**: neither sender nor receiver needs to sign up.
- **Auditable**: deterministic build, source SHA embedded in every HTML response, SRI hashes on every script.
- **Secrets for AI agents**: [`cli/`](cli) contains `vault-ask`, a CLI and MCP server that request a secret from a person and hand it to exactly one command or file, masked in every output and never shown to the agent, and that send a generated secret to a person as a one-time link.

## Where it runs

The component runs as part of [Erseni Vault](https://vault.erseni.com), hosted in the EU. It is not a standalone application: it depends on Erseni's internal framework, and this repository cannot be installed or self-hosted on its own. The source is published so that the cryptography and the server behaviour can be audited.

`vault-ask` in [`cli/`](cli) is the exception: it is a standalone Node.js tool that talks to Erseni Vault.

## Security model

- Secret plaintext never leaves the sender's browser.
- Encryption keys are transported in the URL fragment (`#k=...`), which browsers never send to servers.
- Secrets are deleted on first retrieval (atomic `DELETE ... RETURNING`).
- Expired secrets are purged every minute by a cron job.
- No access logs, no IP retention, no backups of the secrets tables.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Verifying a running instance

Every page served by a `secrets-component` instance includes a `<meta name="build-sha" content="...">` tag. Match that SHA against a tag in this repository to confirm the deployed code.

```bash
curl -s https://secrets.example.com/send | grep build-sha
```

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

## Security disclosure

See [SECURITY.md](SECURITY.md).
