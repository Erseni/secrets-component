# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in `secrets-component`, please **do not** open a public issue. Instead, email `security@erseni.com` with:

- A description of the issue
- Steps to reproduce (proof of concept if possible)
- The commit SHA or tag you tested against
- Whether you have disclosed the issue elsewhere

We aim to acknowledge reports within 48 hours and provide a remediation timeline within 7 days.

## PGP key

For sensitive disclosures, encrypt to `security@erseni.com` using the following key:

```
Fingerprint: F489 9E53 8BD4 DE43 94E4  3745 6649 87BF C5B3 30D0
Created:     2026-09-09
Expires:     2029-09-08
```

The public key is in this repository as [security-pgp-key.asc](security-pgp-key.asc). The same key is referenced from the `Encryption` field of `https://vault.erseni.com/.well-known/security.txt`; compare the fingerprint against both sources before you use it.

## Scope

In scope:

- The code in this repository (server and client)
- The official production instance we operate, `https://vault.erseni.com`

Out of scope:

- Third-party forks and instances we do not operate
- Social engineering of Erseni staff
- DoS attacks against production hosts

## Safe harbor

We will not pursue legal action for security research performed in good faith and in line with this policy. If in doubt, ask before testing destructive behaviour.
