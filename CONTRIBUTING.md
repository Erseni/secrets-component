# Contributing

Thanks for your interest in `secrets-component`.

## Development model

Primary development happens in Erseni's internal monorepo. This public repository is kept in sync by a CI job that adds one release commit to `main` per deployment in which the component changed upstream.

### What this means for contributions

- **Issues** opened here are read and triaged by the maintainers.
- **Merge requests** are welcome. When accepted, the maintainer will cherry-pick the change into the upstream monorepo, and it reaches `main` with the next release commit.
- Open an MR against `main` from a feature branch.

## Local development

The PHP part of the component cannot be built or run outside the upstream monorepo, so there is no local setup for it here. Accepted merge requests are tested upstream before they land.

`vault-ask` in [`cli/`](cli) runs on its own: `cd cli && npm test` (Node.js 20 or newer).

## Code style

The upstream repository runs Laravel Pint and PHPStan on every change, including cherry-picked merge requests.

## Commit messages

Short, imperative, lowercase subject line. Reference the upstream issue ID where applicable.

## License of contributions

By submitting a contribution you agree to license it under the AGPL-3.0-or-later, the licence of this repository.
