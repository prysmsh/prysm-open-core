# Contributing

Thanks for helping improve the Prysm backend!

## Quick Start

1. Fork https://github.com/prysmsh/prysm-open-core
2. `git checkout -b feature/my-change`
3. Run `go test ./...`
4. Commit with context and open a pull request

## Guidelines

- Keep pull requests focused and reviewable
- Add or update tests for functional changes
- Prefer pushing business logic into `internal/services` packages
- Maintain existing logging conventions (`pkg/logger`)
- Avoid introducing proprietary dependencies or datasets

## Code Style

- Run `go fmt ./...`
- Run `golangci-lint run` when available locally
- Keep configurations (Redis, Postgres, cloud credentials) configurable via environment variables

## Security

Security reports should go directly to `security@prysm.sh`. See `SECURITY.md` for details.
