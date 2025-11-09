# Prysm Backend (Open-Core)

This repository hosts the open-core backend for Prysm, a zero-trust infrastructure access platform.

The backend exposes REST and gRPC APIs for authentication, policy enforcement, cluster access brokerage, and observability. Enterprise-only services, analytics pipelines, and UI layers are intentionally omitted from this code drop.

## Status

| Component | State |
| --------- | ----- |
| Backend APIs | ✅ Open core |
| CLI | ✅ Open core |
| Infrastructure agent | ✅ Open core |
| Desktop client | ✅ Open core |
| Analytics & automation | ❌ Proprietary |

## Getting Started

### Prerequisites

- Go 1.24 or newer
- PostgreSQL 14 or newer
- Redis 7 or newer

### Local Build & Run

```bash
go build -o prysm-backend ./cmd/api
POSTGRES_DSN="postgres://prysm:prysmpass@localhost:5432/prysm?sslmode=disable" \
REDIS_URL="redis://localhost:6379" \
./prysm-backend
```

A Docker Compose stack is available in `docker-compose.yml` for easier local experimentation.

### Prysm CLI

The open-core CLI is available under `prysm-cli`. Build and install it locally with:

```bash
cd prysm-cli
go build -o prysm ./cmd/prysm
```

A Homebrew formula is also available: `brew install prysm-open-core`.

### Prysm Desktop (Flutter)

The cross-platform Flutter desktop client lives in `prysm-zero`. To build the Windows bundle locally:

```bash
cd prysm-zero
flutter config --enable-windows-desktop
flutter pub get
flutter build windows --release
```

The packaged build output is written to `build/windows/x64/runner/Release/`. Zip the entire folder when preparing release artifacts so the `.exe`, DLLs, and data files ship together. macOS and Linux builds follow the same pattern with `flutter build macos --release` or `flutter build linux --release`.

Configure the desktop client by exporting environment variables before launching or by editing the in-app Settings screen:

```bash
export PRYSM_API_URL="http://localhost:8080"
export PRYSM_DERP_URL="wss://derp.prysm.sh/derp"
```

These values are cached securely per device. Use **Settings → Reset DERP Identity** to rotate device tokens if needed.

### Prysm Kubernetes Agent

The Kubernetes agent source lives in `prysm-k8s-agent`. Build the agent binary with:

```bash
cd prysm-k8s-agent
go build -o prysm-agent ./cmd/agent
```

You can then containerize or deploy the agent with the manifests under `prysm-k8s-agent/manifests/`.

### Database Migrations

Migrations live in `db_migrations/` and are ordered lexicographically. Apply them with your preferred migration tool (`migrate`, `tern`, etc.).

## Project Layout

- `cmd/api` – service entrypoint
- `internal/` – HTTP handlers, services, integrations
- `internal/middleware` – auth, rate limiting, validation
- `internal/models` – GORM models
- `pkg/` – shared utilities (logging, helpers)
- `prysm-cli/` – open-core CLI source
- `prysm-k8s-agent/` – Kubernetes agent
- `db_migrations/` – SQL schema migrations

## Roadmap Highlights

- Modularize internal packages and strengthen interfaces
- Expand integration and contract test coverage
- Generate OpenAPI schemas and publish SDKs
- Harden telemetry, metrics, and tracing pipelines

See `CONTRIBUTING.md` for collaboration guidelines.

## Enterprise Features

Commercial support and enterprise-only capabilities (advanced analytics, compliance automation, extended integrations) remain available from [prysm.sh](https://prysm.sh).
