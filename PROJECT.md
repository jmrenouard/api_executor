# Project: Certified Native Version Endpoint, Multi-Config Support & Security Hardening

## Architecture
The API Executor (`go-admin-tool`) is a lightweight remote administration daemon written in Go providing synchronous command execution, asynchronous background jobs with worker pools, MCP integration, and Prometheus telemetry.
This project implements the verified architectural requirements from `ORIGINAL_REQUEST.md`:
1. **Certified Native Version Endpoint (`GET /api/v1/version`)**:
   - Implemented via a dedicated `internal/version` package and `internal/api/version_handler.go`.
   - Direct restitution of source truth without intermediary via `runtime/debug.ReadBuildInfo()` with fallback hierarchy:
     - `version`: linker `-ldflags` -> `bi.Main.Version` -> `VERSION` file (`2.2.0`).
     - `git_commit`: linker `-ldflags` -> `vcs.revision` (40 chars) -> `"unknown"`.
     - `build_date`: linker `-ldflags` -> `vcs.time` -> `"unknown"`.
     - `integrity_status` / `integrity`: linker `-ldflags` -> `vcs.modified` (`false` -> `"clean"`, `true` -> `"modified"`) -> `"untracked"`.
     - `uptime` & `uptime_seconds`: computed from `APIEnv.StartTime` set at server bootstrap.
     - `go_version`: `runtime.Version()`.
   - Public unauthenticated endpoint (accessible even when `RequireAuth=true`), protected by IP rate limiting, defensive headers, and 1 MiB body cap.
   - Bound in `knownStaticPaths` in `internal/api/router.go` to prevent Prometheus label cardinality collapse into `"other"`.

2. **Native Multi-Config Support & Backward Compatibility (`GET /api/v1/config`)**:
   - `MultiConfigManager` in `internal/core/config.go` managing named configuration profiles (`default`, `ubuntu`, `redhat`, etc.).
   - Support for `multi_config:` block in `config.yaml` declaring supported profiles and configuration file paths.
   - Native endpoint `GET /api/v1/config` (and `GET /api/v1/configs/{profile}`) exposing active configuration and available profiles with masked/redacted credentials (`[REDACTED]`).
   - Profile resolution via `X-Config-Profile` header, query parameter `?profile=<name>`, or path prefix, cleanly falling back to `default` (`config.yaml`) ensuring 100% backward compatibility.
   - Per-profile command listing and execution in `internal/api/handlers.go`.

3. **Production Hardening Extensions (Proposals #8, #7, #9, #10)**:
   - Proposal #8: `sync.Pool` zero-allocation buffers for chunked `JobLogBuffer` in `internal/jobs/buffer.go`.
   - Proposal #7: Native OpenTelemetry (OTLP) metrics export endpoint (`GET /api/v1/metrics/otlp`) in `internal/api/metrics_otlp.go`.
   - Proposal #9: Cosign OCI container image cryptographic signing via GitHub Actions OIDC in `.github/workflows/docker-publish.yml`.
   - Proposal #10: Rootless container sandbox enforcement (UID 10001 / `--userns=keep-id`) in `internal/core/executor_unix.go`.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Native Version Data Model & Extraction | `internal/version` package extracting VCS metadata, build info, fallback hierarchy, and uptime calculation | M1 | Survey / Prop 1 |
| 2 | Certified Version HTTP Handler & Routing | Public `GET /api/v1/version` endpoint in `internal/api/version_handler.go`, registered in `router.go` and `knownStaticPaths` | M1 | Survey / Prop 1 |
| 3 | Version Endpoint Tests & Non-Regression | Unit tests in `internal/version/version_test.go`, `internal/api/version_test.go`, and E2E in `tests/e2e/tier1_feature_test.go` | M1 | Survey / AC |
| 4 | Multi-Config Manager & Schema | `MultiConfigManager` in `internal/core/config.go` with profile loading, resolution, and YAML schema | M2 | Survey / Req 2 |
| 5 | Native Config Inspection Endpoint | `GET /api/v1/config` returning sanitized configuration and catalog of supported backward-compatible profiles | M2 | Survey / Req 2 |
| 6 | Per-Profile Execution & Backward Compatibility | Profile resolution (`X-Config-Profile`, `?profile=`) wiring into command execution and listing with default fallback | M2 | Survey / Req 2 |
| 7 | Zero-Allocation JobLogBuffer Pooling | `sync.Pool` recycling of log buffers in `internal/jobs/buffer.go` and `internal/jobs/engine.go` | M3 | Prop 8 |
| 8 | OpenTelemetry (OTLP) Metrics Export | Native OTLP metrics export handler (`GET /api/v1/metrics/otlp`) translating Prometheus metric families | M4 | Prop 7 |
| 9 | Cosign OCI Container Signing | Automated Sigstore Cosign signing via GitHub Actions OIDC in `.github/workflows/docker-publish.yml` | M5 | Prop 9 |
| 10 | Rootless Sandbox Enforcement | Enforce UID 10001 / `--userns=keep-id` for containerized executor tasks in `internal/core/executor_unix.go` | M6 | Prop 10 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Certified Version Endpoint | `internal/version/`, `internal/api/version_handler.go`, `router.go`, tests (`ACT-065`) | none | DONE |
| M2 | Native Multi-Config & Backward Compatibility | `internal/core/config.go`, `internal/api/config_handlers.go`, `router.go`, configs, tests (`ACT-066`) | M1 | DONE |
| M3 | Zero-Allocation JobLogBuffer Pooling | `internal/jobs/buffer.go`, `internal/jobs/engine.go`, tests (`ACT-067`) | M2 | PLANNED |
| M4 | OpenTelemetry (OTLP) Metrics Export | `internal/api/metrics_otlp.go`, `internal/api/router.go`, tests (`ACT-067`) | M2 | DONE |
| M5 | Cosign OCI Container Image Signing | `.github/workflows/docker-publish.yml` (`ACT-069`) | M4 | PLANNED |
| M6 | Rootless Container Sandbox Enforcement | `internal/core/executor_unix.go`, `internal/core/config.go`, tests (`ACT-070`) | M5 | PLANNED |

## Interface Contracts
### `GET /api/v1/version` Contract
- Method: `GET` (other methods return `405 Method Not Allowed`)
- Authentication: None (public unauthenticated probe; 200 OK even when `RequireAuth=true`)
- Response Headers: `Content-Type: application/json`, standard security headers
- JSON Response Body:
  ```json
  {
    "version": "2.2.0",
    "git_commit": "40-char-sha or unknown",
    "build_date": "RFC3339 timestamp or unknown",
    "integrity_status": "clean | modified | untracked",
    "integrity": "clean | modified | untracked",
    "uptime": "human-readable duration",
    "uptime_seconds": 123.45,
    "go_version": "go1.x.y",
    "start_time": "RFC3339 timestamp",
    "os": "os name",
    "arch": "arch name",
    "compiler": "gc"
  }
  ```

### `GET /api/v1/config` Contract
- Method: `GET`
- Authentication: Standard RBAC or public read-only summary (with masked credentials)
- Query parameters: `?profile=<name>` (optional)
- Request Headers: `X-Config-Profile: <name>` (optional)
- JSON Response Body:
  ```json
  {
    "active_profile": "default",
    "config_file": "config.yaml",
    "profiles": [
      {"name": "default", "path": "config.yaml", "commands_count": 2},
      {"name": "ubuntu", "path": "configs/ubuntu-tasks.yaml", "commands_count": 4},
      {"name": "redhat", "path": "configs/redhat-tasks.yaml", "commands_count": 4}
    ],
    "server": { "host": "0.0.0.0", "port": 8080, "tls_enabled": true },
    "command_executor": { "enabled": true, "default_timeout": "30s" }
  }
  ```

## Code Layout
- `internal/version/version.go`: Certified version metadata models, `runtime/debug.ReadBuildInfo()` extraction, fallback hierarchy.
- `internal/version/version_test.go`: Unit tests for version resolution, uptime, and fallback logic.
- `internal/api/version_handler.go`: Public HTTP handler for `GET /api/v1/version`.
- `internal/api/version_test.go`: HTTP handler tests for 200 OK, 405 Method Not Allowed, unauthenticated access.
- `internal/core/config.go`: `MultiConfigManager`, `multi_config:` schema, profile loading.
- `internal/api/config_handlers.go`: `ConfigHandler` for `GET /api/v1/config`.
- `internal/jobs/buffer.go`: `sync.Pool` zero-allocation pooling for `JobLogBuffer`.
- `internal/api/metrics_otlp.go`: OTLP metrics translation and export handler.
- `.github/workflows/docker-publish.yml`: Cosign container signing step.
- `internal/core/executor_unix.go`: Rootless container sandbox credential dropping.
- `docs/ACTION_LOGBOOK.md`: Living record of all actions (`ACT-065` onwards).
- `docs/RCA_REGISTER.md`: Living RCA and technical decisions register.
