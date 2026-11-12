# Project: API Executor v2.2.0 Metric Observability

## Architecture
The API Executor provides both synchronous execution (`/api/v1/execute`, `/api/v1/plugins/execute`, `/api/v1/mcp`) and asynchronous background job execution (`/api/v1/jobs`) with worker pools and priority queueing.
In v2.2.0, metric observability is upgraded so Prometheus telemetry explicitly distinguishes between synchronous and asynchronous calls across all API endpoints:
- **Unified Mode-Partitioned Metrics**:
  - `action_mode_calls_total{action, mode, status}`: CounterVec tracking invocations partitioned by execution mode (`sync` vs `async`) and status (`ok`, `failure`, `error`, `timeout`, `cancelled`).
  - `action_mode_call_duration_seconds{action, mode}`: HistogramVec tracking execution latency partitioned by execution mode.
- **Backward Compatibility**:
  - Existing `action_calls_*` (sync-only) and `job_executions_*` / `job_queue_depth` / `job_workers_*` (async-only) remain completely intact and active.
- **Data Flow & Telemetry Ingestion**:
  - `RecordActionCallWithMode(action, mode, outcome, timedOut, duration)` in `internal/api/router.go`.
  - Synchronous handlers in `handlers.go`, `plugin_handlers.go`, and `mcp/server.go` invoke `RecordActionCall` which forwards `mode="sync"`.
  - Asynchronous background worker completion in `internal/jobs/engine.go` invokes `RecordJobExecution` in `internal/api/job_metrics.go`, which records both `job_executions_*` and forwards `mode="async"` to `RecordActionCallWithMode`.
- **Label Cardinality Guard**:
  - All dynamic action labels route through `normalizeActionLabel()` bounded by `MaxDynamicActionLabels = 64` to prevent cardinality explosion attacks.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Mode-Partitioned Metric Declarations | Declare and register `action_mode_calls_total` and `action_mode_call_duration_seconds` in `internal/api` | M1 | Survey |
| 2 | Telemetry Recording Ingestion | Implement `RecordActionCallWithMode` and wire synchronous handlers (`mode="sync"`) and asynchronous workers (`mode="async"`) | M1 | Survey |
| 3 | Cardinality & Initialization Guards | Pre-initialize configured actions for sync/async and provide reset helpers in `ResetActionMetrics()` | M1 | Survey |
| 4 | Unit & Integration Test Suite | Comprehensive unit tests in `internal/api` verifying sync and async metrics, status mapping, and duration histograms | M2 | Survey / R1 |
| 5 | E2E Cross-Feature Telemetry Verification | E2E tests in `tests/e2e/tier3_cross_feature_test.go` verifying simultaneous sync and async metrics on `/metrics` scrapes | M3 | Survey / AC |
| 6 | Version Bump to v2.2.0 | Update `VERSION` file to `2.2.0` and verify release workflow compatibility | M4 | R2 / AC |
| 7 | Governance Registers & Documentation | Update `docs/ACTION_LOGBOOK.md` (`ACT-064`), `docs/RCA_REGISTER.md`, and `README.md` adhering to English-only policy | M4 | R2 / AC |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Metric Telemetry Implementation | `internal/api/router.go`, `internal/api/job_metrics.go` | none | DONE |
| M2 | Unit & Integration Test Verification | `internal/api/metrics_timeout_test.go`, `internal/api/job_handlers_test.go` | M1 | DONE |
| M3 | E2E Testing & Hardening | `tests/e2e/tier3_cross_feature_test.go` | M1, M2 | DONE |
| M4 | Governance, Version & Documentation | `VERSION`, `docs/ACTION_LOGBOOK.md`, `docs/RCA_REGISTER.md`, `README.md` | M1, M2, M3 | DONE |

## Interface Contracts
### `internal/api` Telemetry API
- `RecordActionCallWithMode(action, mode, outcome string, timedOut bool, duration time.Duration)`
  - `action`: string (will be normalized via `normalizeActionLabel`)
  - `mode`: `"sync"` | `"async"`
  - `outcome`: `"ok"` | `"failure"` | `"error"` | `"timeout"` | `"cancelled"`
  - `timedOut`: bool
  - `duration`: `time.Duration`
- `GetActionModeCallCount(action, mode, status string) float64`
  - Returns current counter value for test assertions.

## Code Layout
- `internal/api/router.go`: Prometheus metric declarations, registration, `RecordActionCallWithMode`, initialization, and reset.
- `internal/api/job_metrics.go`: Asynchronous reporter integration forwarding `mode="async"` calls to `RecordActionCallWithMode`.
- `internal/api/metrics_timeout_test.go`: Unit tests for metric collection and differentiation.
- `tests/e2e/tier3_cross_feature_test.go`: E2E tests verifying Prometheus scrape endpoint for sync and async modes.
- `VERSION`: Contains `2.2.0`.
- `docs/ACTION_LOGBOOK.md`: Living log of actions.
- `docs/RCA_REGISTER.md`: Living RCA and technical decisions register.
- `README.md`: Observability and metrics documentation.
