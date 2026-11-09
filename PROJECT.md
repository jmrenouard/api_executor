# Project: Asynchronous Action Execution, Job Queue, Logs, and Audit History

## Architecture
The API Executor (`go-admin-tool`) asynchronous execution architecture decouples long-running operations from synchronous HTTP request threads using a bounded in-memory priority queue, a dedicated worker pool, real-time chunked log capture, persistent SQLite history with in-memory fallback, and cryptographic SHA-256 tamper-evident audit chaining:

- **Core Execution Primitives (`internal/core/`)**:
  - `ExecuteCommandWithContext(ctx, cmdDef, timeout, liveWriter)`: Propagates parent/job contexts directly to `exec.CommandContext`, configuring process group termination (`taskkill /T /F` on Windows, `syscall.Kill(-pid, SIGKILL)` on Unix) and piping stdout/stderr into both the internal buffer and the live `JobLogBuffer`.
- **Asynchronous Job Engine (`internal/jobs/`)**:
  - `Job`: Data model capturing `ID`, `Type` (`command` | `plugin`), `Action`, `PluginID`, `Parameters`, `Priority`, `Status` (`queued`, `running`, `completed`, `failed`, `cancelled`, `timed_out`), timestamps, duration, actor attribution, and output summary.
  - `JobQueue`: Thread-safe priority queue (`container/heap`) with three priority tiers (High, Normal, Low) and FIFO ordering within tiers, with backpressure capacity (`ErrQueueFull`).
  - `WorkerPool`: Bounded worker goroutines consuming jobs from the queue with graceful draining on server shutdown.
  - `JobLogBuffer`: Concurrency-safe byte buffer supporting simultaneous subprocess writes and client chunked reads (`ReadChunk(offset)`) with EOF notifications and memory bounds (`MaxLogBytesPerJob = 2 MiB`).
  - `JobStore`: SQLite table `job_history` with indexed queries (`status`, `action`, `actor_id`, `created_at`) and thread-safe in-memory fallback (`CGO_ENABLED=0`), plus background retention pruning.
- **REST API Endpoints (`internal/api/`)**:
  - `POST /api/v1/jobs`: Submit command or plugin action for background execution (returns `202 Accepted` with `job_id` and poll URLs).
  - `GET /api/v1/jobs`: List active and historical jobs with filtering and pagination.
  - `GET /api/v1/jobs/{id}`: Inspect detailed job metadata and execution state.
  - `GET /api/v1/jobs/{id}/logs`: Tail live/captured logs with byte offset tracking.
  - `POST /api/v1/jobs/{id}/cancel`: Abort a queued or running job with immediate subprocess termination.
  - `GET /api/v1/jobs/queue`: Inspect queue depth and worker pool telemetry.
  - Prometheus path normalization in `normalizeMetricPath` and bounded metric labels.
  - RBAC verification (`jobs:submit`, `jobs:read`, `jobs:cancel`) and service account action scoping.
- **Cryptographic Audit Trail (`internal/audit/`)**:
  - Every job lifecycle transition (`job.enqueued`, `job.started`, `job.completed`, `job.failed`, `job.cancelled`) records a SHA-256 hash-chained `AuditEvent` (`category: "job"`), preserving tamper-evident chain verification.
- **Web Administration Console (`web/static/index.html`)**:
  - Tab 9: `9. Async Jobs & Queue` featuring worker telemetry badges, job submission card (command/plugin), interactive execution history table with status badges, and a live log viewer modal with auto-refresh poll loop (1s/2s) and cancel button.
- **Mandatory Repository Governance**:
  - Strict atomicity: 1 feature/fix = 1 GitHub Issue = 1 Branch = 1 PR = 1 Merge = Close Issue with summary comment.
  - English-only across all code, comments, issues, PRs, comments, and documentation.
  - Pre-commit test pass: 100% passing `go test -v -cover ./...`.
  - Living registers: `docs/ACTION_LOGBOOK.md` and `docs/RCA_REGISTER.md`.

---

## Feature Inventory

Every required feature from the survey and requirements is cataloged and assigned to a milestone:

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Execution Engine Context & Live Stream Support | `ExecuteCommandWithContext` accepting context, timeout, and `io.Writer` live logger | M1 | Survey 1 |
| 2 | Priority Job Queue & Worker Pool | `internal/jobs` package with `JobQueue` (heap), `WorkerPool`, and lifecycle state machine | M1 | Survey 1, 2 |
| 3 | Concurrency-Safe Live & Captured Log Buffer | `JobLogBuffer` for real-time subprocess stdout/stderr capture and offset-based chunk reads | M1 | Survey 1, 2 |
| 4 | Persistent Job History & SQLite / In-Memory Store | `job_history` table, indexed queries, in-memory fallback, and retention pruner | M1 | Survey 2 |
| 5 | Asynchronous REST API Handlers | `POST /api/v1/jobs`, `GET /api/v1/jobs`, `GET /api/v1/jobs/{id}`, `GET /api/v1/jobs/{id}/logs`, `POST /api/v1/jobs/{id}/cancel`, `GET /api/v1/jobs/queue` | M2 | Survey 3 |
| 6 | RBAC Authorization for Async Actions | Scopes `jobs:submit`, `jobs:read`, `jobs:cancel`, and service account allowed actions check | M2 | Survey 3 |
| 7 | Prometheus Telemetry for Async Jobs | Metrics `job_queue_depth`, `job_workers_active`, `job_executions_total`, duration histogram, route normalization | M2 | Survey 3 |
| 8 | SHA-256 Tamper-Evident Audit Integration | Cryptographic chaining of job lifecycle events under `Category: "job"` | M2 | Survey 2, 3 |
| 9 | Web Administration Console Tab 9 Integration | Tab 9 in `web/static/index.html` with telemetry bar, submit card, history table, live log modal & tests in `web_console_test.go` | M3 | Survey 3 |
| 10 | 4-Tier End-to-End (E2E) Test Suite Expansion | 15+ tests across Tiers 1–4 (Feature, Boundary, Cross-Feature, Real-World) in `tests/e2e/` | M4 | Survey 3 |
| 11 | 100% E2E Pass & Test Coverage Verification | Pass 100% tests across all packages (`go test -v -cover ./...`), verify statement coverage | M5 | Requirements |
| 12 | Documentation, OpenAPI/Swagger & Living Registers | Update `README.md`, `docs/swagger.*`, `TEST_INFRA.md`, `TEST_READY.md`, `docs/ACTION_LOGBOOK.md`, `docs/RCA_REGISTER.md` | M5 | Governance |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core Asynchronous Job Engine & Queue Worker Pool | `internal/core/executor.go` context support, `internal/jobs` package (models, queue, pool, buffer, SQLite & in-mem store) with unit tests | none | DONE (PR #85, #87; 388 tests pass, Gate 2 PASS) |
| M2 | REST API Endpoints, RBAC, Metrics & Audit Integration | `internal/api/` handlers for `/api/v1/jobs/*`, RBAC checks, Prometheus gauges/counters, metric path normalization, SHA-256 audit events | M1 | DONE (PR #89, #91; 437 tests pass, Gate 2 PASS) |
| M3 | Web Administration Console Tab 9 Integration | `web/static/index.html` (Tab 9: queue telemetry, submit form, history table, live log modal) & `internal/api/web_console_test.go` | M1, M2 | DONE (PR #93; 439 tests pass, Gate 3 PASS) |
| M4 | 4-Tier End-to-End (E2E) Test Suite Expansion | `tests/e2e/`: Tier 1 (Feature), Tier 2 (Boundary), Tier 3 (Cross-feature RBAC/Audit), Tier 4 (Real-world scenario), publish `TEST_READY.md` | M1, M2, M3 | DONE (Issue #94; 88 E2E tests pass, 461 full repository tests pass) |
| M5 | 100% Verification, Documentation & Governance Registers | Pass 100% `go test -v -cover ./...`, update `README.md`, `docs/swagger.*`, `TEST_INFRA.md`, `docs/ACTION_LOGBOOK.md`, `docs/RCA_REGISTER.md` | M1, M2, M3, M4 | PLANNED |

---

## Interface Contracts

### `internal/jobs` ↔ `internal/api`
- `JobRequest`:
  ```go
  type JobRequest struct {
      Type            JobType        `json:"type"`                // "command" | "plugin"
      Action          string         `json:"action"`
      PluginID        string         `json:"plugin_id,omitempty"`
      Params          map[string]any `json:"params,omitempty"`
      Priority        Priority       `json:"priority,omitempty"`  // High, Normal, Low
      TimeoutOverride time.Duration  `json:"timeout_override,omitempty"`
      ActorType       string         `json:"actor_type,omitempty"`
      ActorID         string         `json:"actor_id,omitempty"`
      SourceIP        string         `json:"source_ip,omitempty"`
  }
  ```
- `Job`:
  ```go
  type Job struct {
      ID          string         `json:"id"`
      Type        JobType        `json:"type"`
      Action      string         `json:"action"`
      PluginID    string         `json:"plugin_id,omitempty"`
      Params      map[string]any `json:"params,omitempty"`
      Priority    Priority       `json:"priority"`
      Status      JobStatus      `json:"status"` // queued, running, completed, failed, cancelled, timed_out
      CreatedAt   time.Time      `json:"created_at"`
      StartedAt   *time.Time     `json:"started_at,omitempty"`
      CompletedAt *time.Time     `json:"completed_at,omitempty"`
      DurationMs  int64          `json:"duration_ms,omitempty"`
      Timeout     time.Duration  `json:"timeout"`
      ActorType   string         `json:"actor_type"`
      ActorID     string         `json:"actor_id"`
      SourceIP    string         `json:"source_ip,omitempty"`
      Error       string         `json:"error,omitempty"`
      ResultData  any            `json:"result_data,omitempty"`
  }
  ```
- `Engine` Methods:
  ```go
  Enqueue(req JobRequest) (*Job, error)
  GetJob(id string) (*Job, bool)
  ListJobs(filter JobFilter) ([]*Job, int)
  GetJobLogs(id string, offset int) (logs string, nextOffset int, truncated bool, eof bool, err error)
  CancelJob(id string) error
  QueueStats() QueueStats
  Shutdown(ctx context.Context) error
  ```

### REST API Endpoints
- `POST /api/v1/jobs`: Submit job (`202 Accepted`: `{"job_id": "...", "status": "queued", "poll_url": "..."}`)
- `GET /api/v1/jobs`: List jobs (`200 OK`: `{"jobs": [...], "total": N, "limit": L, "offset": O}`)
- `GET /api/v1/jobs/{id}`: Detailed job metadata (`200 OK`: `Job`)
- `GET /api/v1/jobs/{id}/logs`: Chunked log retrieval (`200 OK`: `{"job_id": "...", "status": "...", "logs": "...", "offset": X, "next_offset": Y, "eof": bool}`)
- `POST /api/v1/jobs/{id}/cancel`: Abort job (`200 OK`: `{"job_id": "...", "status": "cancelled"}`)
- `GET /api/v1/jobs/queue`: Worker pool stats (`200 OK`: `{"workers_total": W, "workers_busy": B, "queued_jobs": Q, "capacity": C}`)

---

## Code Layout

- `internal/core/`:
  - `executor.go`: Add `ExecuteCommandWithContext` accepting context, timeout, and optional live `io.Writer`.
- `internal/jobs/`:
  - `job.go`: Core models (`Job`, `JobStatus`, `Priority`, `JobRequest`, `JobFilter`, `JobLogBuffer`).
  - `queue.go`: Thread-safe priority queue using `container/heap`.
  - `worker.go`: Worker pool implementation with graceful shutdown.
  - `store.go`: SQLite and thread-safe in-memory `JobStore` with indexed queries and retention pruner.
  - `engine.go`: Main `Engine` orchestrating queue, workers, store, metrics, and audit logging.
  - `jobs_test.go`: Unit tests for engine, queue, worker pool, buffer, and cancellation.
- `internal/api/`:
  - `job_handlers.go`: HTTP endpoints for `/api/v1/jobs/*` with RBAC authorization.
  - `job_handlers_test.go`: Unit tests for job endpoints, error handling, and metric validation.
  - `router.go`: Route registration, static path listing, and path normalization for Prometheus.
- `web/static/`:
  - `index.html`: Tab 9 UI for Async Jobs & Queue with live log viewer modal and polling.
- `tests/e2e/`:
  - `tier1_feature_test.go`: Tier 1 feature happy path tests for async jobs.
  - `tier2_boundary_test.go`: Tier 2 boundary and corner case tests.
  - `tier3_cross_feature_test.go`: Tier 3 cross-feature RBAC and audit tests.
  - `tier4_real_world_test.go`: Tier 4 real-world long-running diagnostic scenario.
- `docs/`:
  - `ACTION_LOGBOOK.md`: Living register of ongoing and completed actions.
  - `RCA_REGISTER.md`: Living register of root-cause analyses, approximations, and ideas.
