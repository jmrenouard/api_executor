# API Executor (`go-admin-tool`) — Security, Code Updates & Missing Capabilities Analysis

## 1. Executive Summary

This document presents the comprehensive security review, dependency/code modernization audit, and enterprise feature gap analysis for **API Executor (`go-admin-tool`)**, along with the implemented remediations across atomic Issues [#2](https://github.com/jmrenouard/api_executor/issues/2) through [#11](https://github.com/jmrenouard/api_executor/issues/11).

---

## 2. Security Audit & Applied Remediations

| Finding ID | Severity | Area | Initial Vulnerability / Risk | Applied Remediation |
|---|---|---|---|---|
| `SEC-01` | **CRITICAL** | Transport Security | Server listened only on cleartext HTTP (`http.ListenAndServe`), exposing credentials, tokens, and command output in transit. | Enabled **HTTPS/TLS 1.2+ by default** (`internal/core/tls.go`) with automatic ECDSA P-256 X.509 certificate generation (`0600` private key), live rotation (`POST /api/v1/tls/renew`), optional mTLS Client CA validation, and `Strict-Transport-Security` (HSTS) header injection (Issue [#4](https://github.com/jmrenouard/api_executor/issues/4)). |
| `SEC-02` | **CRITICAL** | Authentication & Authorization | API endpoints (`/api/v1/execute`, `/api/v1/files`) had no authentication, RBAC, or machine-to-machine scoping. | Implemented `internal/auth/manager.go` supporting RBAC roles (`admin`, `operator`, `viewer`, `service`), Personal Access Tokens (`gat_pat_...`), and Third-Party Service Accounts (`gat_svc_...`) with constant-time hash comparison and per-service `allowed_actions` allowlists (Issue [#7](https://github.com/jmrenouard/api_executor/issues/7)). |
| `SEC-03` | **HIGH** | Process Lifecycle & DoS | `exec.CommandContext` did not isolate child process groups; timed-out commands spawning grandchildren leaked processes and hung HTTP handlers. | Added OS-specific process-group isolation (`Setpgid` on Unix, `WaitDelay` on Unix/Windows) and hierarchical timeouts (`30s` default -> executor default -> per-command -> per-call override capped by `max_timeout_seconds`) (Issue [#3](https://github.com/jmrenouard/api_executor/issues/3)). |
| `SEC-04` | **HIGH** | Metrics Cardinality DoS | Unbounded caller-supplied command names could create arbitrary Prometheus time series. | Added `normalizeActionLabel` in `internal/api/router.go` bounding dynamic action labels to `MaxDynamicActionLabels = 64` and stripping control characters (Issue [#3](https://github.com/jmrenouard/api_executor/issues/3)). |
| `SEC-05` | **HIGH** | Non-Repudiation & Auditability | Action history stored in a mutable SQLite table without cryptographic integrity verification or caller attribution. | Implemented tamper-evident SHA-256 hash-chained audit logging (`internal/audit/audit.go`) linking every event from `GENESIS` (`prev_hash` -> `entry_hash`) with `/api/v1/audit/verify` verification (Issue [#6](https://github.com/jmrenouard/api_executor/issues/6)). |
| `SEC-06` | **HIGH** | Plugin & Database Exposure | Need to expose parameterized commands and SQLite database inspection without risking shell injection or destructive SQL statements. | Declarative plugins (`internal/plugins/declarative.go`) validate every `{{param}}` against strict regexes and execute via `os/exec` argument vectors (zero `sh -c`). `db-exposure` (`internal/plugins/db_exposure.go`) enforces read-only `SELECT` validation blocking `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `ATTACH`, `PRAGMA`, and multi-statement `;` queries (Issue [#8](https://github.com/jmrenouard/api_executor/issues/8)). |
| `SEC-07` | **MEDIUM** | Log File Permissions | Log files were opened with `0666` permissions (`os.O_CREATE`), allowing world-readable access on shared hosts. | Restricted log and audit file permissions to `0600` (`internal/core/logger.go`, `internal/audit/audit.go`) (Issue [#6](https://github.com/jmrenouard/api_executor/issues/6)). |

---

## 3. Code & Dependency Modernization

1. **Docker & Go Toolchain Alignment**:
   - Updated `Dockerfile` builder image from `golang:1.21-alpine` to `golang:1.24-alpine` to match `go.mod` (`go 1.24.0`).
   - Added dedicated multi-stage Dockerfiles for **Ubuntu 24.04 LTS** (`docker/Dockerfile.ubuntu`) and **RedHat UBI 9** (`docker/Dockerfile.redhat`) orchestrated via `docker-compose.os-test.yml`.
2. **Zero-CGO Portability**:
   - Enhanced `internal/database/db.go` with a thread-safe pure-Go in-memory fallback when compiled with `CGO_ENABLED=0` (as used in minimal container builds and Windows/CI environments without GCC).

---

## 4. Predefined OS Task Catalogs (Ubuntu & RedHat)

To make `api_executor` immediately usable across enterprise Linux fleets and testable in containers, two built-in OS preset catalogs are provided in `internal/core/os_presets.go` and `configs/{ubuntu,redhat}-tasks.yaml`:

- **Ubuntu / Debian (`ubuntu:24.04`)**:
  - `ubuntu-os-release`, `ubuntu-kernel-uname`, `ubuntu-dpkg-packages`, `ubuntu-apt-simulated-upgrade`, `ubuntu-apt-sources`, `ubuntu-disk-space`, `ubuntu-memory-stats`, `ubuntu-process-snapshot`, `ubuntu-network-sockets`, `ubuntu-passwd-accounts`.
- **RedHat / RHEL / Rocky / UBI 9 (`redhat/ubi9:latest`)**:
  - `redhat-os-release`, `redhat-system-release`, `redhat-rpm-qa`, `redhat-rpm-verify-crypto`, `redhat-dnf-repolist`, `redhat-disk-space`, `redhat-memory-stats`, `redhat-process-snapshot`, `redhat-kernel-uname`, `redhat-passwd-accounts`.

---

## 5. Asynchronous Action Execution Architecture & Security Analysis

The **Asynchronous Execution Subsystem** (`internal/jobs/`) decouples long-running operational commands, multi-domain plugin workflows, and database queries from synchronous HTTP server goroutines.

### 5.1 Subsystem Architecture & Components

```text
HTTP Client / Web Console (Tab 9)
             │
             ▼
┌───────────────────────────────────────────────┐
│              internal/api/                     │
│  POST /api/v1/jobs ──► RBAC Scope & Action     │
│  GET  /api/v1/jobs ──► List & Query Filter    │
│  GET  /api/v1/jobs/{id}/logs ──► Chunked Log   │
│  POST /api/v1/jobs/{id}/cancel ──► Cancel Job │
└──────────────────────┬────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────┐
│              internal/jobs/                   │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │     JobQueue (container/heap Priority)  │  │
│  │  High > Normal > Low (FIFO Tie-Breaker) │  │
│  │  Capacity Bound: 1000 (ErrQueueFull)   │  │
│  └────────────────────┬────────────────────┘  │
│                       │                       │
│                       ▼                       │
│  ┌─────────────────────────────────────────┐  │
│  │    WorkerPool (Bounded Goroutines)      │  │
│  │  Consumes jobs, passes Context & Buffer │  │
│  └────────────────────┬────────────────────┘  │
│                       │                       │
│        ┌──────────────┴──────────────┐        │
│        ▼                             ▼        │
│  ┌───────────┐                 ┌───────────┐  │
│  │ Core Exec │                 │  Plugins  │  │
│  │ (Process  │                 │ (Native / │  │
│  │  Group)   │                 │ Declarat.)│  │
│  └─────┬─────┘                 └─────┬─────┘  │
│        └──────────────┬──────────────┘        │
│                       ▼                       │
│  ┌─────────────────────────────────────────┐  │
│  │     JobLogBuffer (2 MiB Max, Thread-Safe)│  │
│  │  Simultaneous Subprocess Write & Read   │  │
│  └─────────────────────────────────────────┘  │
└──────────────────────┬────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────┐
│              Persistence & Audit               │
│  JobStore (SQLite / In-Memory Fallback)       │
│  AuditLogger (SHA-256 Chained Hash Log)        │
│  Prometheus Metrics (Gauges & Normalized Path)│
└───────────────────────────────────────────────┘
```

1. **Job Data Model (`internal/jobs/job.go`)**:
   - Manages state machine transitions: `queued` -> `running` -> `completed` | `failed` | `cancelled` | `timed_out`.
   - Immutable terminal state guarantees: once terminal, a job cannot be transitioned or modified (`IsTerminal() == true`).
   - Thread-safe access via `sync.RWMutex` protecting concurrent serialization (`MarshalJSON()`), state queries, and cancellation flags.
2. **Priority Heap Queue (`internal/jobs/queue.go`)**:
   - Implements `container/heap.Interface` across three discrete priority tiers: `High` (level 3), `Normal` (level 2), `Low` (level 1).
   - Monotonic sequence counter (`queueSeq`) provides strict FIFO ordering among jobs within the same priority tier, completely preventing starvation of normal/low priority jobs during burst traffic.
   - Bounded capacity (`QueueCapacity = 1000`) returns `ErrQueueFull` (`429 Too Many Requests`), protecting server heap from unbounded memory exhaustion.
3. **Bounded Worker Pool (`internal/jobs/worker.go`)**:
   - Fixed pool of worker goroutines (default: 4) continuously processing jobs from the queue channel.
   - Synchronous graceful draining on server shutdown (`Engine.Shutdown(ctx)`), allowing active jobs up to the shutdown context deadline to complete.
4. **Concurrency-Safe Live Log Buffer (`internal/jobs/job.go`)**:
   - Concurrency-safe byte buffer supporting simultaneous subprocess write streaming and client HTTP chunked offset reading (`ReadChunk(offset)`).
   - Bounded memory safety (`MaxLogBytesPerJob = 2 MiB`): once log exceeds 2 MiB, excess bytes are discarded, and the `truncated` flag is set to `true`.
   - EOF propagation: setting job completion notifies log readers that no further data will be appended.
5. **Persistent Job History Store (`internal/jobs/store.go`)**:
   - SQLite table `job_history` with indexed queries on `status`, `action`, `actor_id`, and `created_at`.
   - Zero-CGO in-memory fallback store (`MemoryJobStore`) supporting identical filtering semantics when running with `CGO_ENABLED=0`.
   - Background retention pruner running every 10 minutes, pruning records older than `MaxJobAge` (7 days) or exceeding `MaxRetainedJobs` (10,000).

### 5.2 Security Controls & Threat Mitigations

| Threat Vector | Severity | Vulnerability Risk | Implemented Defense Mechanism |
|---|---|---|---|
| **Queue Exhaustion DoS** | **HIGH** | Unauthenticated or malicious clients submitting millions of background jobs to exhaust memory. | Bounded queue capacity (`QueueCapacity = 1000`). When full, `Enqueue` immediately returns `ErrQueueFull`, translating to HTTP `429 Too Many Requests`. |
| **Unauthorized Action Execution** | **CRITICAL** | Callers executing unauthorized system commands or sensitive plugins asynchronously. | **Two-Tier RBAC Authorization**: Caller must possess the `jobs:submit` scope, AND must satisfy the underlying action authorization check (`commands:execute` for command jobs; `plugins:execute` for plugin jobs). Third-party service accounts are additionally checked against their `allowed_actions` whitelist. |
| **Orphan Grandchild Process Leaks** | **HIGH** | Cancelled or timed-out background jobs leaving subprocesses executing indefinitely in the background. | Process group isolation: on cancellation or timeout expiration, the execution context is cancelled, triggering `taskkill /T /F` on Windows and `syscall.Kill(-pid, SIGKILL)` on Unix to terminate all descendants. |
| **Log Buffer Memory Exhaustion** | **HIGH** | A rogue subprocess generating gigabytes of continuous stdout logs, causing an out-of-memory crash. | Hard memory ceiling (`MaxLogBytesPerJob = 2 MiB`). Any bytes beyond 2 MiB are dropped, and `truncated: true` is reported to clients. |
| **Audit Non-Repudiation** | **HIGH** | Inability to prove who submitted or cancelled a background task and its exact parameters. | Cryptographic SHA-256 hash chaining under category `"job"` for every lifecycle event (`job.enqueued`, `job.started`, `job.completed`, `job.failed`, `job.cancelled`). |
| **Prometheus Cardinality DoS** | **HIGH** | Dynamic job IDs in request URLs (`/api/v1/jobs/<id>/logs`) generating unbounded Prometheus metric labels. | Route normalization in `normalizeMetricPath`: dynamic IDs are collapsed to `/api/v1/jobs/:id`, `/api/v1/jobs/:id/logs`, and `/api/v1/jobs/:id/cancel`. |

