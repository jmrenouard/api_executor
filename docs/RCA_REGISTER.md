# API Executor — Root Cause Analysis (RCA) & Technical Transparency Register (`RCA_REGISTER.md`)

This living governance register records all errors encountered, technical dead-ends, current approximations, and unimplemented roadmap ideas on the **API Executor (`go-admin-tool`)** project in accordance with [`AGENTS.md`](../AGENTS.md).

---

## 1. Errors & Bugs Encountered (`RCA-XXX`)

### `RCA-001` — Bundling Multiple Distinct Features into a Monolithic Issue #2 ("Kitchen-Sink / Papa-Maman" Anti-Pattern)
- **Date**: `2026-10-25`
- **Observed Symptom**: Eight distinct requests were initially bundled into Issue #2.
- **Root Cause Analysis**: Lack of an explicit 1-item-per-Issue/Branch/PR/Merge rule in `AGENTS.md`.
- **Applied Change / Fix**: Codified the Strict Atomicity Rule in `AGENTS.md` and `.agents/rules/atomic-workflow.md` and decomposed Issue #2 into atomic Issues `#2` through `#11`.
- **Result**: Enforced across PR #12 and all subsequent atomic PRs.

### `RCA-002` — Grandchild Process Leak on Command Timeout and `CGO_ENABLED=0` SQLite Failure
- **Date**: `2026-10-25`
- **Observed Symptom**:
  1. Standard `exec.CommandContext` only killed the immediate child process on timeout, hanging `cmd.CombinedOutput()` when a grandchild kept stdout/stderr open.
  2. `github.com/mattn/go-sqlite3` failed on `db.Ping()` when running tests or builds with `CGO_ENABLED=0`.
- **Root Cause Analysis**:
  1. Go's default `CommandContext` does not place child processes into a dedicated process group or set `WaitDelay`.
  2. `go-sqlite3` is a CGO wrapper around C SQLite.
- **Applied Change / Fix**:
  1. Added `configureCommandProcessGroup` (`internal/core/executor_unix.go`, `internal/core/executor_windows.go`) and `WaitDelay = 200ms` in `internal/core/executor.go`.
  2. Added transparent thread-safe in-memory fallback in `internal/database/db.go` when `CGO_ENABLED=0` is detected.
- **Result & Non-Regression Test**: Verified by `TestExecuteCommandGrandchildProcessGroupTimeout` and `TestDatabaseRecordActionAndValidation`.

---

## 2. Technical Dead-Ends & Abandoned Leads (`IMP-XXX`)

### `IMP-001` — Monolithic Catch-All Pull Requests
- **Context**: Delivering multiple unrelated features in a single PR.
- **Reason for Abandonment**: Violates atomic engineering governance (`1 item = 1 Issue = 1 Branch = 1 PR = 1 Merge`).

### `IMP-002` — Unbounded Dynamic Action Labels in Prometheus
- **Context**: Using raw caller-supplied `name` values directly as Prometheus `action` labels when `Command not found` occurs.
- **Reason for Abandonment**: Enables Prometheus cardinality explosion DoS; replaced with `normalizeActionLabel` capped at `MaxDynamicActionLabels = 64` and falling back to `"unknown"`.

---

## 3. Current Approximations & Simplifying Assumptions (`APP-XXX`)

| ID | Module | Approximation / Assumption | Impact | Condition for Removal |
|---|---|---|---|---|
| `APP-001` | `internal/database` | SQLite local file storage (`history.db`) with pure-Go in-memory fallback when `CGO_ENABLED=0`. | Single-node persistence; in-memory mode resets on process restart. | Enable CGO in container builds or add pure-Go SQLite / PostgreSQL driver. |

---

## 4. Unimplemented Ideas & Future Roadmap (`IDEA-XXX`)

| ID | Priority | Target Module | Description |
|---|---|---|---|
| `IDEA-001` | `P2` | `internal/auth` | External OIDC / OAuth2 identity provider federation. |
| `IDEA-002` | `P2` | `internal/core/tls` | Automatic ACME / Let's Encrypt certificate provisioning. |
| `IDEA-003` | `P3` | `internal/audit` | Remote syslog / OpenTelemetry OTLP sink for audit events. |
