# API Executor — Root Cause Analysis (RCA) & Technical Transparency Register (`RCA_REGISTER.md`)

This living governance register records all errors encountered, technical dead-ends, current approximations, and unimplemented roadmap ideas on the **API Executor (`go-admin-tool`)** project in accordance with [`AGENTS.md`](../AGENTS.md).

---

## 1. Errors & Bugs Encountered (`RCA-XXX`)

### `RCA-001` — Bundling Multiple Distinct Features into a Monolithic Issue #2 ("Kitchen-Sink / Papa-Maman" Anti-Pattern)
- **Date**: `2026-10-25`
- **Applied Change / Fix**: Codified the Strict Atomicity Rule in `AGENTS.md` and `.agents/rules/atomic-workflow.md` and decomposed Issue #2 into atomic Issues `#2` through `#11`.

### `RCA-002` — Grandchild Process Leak on Command Timeout and `CGO_ENABLED=0` SQLite Failure
- **Date**: `2026-10-25`
- **Applied Change / Fix**: Process-group kill (`Setpgid` on Unix, `WaitDelay` on Windows/Unix) and pure-Go in-memory fallback in `internal/database/db.go`.

### `RCA-003` — Static `tls.LoadX509KeyPair` Prevented Zero-Downtime Certificate Renewal
- **Date**: `2026-10-25`
- **Applied Change / Fix**: Dynamic `CertManager.GetCertificate` callback protected by `sync.RWMutex` in `internal/core/tls.go`.

### `RCA-004` — RedHat UBI9 Minimal Base Missing `ps` and `ss` Utilities by Default
- **Date**: `2026-10-25`
- **Applied Change / Fix**: Installed `procps-ng` and `iproute` in `docker/Dockerfile.redhat`.

### `RCA-005` — World-Readable `0666` Log File Permissions and Unverifiable Audit Records
- **Date**: `2026-10-25`
- **Observed Symptom**: `internal/core/logger.go` previously opened log files with `0666`, and `action_history` had no cryptographic tamper detection.
- **Root Cause Analysis**: Permissive default file mode in `os.OpenFile` and lack of hash chaining between sequential operational records.
- **Applied Change / Fix**: Tightened log file permissions to `0600` in `internal/core/logger.go` and implemented SHA-256 hash chaining (`prev_hash` -> `entry_hash` from `GENESIS`) in `internal/audit/audit.go`.
- **Result & Non-Regression Test**: Verified by `TestAuditLoggerHashChainAndQuery` and `TestAuditLogsVerifyAndSystemLogsEndpoints`.

### `RCA-006` — Missing Principal Authentication and Admin Role Enforcement on Service Account Rotation and User Mutation Endpoints
- **Date**: `2026-10-26`
- **Observed Symptom**: During review of `internal/api/auth_handlers.go` for Issue #7, `AuthServiceAccountRotateHandler` did not invoke `env.resolvePrincipal(r)`, and `PATCH`/`DELETE` on `/api/v1/auth/users` and `POST`/`DELETE` on `/api/v1/auth/service-accounts` did not enforce `p.Role == auth.RoleAdmin`.
- **Root Cause Analysis**: Only `POST /api/v1/auth/users` initially checked `p.Role != auth.RoleAdmin`, leaving adjacent administrative mutation handlers open to authenticated non-admin operators or unauthenticated callers when `RequireAuth=true`.
- **Applied Change / Fix**: Enforced `env.resolvePrincipal(r)` and `p.Role == auth.RoleAdmin` across all administrative user and service account mutation handlers in `internal/api/auth_handlers.go`.
- **Result & Non-Regression Test**: Verified by `TestAuthEndpointsAndServiceAccountCommandScoping` (steps 6 & 7 asserting `401 Unauthorized` and `403 Forbidden`).

### `RCA-007` — Relative `./web/static` Path Returned 404 When Running Router Tests Inside `internal/api`
- **Date**: `2026-10-26`
- **Observed Symptom**: `http.FileServer(http.Dir("./web/static"))` in `internal/api/router.go` assumed the process working directory was always the repository root, causing `GET /` inside package-level tests (`internal/api`) to fail to locate `web/static/index.html`.
- **Root Cause Analysis**: `go test ./...` executes each package test binary with its working directory set to the package folder (`internal/api`), where `./web/static` does not exist.
- **Applied Change / Fix**: Added `resolveStaticDir()` in `internal/api/router.go` to probe `./web/static` and `../../web/static`.
- **Result & Non-Regression Test**: Verified by `TestWebAdministrationConsoleServed` in `internal/api/web_console_test.go`.

---

## 2. Technical Dead-Ends & Abandoned Leads (`IMP-XXX`)

### `IMP-001` — Monolithic Catch-All Pull Requests
- **Reason for Abandonment**: Violates atomic engineering governance (`1 item = 1 Issue = 1 Branch = 1 PR = 1 Merge`).

### `IMP-002` — Unbounded Dynamic Action Labels in Prometheus
- **Reason for Abandonment**: Replaced with `normalizeActionLabel` capped at `MaxDynamicActionLabels = 64`.

### `IMP-003` — Using `systemctl` in Containerized OS Preset Tasks
- **Reason for Abandonment**: Replaced with container-safe inspection commands (`dpkg-query`, `apt-get -s upgrade`, `rpm -qa`, `dnf repolist`, `ps -ef`, `ss -tuln`).

### `IMP-004` — Storing Plaintext Personal Access Tokens or Service Account Keys
- **Reason for Abandonment**: Plaintext token storage would expose all remote credentials if `auth_store.json` were leaked. Replaced with one-time secret return (`gat_pat_...`, `gat_svc_...`) and SHA-256 hashed storage compared via `crypto/subtle.ConstantTimeCompare`.

### `IMP-005` — Unsanitized `{{param}}` Shell Interpolation or Unrestricted SQL Execution in Plugins
- **Reason for Abandonment**: Passing declarative plugin parameters to `sh -c` or allowing arbitrary SQL statements (`DROP`, `DELETE`, `PRAGMA`, `ATTACH`, `--`, `;`) in `db-exposure` would enable remote code execution or data tampering. Replaced with `exec.CommandContext` direct argv substitution validated against `^[a-zA-Z0-9._:/-]+$` (or custom regex) and `ValidateReadOnlySQL` enforcing single-statement `SELECT` with `LIMIT` bounding.

---

## 3. Current Approximations & Simplifying Assumptions (`APP-XXX`)

| ID | Module | Approximation / Assumption | Impact | Condition for Removal |
|---|---|---|---|---|
| `APP-001` | `internal/database` | SQLite local file storage (`history.db`) with pure-Go in-memory fallback when `CGO_ENABLED=0`. | Single-node persistence; in-memory mode resets on process restart. | Enable CGO in container builds or add pure-Go SQLite / PostgreSQL driver. |
| `APP-002` | `internal/core/tls` | Self-signed ECDSA P-256 certificate generated by default when no external CA-signed cert is mounted. | Browsers and `curl` require `-k` or downloading `/api/v1/tls/certificate` into trust store. | Mount enterprise PKI certificate or enable ACME (`IDEA-002`). |
| `APP-003` | `internal/audit` | Sliding window in-memory audit cache (`MaxMemoryLog = 1000`) alongside optional JSONL file / SQLite table. | In-memory query window is bounded to prevent heap growth. | Query persistent SQLite/SIEM store for historical archives beyond 1,000 events. |
| `APP-004` | `internal/auth` | Pure-Go iterated SHA-256 (10,000 rounds + 128-bit random salt) password hashing and `RequireAuth: false` default unless configured. | Avoids external `golang.org/x/crypto` dependency while preserving backward compatibility for unauthenticated local configs. | Set `auth.require_auth: true` in production and optionally migrate to Argon2id (`IDEA-001`). |
| `APP-005` | `internal/plugins` | `db-exposure` simulates `SELECT` projection over `action_history` when running in pure-Go in-memory fallback mode (`db.Conn() == nil`). | Ensures identical read-only SQL validation and deterministic test/runtime behavior even when compiled with `CGO_ENABLED=0`. | Compile with CGO SQLite or connect to an external SQL engine. |
| `APP-006` | `internal/mcp` | Synchronous HTTP JSON-RPC 2.0 transport (`POST /api/v1/mcp`) with bounded in-memory ring buffer (`MaxTraces = 500`) + SQLite/JSONL persistence. | Request/response RPC calls complete in a single HTTP round-trip without requiring long-lived SSE state. | Add Streamable HTTP / SSE server-initiated notification transport if bidirectional MCP server-to-client sampling is required (`IDEA-005`). |
| `APP-007` | `web/static` | Single-file zero-build Web Administration Console (`web/static/index.html`) using Alpine.js and Tailwind CSS via CDN. | Requires no Node.js/npm build step; air-gapped deployments without internet access need vendored static CSS/JS assets. | Vendor Alpine.js and compiled CSS into `web/static/vendor/` for offline air-gapped environments. |

---

## 4. Unimplemented Ideas & Future Roadmap (`IDEA-XXX`)

| ID | Priority | Target Module | Description |
|---|---|---|---|
| `IDEA-001` | `P2` | `internal/auth` | External OIDC / OAuth2 identity provider federation and Argon2id password KDF. |
| `IDEA-002` | `P2` | `internal/core/tls` | Automatic ACME / Let's Encrypt certificate provisioning. |
| `IDEA-003` | `P3` | `internal/audit` | Remote syslog / OpenTelemetry OTLP sink for audit events. |
| `IDEA-004` | `P3` | `internal/plugins` | Out-of-process gRPC / WebAssembly (WASI) plugin sandboxing for untrusted third-party modules. |
| `IDEA-005` | `P3` | `internal/mcp` | Streamable HTTP / SSE notification stream and stdio CLI bridge for local desktop MCP hosts. |
