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

### `RCA-008` — RBAC Privilege Escalation on `/api/v1/auth/tokens`, Service Account Bypass via MCP `tools/call`, and Unauthenticated TLS/Preset Mutations
- **Date**: `2026-10-26`
- **Observed Symptom**:
  1. Authenticated non-admin principals (`operator`, `viewer`, or `service_account`) could call `POST /api/v1/auth/tokens` with `{"user_id": "admin"}` and receive a valid `admin` Personal Access Token (`scopes: ["*"]`), or call `DELETE /api/v1/auth/tokens` to revoke admin tokens.
  2. A third-party `service_account` restricted to specific `allowed_actions` (e.g. `["mcp-test-cmd"]`) could bypass its command/plugin allowlist by invoking `POST /api/v1/mcp` (`tools/call` -> `execute_command` / `execute_plugin`).
  3. `POST /api/v1/tls/renew` and `POST /api/v1/presets/activate` executed without calling `resolvePrincipal` or recording an event in `AuditLogger`.
- **Root Cause Analysis**:
  - `AuthTokensHandler` validated the caller's token via `resolvePrincipal` but did not verify that non-admin callers could only issue/revoke tokens for their own user account and within their own granted scopes.
  - `MCPHandler` authorized `mcp:access` with an empty `targetAction` (`""`), and `MCPServer.HandleJSONRPC` did not receive a per-tool `ToolAuthorizer` callback to check `commands:execute` / `plugins:execute` against the caller's `AllowedActions`.
  - `TLSRenewHandler` and `ActivatePresetsHandler` were implemented before `AuthManager` and `AuditLogger` were wired into `APIEnv`.
- **Applied Change / Fix**:
  - Enforced role, user-ownership, and scope-subset checks in `AuthTokensHandler` (`internal/api/auth_handlers.go`).
  - Added `HandleJSONRPCWithAuthorizer` and `ToolAuthorizer` enforcement across `execute_command`, `execute_plugin`, `db_query`, and `db_list_tables` in `internal/mcp/server.go` and `internal/api/mcp_handlers.go`.
  - Added `resolvePrincipal`, role/scope checks, and `AuditLogger.Record` calls to `TLSRenewHandler` and `ActivatePresetsHandler`.
- **Result & Non-Regression Test**: Verified by `TestAuthTokensPrivilegeEscalationPrevention`, `TestMCPEndpointsAndTraceInspection` (step 6), `TestTLSRenewEndpoint`, and `TestPresetsEndpointsListAndActivate`.

### `RCA-009` — Web Console Preset Catalog JSON Key Mismatch (`cat.tasks` vs `cat.commands`, `os_families` vs `families`) and Missing Declarative Plugin / Log Panels
- **Date**: `2026-10-26`
- **Observed Symptom**:
  1. In Tab 2 of `web/static/index.html`, OS preset catalogs rendered `0 tasks` and zero command cards despite `GET /api/v1/presets` returning 10 Ubuntu and 10 RedHat commands.
  2. Clicking "Activate Ubuntu Presets" sent `{"os_families": ["ubuntu"]}` to `POST /api/v1/presets/activate`, which only bound `json:"families"`, causing `req.Families` to be empty and activating all 20 OS presets instead of only 10 Ubuntu presets.
  3. Tab 5 and Tab 7 did not expose UI panels for `POST /api/v1/plugins/declarative`, `GET /api/v1/logs`, or `GET /api/v1/history`.
- **Root Cause Analysis**:
  - `core.OSPresetCatalog` serializes its command slice as `json:"commands"`, while `web/static/index.html` bound `cat.tasks`.
  - `ActivatePresetsHandler` defined `Families []string` with `json:"families"` while the frontend sent `os_families`.
- **Applied Change / Fix**:
  - Updated `web/static/index.html` to iterate `(cat.commands || cat.tasks || [])`, pass `cat.os_family` into `runPresetTask`, and wire UI panels for `/api/v1/plugins/declarative`, `/api/v1/logs`, and `/api/v1/history`.
  - Updated `ActivatePresetsHandler` to accept both `families` and `os_families`.
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

### `IMP-006` — External Raster Image Links for Repository Logo and Banner
- **Reason for Abandonment**: External image URLs break in offline/air-gapped environments and cannot be verified in unit tests. Replaced with repository-local pure SVG assets (`docs/assets/logo.svg`, `docs/assets/header-banner.svg`) validated via `encoding/xml` in `docs/branding_test.go`.

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
