# API Executor — Root Cause Analysis (RCA) & Technical Transparency Register (`RCA_REGISTER.md`)

This living governance register records all errors encountered, technical dead-ends, current approximations, and unimplemented roadmap ideas on the **API Executor (`go-admin-tool`)** project in accordance with [`AGENTS.md`](../AGENTS.md).

---

## 1. Errors & Bugs Encountered (`RCA-XXX`)

### `RCA-001` — Bundling Multiple Distinct Features into a Monolithic Issue #2 ("Kitchen-Sink / Papa-Maman" Anti-Pattern)
- **Date**: `2026-10-25`
- **Observed Symptom**: Multiple unrelated engineering domains (metrics, timeouts, TLS, OS presets, RBAC, plugins, MCP, Web UI, and branding) were initially grouped into a single catch-all issue.
- **Root Cause Analysis**: Lack of an explicit repository rule enforcing `1 Item = 1 Issue = 1 Branch = 1 PR = 1 Merge`.
- **Applied Change / Fix**: Codified the Strict Atomicity Rule in `AGENTS.md` and `.agents/rules/atomic-workflow.md` and decomposed the backlog into atomic Issues `#2` through `#11`.
- **Result & Non-Regression Test**: Verified via isolated atomic branches and PRs `#12` through `#21`.

### `RCA-002` — Grandchild Process Leak on Command Timeout and `CGO_ENABLED=0` SQLite Failure
- **Date**: `2026-10-25`
- **Observed Symptom**: `exec.CommandContext` only sent `SIGKILL` to the direct child process on timeout, leaving spawned background grandchild processes alive, and `go-sqlite3` failed at runtime when compiled with `CGO_ENABLED=0`.
- **Root Cause Analysis**: Default `os/exec` behavior kills only the process leader PID unless a process group (`Setpgid`) and `WaitDelay` are configured; `mattn/go-sqlite3` requires CGO.
- **Applied Change / Fix**: Process-group kill (`Setpgid` on Unix, `WaitDelay` on Windows/Unix) in `internal/core/executor.go` and pure-Go in-memory fallback in `internal/database/db.go`.
- **Result & Non-Regression Test**: Verified by `TestExecuteCommandGrandchildProcessGroupTimeout` and `TestDatabaseRecordActionAndValidation`.

### `RCA-003` — Static `tls.LoadX509KeyPair` Prevented Zero-Downtime Certificate Renewal
- **Date**: `2026-10-25`
- **Observed Symptom**: Standard `http.Server.ListenAndServeTLS(certFile, keyFile)` loads the certificate once at startup and ignores subsequent rotations.
- **Root Cause Analysis**: Static certificate loading in `crypto/tls` does not re-read rotated key pairs without a dynamic `GetCertificate` callback.
- **Applied Change / Fix**: Dynamic `CertManager.GetCertificate` callback protected by `sync.RWMutex` in `internal/core/tls.go`.
- **Result & Non-Regression Test**: Verified by `TestCertManagerRotateAndRealHTTPSHandshake` and `TestTLSRenewEndpoint`.

### `RCA-004` — RedHat UBI9 Minimal Base Missing `ps` and `ss` Utilities by Default
- **Date**: `2026-10-25`
- **Observed Symptom**: Containerized RedHat preset tasks (`redhat-process-tree`, `redhat-listening-sockets`) failed if `procps-ng` and `iproute` were not installed in the UBI9 image.
- **Root Cause Analysis**: RedHat UBI9 minimal base image omits `ps` (`procps-ng`) and `ss` (`iproute`) by default.
- **Applied Change / Fix**: Installed `procps-ng` and `iproute` in `docker/Dockerfile.redhat`.
- **Result & Non-Regression Test**: Verified by `TestOSPresetCatalogsUbuntuAndRedHat` and `docker/Dockerfile.redhat`.

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

### `RCA-010` — README cURL Example Mismatches (`redhat-rpm-packages`, `runtime-stats`) and Root `Dockerfile` Non-Root Write Permission Failure
- **Date**: `2026-10-26`
- **Observed Symptom**:
  1. `README.md` line 124 invoked `{"name": "redhat-rpm-packages"}` (actual preset name: `"redhat-rpm-qa"`) and line 205 invoked `{"plugin_id": "sys-diagnostics", "action": "runtime-stats"}` (which returned `404` because `sys-diagnostics` only matched `"runtime_stats"`).
  2. Root `Dockerfile` ran as `USER appuser` without `chown -R appuser:appgroup /app`, `/app/certs`, or `COPY --from=builder /app/plugins ./plugins`.
- **Root Cause Analysis**:
  - `README.md` examples were written without normalizing hyphenated action names in `sys_diagnostics.go` or checking the exact preset name in `internal/core/os_presets.go`.
  - Root `Dockerfile` was not updated when default HTTPS certificate auto-generation (`./certs`) and declarative plugins (`./plugins`) were introduced in Issues #4 and #8.
- **Applied Change / Fix**:
  - Normalized hyphen/underscore action names in `internal/plugins/sys_diagnostics.go`, updated `README.md` to use `redhat-rpm-qa`, and updated `Dockerfile`, `docker/Dockerfile.ubuntu`, and `docker/Dockerfile.redhat` to copy `plugins/` and grant `appuser:appgroup` ownership of `/app` and `/app/certs`.
- **Result & Non-Regression Test**: Verified by `TestSVGAssetsAreValidXMLAndREADMEIncludesBranding` (`docs/branding_test.go`) and `TestSystemDiagnosticsPlugin` (`internal/plugins/plugins_test.go`).

### `RCA-011` — Unclosed File Handle in `core.Logger` on Windows and Untestable Monolithic `main()` in `cmd/server/main.go`
- **Date**: `2026-10-26`
- **Observed Symptom**:
  1. Writing unit tests for `core.NewLogger` with a file-backed `LoggingConfig.Path` inside `t.TempDir()` failed on Windows during test cleanup with `The process cannot access the file because it is being used by another process`.
  2. `cmd/server` had `0.0%` unit test coverage and hardcoded `"config.yaml"` inside `func main()`.
- **Root Cause Analysis**:
  - `core.NewLogger` opened the log file via `os.OpenFile` and passed it to `log.New(output, "", 0)` without exposing a `Close() error` method on `*core.Logger` to release the OS file descriptor.
  - All server bootstrap wiring in `cmd/server/main.go` was coupled directly to `log.Fatalf` / `os.Exit(1)` and `ListenAndServe` inside `main()`.
- **Applied Change / Fix**:
  - Added `(*core.Logger).Close() error` in `internal/core/logger.go` to safely close file-backed log writers.
  - Extracted `resolveConfigPath()`, `initializeServerEnv(configPath string)`, and `buildHTTPServer(env, router)` in `cmd/server/main.go` and added unit tests in `cmd/server/main_test.go`.
- **Result & Non-Regression Test**: Verified by `TestLoggerLevelsStructuredOutputAndRingBuffer` (`internal/core/logger_test.go`) and `TestResolveConfigPathAndInitializeServerEnv` (`cmd/server/main_test.go`).

### `RCA-012` — Declarative Plugin Registration Banner Key Mismatch (`d.plugin.id` vs `d.id`) and Missing Favicon Console Error in Web Administration Console
- **Date**: `2026-10-26`
- **Observed Symptom**:
  1. Clicking "Register Declarative Plugin" in Tab 5 of `web/static/index.html` displayed `"Registered declarative plugin "` without the newly registered plugin ID (`custom-ops`), and mutating actions across Tabs 2–5 did not immediately refresh the Tab 7 SHA-256 Audit badge count.
  2. Navigating to the Web Administration Console in MCP Playwright logged a browser console error: `Failed to load resource: the server responded with a status of 404 (Not Found) @ /favicon.ico`.
- **Root Cause Analysis**:
  - `POST /api/v1/plugins/declarative` (`PluginsHandler` in `internal/api/plugin_handlers.go`) serializes `plugins.PluginInfo` directly at the root JSON object (`{"id": "custom-ops", ...}`), whereas `registerDeclarativePlugin()` in `web/static/index.html` checked `d.plugin ? d.plugin.id : ''`.
  - `web/static/index.html` did not declare a `<link rel="icon">` tag in `<head>`, causing Chromium to request `/favicon.ico`.
- **Applied Change / Fix**:
  - Updated `registerDeclarativePlugin()` in `web/static/index.html` to read `const pluginID = d.id || (d.plugin && d.plugin.id) || ''`, added `this.loadAuditAndLogs()` refresh calls after preset, user, PAT, service-account, plugin, SQL, and TLS mutations, and added an inline SVG data-URI favicon `<link rel="icon" type="image/svg+xml" ...>`.
- **Result & Non-Regression Test**: Verified interactively via MCP Playwright across all 8 tabs (`0` console errors) and by `TestWebAdministrationConsoleServed` and `TestWebAdministrationConsoleEndToEndWorkflows` in `internal/api/web_console_test.go`.

### `RCA-013` — Unaudited RBAC Credential Deletions/Rotations, Unawaited Async Refreshes & Missing `401`/`403` Banner Feedback in Web Console, and `cmd/server` Coverage Below 80%
- **Date**: `2026-10-26`
- **Observed Symptom**:
  1. `PATCH`/`DELETE /api/v1/auth/users`, `DELETE /api/v1/auth/tokens`, `DELETE /api/v1/auth/service-accounts`, and `POST /api/v1/auth/service-accounts/rotate` succeeded without recording SHA-256 audit events (`user.update`, `user.delete`, `token.revoke`, `service_account.delete`, `service_account.rotate`) in `AuditLogger`.
  2. In `web/static/index.html`, `deleteUser()`, `revokeToken()`, and `deleteServiceAccount()` discarded HTTP responses without updating `statusBanner` or calling `loadAuditAndLogs()`; `loadPrincipal()` left stale `principal` data displayed when `GET /api/v1/auth/me` returned `401 Unauthorized`; `executePlugin()` and `runDBQuery()` did not update `statusBanner`; and `loadAuthData()`/`loadAuditAndLogs()` were invoked without `await` inside async mutation methods.
  3. `cmd/server` statement coverage was `66.0%` (below the 80% minimum threshold) because listener dispatch remained inside `func main()`.
- **Root Cause Analysis**:
  - `internal/api/auth_handlers.go` wired `env.AuditLogger.Record` on `POST` creation handlers (`login`, `user.create`, `token.create`, `service_account.create`) but omitted `PATCH`, `DELETE`, and key rotation handlers.
  - `web/static/index.html` omitted `!r.ok` handling and `await` on secondary refresh promises in its Alpine.js controller methods.
  - `cmd/server/main.go` coupled `buildHTTPServer` and `ListenAndServe`/`ListenAndServeTLS` directly to `main()`.
- **Applied Change / Fix**:
  - Added `env.AuditLogger.Record` calls for `user.update`, `user.delete`, `token.revoke`, `service_account.delete`, and `service_account.rotate` in `internal/api/auth_handlers.go`.
  - Updated `web/static/index.html` to reset `this.principal = null` on `401`, surface `statusBanner` feedback across all RBAC mutations and `401`/`403` responses, and `await` `loadAuthData()`, `loadMCPTraces()`, and `loadAuditAndLogs()`.
  - Extracted `runServer(configPath, serveFn)` in `cmd/server/main.go` and expanded `cmd/server/main_test.go` (`66.0%` -> `82.4%` statement coverage).
- **Result & Non-Regression Test**: Verified by `TestAuthTokensPrivilegeEscalationPrevention` (`internal/api/auth_test.go`), `TestWebAdministrationConsoleServed` (`internal/api/web_console_test.go`), `TestResolveConfigPathAndInitializeServerEnv` (`cmd/server/main_test.go`), and live MCP Playwright E2E verification across all 8 tabs.

### `RCA-014` — Windows Declarative Subprocess Execution Failure for `echo` Builtin
- **Date**: `2026-10-27`
- **Observed Symptom**: When declarative command actions configured with `command: "echo"` were invoked on Windows, `exec.CommandContext` failed with `exec: "echo": executable file not found in %PATH%`, returning status `error` (HTTP 400).
- **Root Cause Analysis**: On Windows, `echo` is a built-in command of `cmd.exe` rather than an independent binary executable in `%PATH%`. Direct argv subprocess execution (`exec.CommandContext` without a shell) requires invoking `cmd` with `["/C", "echo", ...]` on Windows.
- **Applied Change / Fix**: Implemented a cross-platform helper `crossPlatformEcho()` in test harnesses checking `runtime.GOOS == "windows"` and using `cmd /C echo` on Windows while using `echo` on Linux/POSIX, mirroring `DefaultDeclarativeOpsPlugin()`.
- **Result & Non-Regression Test**: Verified by `TestTier1_F4_DeclarativePlugin_DynamicRegistrationAndExecution`, `TestTier3_Combination_APIFilterAndExecuteWorkflow`, and `TestTier4_Scenario_DynamicOpsRemediationAndAuditLifecycle` passing 100% on both Windows and Linux.

### `RCA-015` — InsecureSkipVerify Omission in SSL Redirect Check and Test Registry Assumption
- **Date**: `2026-10-27`
- **Observed Symptom**:
  1. `http-latency-probe` action `ssl_redirect_check` failed in unit tests when probing local test HTTPS servers with `x509: certificate signed by unknown authority`.
  2. Registering all 24 native plugins by default in `NewRegistry()` caused legacy tests assuming an initially empty or 2-plugin registry to fail.
- **Root Cause Analysis**:
  1. `ssl_redirect_check` used `http.Client{CheckRedirect: ...}` without configuring `InsecureSkipVerify: true` on `http.Transport{TLSClientConfig: ...}` for testing and arbitrary internal TLS environments, causing untrusted self-signed certificate handshakes to fail immediately during redirect evaluation.
  2. Legacy unit tests in `internal/plugins/plugins_test.go` instantiated `NewRegistry()` and asserted exact counts of registered plugins (`len(reg.List()) == 2`) based on the previous baseline of only `sys-diagnostics` and `db-exposure`.
- **Applied Change / Fix**:
  1. Added `Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}` to the HTTP redirect client in `internal/plugins/native_crypto.go`.
  2. Added `NewEmptyRegistry()` in `internal/plugins/plugin.go` for isolated test scenarios and updated legacy assertions in `internal/plugins/plugins_test.go`.
- **Result & Non-Regression Test**: Verified by `TestAll24NativePluginsActions` and `TestRegistryEmptyAndDuplicate` in `internal/plugins/plugins_test.go` (100% test pass rate across 145 tests, 85.9% plugin coverage).

### `RCA-016` — Fail-Open on Unrecognized Plugin Types, Omitted Metadata on Declarative Registration, and Unhandled Errors in Native HTTP/JWT Plugins
- **Date**: `2026-10-27`
- **Observed Symptom**:
  1. `Registry.ListFiltered` with an unrecognized or non-existent type query (e.g. `?type=bogus-type`) returned all 25 registered plugins instead of an empty slice.
  2. `POST /api/v1/plugins/declarative` returned `PluginInfo` with empty `type: ""` and `category: ""` in JSON response.
  3. `http-latency-probe` actions `inspect_headers` and `ssl_redirect_check` triggered a runtime panic (`nil pointer dereference`) when supplied with a malformed URL like `"://invalid-url"`.
  4. `jwt-token-inspector` discarded `json.Unmarshal` errors with `_`, causing non-JSON payloads (`"eyJhbGciOiJIUzI1NiJ9.YQ.sig"` where payload is `"a"`) and empty segments (`".."`) to return `status: "ok"` and `valid: true`.
- **Root Cause Analysis**:
  1. `ListFiltered` used cascading positive `if` checks for `"native"`, `"advanced"`, and `"declarative"` without a default drop case, allowing any unknown type string to fall through without hitting `continue`.
  2. `PluginDeclarativeRegisterHandler` constructed `PluginInfo` without setting the `Type` and `Category` fields introduced during Milestone 1 metadata enrichment.
  3. `inspect_headers` and `ssl_redirect_check` discarded the error from `http.NewRequestWithContext(ctx, method, targetURL, nil)` using `_`, passing `req == nil` to `client.Do(req)`.
  4. `jwt-token-inspector` discarded errors from `json.Unmarshal(payloadBytes, &claims)`, leaving `claims` as `nil` so `claims["exp"]` was absent, `isExpired` remained `false`, and `valid` evaluated to `!isExpired` (`true`); also omitted `nbf` validation.
- **Applied Change / Fix**:
  1. Replaced cascading `if` checks in `internal/plugins/plugin.go` with `switch pluginType` featuring `default: continue`.
  2. Populated `Type: declPlugin.Type()` and `Category: declPlugin.Category()` in `internal/api/plugin_handlers.go`.
  3. Added error checking on `http.NewRequestWithContext` returning `Status: "error"` in `internal/plugins/native_crypto.go`.
  4. Added explicit `json.Unmarshal` error handling and non-nil map checks in `internal/plugins/native_crypto.go`, and evaluated `nbf` constraint.
- **Result & Non-Regression Test**:
  - Verified by `TestRegistry_ListFiltered_InvalidTypeDropsAll`, `TestHTTPLatencyProbe_MalformedURLs`, and `TestJWTTokenInspector_ValidationAndMalformedPayloads` in `internal/plugins/plugins_test.go`, and `TestPluginDeclarativeRegisterHandlerMetadataCompleteness` in `internal/api/plugin_handlers_test.go`; 199 unit tests and 65 E2E tests passing 100% (`internal/plugins` 86.3%, `internal/api` 89.9%).

### `RCA-017` — Compilation Failure on `a.Command` When Asserting Public `PluginAction` Metadata
- **Date**: `2026-10-27`
- **Observed Symptom**:
  - `plugins_test.go: a.Command undefined (type PluginAction has no field or method Command)` occurred while verifying loaded declarative action fields.
- **Root Cause Analysis**:
  - `PluginAction` in `internal/plugins/plugin.go` is the public API contract exposed by plugins and purposefully exposes only `Name`, `Description`, `Timeout`, and `Parameters`. Direct process execution mechanics (`Command`, `Args`) are encapsulated within `DeclarativeActionSpec` in `internal/plugins/declarative.go` by design to prevent leaking underlying OS binary invocation paths.
- **Applied Change / Fix**:
  - Updated `TestLoadDeclarativeDirectory_AllDeclarativePlugins` in `internal/plugins/plugins_test.go` to validate non-empty `a.Name` and `a.Description`.
- **Result & Non-Regression Test**:
  - Verified by `TestLoadDeclarativeDirectory_AllDeclarativePlugins` passing 100% across all 141 declarative plugins (140 new + 1 baseline).

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
| `APP-008` | `tests/e2e` | Synthetic domain catalog fixtures pre-populated in test harness to guarantee 300+ plugins across 10 domains. | Allows full catalog scale and multi-domain operations testing before domain pack manifests are integrated into `plugins/`. | Partially fulfilled by Milestone 2 (140 declarative plugins added across 5 domains); fully replaced once Milestone 3 adds remaining 140 declarative plugins. |


---

## 4. Unimplemented Ideas & Future Roadmap (`IDEA-XXX`)

| ID | Priority | Target Module | Description |
|---|---|---|---|
| `IDEA-001` | `P2` | `internal/auth` | External OIDC / OAuth2 identity provider federation and Argon2id password KDF. |
| `IDEA-002` | `P2` | `internal/core/tls` | Automatic ACME / Let's Encrypt certificate provisioning. |
| `IDEA-003` | `P3` | `internal/audit` | Remote syslog / OpenTelemetry OTLP sink for audit events. |
| `IDEA-004` | `P3` | `internal/plugins` | Out-of-process gRPC / WebAssembly (WASI) plugin sandboxing for untrusted third-party modules. |
| `IDEA-005` | `P3` | `internal/mcp` | Streamable HTTP / SSE notification stream and stdio CLI bridge for local desktop MCP hosts. |
