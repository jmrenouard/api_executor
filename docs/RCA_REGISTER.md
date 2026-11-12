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

### `RCA-018` — Relative Path Parameters in DevOps Manifests Allowed Unrooted Path Traversal Sequences
- **Date**: `2026-10-27`
- **Observed Symptom**: During adversarial security testing of the declarative catalog expansion, `TestM2Adversarial_AllParameters_PathTraversalRejection` detected that parameters with relative path regex `^[a-zA-Z0-9._/-]+$` (in `golang-vet-check`, `jsonlint-file`, `yamllint-file`, `shellcheck-script`, and `dockerfile-hadolint`) accepted unrooted path traversal strings (e.g. `../../../../etc/passwd` or `subdir/../../shadow`).
- **Root Cause Analysis**: Regex patterns without an anchored leading root slash allowed relative directory traversing tokens (`../` and `..\`), which caused subprocesses to execute on invalid traversal paths instead of halting early during parameter security validation.
- **Applied Change / Fix**:
  1. Enforced strict path traversal rejection in `internal/plugins/declarative.go` (`strings.Contains(rawVal, "../") || strings.Contains(rawVal, "..\\")`).
### `RCA-019` — Dynamic Form Parameter Synchronization and Type Coercion for Boolean and Integer Inputs in Web Console Tab 5
- **Date**: `2026-10-27`
- **Observed Symptom**: When dynamically generating parameter form fields for actions declaring integer (`int`) or boolean (`bool`) parameters, standard HTML `<input>` elements bind values as strings (e.g. `"10"` or `"true"`), causing strict JSON parameter validators in declarative plugin runners to reject requests or fail type regex assertions.
- **Root Cause Analysis**: HTML input elements inherently treat values as strings unless explicit numerical/boolean parsing and reactive two-way synchronization between the form state (`actionParamValues`) and the JSON payload (`pluginParamsJSON`) are performed before submission.
- **Applied Change / Fix**:
  1. Implemented typed input controls in `web/static/index.html` with explicit `.number` bindings and checkbox boolean states.
  2. Implemented pre-execution type coercion in `executePlugin()` that iterates `currentActionParameters()` and casts numeric/boolean strings to native JavaScript numbers and booleans.
  3. Added bi-directional synchronization helpers (`syncParamsToJSON()` and `syncJSONToParams()`) allowing seamless switching between Dynamic Form and Raw JSON modes.
- **Result & Non-Regression Test**: Verified by `TestWebAdministrationConsole_Tab5_CatalogSearchFilteringPaginationAndForms` in `internal/api/web_console_test.go` and verified end-to-end execution of `sys-diagnostics:runtime_stats` through the Web Console API flow.

### `RCA-020` — Headless Browser Verification and Self-Signed TLS Certificate Policy
- **Date**: `2026-10-27`
- **Observed Symptom**: When running automated headless browser test suites (Playwright MCP) against the API Executor web server on localhost, the default auto-generated self-signed ECDSA certificate causes standard browser engines to abort navigation with security certificate warnings unless `--ignore-certificate-errors` is configured or plain HTTP mode is used.
- **Root Cause Analysis**: Modern Chromium and WebKit security policies block navigation to self-signed TLS endpoints without user confirmation or explicit headless test runner flags.
- **Applied Change / Fix**: Configured dedicated ephemeral test configuration (`server.tls.enabled: false`) on a test port (`8089`) for live Playwright browser validation, keeping production HTTPS defaults intact in `config.yaml`.
- **Result & Non-Regression Test**: 100% verified via Playwright MCP navigating to `http://127.0.0.1:8089/`, validating 306 plugins loaded in Alpine.js, all 10 domain category filters (32 SysAdmin, 30 NetOps, 30 SecOps, 30 ContainerOps, 30 Kubernetes, 31 DataOps, 30 DevOps, 30 SRE, 30 AIOps, 28 WebUtils), keyword search, type toggles, pagination across 31 pages, dynamic parameter form generation, and real API action execution.

### `RCA-021` — Destructive Deletion of Entire `docs/` Directory by `make clean`
- **Date**: `2026-11-01`
- **Observed Symptom**: Executing `make clean` ran `rm -rf ./docs`, completely deleting non-generated living governance registers (`docs/ACTION_LOGBOOK.md`, `docs/RCA_REGISTER.md`), architectural documentation (`docs/SECURITY_AND_ARCHITECTURE_ANALYSIS.md`), and brand SVG assets (`docs/assets/`).
- **Root Cause Analysis (5 Whys)**:
  1. *Why did `make clean` delete governance registers?* Because `clean` invoked `rm -rf ./docs`.
  2. *Why did `clean` invoke `rm -rf ./docs`?* Because Swagger documentation generation (`make swagger`) outputs artifacts into the `docs/` directory (`docs.go`, `swagger.json`, `swagger.yaml`).
  3. *Why was `rm -rf` used on the whole directory?* Early build scripts assumed `docs/` was exclusively generated by `swag init`.
  4. *Why did this become a critical defect?* Subsequent milestones introduced living governance files, architecture docs, and assets directly inside `docs/`.
  5. *Root Cause*: Overbroad directory-level cleanup in Makefile rather than targeted deletion of generated build artifacts.
- **Applied Change / Fix**: Replaced `rm -rf ./docs` in `Makefile` with targeted cleanup of generated swagger artifacts: `rm -f docs/docs.go docs/swagger.json docs/swagger.yaml`.
- **Result & Non-Regression Test**: Verified by `go test -v -cover ./...` (100% pass across 215 tests in 10 packages) and verified `make clean` preserves `docs/` governance registers while removing generated swagger files.

### `RCA-022` — Omission of 22 Compiled Native Go Plugins in Production Server Runtime
- **Date**: `2026-11-01`
- **Observed Symptom**: In `cmd/server/main.go`, the server daemon initialized the plugin registry and only explicitly loaded `DefaultDeclarativeOpsPlugin`, `DatabaseExposurePlugin`, and `SystemDiagnosticsPlugin`, omitting 22 of the 24 compiled native Go plugins from runtime initialization with active database bindings and configured row bounds. Furthermore, initializing with `plugins.NewRegistry()` pre-populated default plugins with `nil` database instances even when `plugins.enabled` was set to `false`.
- **Root Cause Analysis (5 Whys)**:
  1. *Why were 22 native plugins omitted from production server runtime?* Because `cmd/server/main.go` never called `plugins.RegisterDefaultNativePlugins(pluginRegistry, db, config.Plugins.MaxQueryRows)`.
  2. *Why was `RegisterDefaultNativePlugins` not called in `cmd/server/main.go`?* Because early server bootstrapping only wired `db-exposure` and `sys-diagnostics` before the 24 native plugins were compiled across 10 operational domains in Milestone 1.
  3. *Why did `plugins.NewRegistry()` not suffice?* `plugins.NewRegistry()` passes `nil` database reference and a hardcoded limit of `200` rows without dynamic configuration bindings, and would register plugins unconditionally even when `plugins.enabled: false`.
  4. *Why did subsequent re-registration fail?* `Registry.Register` prohibits duplicate IDs to prevent silent overrides, returning `ErrDuplicatePlugin` on re-registration of the other 22 native plugins.
  5. *Root Cause*: Lack of clean initialization via `plugins.NewEmptyRegistry()` followed by explicit guarded invocation of `plugins.RegisterDefaultNativePlugins` inside `cmd/server/main.go`.
- **Applied Change / Fix**:
  1. Updated `cmd/server/main.go` to construct the registry using `plugins.NewEmptyRegistry()`.
  2. Injected all 24 native Go plugins with production database reference `db` and `config.Plugins.MaxQueryRows` via `plugins.RegisterDefaultNativePlugins` when `config.Plugins.Enabled` is true.
  3. Added clean unregistration for `db-exposure` and `sys-diagnostics` when their respective feature flags (`enable_db_exposure`, `enable_sys_diagnostics`) are disabled.
  4. Added telemetry logging for mounted plugin counts and directory loading metrics.
- **Result & Non-Regression Test**: Verified by `TestResolveConfigPathAndInitializeServerEnv` asserting all 24 native plugin IDs in `cmd/server/main_test.go`, `TestInitializeServerEnv_All24NativePluginsMounted` asserting all 10 operational domains, `TestInitializeServerEnv_PluginsDisabled` asserting 0 plugins when disabled, and `TestInitializeServerEnv_FeatureFlagToggles` (100% pass across 4 tests in `cmd/server` with 82.4% coverage; 218 unit + 65 E2E tests passing 100%).

### `RCA-023` — Unbounded HTTP Server Timeouts (Slowloris Vulnerability) and Abrupt Process Termination on OS Signals
- **Date**: `2026-11-01`
- **Observed Symptom**: In `cmd/server/main.go`, `buildHTTPServer` initialized `http.Server` with zero timeouts, leaving the server vulnerable to connection exhaustion via Slowloris attacks. Furthermore, `runServer` directly invoked `serveFn` on the main goroutine without trapping `SIGINT` or `SIGTERM`, causing abrupt daemon termination, dropped in-flight requests, and risk of SQLite write interruption upon container shutdown.
- **Root Cause Analysis (5 Whys)**:
  1. *Why was the server susceptible to Slowloris attacks?* Because `http.Server` was instantiated with zero values for `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, and `IdleTimeout`.
  2. *Why were timeouts not configured?* Go's `http.Server` defaults all timeout fields to zero (unbounded), requiring explicit developer configuration.
  3. *Why did the daemon exit abruptly on container shutdown?* Because no signal handler caught `os.Interrupt` (`SIGINT`) or `syscall.SIGTERM` to coordinate a graceful shutdown sequence.
  4. *What was the impact of abrupt exit?* Active HTTP connections were dropped immediately without sending response trailers or status codes, and open SQLite transactions risked leaving the WAL journal in an uncheckpointed state.
  5. *Root Cause*: Omission of defensive HTTP connection timeout limits on `http.Server` and absence of an OS signal notification context with bounded graceful shutdown.
- **Applied Change / Fix**:
  1. Configured defensive timeouts in `buildHTTPServer` (`ReadHeaderTimeout: 5s`, `ReadTimeout: 15s`, `WriteTimeout: 30s`, `IdleTimeout: 60s`).
  2. Structured `runServer` to trap `os.Interrupt` and `syscall.SIGTERM` using `signal.NotifyContext`.
  3. Ran listener execution in a dedicated goroutine and coordinated clean shutdown via `srv.Shutdown(shutdownCtx)` with a 10-second timeout context.
  4. Handled `http.ErrServerClosed` cleanly and ensured deferred cleanup functions release database and logger resources.
- **Result & Non-Regression Test**: Verified by `TestBuildHTTPServer_TimeoutsConfigured`, `TestRunServerWithContext_GracefulShutdown`, and `TestRunServerWithContext_RealListenerGracefulShutdown` in `cmd/server/main_test.go` (100% pass across 7 tests in `cmd/server` with 82.3% statement coverage; 221 unit + 65 E2E tests passing 100%).

### `RCA-024` — Unbounded Prometheus Metric Route Path Cardinality Explosion (OOM DoS Vulnerability)
- **Date**: `2026-11-01`
- **Observed Symptom**: In `internal/api/router.go`, `prometheusMiddleware` extracted raw `r.URL.Path` and passed it directly as a Prometheus metric label value for `http_requests_total` (`method`, `path`, `status`) and `http_request_duration_seconds` (`method`, `path`). Any client querying dynamic parameterized endpoints (e.g. `/api/v1/files/:filename`, `/api/v1/mcp/traces/:trace_id`) or fuzzing random 404 paths created a new metric time series in memory for every distinct URI, causing unbounded Prometheus registry memory growth and exposing the server to out-of-memory (OOM) denial-of-service.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did metric time series grow without bound?* Because `prometheusMiddleware` passed raw `r.URL.Path` directly as a Prometheus label value.
  2. *Why was raw path used?* Standard `http.ServeMux` does not automatically annotate requests with route pattern templates (unlike gorilla/mux or gin), leaving `r.URL.Path` as the raw path string.
  3. *Why is this a security vulnerability?* Prometheus stores every distinct combination of label values as a persistent in-memory time series (`MetricFamily`). Attackers or clients scanning random paths can generate millions of time series, causing memory exhaustion.
  4. *Why were dynamic routes particularly vulnerable?* Routes such as `/api/v1/files/{filename}` and `/api/v1/mcp/traces/{trace_id}` take arbitrary identifiers in the path component.
  5. *Root Cause*: Absence of a route path normalization layer (`normalizeMetricPath`) to collapse parameterized routes to route templates and fall back to a strictly bounded `"other"` label for arbitrary or unrecognized URLs.
- **Applied Change / Fix**:
  1. Defined `knownStaticPaths` lookup set in `internal/api/router.go` for all legitimate static application endpoints.
  2. Implemented `normalizeMetricPath` collapsing dynamic parameterized routes (`/api/v1/files/*` -> `/api/v1/files/:filename`, `/api/v1/mcp/traces/*` -> `/api/v1/mcp/traces/:trace_id`), collapsing Swagger doc paths to `/swagger`, preserving recognized static routes (with optional trailing slash tolerance), and collapsing any unrecognized path or random 404 to `"other"`.
  3. Integrated `normalizeMetricPath` into `prometheusMiddleware` so Prometheus metrics record only bounded template labels.
  4. Added `ResetHTTPMetrics()` for isolated metric test verification.
  5. Implemented comprehensive test coverage in `internal/api/router_test.go` verifying dynamic template normalization, static route preservation, and cardinality bounding under fuzzing attacks.
- **Result & Non-Regression Test**: Verified by `TestNormalizeMetricPath`, `TestPrometheusMetricDynamicRouteNormalization`, `TestPrometheusMetricPathCardinalityBounding`, and `TestPrometheusMetricStaticRoutesPreserved` in `internal/api/router_test.go` (100% pass across 94 tests in `internal/api`; full suite 276 tests passing 100% across all 10 packages).

### `RCA-025` — Unauthenticated Access to Administrative File Server, Command Metadata, and Audit/Log Endpoints
- **Date**: `2026-11-01`
- **Observed Symptom**: When `auth.require_auth: true` was configured, several sensitive administrative endpoints (`/api/v1/files`, `/api/v1/files/:filename`, `/api/v1/commands`, `/api/v1/audit/logs`, `/api/v1/audit/verify`, `/api/v1/logs`, and `/api/v1/history`) completely bypassed authentication. Unauthenticated clients could list server files, download sensitive file payloads, inspect command timeouts/names, read tamper-evident audit events, verify audit chains, view ring-buffered system logs, and inspect execution history.
- **Root Cause Analysis (5 Whys)**:
  1. *Why could unauthenticated callers access sensitive endpoints?* Because `ListFilesHandler`, `DownloadFileHandler`, `ListCommandsHandler`, `AuditLogsHandler`, `AuditVerifyHandler`, `SystemLogsHandler`, and `ActionHistoryHandler` never invoked `resolvePrincipal(r)` or checked `RequireAuth`.
  2. *Why was authentication not checked in those handlers?* They were initially implemented as read-only diagnostic or utility endpoints prior to the introduction of the RBAC and authentication subsystem in Milestone 1.
  3. *Why did existing auth tests not detect the gap?* Existing auth tests focused on mutation endpoints (`/api/v1/execute`, `/api/v1/auth/*`, `/api/v1/tls/renew`, `/api/v1/presets/activate`, `/api/v1/plugins/execute`), while file and audit tests only ran with `RequireAuth: false`.
  4. *What was the security impact?* An unauthenticated remote attacker could enumerate server files, download arbitrary files from the secure directory, read internal application logs, and inspect audit trails even in hardened environments where authentication was strictly required.
  5. *Root Cause*: Lack of uniform authentication enforcement across all administrative and diagnostic handlers upon enabling `RequireAuth`.
- **Applied Change / Fix**:
  1. Added `p, err := env.resolvePrincipal(r)` and `RequireAuth` checks returning `401 Unauthorized` across `ListFilesHandler`, `DownloadFileHandler`, and `ListCommandsHandler` in `internal/api/handlers.go`.
  2. Added `p, err := env.resolvePrincipal(r)` and `RequireAuth` checks returning `401 Unauthorized` across `AuditLogsHandler`, `AuditVerifyHandler`, `SystemLogsHandler`, and `ActionHistoryHandler` in `internal/api/audit_handlers.go`.
  3. Created `internal/api/endpoint_auth_test.go` verifying 100% enforcement across all 7 endpoints for unauthenticated requests, invalid tokens, Bearer/X-API-Token credentials, and backward compatibility when `RequireAuth: false`.
- **Result & Non-Regression Test**: Verified by `TestProtectedEndpoints_RequireAuth_UnauthenticatedReturns401`, `TestProtectedEndpoints_RequireAuth_AuthenticatedSucceeds200`, `TestProtectedEndpoints_RequireAuthFalse_BackwardCompatibility`, and `TestProtectedEndpoints_RequireAuth_NilAuthManagerReturns401` in `internal/api/endpoint_auth_test.go` (100% pass across 126 tests in `internal/api` with 90.3% coverage; 308 tests passing 100% across all 10 packages).

### `RCA-026` — Anonymous Authentication Privilege Escalation on Administrative Endpoints (CWE-284 / CWE-269)
- **Date**: `2026-11-02`
- **Observed Symptom**: In `internal/api/auth_handlers.go`, when `auth.require_auth: false` (default configuration), `resolvePrincipal` returned `auth.RoleAdmin` with wildcard scopes `["*"]` for anonymous requests. Furthermore, administrative handlers (`AuthUsersHandler` POST/PATCH/DELETE, `AuthTokensHandler` POST/DELETE, `AuthServiceAccountsHandler` POST/DELETE, `AuthServiceAccountRotateHandler` POST) checked `if p.Type != "anonymous" && p.Role != auth.RoleAdmin`, which evaluated to `false` for any anonymous caller (`p.Type == "anonymous"`), allowing unauthenticated remote clients to create admin users, delete user accounts, issue Personal Access Tokens, and generate third-party service account credentials.
- **Root Cause Analysis (5 Whys)**:
  1. *Why could unauthenticated callers create users and issue credentials?* Because the authorization check `if p.Type != "anonymous" && p.Role != auth.RoleAdmin` inverted the logic by assuming anonymous callers should not be checked for admin role, while `resolvePrincipal` also assigned `RoleAdmin` with wildcard scopes `["*"]` to anonymous requests.
  2. *Why was `p.Type != "anonymous"` used in the conditional?* The author mistakenly intended "if authenticated but not admin, forbid", intending to exempt unauthenticated access in non-auth setups without realizing it opened administrative mutations to any unauthenticated caller.
  3. *Why did `resolvePrincipal` assign `RoleAdmin` and wildcard scopes `["*"]` to anonymous requests?* When `RequireAuth: false` was implemented, `resolvePrincipal` granted full administrator privileges as a shortcut so general endpoints (e.g., command execution) wouldn't be rejected by `auth.Authorize`.
  4. *What was the security impact?* Critical privilege escalation: any unauthenticated attacker could remotely take over the tool by creating admin users, deleting legitimate accounts, or minting API tokens and service account secrets.
  5. *Root Cause*: Granting `RoleAdmin` with wildcard scopes `["*"]` to anonymous callers in `resolvePrincipal` combined with flawed boolean logic `p.Type != "anonymous"` that bypassed admin checks in administrative handlers.
- **Applied Change / Fix**:
  1. Updated `resolvePrincipal` in `internal/api/auth_handlers.go`: when `RequireAuth: false`, anonymous principals are assigned `Role: auth.RoleViewer` and explicit non-admin operational scopes (`commands:read`, `commands:execute`, `plugins:read`, `plugins:execute`, `mcp:access`, `files:read`, `audit:read`), stripping `RoleAdmin` and wildcard `*`.
  2. Enforced strict administrative authorization across all mutation handlers in `internal/api/auth_handlers.go`: `if p.Type == "anonymous" || p.Role != auth.RoleAdmin { writeJSONError(w, "Admin role required...", http.StatusForbidden); return }` and blocked anonymous callers from issuing or revoking Personal Access Tokens.
  3. Added `TestAnonymousPrivilegeEscalationPrevention` in `internal/api/auth_test.go` asserting HTTP 403 Forbidden across all 8 administrative endpoints for anonymous callers and verifying authenticated administrators retain full access.
- **Result & Non-Regression Test**: Verified by `TestAnonymousPrivilegeEscalationPrevention` in `internal/api/auth_test.go` (127 unit tests in `internal/api` passing 100% with 91.0% coverage; 309 tests passing 100% across all 10 packages).

### `RCA-027` — Concurrency Data Race on OS Preset Dynamic Activation and Residual Admin Check Bypasses
- **Date**: `2026-11-02`
- **Observed Symptom**: In `internal/api/presets_handlers.go`, `ActivatePresetsHandler` dynamically mutated `env.Config.Executor.Commands = core.MergeOSPresets(...)`. Concurrently, other request handler goroutines in `ExecuteCommandHandler` and `ListCommandsHandler` iterated over `env.Config.Executor.Commands` without mutex synchronization, causing a Go runtime data race on concurrent preset activation. In addition, `ActivatePresetsHandler`, `TLSRenewHandler`, and `PluginDeclarativeRegisterHandler` checked `if p.Type != "anonymous" && p.Role != auth.RoleAdmin`, which allowed unauthenticated anonymous callers to trigger live certificate rotations, declarative plugin registrations, and preset command expansions.
- **Root Cause Analysis (5 Whys)**:
  1. *Why was there a data race when activating OS presets?* `ActivatePresetsHandler` reassigned the slice header and mutated elements in `env.Config.Executor.Commands` while `ExecuteCommandHandler` and `ListCommandsHandler` read the slice concurrently from separate HTTP worker goroutines without synchronization.
  2. *Why was `env.Config.Executor.Commands` not synchronized?* `Commands` was originally loaded once at server startup as a static configuration slice, and dynamic runtime mutation via `MergeOSPresets` was added in Milestone 2 without introducing concurrency primitives.
  3. *Why could Prometheus metrics re-indexing cause deadlock if synchronized naively?* `initConfiguredActionMetrics` also iterates `env.Config.Executor.Commands`; acquiring the same mutex inside `initConfiguredActionMetrics` when already held by `ActivatePresetsHandler` would deadlock Go's non-reentrant `sync.RWMutex`.
  4. *Why did anonymous callers bypass admin authorization on `POST /api/v1/presets/activate`, `POST /api/v1/tls/renew`, and `POST /api/v1/plugins/declarative`?* The inverted boolean check `if p.Type != "anonymous" && p.Role != auth.RoleAdmin` was left in these three handlers when ACT-029 patched user and token administrative handlers, allowing anonymous callers (`p.Type == "anonymous"`) to short-circuit the condition.
  5. *Root Cause*: Lack of `sync.RWMutex` synchronization protecting `env.Config.Executor.Commands` during runtime mutation combined with residual flawed boolean authorization conditions (`p.Type != "anonymous"`) in administrative mutation endpoints.
- **Applied Change / Fix**:
  1. Added `commandsMu sync.RWMutex` to `APIEnv` in `internal/api/handlers.go` and implemented thread-safe accessors (`CommandsRLock`, `CommandsRUnlock`, `CommandsLock`, `CommandsUnlock`, `GetCommands`, `FindCommand`).
  2. Protected command slice reads in `ExecuteCommandHandler` via `env.FindCommand` and `ListCommandsHandler` via `env.GetCommands`.
  3. Protected command slice mutation in `ActivatePresetsHandler` using `env.commandsMu.Lock()`, and separated Prometheus re-indexing into `initConfiguredActionMetricsLocked` to prevent recursive mutex deadlock.
  4. Enforced strict admin authorization across `ActivatePresetsHandler`, `TLSRenewHandler`, and `PluginDeclarativeRegisterHandler`: `if p.Type == "anonymous" || p.Role != auth.RoleAdmin { writeJSONError(w, "Admin role required...", http.StatusForbidden); return }` with audit logging.
  5. Added `TestConcurrentPresetActivationAndCommandExecution` in `internal/api/presets_test.go` asserting thread safety across concurrent goroutines activating presets, listing commands, and executing commands.
- **Result & Non-Regression Test**: Verified by `TestConcurrentPresetActivationAndCommandExecution` and full test suite (128 passed in `internal/api` with 90.8% coverage, 310 passed across all 10 packages).

### `RCA-028` — SQLite Database Locking and Concurrency Contention under Multi-Goroutine Load
- **Date**: `2026-11-02`
- **Observed Symptom**: Under concurrent execution of API commands, audit logging, and background workers, SQLite operations risked encountering `database is locked` or `busy` errors when multiple goroutines attempted simultaneous writes, or when concurrent readers blocked writers under default rollback journaling (`journal_mode=DELETE`).
- **Root Cause Analysis (5 Whys)**:
  1. *Why did concurrent database operations encounter `database is locked`?* Because SQLite default rollback journaling locks the entire database file during writes, blocking concurrent readers and failing concurrent writers immediately.
  2. *Why did concurrent writers fail immediately instead of waiting?* SQLite's default busy timeout is 0 ms (`busy_timeout=0`), returning an immediate `busy` error if another connection holds a lock.
  3. *Why did multiple connections attempt simultaneous writes within the same Go process?* Go's `database/sql` connection pool defaults to unbounded open connections (`maxOpen = 0`), opening multiple physical connections to the SQLite file across HTTP handler goroutines.
  4. *Why is unbounded connection pooling problematic for SQLite?* SQLite is an embedded single-writer database engine; having multiple connections in the same process attempt concurrent writes causes self-contention and lock conflicts.
  5. *Root Cause*: Lack of connection pool serialization (`SetMaxOpenConns(1)`), absence of Write-Ahead Logging (`journal_mode=WAL`), absence of a busy wait timeout (`busy_timeout=5000`), and unconfigured synchronous/foreign key pragmas in `internal/database/db.go`.
- **Applied Change / Fix**:
  1. Bounded the Go connection pool to `SetMaxOpenConns(1)`, `SetMaxIdleConns(1)`, and `SetConnMaxLifetime(time.Hour)` in `ConfigurePool`.
  2. Configured WAL mode (`PRAGMA journal_mode=WAL;`), busy timeout (`PRAGMA busy_timeout=5000;`), synchronous NORMAL (`PRAGMA synchronous=NORMAL;`), and foreign keys (`PRAGMA foreign_keys=ON;`) in `applyPragmas`.
  3. Implemented `BuildDSN` augmenting connection strings with DSN query options for driver-level connection initialization.
  4. Implemented `GetPragma` and connection pool getters (`PoolStats`, `MaxOpenConns`, `MaxIdleConns`, `ConnMaxLifetime`, `BusyTimeout`) for runtime verification.
  5. Added comprehensive concurrency tests in `internal/database/db_test.go` with 40 parallel goroutines verifying zero locking errors on both in-memory and SQL-backed stores.
- **Result & Non-Regression Test**: Verified by `TestBuildDSN`, `TestDatabaseConnectionPoolAndGetters`, `TestDatabasePragmasAppliedAndQueryable`, `TestConcurrentActionHistoryAccessInMemory`, and `TestConcurrentActionHistoryAccessSQLBacked` in `internal/database/db_test.go` (100% pass across 12 tests in `internal/database` with 95.2% coverage; 320 tests passing 100% across all 10 packages).

### `RCA-029` — Fake Mock Metric Fallback and Ignored Scrape Errors in SRE Prometheus Scraper Plugin
- **Date**: `2026-11-02`
- **Observed Symptom**: In `internal/plugins/native_sre.go`, `PrometheusScraperPlugin` silently returned hardcoded Prometheus metrics (`api_executor_actions_total... 42`, `api_executor_heap_bytes 8452100`) when HTTP scraping failed, and discarded errors returned by `getMetricsContent` (`content, _ := p.getMetricsContent(ctx, params)`). Furthermore, non-2xx HTTP responses (e.g., 500, 404) were treated as valid exposition payloads without status validation.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did `scrape_metrics` return fake metrics on failure?* Because `getMetricsContent` caught `err != nil` from `client.Do(req)` and returned hardcoded sample metric text with a `nil` error to provide "mock self metrics".
  2. *Why was mock self metrics returned by default?* Early prototyping intended to provide a working out-of-the-box demonstration without requiring a running Prometheus target.
  3. *Why is this a system integrity and forensic honesty defect?* It masked actual network partitions, dead endpoints, or exporter failures, emitting false telemetry and deceiving operators into believing the target service was healthy.
  4. *Why were non-2xx HTTP responses unhandled?* `resp.StatusCode` was never evaluated, reading error HTML/text bodies as if they were valid Prometheus exposition format.
  5. *Root Cause*: Lack of strict error propagation in `Execute` and silent fallback to synthetic mock data instead of requiring explicit opt-in (`allow_mock: true`).
- **Applied Change / Fix**:
  1. Added `allow_mock` action parameter (default `"false"`) to `PrometheusScraperPlugin` actions.
  2. Replaced default fake mock fallback in `getMetricsContent` with explicit error returns for network errors, timeouts, connection failures, and HTTP status codes outside 200-299.
  3. Conditioned mock fallback strictly on `allow_mock: true`.
  4. Evaluated and propagated `err` in `Execute`, returning `Status: "error"` and the genuine error.
  5. Implemented comprehensive test coverage in `internal/plugins/native_sre_test.go` with `httptest.Server`.
- **Result & Non-Regression Test**: Verified by `TestPrometheusScraperPlugin_RealScrapeSuccess`, `TestPrometheusScraperPlugin_UnreachableTargetGenuineError`, `TestPrometheusScraperPlugin_HTTP500GenuineError`, `TestPrometheusScraperPlugin_HTTP404GenuineError`, and `TestPrometheusScraperPlugin_ExplicitAllowMock` (69 tests passing in `internal/plugins`, full repository suite 329 tests passing 100% across all 10 packages).

### `RCA-030` — Inverted Authorization Check on MCP Trace Deletion, Variable-Time HMAC Verification, and Sibling Prefix Path Confinement
- **Date**: `2026-11-02`
- **Observed Symptom**:
  1. In `internal/plugins/native_crypto.go`, `verify_hmac` compared computed digest with expected digest via standard string equality (`computed == expected`), vulnerable to timing side-channel attacks.
  2. In `internal/api/handlers.go` (`DownloadFileHandler`), path boundary check used `strings.HasPrefix(absFilePath, absSecureDir)`. If `absSecureDir` was `/var/uploads` and a sibling directory `/var/uploads_private` existed, `HasPrefix` returned true without verifying directory boundaries.
  3. In `internal/api/mcp_handlers.go` (`DELETE /api/v1/mcp/traces`), authorization check was inverted (`if p.Type != "anonymous" && p.Role != auth.RoleAdmin`), allowing unauthenticated anonymous callers to bypass admin checks and delete traces while blocking non-admin authenticated users.
- **Root Cause Analysis (5 Whys)**:
  1. *Why was string equality used for HMAC verification?* Standard equality was used for simplicity without considering side-channel timing discrepancy between byte-by-byte comparison and constant-time comparison.
  2. *Why did path prefix check allow sibling directory bypasses?* `strings.HasPrefix` checked raw string prefix rather than directory tree confinement (`filepath.Rel` or path separator suffix).
  3. *Why did anonymous callers bypass the MCP trace deletion check?* A Boolean logic inversion (`!= "anonymous" && != RoleAdmin` instead of `== "anonymous" || != RoleAdmin`) left anonymous callers unchecked because `p.Type != "anonymous"` evaluated to false.
  4. *Why did prior tests not catch the anonymous deletion vulnerability?* The test suite previously ran `DELETE /api/v1/mcp/traces` before initializing auth, asserting that the anonymous call succeeded with 200 OK.
  5. *Root Cause*: Inconsistent defense-in-depth patterns across handlers and lack of constant-time primitives for cryptographic verification.
- **Applied Change / Fix**:
  1. Used `crypto/subtle.ConstantTimeCompare` for HMAC comparison in `internal/plugins/native_crypto.go`.
  2. Replaced path prefix check in `internal/api/handlers.go` with `filepath.Rel` and `baseWithSep` path separator enforcement.
  3. Corrected authorization condition in `internal/api/mcp_handlers.go` to `if p == nil || p.Type == "anonymous" || p.Role != auth.RoleAdmin`.
  4. Added unit tests across `internal/plugins/native_crypto_test.go`, `internal/api/files_test.go`, and `internal/api/mcp_test.go`.
- **Result & Non-Regression Test**: Verified by `TestCryptoHashUtilityPlugin_VerifyHMAC_MatchingAndNonMatching`, `TestDownloadFileHandler_DirectoryBoundaryAndSiblingConfinement`, and `TestMCPEndpointsAndTraceInspection` (71 tests in `internal/plugins`, 129 tests in `internal/api`, and 332 tests passing 100% across all 10 packages).

### `RCA-031` — Missing Root .dockerignore, RedHat Container Healthcheck Failure, and Suboptimal Docker Layer Caching
- **Date**: `2026-11-02`
- **Observed Symptom**:
  1. The repository root had no `.dockerignore` file, transferring `.git/`, `.worktrees/`, `.agents/`, test databases (`history.db`), log files, and IDE directories into container build contexts, bloating context transfer time and risking credential/metadata leaks.
  2. Running `docker-compose.os-test.yml` for `api-executor-redhat` failed its healthcheck (`test: ["CMD", "curl", "-k", "-f", "https://localhost:8080/api/v1/commands"]`) because the `redhat/ubi9:latest` base image does not package `curl` by default.
  3. In `Dockerfile`, `COPY . .` was executed before `go mod tidy` and `go install ...`, invalidating Go dependency cache layers on every single application source code modification.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did the RedHat healthcheck fail?* Because `curl` was missing from the container image.
  2. *Why was curl missing?* RedHat UBI9 minimal images do not include `curl` or `ca-certificates` in their standard package payload.
  3. *Why did Docker builds invalidate dependency downloads on every change?* Because `COPY . .` was placed before dependency resolution, busting the Docker layer cache when any repository file changed.
  4. *Why was build context unnecessarily large?* No `.dockerignore` file existed at the repository root to exclude git metadata, local databases, and temporary directories.
  5. *Root Cause*: Omission of `.dockerignore`, absence of healthcheck dependencies in RedHat container image, and suboptimal Dockerfile instruction ordering.
- **Applied Change / Fix**:
  1. Created root `.dockerignore` excluding `.git`, `.worktrees`, `.agents`, `bin/`, `tmp/`, `*.db`, `*.sqlite*`, `*.log`, `.vscode/`, `.idea/`, and coverage artifacts.
  2. Updated `docker/Dockerfile.redhat` to install `ca-certificates` and `curl-minimal` via `dnf install -y --nodocs`.
  3. Reordered root `Dockerfile` to run `go mod download` and `go install ...` immediately after `COPY go.mod go.sum ./` before copying application source.
  4. Added `RUN go mod download` to `docker/Dockerfile.redhat` and `docker/Dockerfile.ubuntu`.
  5. Added `TestDockerHygieneAndIgnoreRules` in `docs/branding_test.go`.
- **Result & Non-Regression Test**: Verified by `TestDockerHygieneAndIgnoreRules` and `python scripts/lint_dockerfile.py` passing cleanly (333 tests passing 100% across all 10 packages).

### `RCA-032` — Web Admin Console Spurious Initial 401 Error Banner, Unhandled Action Fetch Rejections, Outdated cURL Auth Header, and Race-Prone Refresh Coordination
- **Date**: `2026-11-02`
- **Observed Symptom**:
  1. On initial page load or when unauthenticated (`!this.authToken`), the Web Admin Console (`web/static/index.html`) displayed a red error banner (`"Authentication failed (401)"`) because `loadPrincipal()` queried `GET /api/v1/auth/me` and unconditionally set `this.statusBanner = d.error || ('Authentication failed (' + r.status + ')')`.
  2. The generated cURL snippet in `curlSnippet()` emitted deprecated `-H "X-API-Token: ..."` instead of `-H "Authorization: Bearer ..."`, causing cURL examples to mismatch `headers()`.
  3. Action methods executing `fetch()` (`activatePresets`, `loginUser`, `createUser`, `deleteUser`, `createPAT`, `revokeToken`, `createServiceAccount`, `rotateServiceAccount`, `deleteServiceAccount`, `registerDeclarativePlugin`, `loadDBTables`, `runDBQuery`, `sendRawMCP`, `renewTLSCertificate`) lacked `try...catch` blocks, triggering uncaught Promise rejections and leaving UI spinners/banners frozen upon network disconnections or server restarts.
  4. `refreshAll()` initiated 9 independent async functions without coordination or `await`, leading to race-condition banner overwrites and unhandled background rejections.
- **Root Cause Analysis (5 Whys)**:
  1. *Why was a red error banner visible on first page load?* Because `loadPrincipal()` handled 401 responses by setting `statusBanner` even when the user had not yet provided an authentication credential.
  2. *Why was cURL authorization outdated?* Because `curlSnippet()` had not been updated when the backend was modernized to support standard Bearer authorization alongside Service Keys.
  3. *Why did UI actions crash on network drops?* Because asynchronous `fetch()` invocations were not enclosed in error boundaries (`try...catch`).
  4. *Why did panels experience race conditions?* Because `refreshAll()` fired async data loaders without synchronization or `Promise.allSettled()`.
  5. *Root Cause*: Lack of unauthenticated state guards on initial load, outdated cURL string templates, absence of defensive error boundaries on user actions, and uncoordinated async panel refreshes in `web/static/index.html`.
- **Applied Change / Fix**:
  1. Guarded `this.statusBanner` assignment in `loadPrincipal()` with `if (this.authToken)`.
  2. Updated `curlSnippet()` to format `-H "Authorization: Bearer ${this.authToken || 'gat_pat_<your_token>'}"`.
  3. Enclosed all bare `fetch()` action methods in defensive `try...catch` blocks setting user-facing error banners.
  4. Synchronized `refreshAll()` using `await Promise.allSettled([...])` and updated callers to await its resolution.
  5. Added non-regression unit tests in `internal/api/web_console_test.go` (`TestWebAdministrationConsole_ResilienceGuarantees`).
- **Result & Non-Regression Test**: Verified by `TestWebAdministrationConsole_ResilienceGuarantees` (130 tests passing in `internal/api` and 334 tests passing 100% across all 10 packages).

### `RCA-033` — Quadratic Manifest File Parsing in E2E Test Setup and Redundant Duplicate Workflow Rule Files
- **Date**: `2026-11-02`
- **Observed Symptom**:
  1. In `tests/e2e/setup_test.go` (`setupE2ETestServer`), initializing an ephemeral test server invoked `filepath.WalkDir` over `plugins/` and executed `pluginReg.LoadDeclarativeDirectory(filepath.Dir(path))` on every single manifest file. Because directories contained up to 32 YAML manifests each, `LoadDeclarativeDirectory` was redundantly called up to 32 times on the same folder, re-reading every file each time and causing ~7,800 unnecessary disk reads across E2E test runs.
  2. In `.agents/rules/`, three separate files (`atomic-workflow.md`, `git-workflow.md`, `github-workflow.md`) codified the atomic workflow with overlapping formulations and slight differences in granularity, creating rule sprawl and maintenance divergence.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did E2E server setup re-parse directories dozens of times?* Because `filepath.WalkDir` triggered on individual file matches rather than directory entries, and invoked directory loading without caching previously visited folder paths.
  2. *Why was directory loading invoked per-file?* Because the callback checked file extensions (`.yaml`, `.yml`, `.json`) before invoking `LoadDeclarativeDirectory(filepath.Dir(path))`.
  3. *Why did multiple overlapping rule files exist in `.agents/rules/`?* Successive milestones introduced `git-workflow.md` and `github-workflow.md` alongside `atomic-workflow.md` without pruning redundant predecessors.
  4. *What was the impact?* Increased E2E initialization latency and potential confusion regarding which workflow rule was canonical.
  5. *Root Cause*: Lack of a directory visitation cache in `setup_test.go` and absence of rule consolidation to a single canonical file in `.agents/rules/`.
- **Applied Change / Fix**:
  1. Added `visitedDirs := make(map[string]bool)` in `setupE2ETestServer` (`tests/e2e/setup_test.go`) so `LoadDeclarativeDirectory(dir)` executes strictly once per unique directory.
  2. Consolidated all atomic workflow guidelines into `atomic-workflow.md` and deleted redundant copies `git-workflow.md` and `github-workflow.md`.
  3. Added non-regression tests in `tests/e2e/setup_test.go` (`TestE2ESetup_PluginDirectorySinglePassLoading`) and `docs/branding_test.go` (`TestAgentRulesConsolidationAndDeduplication`).
- **Result & Non-Regression Test**: Verified by `TestE2ESetup_PluginDirectorySinglePassLoading` and `TestAgentRulesConsolidationAndDeduplication` (66 tests in `tests/e2e`, 3 tests in `docs`, and full repository test suite 336 unit + 66 E2E tests passing 100%).

### `RCA-034` — Linear O(N) Credential Scan Under Exclusive Lock on Every Authenticated HTTP Request
- **Date**: `2026-11-08`
- **Observed Symptom**: In `internal/auth/manager.go`, `Manager.AuthenticateCredential` iterated linearly over every entry in `m.tokens` and `m.serviceAccounts` while holding `m.mu.Lock()`, causing `O(N)` authentication latency and lock contention as the number of issued Personal Access Tokens and Service Accounts grew.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did credential authentication scale as O(N)?* Because `AuthenticateCredential` ranged over the full `m.tokens` and `m.serviceAccounts` maps keyed by entity ID (`tok_...`, `svc_...`) rather than credential hash.
  2. *Why were the maps keyed only by entity ID?* Administrative CRUD operations (`RevokeToken`, `DeleteServiceAccount`, `RotateServiceAccountKey`) reference credentials by their public ID rather than their secret hash.
  3. *Why did this become a hot-path bottleneck?* Every authenticated API request invokes `resolvePrincipal` -> `AuthenticateCredential`, making credential lookup the most frequently executed path in the server.
  4. *Why was lock contention amplified?* `AuthenticateCredential` acquires `m.mu.Lock()` to update `LastUsedAt` and `UseCount` / `CallCount`; holding that lock during a linear scan serialized concurrent HTTP requests.
  5. *Root Cause*: Absence of secondary `O(1)` hash-to-ID lookup indices (`tokenByHash` and `serviceAccountByHash`) on `auth.Manager`.
- **Applied Change / Fix**:
  1. Added `tokenByHash` and `serviceAccountByHash` maps to `auth.Manager` in `internal/auth/manager.go` and implemented `rebuildHashIndicesLocked()`.
  2. Synchronized index insertions, updates, and evictions across `NewManager`, `loadFromFile`, `DeleteUser`, `CreateToken`, `RevokeToken`, `CreateServiceAccount`, `RotateServiceAccountKey`, and `DeleteServiceAccount`.
  3. Updated `AuthenticateCredential` to perform `O(1)` hash lookup followed by `constantTimeEqualsHex` verification.
  4. Added `TestAuthenticateCredential_O1HashIndexAndLifecycle` in `internal/auth/manager_test.go`.
- **Result & Non-Regression Test**: Verified by `TestAuthenticateCredential_O1HashIndexAndLifecycle` in `internal/auth/manager_test.go` (5 tests passing in `internal/auth`, full suite 337 tests passing 100% across all 10 packages).

### `RCA-035` — Per-Execution Regex Recompilation, Uncached Catalog Sorting, and Composite Parameter Stringification in Declarative Plugins
- **Date**: `2026-11-08`
- **Observed Symptom**:
  1. `DeclarativePlugin.Execute` in `internal/plugins/declarative.go` called `regexp.Compile(paramDef.Pattern)` on every action execution despite `NewDeclarativePlugin` already compiling the same pattern at load time.
  2. `Registry.ListFiltered` in `internal/plugins/plugin.go` reconstructed all 305 `PluginInfo` structs and executed `sort.Slice` (`O(N log N)`) on every catalog request.
  3. Passing a composite value (`[]string` or `map[string]any`) into `params` converted it via `fmt.Sprintf("%v", v)` into `"[invalid slice input]"` or `"map[key:value]"`, which matched `docker-container-stats.yaml` because `^[a-zA-Z0-9. _\t-{}]+$` contained an unescaped hyphen creating an ASCII range from `\t` (`0x09`) to `{` (`0x7B`).
- **Root Cause Analysis (5 Whys)**:
  1. *Why was `regexp.Compile` called on every execution?* `NewDeclarativePlugin` discarded the `*regexp.Regexp` returned during validation instead of storing it on `DeclarativePlugin`.
  2. *Why did `ListFiltered` sort 305 plugins on every request?* `Registry` stored plugins only in an unordered `map[string]Plugin` without caching the sorted `[]PluginInfo` projection.
  3. *Why did `docker-container-stats` accept slice and map inputs when Docker was running?* `DeclarativePlugin.Execute` did not check `reflect.Kind` before `fmt.Sprintf("%v", v)`, and `\t-{` in `docker-container-stats.yaml` matched `[`, `]`, and `:`.
  4. *Why was this previously masked?* When the `docker` daemon was not running on the test host, subprocess execution failed with exit code 1, masking the validation pass.
  5. *Root Cause*: Lack of pre-compiled regex storage, lack of sorted catalog caching in `Registry`, missing scalar-kind enforcement in `DeclarativePlugin.Execute`, and an unescaped hyphen in `docker-container-stats.yaml`.
- **Applied Change / Fix**:
  1. Stored pre-compiled `*regexp.Regexp` instances in `DeclarativePlugin.compiledRegex` during `NewDeclarativePlugin` and rejected composite `reflect.Kind` values in `DeclarativePlugin.Execute`.
  2. Moved the literal hyphen to the end of the character class (`^[a-zA-Z0-9. _\t{}-]+$`) in `plugins/containerops/docker-container-stats.yaml`.
  3. Cached the sorted `[]PluginInfo` catalog in `Registry.sortedCache` with automatic invalidation on `Register`, `RegisterOrReplace`, and `Unregister`.
  4. Added `TestDeclarativePlugin_PrecompiledRegexAndRegistryCatalogCache` in `internal/plugins/plugins_test.go`.
- **Result & Non-Regression Test**: Verified by `TestDeclarativePlugin_PrecompiledRegexAndRegistryCatalogCache` and `TestM2Adversarial_AllParameters_InvalidTypeRejection` (72 tests passing 100% in `internal/plugins`; full repository suite 338 tests passing 100% across all 10 packages).

### `RCA-036` — Unbounded Subprocess Output Buffering (`cmd.CombinedOutput()`) Risking Heap Exhaustion
- **Date**: `2026-11-08`
- **Observed Symptom**: In `internal/core/executor.go`, `ExecuteCommandWithTimeout` invoked `cmd.CombinedOutput()`, which reads all child stdout and stderr into an unbounded `bytes.Buffer` in memory, followed by `string(output)` allocation and double retention inside `database.RecordAction` and `audit.Record`. A verbose or runaway command producing hundreds of megabytes of output before its timeout expired could exhaust server memory (OOM).
- **Root Cause Analysis (5 Whys)**:
  1. *Why could a subprocess exhaust Go heap memory before its timeout fired?* Because `os/exec.Cmd.CombinedOutput()` uses an unrestricted `bytes.Buffer` that grows until EOF or process termination.
  2. *Why was a timeout alone insufficient to bound memory?* Within a 15–30 second execution window, a fast local command can write hundreds of megabytes per second to stdout/stderr pipes.
  3. *Why was memory pressure amplified downstream?* Converting `[]byte` to `string(output)` duplicated the buffer on the heap, and storing that string in both the in-memory `action_history` slice and the `AuditLogger` ring buffer retained the oversized payload.
  4. *Why can't the pipe simply be closed once the limit is reached?* Closing the child's stdout/stderr pipe while it is still running causes `SIGPIPE` / broken-pipe failures in legitimate commands; excess bytes after the cap must be drained and discarded (`len(p)` returned) while marking the output as truncated.
  5. *Root Cause*: Use of unbounded `cmd.CombinedOutput()` instead of a bounded `io.Writer` (`limitedOutputBuffer`) capped at `MaxCommandOutputBytes` (1 MiB).
- **Applied Change / Fix**:
  1. Defined `MaxCommandOutputBytes = 1 << 20` (1 MiB) and implemented `limitedOutputBuffer` in `internal/core/executor.go`.
  2. Replaced `cmd.CombinedOutput()` in `ExecuteCommandWithTimeout` with `outBuf := newLimitedOutputBuffer(MaxCommandOutputBytes)` attached to `cmd.Stdout` and `cmd.Stderr` followed by `cmd.Run()`.
  3. Appended a deterministic truncation suffix (`\n...[output truncated at 1048576 bytes]`) when output exceeds `MaxCommandOutputBytes`.
  4. Added `TestLimitedOutputBufferAndMaxCommandOutputBytes` in `internal/core/executor_test.go`.
- **Result & Non-Regression Test**: Verified by `TestLimitedOutputBufferAndMaxCommandOutputBytes` in `internal/core/executor_test.go` (40 tests passing 100% in `internal/core`; full repository suite 339 tests passing 100% across all 10 packages).

### `RCA-037` — Per-Event `os.OpenFile`/`Close` Syscall Overhead Under Memory Lock and Per-Insert Statement Preparation
- **Date**: `2026-11-08`
- **Observed Symptom**:
  1. `AuditLogger.Record` (`internal/audit/audit.go`) called `os.OpenFile` and `f.Close()` on every single audit event while holding `al.mu.Lock()`, and also executed `al.db.Exec` and `al.logger.LogStructured` inside `al.mu.Lock()`, blocking concurrent readers (`Query`, `VerifyChain`, `Count`) during disk and SQLite I/O.
  2. `Server.recordTrace` (`internal/mcp/server.go`) called `os.MkdirAll`, `os.OpenFile`, and `f.Close()` on every MCP JSON-RPC trace event.
  3. `DB.RecordAction` (`internal/database/db.go`) called `db.Prepare` + `defer stmt.Close()` on every insert instead of a single `db.Exec` call.
- **Root Cause Analysis (5 Whys)**:
  1. *Why were file descriptors opened and closed on every event?* `AuditLogger` and `mcp.Server` stored only the path string (`cfg.FilePath` / `cfg.TraceFilePath`) instead of retaining an open `*os.File` handle across the server lifecycle.
  2. *Why did `AuditLogger.Record` block concurrent readers during I/O?* `defer al.mu.Unlock()` was placed at the top of `Record`, keeping the exclusive lock held across JSONL file writes, SQLite inserts, and structured log formatting.
  3. *Why did `DB.RecordAction` prepare and close a statement on every call?* `RecordAction` used `db.Prepare` + `defer stmt.Close()` without caching the statement, whereas `db.Exec` allows `database/sql` drivers to execute parameterized inserts directly.
  4. *Why must persistent file handles have explicit `Close()` lifecycle methods?* On Windows, open file handles inside `t.TempDir()` prevent temporary directory removal unless closed via `defer Close()` (cf. `RCA-011`).
  5. *Root Cause*: Lack of persistent `*os.File` lifecycle management on `AuditLogger` and `mcp.Server`, overly broad mutex scope in `AuditLogger.Record`, and redundant per-call `db.Prepare` in `DB.RecordAction`.
- **Applied Change / Fix**:
  1. Added persistent `file *os.File` and `fileMu sync.Mutex` to `AuditLogger` (`internal/audit/audit.go`) and `traceFile *os.File` and `fileMu sync.Mutex` to `mcp.Server` (`internal/mcp/server.go`), with `Close() error` and `HasOpenFile()` / `HasOpenTraceFile()` methods wired into `cmd/server/main.go`.
  2. Narrowed `al.mu.Lock()` in `AuditLogger.Record` strictly to hash-chain computation and in-memory ring-buffer insertion, performing file, SQLite, and logger I/O after `al.mu.Unlock()`.
  3. Replaced `db.Prepare` + `defer stmt.Close()` in `DB.RecordAction` (`internal/database/db.go`) with direct `db.Exec`.
  4. Updated `internal/audit/audit_test.go` and `internal/mcp/server_test.go` to verify persistent handle lifecycle and `Close()`.
- **Result & Non-Regression Test**: Verified by `TestAuditLoggerHashChainAndQuery`, `TestMCPServerLifecycleAndAllTools`, and `TestDatabaseSQLDriverBackedExecutionAndErrors` (339 tests passing 100% across all 10 packages).

### `RCA-038` — 9 Copylocks Violations from Struct Embedding `sync.RWMutex` Value Copies
- **Date**: `2026-11-09`
- **Observed Symptom**: Running `go vet ./internal/jobs/...` returned 9 copylocks violations across `internal/jobs/job.go`, `internal/jobs/store.go`, and `internal/jobs/jobs_test.go`.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did `go vet` flag copylocks errors?* The `Job` struct embeds an unexported `mu sync.RWMutex` to guard state, and several methods copied the struct value.
  2. *Where was the lock copied?* `Snapshot()` dereferenced the job pointer (`snap := *j`) and returned `Job` by value, copying `j.mu` to the caller.
  3. *Why did `MemoryJobStore` copy locks?* It was declared as `jobs map[string]Job` (storing values instead of pointers), causing every map lookup, assignment, and slice iteration to copy the lock.
  4. *Why did tests copy locks?* `jobs_test.go` passed `snap` (a value embedding `mu`) directly to `t.Errorf("%+v", snap)`, and `m1_stress_challenge_test.go` passed `&snap`.
  5. *Root Cause*: Returning struct values instead of pointer references (`*Job`) for structs embedding synchronization primitives (`sync.RWMutex`).
- **Applied Change / Fix**:
  1. Refactored `Job.Snapshot()` to return `*Job`, allocating `snap := &Job{...}` with scalar and map fields copied explicitly, leaving `snap.mu` freshly initialized and zeroed.
  2. Refactored `MemoryJobStore.jobs` to `map[string]*Job`, returning `snap.Snapshot()` on `GetJob` and `ListJobs` to maintain deep-cloning immutability without copying locks.
  3. Formatted scalar fields in `t.Errorf` in `jobs_test.go` and passed `snap` directly to `store.SaveJob` in `m1_stress_challenge_test.go`.
- **Result & Non-Regression Test**: Verified by `go vet ./...` exiting with code 0 (zero copylocks violations), and unit tests `TestJobSnapshot`, `TestMemoryJobStoreCRUDAndFilter`, and `TestChallenger_MemoryJobStore_DeepCloningImmutability` passing 100%.

### `RCA-039` — Engine Log Buffer Memory Leak on Enqueue Rejection and pruneTicker Data Race / SIGSEGV on Shutdown
- **Date**: `2026-11-09`
- **Observed Symptom**:
  1. When `Engine.Enqueue` was rejected due to full queue or store failure, the 2 MiB `JobLogBuffer` remained registered in `e.logBuffers` indefinitely.
  2. Completed terminal jobs never had their log buffers evicted, accumulating unbounded memory.
  3. `Engine.Shutdown` set `e.pruneTicker = nil` while `pruneLoop` concurrently evaluated `case <-e.pruneTicker.C:`, causing data race and fatal SIGSEGV nil pointer dereference under `go test -race`.
  4. `handleJobExecution` wrote directly to `job.ResultData = res` without `job.mu.Lock()`.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did `logBuffers` leak on rejection?* `e.logBuffers[jobID]` was inserted before `SaveJob` and `queue.Enqueue`, without cleanup in error return blocks.
  2. *Why did terminal jobs retain buffers?* `e.store.Prune` pruned store records but `Engine` had no log buffer pruning mechanism.
  3. *Why did `pruneLoop` crash on shutdown?* Go select statement evaluates channel operands (`e.pruneTicker.C`) on every loop iteration; setting `e.pruneTicker = nil` from another goroutine raced and caused nil pointer dereference.
  4. *Why was `job.ResultData` unsynchronized?* `ResultData` lacked a mutex-guarded accessor method, unlike other state fields.
  5. *Root Cause*: Missing error recovery cleanup in `Enqueue`, missing memory eviction loop, unsynchronized field access, and accessing a mutable struct field inside a goroutine `select` loop without local variable capture or `sync.WaitGroup` coordination.
- **Applied Change / Fix**:
  1. Added `delete(e.logBuffers, jobID)` and `job.SetLogBuffer(nil)` on `Enqueue` error branches.
  2. Implemented `pruneLogBuffers()` / `PruneLogBuffers()` in `Engine` to evict terminal buffers older than `MaxJobAge` or pruned from store; reset `e.logBuffers` on `Shutdown`.
  3. Passed ticker instance directly to `pruneLoop(ticker *time.Ticker)` stack and coordinated shutdown with `e.pruneWg sync.WaitGroup`.
  4. Added `SetResultData(res)` and `GetResultData()` to `Job`, and guarded worker terminal transitions in `WorkerPool.runJob`.
- **Result & Non-Regression Test**: Verified by `TestEngineLogBufferEvictionOnEnqueueFailure`, `TestEngineLogBufferPruning`, and `TestChallenger_Engine_ShutdownPruneLoopNilPointerRace` under `go test -v -race` in WSL (0 races, 0 panics).

### `RCA-040` — Trailing Slash Normalization Inversion for Static Job Path in `normalizeMetricPath`
- **Date**: `2026-11-09`
- **Observed Symptom**: Requests to `/api/v1/jobs/` (with a trailing slash) were classified as `"other"` instead of being normalized to `"/api/v1/jobs"` in Prometheus metrics, failing `TestNormalizeMetricPath/jobs_with_trailing_slash`.
- **Root Cause Analysis (5 Whys)**:
  1. *Why was `/api/v1/jobs/` normalized to "other"?* Because `normalizeMetricPath` evaluated `trimmed := strings.TrimSuffix(path, "/")` resulting in `"/api/v1/jobs"`, and then called `sub := strings.TrimPrefix(trimmed, "/api/v1/jobs/")`.
  2. *Why did TrimPrefix fail?* Because `trimmed` was `"/api/v1/jobs"`, which does not contain the trailing slash required by the prefix pattern `"/api/v1/jobs/"`.
  3. *What happened next?* `sub` retained the full string `"/api/v1/jobs"`, and `strings.Split(sub, "/")` produced 4 elements (`["", "api", "v1", "jobs"]`).
  4. *Why did that return "other"?* Because `len(parts) == 4`, falling through the segment boundary checks.
  5. *Root Cause*: Attempting to trim a trailing-slash prefix on a string that had already been stripped of trailing slashes without checking for exact equality with the base route.
- **Applied Change / Fix**:
  Added an explicit equality check `if trimmed == "/api/v1/jobs" { return "/api/v1/jobs" }` immediately after stripping the trailing slash in `internal/api/router.go`.
- **Result & Non-Regression Test**: Verified by `TestNormalizeMetricPath` (63 table cases passing 100%) and `TestPrometheusMetricJobRouteNormalization`.

### `RCA-041` — Data Race Under Go Race Detector Between Background Worker State Transition and `SubmitJobHandler` Response Serialization
- **Date**: `2026-11-09`
- **Observed Symptom**: Executing `go test -race ./internal/api/...` under Linux/WSL consistently triggered a Go runtime data race: `Write at 0x... by goroutine (jobs.(*Job).SetRunning at job.go:222)` concurrent with `Previous read at 0x... by goroutine (api.(*APIEnv).SubmitJobHandler at job_handlers.go:256)`.
- **Root Cause Analysis (5 Whys)**:
  1. *Why was a data race detected?* A worker goroutine called `job.SetRunning()` which locked `job.mu` and wrote `j.Status = StatusRunning`, while `SubmitJobHandler` read `job.Status` concurrently without acquiring `job.mu`.
  2. *Why did SubmitJobHandler have the live pointer to Job?* `Engine.Enqueue(jobReq)` enqueued the `*Job` into the priority queue and returned the same live pointer to the HTTP handler.
  3. *Why did the worker start so quickly?* The queue's condition variable immediately signaled a waiting worker in `workerLoop()`, which began executing `runJob()` concurrently before `SubmitJobHandler` encoded its JSON response.
  4. *Why did SubmitJobHandler read `job.Status` directly?* The handler constructed `SubmitJobResponse` using direct struct field access rather than thread-safe accessors or the contractual submission state.
  5. *Root Cause*: Lack of memory synchronization on mutable `Job.Status` in HTTP handlers; direct struct field read instead of utilizing `jobs.StatusQueued` for initial submission or thread-safe getter `job.GetStatus()`.
- **Applied Change / Fix**:
  1. Replaced direct read `Status: job.Status` with constant `Status: jobs.StatusQueued` in `SubmitJobHandler` (`internal/api/job_handlers.go:256`), providing 100% deterministic conformance with the HTTP 202 Accepted submission contract and zero lock contention.
  2. Replaced direct field read `status = job.Status` with `status = job.GetStatus()` in `GetJobLogsHandler` (`internal/api/job_handlers.go:479`).
  3. Replaced direct field read `if job.Status.IsTerminal()` with `if job.GetStatus().IsTerminal()` in `CancelJobHandler` (`internal/api/job_handlers.go:518`).
- **Result & Non-Regression Test**: Verified by `go test -race -v ./internal/api/...` under WSL Ubuntu 24.04 passing 100% with 0 data races, and `go test -v -cover ./...` on Windows passing 432/432 tests across all 11 packages.

### `RCA-042` — Asynchronous Job Process-Tree Cancellation Latency on Windows Under Multi-Core Test Concurrency
- **Date**: `2026-11-09`
- **Observed Symptom**: During high-concurrency stress testing (`internal/jobs/m1_stress_challenge_test.go` and `tests/e2e/tier3_cross_feature_test.go`) on Windows hosts under full multi-core parallel execution, cancelling an active asynchronous job occasionally exceeded tight 200ms test assertion timeouts.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did job cancellation take longer than 200ms on Windows?* Terminating a process tree on Windows requires spawning an external helper executable (`taskkill.exe /T /F /PID <pid>`), unlike Unix where `syscall.Kill(-pgid, syscall.SIGKILL)` is an instant in-kernel syscall (~1-5ms).
  2. *Why was taskkill delayed?* Under intense CPU saturation (multiple parallel packages running `go test`), Windows process creation and executable loading for `taskkill.exe` incur scheduling latency up to 300–500ms.
  3. *Why did child process stdout/stderr pipes delay command termination?* If child processes spawned sub-children holding inherited stdout/stderr file handles open, Go's `cmd.Wait()` blocked until pipe EOF unless an explicit exit deadline was enforced.
  4. *How did this impact command classification?* If context cancellation raced with command completion, `err` returned by `exec.CommandContext` could be ambiguous without explicit `errors.Is(ctx.Err(), context.Canceled)` probing.
  5. *Root Cause*: Operating system disparity in process tree termination primitives (Windows `taskkill` vs Unix process group signal) exacerbated by stdout/stderr pipe descriptor retention under multi-core parallel test load.
- **Applied Change / Fix**:
  1. Configured `cmd.WaitDelay = 200 * time.Millisecond` in `internal/core/executor.go` to ensure child processes holding inherited pipe handles do not block termination indefinitely.
  2. Implemented `ErrCommandCancelled` and `IsCommandCancelled` in `internal/core/executor.go` to deterministically classify cancelled commands.
  3. Calibrated test polling intervals to 10ms and cancellation latency thresholds to 800ms for parallel Windows test suites, while maintaining sub-second SLA in production.
  4. Verified in `tests/e2e/setup_test.go` via `pollJobTerminal` with a safe 5-second deadline.
- **Result & Non-Regression Test**: Verified by `TestTier3_Combination_AsyncJob_ImmediateCancellationSubprocessTreeKill` in `tests/e2e/tier3_cross_feature_test.go` and `TestChallenger_Engine_CancellationLatency` in `internal/jobs/m1_stress_challenge_test.go` passing 100% on both Windows and Linux.

### `RCA-043` — Windows Process-Tree Cancellation Delay Causing Backpressure E2E Test Flakiness
- **Date**: `2026-11-09`
- **Observed Symptom**: During empirical challenger verification of release v2.1.0, `go test -v ./tests/e2e/...` failed on Run 1 with exit code 1 (`TestTier2_Boundary_Jobs_QueueCapacityBackpressure` failed at `tier2_boundary_test.go:456: expected 202 Accepted after queue drained, got 429: {"error":"Queue capacity exceeded"}`).
- **Root Cause Analysis (5 Whys)**:
  1. *Why did the test fail with HTTP 429?* Because the queue was still at maximum capacity (`queued_jobs == 2`) when `httpSubmitJob` was called.
  2. *Why was the queue still full after calling `httpCancelJob`?* Because the cancellation request had not completed process termination: the worker had not yet killed the blocker process, updated the job status to `cancelled`, and dequeued the next waiting job.
  3. *Why was process termination delayed?* On Windows, terminating a process tree spawns `taskkill.exe /T /F /PID <pid>`. Under concurrent test execution and CPU pressure, launching and executing `taskkill.exe` plus OS pipe closing takes up to 600–800ms.
  4. *Why was a fixed sleep used?* The test author assumed a 500ms sleep would always suffice for process teardown and worker queue drainage.
  5. *Root Cause*: Relying on a fixed delay (`time.Sleep(500 * time.Millisecond)`) for an asynchronous multi-process teardown sequence on an operating system with non-deterministic process termination latency (Windows), rather than an active polling loop with a bounded timeout.
- **Applied Change / Fix**:
  In `tests/e2e/tier2_boundary_test.go`, replaced the fixed 500ms sleep with a bounded queue polling loop (evaluating every 50ms up to a 3-second deadline) until `queued_jobs < QueueCapacity` before submitting the subsequent job.
- **Result & Non-Regression Test**:
  Verified by `go test -v -run TestTier2_Boundary_Jobs_QueueCapacityBackpressure -count=5 ./tests/e2e/...` and `go test -v ./tests/e2e/...` passing 100% deterministically across consecutive runs on Windows.

### `RCA-044` — Developer-Time Swaggo Code Generation Invocation During Container Build Causing Docker Build Failure and Build Slowdowns
- **Date**: `2026-11-09`
- **Observed Symptom**:
  Executing `docker build -t api-executor:test .` failed at build step `RUN swag init -g cmd/server/main.go` with exit code 1:
  `Error parsing type definition 'jobs.Job': [timeout]: cannot find type definition: time.Duration`
  `Error parsing type definition 'api.JobListResponse': [jobs]: jobs.Job: [timeout]: cannot find type definition: time.Duration`
  `ParseComment error in file /app/internal/api/job_handlers.go for comment: '// @Success 200 {object} JobListResponse "OK"': JobListResponse: [jobs]: jobs.Job: [timeout]: cannot find type definition: time.Duration`
  In addition, `RUN go install github.com/swaggo/swag/cmd/swag@latest` in `Dockerfile` incurred 26+ seconds of redundant network package downloads on every non-cached build, and could cause build timeouts under multi-arch QEMU emulation.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did `swag init` fail?* Because `swag init` in `Dockerfile:18` lacked the `--parseInternal` flag required to parse type definitions in package `jobs.Job`.
  2. *Why was `swag init` running in Dockerfile?* It was included in the multi-stage build instructions to ensure Swagger artifacts were up to date before compiling the server binary.
  3. *Was `swag init` required at container build time?* No; Swagger documentation artifacts (`docs/docs.go`, `docs/swagger.json`, `docs/swagger.yaml`) are development-time artifacts that are already generated, committed to the Git repository, and imported directly into `cmd/server/main.go` via `_ "go-admin-tool/docs"`.
  4. *What was the performance impact?* Every fresh build downloaded and compiled `swag@latest` (downloading ~20 external Go modules), adding significant overhead and breaking cross-architecture compilation under QEMU.
  5. *Root Cause*: Architectural anti-pattern of invoking development-time code generation tooling (`swag init`) during production container image compilation when generated artifacts are already checked into source control.
- **Applied Change / Fix**:
  1. Removed `RUN go install github.com/swaggo/swag/cmd/swag@latest` and `RUN swag init -g cmd/server/main.go` from `Dockerfile`.
  2. Maintained the canonical development-time Swagger generation workflow in `Makefile` (`swag init -g cmd/server/main.go --parseInternal`).
  3. Preserved existing static Swagger artifacts in `docs/` and import in `cmd/server/main.go`.
- **Result & Non-Regression Test**:
  Verified by `docker build -t api-executor:test .` building cleanly with zero errors, and `go test -v ./docs -run "TestSVGAssetsAreValidXMLAndREADMEIncludesBranding|TestDockerHygieneAndIgnoreRules"` passing 100%.

### `RCA-045` — Omission of Cross-Compiled Binary Deliverables and Automated Workflow Execution on GitHub Release v2.1.0 Publication
- **Date**: `2026-11-12`
- **Observed Symptom**: GitHub Release `v2.1.0` (`tag/v2.1.0`) was published with `"assets": []`, requiring end users to compile the project from source code archives. Additionally, `.github/workflows/release.yml` was configured only with `on: release: types: [published]`, which does not trigger retroactively for previously published tags, was missing standard `push: tags: ['v*']` triggers, and cross-compiled only 4 architectures (omitting `darwin/amd64` and `windows/arm64`).
- **Root Cause Analysis**:
  1. *Why were no precompiled binaries present in release v2.1.0?* The release was published on Nov 9 before automated release workflows were created.
  2. *Why was the release workflow not executed?* `.github/workflows/release.yml` was only authored on Nov 10 in `ACT-052` (PR #105), subsequent to the tag publication.
  3. *Why did subsequent tag pushes not trigger release builds?* The workflow lacked a `push: tags: ['v*.*.*', 'v*']` event trigger.
  4. *Why did manual `workflow_dispatch` skip asset uploads?* The upload job was guarded with `if: github.event_name == 'release'`, skipping asset publishing on manual dispatch or push events.
  5. *Why were target platforms incomplete?* Initial cross-compilation matrix omitted Intel macOS (`darwin/amd64`) and Windows ARM64 (`windows/arm64`).
- **Applied Change / Fix**: Upgraded `.github/workflows/release.yml` to trigger on `push: tags: ['v*.*.*', 'v*']`, `workflow_dispatch`, and `release: types: [published]`; expanded the matrix to all 6 platforms (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`); updated upload gates to support tag pushes and dispatch; added `.github/workflows/docker-publish.yml` for automated multi-arch Docker image publication; and prepared standalone archive packaging for `v2.1.0` assets via `gh release upload`.
- **Result & Non-Regression Test**: Validated YAML syntax for `.github/workflows/release.yml` and `.github/workflows/docker-publish.yml`; full matrix build definitions verified; 100% test suite pass across unit, E2E, and documentation suites (`go test -v -cover ./...` and `go test -v ./tests/e2e/...`).

### `RCA-046` — Actionlint Schema Failure on `steps.meta.outputs.created` and Release Tag Filter Asymmetry in Docker Workflow
- **Date**: `2026-11-12`
- **Observed Symptom**:
  Adversarial validation with `actionlint` failed on `.github/workflows/docker-publish.yml` with exit code 1:
  `property "created" is not defined in object type {annotations: string; bake-file: string; bake-file-annotations: string; bake-file-labels: string; bake-file-tags: string; json: string; labels: string; tag-names: string; tags: string; version: string} [expression]` at line 78.
  In addition, tag pattern analysis revealed that `docker-publish.yml` listened only to `push: tags: ['v*.*.*']`, whereas `release.yml` listened to `['v*']`, creating release divergence where shortened semantic tags (e.g. `v2.1`) trigger binary packaging but fail to trigger Docker image publishing.
  Finally, inline secret interpolation in `if [ -z "${{ secrets.DOCKERHUB_USERNAME }}" ]` breached CI/CD shell security best practices.
- **Root Cause Analysis**:
  1. *Why did actionlint fail?* `docker/metadata-action@v5` does not define a top-level `created` output property. It encodes creation timestamps within `labels` (`org.opencontainers.image.created`) or raw `json`.
  2. *Why was `created` passed in build-args?* An assumption was made that `metadata-action` mirrors all standard OCI build arguments as direct step outputs.
  3. *Why did tag filter divergence occur?* `release.yml` used a broad glob (`v*`), while `docker-publish.yml` used a strict 3-segment glob (`v*.*.*`), omitting valid 2-segment semantic releases like `v2.1`.
  4. *Why were secrets interpolated into bash?* The verification script checked secret presence using direct template interpolation `${{ secrets... }}` inside `run: |` rather than step `env:` variables.
  5. *What is the risk of inline secret interpolation?* Untrusted or special characters (`"`, `$`, `\`) can lead to bash syntax breakage or injection vulnerabilities.
- **Applied Change / Fix**:
  1. Removed `CREATED=${{ steps.meta.outputs.created }}` from `build-args` in `.github/workflows/docker-publish.yml`, relying on `labels: ${{ steps.meta.outputs.labels }}` for standard OCI creation timestamping.
  2. Expanded `push: tags` in `.github/workflows/docker-publish.yml` to `['v*.*.*', 'v*.*', 'v*']`, harmonizing triggers with `release.yml`.
  3. Mapped `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` via step `env:` variables (`DOCKERHUB_USER`, `DOCKERHUB_PASS`) in `docker-publish.yml`.
- **Result & Non-Regression Test**:
  - `actionlint .github/workflows/docker-publish.yml` exits with code 0 (clean).
  - Python `fnmatch` confirms tags `v2.1.0`, `v2.1`, `v2` match both `release.yml` and `docker-publish.yml`.
  - 100% test pass on Go unit, E2E, and documentation suites (`go test -v -cover ./...` and `go test -v ./tests/e2e/...`).

### `RCA-047` — Linux CI Test Failure in `TestChallenger_RecursiveDirectoryDiscovery_DeepAndMixed` Caused by Symlink Target Inside Scanned Directory Tree
- **Date**: `2026-11-12`
- **Observed Symptom**:
  On GitHub Actions Linux CI runners (`Test & Build` job) and local WSL Ubuntu-24.04, `TestChallenger_RecursiveDirectoryDiscovery_DeepAndMixed` in `internal/plugins/m1_stress_challenge_test.go` failed with:
  `LoadDeclarativeDirectory failed unexpectedly: plugin already registered: plugin with ID "deep-sysadmin" is already registered`.
  Meanwhile, the test passed on local Windows host without failure.
- **Root Cause Analysis**:
  1. *Why did the test fail on Linux but pass on Windows?* On Windows, unprivileged user accounts cannot create symbolic links without Developer Mode, so `_ = os.Symlink(...)` returned an error and was silently ignored. On Linux, unprivileged users can create symlinks, so the symlink was successfully created.
  2. *Why was a duplicate plugin ID encountered?* The test created a symlink `tmpDir/netops/symlinked.yaml` pointing to `tmpDir/sysadmin/a/b/c/d/deep.yaml`. Both the symlink and the original target file resided within the same scanned root `tmpDir`.
  3. *Why did `LoadDeclarativeDirectory` encounter the plugin twice?* `filepath.WalkDir` walked the entire directory tree. In lexical order, `netops/symlinked.yaml` was visited first; `os.ReadFile` dereferenced the symlink and loaded `deep.yaml` with `id: deep-sysadmin`. Next, `sysadmin/a/b/c/d/deep.yaml` was visited and read with the identical `id: deep-sysadmin`.
  4. *Why did registration fail?* `Registry.Register` strictly enforces plugin ID uniqueness and returns `ErrDuplicatePlugin`.
  5. *What was the design flaw in the test?* The symlink target was placed inside the discovery directory tree rather than an external directory, conflating directory traversal with duplicate file detection.
- **Applied Change / Fix**:
  1. Isolated the symlink target by writing `external.yaml` (`id: external-symlink`) into a separate temporary directory (`outsideDir := t.TempDir()`).
  2. Created the symlink `tmpDir/netops/symlinked.yaml` targeting `outsideDir/external.yaml`.
  3. Added an explicit assertion verifying that when `symlinkCreated` is true, `external-symlink` is registered with inferred category `"NetOps"`.
  4. Preserved non-privileged fallback when symlink creation is not permitted by host OS.
- **Result & Non-Regression Test**:
  - `go test -v ./internal/plugins -run TestChallenger_RecursiveDirectoryDiscovery_DeepAndMixed` passes on both Windows and WSL Ubuntu-24.04 (exit code 0).
  - 100% test pass on Go unit and E2E suites (`go test -v -cover ./...` and `go test -v ./tests/e2e/...`).

### `RCA-048` — CommonMark Indented Code Block Collapse from Workflow Heredoc Leading Indentation
- **Date**: `2026-11-12`
- **Observed Symptom**:
  When `.github/workflows/release.yml` generated `dist/RELEASE_NOTES_VERIFICATION.md` using an inline bash heredoc `cat << 'EOF'`, every line was indented with 10 spaces to match YAML scalar block formatting. Under CommonMark specification (GitHub Flavored Markdown), any block indented by 4 or more spaces is parsed as an indented code block (`<pre><code>`). Consequently, the headings (`### Cryptographic Checksum Verification`), bullet lists, and fenced code blocks failed to render as HTML and appeared as a raw monospace code block on GitHub Releases.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did release notes render as a raw code block?* Because every line in `RELEASE_NOTES_VERIFICATION.md` started with 10 spaces.
  2. *Why were there 10 spaces?* The heredoc body was indented inside the GitHub Actions YAML `run: |` block without an un-indentation filter.
  3. *Why was heredoc indentation used?* The author styled the workflow YAML for visual alignment with parent YAML step indentation.
  4. *Why did standard tests not catch it?* Unit tests only asserted that `body_path: dist/RELEASE_NOTES_VERIFICATION.md` was referenced; they did not inspect the rendered output or verify column-0 markdown structure.
  5. *Root Cause*: Generating markdown release notes via an inline indented heredoc without stripping leading whitespace, violating CommonMark column-0 requirements.
- **Applied Change / Fix**:
  Created a dedicated, tracked template `.github/RELEASE_NOTES_VERIFICATION.md` with column-0 unindented markdown, leading newline separation, and macOS `shasum -a 256` documentation. Updated the release workflow step to copy `.github/RELEASE_NOTES_VERIFICATION.md` directly into `dist/`. Added test assertions in `docs/branding_test.go` ensuring zero leading indentation before markdown headings and code fences.
- **Result & Non-Regression Test**:
  Verified by `TestReleaseWorkflowChecksumDeliverablesAndREADMEHygiene` in `docs/branding_test.go` confirming all markdown headers and code blocks begin at column 0.

### `RCA-049` — Unmatched Shell Glob Failure on Partial Matrix in Checksum Generation (`set -e`)
- **Date**: `2026-11-12`
- **Observed Symptom**:
  Executing `sha256sum api_executor-*.tar.gz api_executor-*.zip > SHA256SUMS.txt` aborted with exit code 1 (`sha256sum: api_executor-*.zip: No such file or directory`) whenever a build run produced only tar.gz archives (e.g., partial matrix, single-platform test dispatch, or filtered build).
- **Root Cause Analysis (5 Whys)**:
  1. *Why did sha256sum fail?* Bash passed the literal string `api_executor-*.zip` as an argument because no matching files existed in `dist/`.
  2. *Why did bash pass the literal string?* In bash, default glob behavior leaves unmatched globs unexpanded as literal strings rather than resolving to empty strings.
  3. *Why did the step abort?* GitHub Actions runs bash scripts with `set -e`, treating any non-zero exit code as a fatal workflow failure.
  4. *Why did the loop not fail?* The previous loop used `[ -f "$file" ] || continue`, but the manifest command `sha256sum api_executor-*.tar.gz api_executor-*.zip` lacked glob protection.
  5. *Root Cause*: Executing `sha256sum` with multiple fixed extension globs without enabling `shopt -s nullglob`.
- **Applied Change / Fix**:
  Added `shopt -s nullglob` immediately before archive iteration and manifest generation in `.github/workflows/release.yml`, ensuring unmatched glob patterns expand to nothing instead of literal non-existent file paths.
- **Result & Non-Regression Test**:
  Verified via WSL bash simulation with single-archive inputs (exit code 0) and asserted `shopt -s nullglob` in `docs/branding_test.go`.

### `RCA-050` — Stdin Hang on `sha256sum` with `nullglob` on Zero Matched Archives, Broken Release Notes Link, and Missing Windows Manifest Verification
- **Date**: `2026-11-12`
- **Observed Symptom**:
  In `.github/workflows/release.yml`, when `download/` contained zero release archives (e.g., failed artifact download, single-platform dry runs, or empty artifact directory), `shopt -s nullglob` expanded `api_executor-*.tar.gz api_executor-*.zip` to zero positional arguments. `sha256sum > SHA256SUMS.txt` was then invoked without operands, reading from standard input (stdin) and hanging indefinitely until GitHub Actions runner timeout (up to 360 minutes). Furthermore, `.github/RELEASE_NOTES_VERIFICATION.md` contained a broken relative link `[SHA256SUMS.txt](SHA256SUMS.txt)` that returned HTTP 404 on GitHub Releases, and omitted Option B (manifest verification via `Select-String`) in Windows PowerShell guidance.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did sha256sum hang indefinitely?* `sha256sum` was invoked with zero positional arguments because both globs expanded to empty strings under `shopt -s nullglob`.
  2. *Why did sha256sum wait on stdin instead of erroring?* By POSIX and GNU coreutils specification, `sha256sum` defaults to reading standard input when no file operand is supplied.
  3. *Why was the array not validated before invoking sha256sum?* The step assumed at least one archive would always be downloaded, failing to guard against an empty array.
  4. *Why was the relative link broken on GitHub Releases?* Release notes are rendered in the context of `/releases/tag/<tag>`, where `(SHA256SUMS.txt)` resolves as a relative URL (`/releases/tag/SHA256SUMS.txt`) rather than pointing to release assets.
  5. *Root Cause*: Lack of zero-argument array bounds checking before invoking `sha256sum`, and using relative file paths in GitHub Release notes.
- **Applied Change / Fix**:
  1. Populated bash array `archives=(api_executor-*.tar.gz api_executor-*.zip)` and added an explicit check `if [ ${#archives[@]} -eq 0 ]; then echo "Error: No release archives found..." >&2; exit 1; fi`.
  2. Guarded checksum files check with `ckfiles=(api_executor-*.sha256)` before verification.
  3. Set `fail_on_unmatched_files: false` in `softprops/action-gh-release@v2`.
  4. Replaced broken relative link `[SHA256SUMS.txt](SHA256SUMS.txt)` with code formatting `` `SHA256SUMS.txt` `` in `.github/RELEASE_NOTES_VERIFICATION.md`.
  5. Added Option B Windows PowerShell manifest verification in `.github/RELEASE_NOTES_VERIFICATION.md`.
  6. Expanded `TestReleaseWorkflowChecksumDeliverablesAndREADMEHygiene` in `docs/branding_test.go` to assert archive presence checks, relative link ban, and Option B manifest verification.
- **Result & Non-Regression Test**:
  Verified via WSL bash simulation (zero archives returns exit code 1 immediately with error message instead of hanging; non-empty archives succeed with exit code 0) and Go tests in `docs/branding_test.go`.

### `RCA-051` — Excessive Workflow-Level `contents: write` Permissions and Missing Job-Level Trigger Constraint in Release Workflow
- **Date**: `2026-11-12`
- **Observed Symptom**:
  In `.github/workflows/release.yml`, `permissions: contents: write` was declared globally at the workflow root, granting repository write tokens to all 6 matrix runners (`linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`, `windows-amd64`, `windows-arm64`) in the `build-binaries` job. Furthermore, `publish-github-release` lacked an `if` condition at the job level; the trigger check was present only on the final step (`Attach Assets to GitHub Release`), causing the release job runner to be provisioned, artifacts downloaded, and checksums computed even if no release was to be published.
- **Root Cause Analysis (5 Whys)**:
  1. *Why did matrix build runners receive write tokens?* The workflow declared `contents: write` at the root rather than at the specific job level.
  2. *Why was root write permission specified?* Initial authoring set write permissions globally for the release step without scoping down build jobs.
  3. *Why does this violate security standards?* Under the Principle of Least Privilege and GitHub Actions hardening guidelines, build runners compiling code and downloading dependencies should never hold write access to repository contents.
  4. *Why did publish-github-release run steps when not publishing?* The `if` condition was placed at the step level instead of the job level.
  5. *Root Cause*: Lack of job-level permission isolation (`contents: read` global vs `contents: write` job-level) and absent job-level `if` guard on `publish-github-release`.
- **Applied Change / Fix**:
  1. Configured top-level `permissions: contents: read` in `.github/workflows/release.yml`.
  2. Explicitly assigned `permissions: contents: write` to `publish-github-release`.
  3. Added job-level `if: startsWith(github.ref, 'refs/tags/v') || github.event_name == 'release' || github.event_name == 'workflow_dispatch'` to `publish-github-release`.
  4. Expanded regression test `TestReleaseWorkflowChecksumDeliverablesAndREADMEHygiene` in `docs/branding_test.go` to assert least-privilege permissions and job-level trigger constraints.
- **Result & Non-Regression Test**:
  Verified via YAML parser (`python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`) and Go tests in `docs/branding_test.go`.

### `RCA-052` — Unbounded HTTP Request Bodies (`CWE-400`), Missing Per-IP Rate Limiting (`CWE-770`), Fail-Open `resolvePrincipal` When `AuthManager == nil` (`CWE-287`), and Missing `mcp:access` Check on MCP Trace Read Endpoints (`CWE-862`)
- **Date**: `2026-11-12`
- **Observed Symptom**:
  During the `/repo-scan` and `/ponytail-audit` security audit of `internal/api` (Issue #126):
  1. None of the 12 JSON `POST`/`PUT`/`PATCH` handlers bounded `r.Body` with `http.MaxBytesReader`, allowing an attacker to send a multi-gigabyte JSON body or chunked stream to exhaust server heap memory (`CWE-400`).
  2. No per-IP HTTP rate limiter was wired into `NewRouter`, allowing volumetric request floods or `/api/v1/auth/login` brute-force floods from a single IP without `429 Too Many Requests` throttling (`CWE-770`).
  3. `resolvePrincipal` in `internal/api/auth_handlers.go` checked `env.Config.Auth.Enabled && env.Config.Auth.RequireAuth && env.AuthManager != nil`; if `RequireAuth` was `true` while `AuthManager` was `nil` or `Auth.Enabled` was `false`, `resolvePrincipal` fell through and returned an `anonymous` principal with `commands:execute`, `plugins:execute`, `mcp:access`, and `jobs:submit` scopes (`CWE-287`).
  4. `MCPTracesHandler` (`GET /api/v1/mcp/traces`) and `MCPTraceByIDHandler` (`GET /api/v1/mcp/traces/{trace_id}`) called `resolvePrincipal` but did not verify `auth.Authorize(p, "mcp:access", "")`, allowing a `viewer` principal without `mcp:access` to read all MCP interaction traces (`CWE-862`).
- **Root Cause Analysis (5 Whys)**:
  1. *Why were request bodies unbounded?* Handlers called `json.NewDecoder(r.Body).Decode(&req)` directly on the raw `net/http` stream without a centralized middleware applying `http.MaxBytesReader`.
  2. *Why was rate limiting absent on HTTP routes?* Backpressure was previously implemented at the async job queue (`QueueCapacity = 1000`) and subprocess timeout layers, but not at the HTTP ingress layer per client IP.
  3. *Why could `resolvePrincipal` fail open when `RequireAuth: true`?* The guard coupled `RequireAuth` to `Auth.Enabled && env.AuthManager != nil` in a single conditional instead of failing closed whenever `RequireAuth` is true and no authenticated principal can be resolved.
  4. *Why did `GET /api/v1/mcp/traces` allow `viewer` access?* `MCPTracesHandler` only enforced `p.Role == auth.RoleAdmin` on `DELETE` and omitted `auth.Authorize(p, "mcp:access", "")` on `GET`.
  5. *Root Cause*: Lack of a centralized HTTP security middleware (`securityMiddleware`) for body caps, per-IP rate limiting, and defensive headers, combined with incomplete fail-closed/scope checks in `resolvePrincipal` and `MCPTracesHandler`.
- **Applied Change / Fix**:
  1. Created `internal/api/security_middleware.go` implementing defensive HTTP headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Permitted-Cross-Domain-Policies: none`, `Strict-Transport-Security`), `IPRateLimiter` (per-IP token bucket with `MaxTrackedRateLimitIPs = 10000` and stale-entry eviction returning `429 Too Many Requests`), and `MaxRequestBodyBytes = 1 MiB` request body bounding returning `413 Request Entity Too Large`.
  2. Hardened `resolvePrincipal` in `internal/api/auth_handlers.go` to fail closed (`return nil, auth.ErrInvalidToken`) whenever `env.Config != nil && env.Config.Auth.RequireAuth` and no valid credential is provided or `AuthManager` is unavailable.
  3. Added `auth.Authorize(p, "mcp:access", "")` enforcement to `MCPTracesHandler` (`GET`) and `MCPTraceByIDHandler` (`GET`) in `internal/api/mcp_handlers.go`.
  4. Added `internal/api/security_audit_test.go`, `.github/workflows/security.yml`, and root `SECURITY.md`.
- **Result & Non-Regression Test**:
  Verified by `TestAPISecurityAudit_UnauthorizedAccessMatrix`, `TestAPISecurityAudit_PrivilegeEscalationAndForbiddenMutations`, `TestAPISecurityAudit_InjectionAndConfinementPrevention`, and `TestAPISecurityAudit_DDoSRateLimitAndResourceExhaustion` in `internal/api/security_audit_test.go` (100% pass).

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

### `IMP-007` — Unbounded Dynamic Job ID or Action Labels in Prometheus Metrics
- **Reason for Abandonment**: Registering dynamic Prometheus labels such as unique UUID `job_id` or unvalidated user-supplied `action` strings on gauges or counters (`job_executions_total{job_id="..."}`) causes an unbounded time-series cardinality explosion ($O(N)$ memory growth), which can exhaust server memory in Prometheus/Grafana. Replaced with normalized route patterns (`/api/v1/jobs/:id`, `/api/v1/jobs/:id/logs`, `/api/v1/jobs/:id/cancel`) in `normalizeMetricPath` and bounded action labels via `normalizeActionLabel` capped at `MaxDynamicActionLabels = 64` with fallback to `"other"`.

### `IMP-008` — Raw String Interpolation or Unbounded In-Memory Buffering for Live Process Log Streaming
- **Reason for Abandonment**: Streaming process stdout/stderr via raw string concatenation (`str += chunk`) creates quadratic GC heap churn ($O(N^2)$ allocations), and unbounded buffering risks out-of-memory crashes (OOM) if a subprocess outputs hundreds of megabytes. Replaced with `JobLogBuffer` enforcing a strict memory ceiling (`DefaultMaxLogBytes = 2 MiB`), overflow ring draining, deterministic `[output truncated]` marker, and offset-based chunked read semantics (`GET /api/v1/jobs/{id}/logs?offset=X`) returning `next_offset` and `eof`.

### `IMP-009` — Uploading Unbundled Raw Executables Directly to GitHub Releases Without Manifests or Runtime Assets
- **Reason for Abandonment**: Uploading standalone raw executables (`go-admin-tool`, `go-admin-tool.exe`) directly as release assets without bundling companion runtime dependencies (`config.yaml`, the 305+ plugins in `plugins/`, the Web Console in `web/`, `LICENSE`, `README.md`) causes runtime failures (HTTP 404 on Web Console, missing plugin commands, uninitialized configs) when users execute the binary. Furthermore, releasing without a cryptographic checksums manifest (`SHA256SUMS.txt`) prevents automated integrity verification. Release deliverables must strictly be packaged into self-contained directory archives (`.tar.gz` for Linux/macOS, `.zip` for Windows) containing the executable and all runtime assets, verified by `SHA256SUMS.txt`.

### `IMP-010` — Passing Non-Existent Step Outputs to Docker Build-Args
- **Reason for Abandonment**: Attempting to pass `${{ steps.meta.outputs.created }}` from `docker/metadata-action@v5` into `docker/build-push-action@v6` build-args causes static analysis failure under `actionlint` (exit code 1) and injects an empty string argument (`CREATED=""`). Since `docker/metadata-action` already generates standard OCI labels (including `org.opencontainers.image.created`) in `steps.meta.outputs.labels`, passing `CREATED` as a build argument is both invalid and redundant.

### `IMP-011` — Using Unpinned Latest-Only Container Image References in Production Documentation
- **Reason for Abandonment**: Documenting only `jmrenouard/api_executor:latest` without pinning explicit immutable semantic release tags (`jmrenouard/api_executor:v2.1.0`) prevents reproducible deployments, makes container rollback unmanageable, and risks breaking production environments when new major or breaking updates are published. Best practices require documenting explicit immutable semantic tags (`:v2.1.0`) as the primary target alongside `:latest`.

### `IMP-012` — Pushing Multi-Architecture Container Images Without BuildKit / Buildx Manifest Lists or Unauthenticated Push
- **Reason for Abandonment**: Attempting to push container images to Docker Hub (`jmrenouard/api_executor`) without authenticated credentials fails immediately with HTTP 401/403 (`denied: requested access to the resource is denied`). Furthermore, utilizing standard legacy `docker build` and `docker push` only builds and publishes an image for the host CPU architecture (e.g. `linux/amd64`), overwriting or lacking multi-architecture OCI manifest lists (`linux/amd64` and `linux/arm64`). Modern production deployments require multi-platform container images to be compiled and pushed as an OCI manifest list using Docker Buildx (`docker buildx build --platform linux/amd64,linux/arm64 --push ...`) or via GitHub Actions `docker/build-push-action@v6` with configured credentials.

### `IMP-013` — Hardcoding Release-Specific Hashes and Checksum Matrices in Repository README
- **Reason for Abandonment**: Embedding immutable cryptographic hashes and download tables for a specific release (e.g. v2.1.0) directly into root documentation (`README.md`) creates maintenance toil, causes documentation rot as soon as newer versions are published, and contradicts the principle that immutable release artifacts belong strictly in GitHub Release assets and release notes. Release deliverables must be verified using generic, templated instructions, and release checksums (`SHA256SUMS.txt`, `<archive>.sha256`) must be attached directly to the GitHub Release.

### `IMP-014` — Unbounded Per-IP Rate Limiter Maps Without Eviction Under Spoofed-IP Floods
- **Reason for Abandonment**: A naive `map[string]*tokenBucket` per-IP rate limiter that never evicts entries can itself become a memory exhaustion DDoS vector if an attacker sends requests with millions of spoofed `RemoteAddr` or `X-Forwarded-For` addresses. Replaced in `internal/api/security_middleware.go` with `IPRateLimiter` capped at `MaxTrackedRateLimitIPs = 10000` with stale-bucket eviction (`RateLimitStaleTTL = 10m`) and oldest-entry eviction when capacity is reached.

---

## 3. Current Approximations & Simplifying Assumptions (`APP-XXX`)

| ID | Module | Approximation / Assumption | Impact | Condition for Removal |
|---|---|---|---|---|
| `APP-001` | `internal/database`, `internal/jobs` | SQLite local file storage (`history.db`) for `action_history` and `job_history`, with pure-Go in-memory fallback (`MemoryJobStore`) when compiled with `CGO_ENABLED=0`. | Single-node persistence; in-memory mode resets on process restart. | Enable CGO in container builds or add pure-Go SQLite / PostgreSQL driver. |
| `APP-002` | `internal/core/tls` | Self-signed ECDSA P-256 certificate generated by default when no external CA-signed cert is mounted. | Browsers and `curl` require `-k` or downloading `/api/v1/tls/certificate` into trust store. | Mount enterprise PKI certificate or enable ACME (`IDEA-002`). |
| `APP-003` | `internal/audit` | Sliding window in-memory audit cache (`MaxMemoryLog = 1000`) alongside optional JSONL file / SQLite table. Cryptographic SHA-256 tamper-evident chaining verified across `Category: "job"`. | In-memory query window is bounded to prevent heap growth; tamper-evident verification covers complete lifecycle (`job.enqueued`, `job.started`, `job.completed`, `job.cancelled`). | Query persistent SQLite/SIEM store for historical archives beyond 1,000 events. |
| `APP-004` | `internal/auth` | Pure-Go iterated SHA-256 (10,000 rounds + 128-bit random salt) password hashing and `RequireAuth: false` default unless configured. | Avoids external `golang.org/x/crypto` dependency while preserving backward compatibility for unauthenticated local configs. | Set `auth.require_auth: true` in production and optionally migrate to Argon2id (`IDEA-001`). |
| `APP-005` | `internal/plugins` | `db-exposure` simulates `SELECT` projection over `action_history` when running in pure-Go in-memory fallback mode (`db.Conn() == nil`). | Ensures identical read-only SQL validation and deterministic test/runtime behavior even when compiled with `CGO_ENABLED=0`. | Compile with CGO SQLite or connect to an external SQL engine. |
| `APP-006` | `internal/mcp` | Synchronous HTTP JSON-RPC 2.0 transport (`POST /api/v1/mcp`) with bounded in-memory ring buffer (`MaxTraces = 500`) + SQLite/JSONL persistence. | Request/response RPC calls complete in a single HTTP round-trip without requiring long-lived SSE state. | Add Streamable HTTP / SSE server-initiated notification transport if bidirectional MCP server-to-client sampling is required (`IDEA-005`). |
| `APP-007` | `web/static` | Single-file zero-build Web Administration Console (`web/static/index.html`) using Alpine.js and Tailwind CSS via CDN. | Requires no Node.js/npm build step; air-gapped deployments without internet access need vendored static CSS/JS assets. | Vendor Alpine.js and compiled CSS into `web/static/vendor/` for offline air-gapped environments. |
| `APP-008` | `tests/e2e` | Synthetic domain catalog fixtures pre-populated in test harness to guarantee 300+ plugins across 10 domains. | Allows full catalog scale and multi-domain operations testing before domain pack manifests are integrated into `plugins/`. | Fully fulfilled and replaced in Milestones 2, 3, and 5 by 281 live filesystem declarative plugin YAML manifests and 24 native pure-Go plugins (total 305/306 plugins). |
| `APP-009` | `internal/jobs` | In-memory log buffer retained per active job bounded to 2 MiB (`DefaultMaxLogBytes = 2 MiB`), with completed log eviction upon engine pruning. | Bounded memory consumption; historical logs after memory eviction rely on output summaries stored in `JobStore`. | Add persistent chunked log archive to disk or object storage if unbounded historical log retrieval is needed (`IDEA-007`). |
| `APP-010` | `internal/api` | In-memory chunked log streaming via `JobLogBuffer` returns `eof=true` and empty chunk after buffer eviction, relying on output summary in `JobStore`. | Historical logs after buffer eviction cannot be re-streamed byte-for-byte via the chunked log endpoint. | Add persistent chunked log archive to disk or object storage (`IDEA-007`). |
| `APP-011` | `.github/workflows`, CI/CD | GitHub Actions automated Docker Hub publishing relies on repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. Verified during Milestone M4 execution (`DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` configured in GitHub Secrets; automated workflow `.github/workflows/docker-publish.yml` executed and verified on Docker Hub). For third-party forks or unauthenticated runners, secrets remain absent or restricted, requiring maintainer secrets setup or local authenticated Buildx push. | CI/CD cannot push Docker images from unauthenticated forks without repository secrets; out-of-band releases require maintainer token configuration or local maintainer CLI invocation. | Maintainer sets secrets: `gh secret set DOCKERHUB_USERNAME -b "jmrenouard"` and `gh secret set DOCKERHUB_TOKEN -b "<token>"`, then dispatches `gh workflow run docker-publish.yml -f tag=v2.1.0`, or pushes locally via `docker buildx build --platform linux/amd64,linux/arm64 -t jmrenouard/api_executor:v2.1.0 -t jmrenouard/api_executor:latest --push .`. Alternatively, migrate to `ghcr.io` (`IDEA-013`). |
| `APP-012` | `Dockerfile`, Deployment | Non-root container UID/GID 10001 host volume permissions: Bind-mounted host directories (`./certs`, `./data`, `./secure_files`) must grant write permissions to UID 10001 if the server auto-generates certificates or writes `history.db`. | Auto-generation or database writes fail with permission denied if host directories are owned strictly by root without 10001 write access. | Document named Docker volumes and explicit `chown -R 10001:10001` commands for bind-mounted host volumes. |
| `APP-013` | `internal/api` | Per-IP token-bucket rate limiter (`IPRateLimiter`) maintains state in local process memory (`MaxTrackedRateLimitIPs = 10000`). | Rate limits are enforced per API Executor instance rather than globally across a multi-node horizontal cluster. | Use a shared Redis token-bucket store (`IDEA-015`) or upstream ingress rate limiting (Envoy / NGINX / Cloudflare) in multi-replica deployments. |
| `APP-014` | `internal/api` | Dual-mode Prometheus telemetry partition: unified `action_mode_calls_total` and `action_mode_call_duration_seconds` for sync & async execution while preserving legacy `action_calls_*` and `job_executions_*` intact. | Maintains 100% backward compatibility with legacy dashboards while providing mode-differentiated telemetry; legacy metrics duplicate time-series storage. | Deprecate legacy `action_calls_*` in future v3.0 major release after dashboard migration. |
| `APP-015` | `internal/version` | Build metadata resolution fallback hierarchy when binary is compiled without VCS (`-buildvcs=false`) or outside git repo (falls back to `VERSION` file, `integrity: "untracked"`, `git_commit: "unknown"`, `build_date: "unknown"`). | Guarantees non-failing resolution across local dev, test binaries, and stripped production containers; build commit SHA and exact timestamp are absent when VCS information is disabled. | Build binaries with Git repository present and `-buildvcs=true` or pass linker `-ldflags` during CI/CD. |
| `APP-016` | `internal/core`, `internal/api` | Multi-config profile switching per request governs command suites and metadata; daemon socket bindings (HTTP port, TLS cert manager) remain bound to process startup. | Allows concurrent multi-OS command execution and backward compatibility without requiring multiple daemon instances; port/host changes require restart. | Use upstream ingress / reverse proxy routing if different profiles require separate physical listening ports. |

---

## 4. Unimplemented Ideas & Future Roadmap (`IDEA-XXX`)

| ID | Priority | Target Module | Description |
|---|---|---|---|
| `IDEA-001` | `P2` | `internal/auth` | External OIDC / OAuth2 identity provider federation and Argon2id password KDF. |
| `IDEA-002` | `P2` | `internal/core/tls` | Automatic ACME / Let's Encrypt certificate provisioning. |
| `IDEA-003` | `P3` | `internal/audit` | Remote syslog / OpenTelemetry OTLP sink for audit events. |
| `IDEA-004` | `P3` | `internal/plugins` | Out-of-process gRPC / WebAssembly (WASI) plugin sandboxing for untrusted third-party modules. |
| `IDEA-005` | `P3` | `internal/mcp` | Streamable HTTP / SSE notification stream and stdio CLI bridge for local desktop MCP hosts. |
| `IDEA-006` | `P3` | `web/static` | Virtualized catalog scrolling / infinite scroll for Web Console Tab 5 when plugin ecosystem scales beyond 1,000 plugins. |
| `IDEA-007` | `P2` | `internal/jobs` | Distributed Redis / PostgreSQL queue backend and persistent S3/MinIO chunked log streaming for multi-node deployments. |
| `IDEA-008` | `P2` | `internal/api` | WebSocket / Server-Sent Events (SSE) live push streaming endpoint (`/api/v1/jobs/{id}/stream`) for real-time output and status updates without client HTTP offset polling. |
| `IDEA-009` | `P3` | `internal/jobs` | Job Dependency DAG & Workflow Chaining: Allow defining multi-step workflow pipelines where downstream jobs execute only upon successful completion of prerequisite jobs (e.g., diagnostic run followed by automated remediation). |
| `IDEA-010` | `P3` | `web/static` | Web Console Live Output Terminal via xterm.js: Upgrade Tab 9 log modal with ANSI color escape code rendering and interactive terminal controls. |
| `IDEA-011` | `P3` | `packaging` | Native OS package manager distribution: Homebrew formula for macOS, Winget / Chocolatey manifests for Windows, and automated Debian (.deb) / RPM (.rpm) package generation via GoReleaser or nfpm. |
| `IDEA-012` | `P3` | `packaging/helm` | Production Helm Chart & Kubernetes Operator Manifests: Package an official Helm chart (`charts/api-executor`) with configurable values for ingress TLS, persistent volume claims (PVC) for SQLite `history.db`, horizontal pod autoscaler (HPA), and Prometheus Operator ServiceMonitor. |
| `IDEA-013` | `P2` | `ci/cd`, `packaging/docker` | Multi-Registry Dual Publication (`ghcr.io` + `docker.io`) & Cosign Container Image Signing: Configure automated publishing to GitHub Container Registry (`ghcr.io/jmrenouard/api_executor`) leveraging native `GITHUB_TOKEN` alongside Docker Hub, and sign container image digests with Sigstore Cosign (`cosign sign`) providing cryptographic supply chain attestation (SLSA Level 3). |
| `IDEA-014` | `P3` | `ci/cd`, `packaging` | Automated SLSA Provenance Generation & GitHub Artifact Attestations for Binary Deliverables: Integrate GitHub Actions artifact attestations (`actions/attest-build-provenance@v2`) into `.github/workflows/release.yml` to generate cryptographic build provenance conforming to SLSA Level 3 for all cross-compiled standalone binaries and archives, verifiable via GitHub CLI (`gh attestation verify`). |
| `IDEA-015` | `P3` | `internal/api` | Distributed Redis-Backed Rate Limiting & Adaptive CIDR Reputation Blocking: Extend `IPRateLimiter` with an optional Redis sliding-window backend and automatic temporary ban escalation for IPs that repeatedly trigger `401 Unauthorized` or `429 Too Many Requests`. |
| `IDEA-016` | `P2` | `internal/api`, `internal/jobs` | Dynamic Prometheus Exemplars & OpenTelemetry Trace Correlation: Inject OpenTelemetry trace IDs and W3C `traceparent` contexts into Prometheus exemplars on `action_mode_call_duration_seconds` to link mode-partitioned metric spikes directly to Grafana Tempo / Jaeger traces. |
| `IDEA-017` | `P2` | `internal/version`, `ci/cd` | In-toto / SLSA Provenance Attestation REST Restitution: Expose build provenance cryptographic attestations directly within `GET /api/v1/version` under an `attestation` claim verifying verifiable build supply chain integrity. |
| `IDEA-018` | `P2` | `internal/core`, `internal/api` | Dynamic Multi-Config Hot-Reloading & Remote Profile Sinks: Support file-watcher (fsnotify) automatic reload of secondary profile YAML files and remote Git/HTTP profile fetching. |
