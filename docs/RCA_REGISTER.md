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
| `APP-008` | `tests/e2e` | Synthetic domain catalog fixtures pre-populated in test harness to guarantee 300+ plugins across 10 domains. | Allows full catalog scale and multi-domain operations testing before domain pack manifests are integrated into `plugins/`. | Fully fulfilled and replaced in Milestones 2, 3, and 5 by 281 live filesystem declarative plugin YAML manifests and 24 native pure-Go plugins (total 305/306 plugins). |


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
