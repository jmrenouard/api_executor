# API Executor — Action Logbook (`ACTION_LOGBOOK.md`)

This living governance register tracks all ongoing and completed engineering actions on the **API Executor (`go-admin-tool`)** repository.
In accordance with [`AGENTS.md`](../AGENTS.md) and [`.agents/rules/atomic-workflow.md`](../.agents/rules/atomic-workflow.md), every distinct item is tracked atomically (**1 Item = 1 Issue = 1 Branch = 1 Pull Request = 1 Merge**).

---

## 1. Ongoing Actions (`IN PROGRESS`)

| Action ID | Timestamp (UTC) | Atomic Issue | Branch | Request Summary |
|---|---|---|---|---|
| *(None — all atomic issues `#2` through `#11` and `#22`, `#24`, `#26`, `#28` completed)* | — | — | — | — |

---

## 2. Completed Actions (`COMPLETED`)

### `ACT-014` — Expand Unit and Integration Test Coverage Across Core Packages and REST API Endpoints
- **Timestamp (UTC)**: `2026-10-26T22:04:00Z`
- **GitHub Issue**: [#28](https://github.com/jmrenouard/api_executor/issues/28)
- **Branch**: `test/issue-28-unit-and-api-test-coverage`
- **Request**:
  - Expand unit and integration tests across `internal/core`, `internal/database`, `internal/audit`, `internal/auth`, `internal/plugins`, `internal/mcp`, `internal/api`, and `cmd/server` to achieve >= 85% statement coverage across all internal packages and cover all error/boundary paths.
- **Changes**:
  - Added [`internal/core/logger_test.go`](../internal/core/logger_test.go), [`internal/api/files_test.go`](../internal/api/files_test.go), and [`cmd/server/main_test.go`](../cmd/server/main_test.go).
  - Updated [`internal/core/logger.go`](../internal/core/logger.go), [`cmd/server/main.go`](../cmd/server/main.go), [`internal/database/db_test.go`](../internal/database/db_test.go), [`internal/audit/audit_test.go`](../internal/audit/audit_test.go), [`internal/auth/manager_test.go`](../internal/auth/manager_test.go), [`internal/plugins/plugins_test.go`](../internal/plugins/plugins_test.go), [`internal/mcp/server_test.go`](../internal/mcp/server_test.go), [`internal/api/audit_test.go`](../internal/api/audit_test.go), [`internal/api/auth_test.go`](../internal/api/auth_test.go), [`internal/api/mcp_test.go`](../internal/api/mcp_test.go), [`internal/api/plugin_test.go`](../internal/api/plugin_test.go), [`docs/ACTION_LOGBOOK.md`](ACTION_LOGBOOK.md), and [`docs/RCA_REGISTER.md`](RCA_REGISTER.md).
- **Result**:
  - `go test -v -cover ./...` passing (`docs` 100.0%, `internal/database` 96.2%, `internal/audit` 95.5%, `internal/auth` 94.3%, `internal/mcp` 94.2%, `internal/plugins` 93.0%, `internal/api` 88.4%, `internal/core` 88.2%, `cmd/server` 66.0%).

### `ACT-013` — Align README cURL Examples, `sys-diagnostics` Action Aliases, Dockerfiles, and Governance Registers
- **Timestamp (UTC)**: `2026-10-26T20:09:00Z`
- **GitHub Issue**: [#26](https://github.com/jmrenouard/api_executor/issues/26)
- **Branch**: `fix/issue-26-readme-docker-and-governance-completeness`
- **Request**:
  - Fix `README.md` cURL preset example (`redhat-rpm-qa`), support hyphenated action aliases (`runtime-stats`, `network-interfaces`, `env-summary`) in `sys-diagnostics`, copy `plugins/` and configure `/app/certs` ownership for `appuser` in `Dockerfile`, `docker/Dockerfile.ubuntu`, and `docker/Dockerfile.redhat`, and restore full `Request`/`Changes`/`Result` and `Observed Symptom`/`Root Cause Analysis` fields across `docs/ACTION_LOGBOOK.md` and `docs/RCA_REGISTER.md`.
- **Changes**:
  - Updated [`internal/plugins/sys_diagnostics.go`](../internal/plugins/sys_diagnostics.go), [`internal/plugins/plugins_test.go`](../internal/plugins/plugins_test.go), [`README.md`](../README.md), [`Dockerfile`](../Dockerfile), [`docker/Dockerfile.ubuntu`](../docker/Dockerfile.ubuntu), [`docker/Dockerfile.redhat`](../docker/Dockerfile.redhat), [`docs/branding_test.go`](branding_test.go), [`docs/ACTION_LOGBOOK.md`](ACTION_LOGBOOK.md), and [`docs/RCA_REGISTER.md`](RCA_REGISTER.md).
- **Result**:
  - `go test -v -cover ./...` passing (`docs` 100.0%, `internal/api` 77.3%, `internal/auth` 85.1%, `internal/audit` 79.1%, `internal/core` 72.5%, `internal/mcp` 65.9%, `internal/plugins` 67.2%).

### `ACT-012` — Fix OS Preset Catalog Rendering in Web Console and Add Declarative Plugin & System Log Panels
- **Timestamp (UTC)**: `2026-10-26T20:03:00Z`
- **GitHub Issue**: [#24](https://github.com/jmrenouard/api_executor/issues/24) (PR [#25](https://github.com/jmrenouard/api_executor/pull/25), commit `52bd633`)
- **Branch**: `fix/issue-24-web-console-presets-plugins-logs`
- **Request**:
  - Fix Tab 2 of `web/static/index.html` where `cat.tasks` was referenced instead of `cat.commands` (causing `0 tasks` to render), pass `cat.os_family` into `runPresetTask`, and add Web Console UI panels for dynamic declarative plugin registration (`POST /api/v1/plugins/declarative`), system application logs (`GET /api/v1/logs`), and action execution history (`GET /api/v1/history`).
- **Changes**:
  - Updated [`web/static/index.html`](../web/static/index.html) and [`internal/api/web_console_test.go`](../internal/api/web_console_test.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/api` 77.3%, `docs` 100.0%, `internal/auth` 85.1%, `internal/audit` 79.1%, `internal/core` 72.5%, `internal/mcp` 65.9%, `internal/plugins` 66.9%).

### `ACT-011` — Enforce RBAC and Service Account Authorization on PAT Issuance, MCP Tool Calls, TLS Renewal, and Preset Activation
- **Timestamp (UTC)**: `2026-10-26T19:50:00Z`
- **GitHub Issue**: [#22](https://github.com/jmrenouard/api_executor/issues/22) (PR [#23](https://github.com/jmrenouard/api_executor/pull/23), commit `51eab49`)
- **Branch**: `fix/issue-22-rbac-mcp-tls-preset-authorization`
- **Request**:
  - Remediate privilege escalation on `POST`/`DELETE /api/v1/auth/tokens`, enforce service-account `allowed_actions` and RBAC scopes on MCP `tools/call` (`execute_command`, `execute_plugin`, `db_query`, `db_list_tables`), and enforce authentication, authorization, and SHA-256 audit logging on `POST /api/v1/tls/renew` and `POST /api/v1/presets/activate`.
- **Changes**:
  - Updated [`internal/api/auth_handlers.go`](../internal/api/auth_handlers.go), [`internal/mcp/server.go`](../internal/mcp/server.go), [`internal/api/mcp_handlers.go`](../internal/api/mcp_handlers.go), [`internal/api/handlers.go`](../internal/api/handlers.go), [`internal/api/presets_handlers.go`](../internal/api/presets_handlers.go), [`internal/api/auth_test.go`](../internal/api/auth_test.go), [`internal/api/mcp_test.go`](../internal/api/mcp_test.go), [`internal/api/tls_test.go`](../internal/api/tls_test.go), and [`internal/api/presets_test.go`](../internal/api/presets_test.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/api` 77.2%, `internal/auth` 85.1%, `internal/audit` 79.1%, `internal/core` 72.5%, `internal/mcp` 65.9%, `internal/plugins` 66.9%).

### `ACT-010` — Add Custom SVG Logo, Panoramic Header Banner, and Comprehensive English README
- **Timestamp (UTC)**: `2026-10-26T19:29:00Z`
- **GitHub Issue**: [#11](https://github.com/jmrenouard/api_executor/issues/11) (PR [#21](https://github.com/jmrenouard/api_executor/pull/21), commit `573f337`)
- **Branch**: `docs/issue-11-svg-branding-and-english-readme`
- **Request**:
  - Create a custom vector SVG logo (`docs/assets/logo.svg`) and panoramic header banner (`docs/assets/header-banner.svg`) and rewrite `README.md` in English covering all v2.0 enterprise subsystems (HTTPS/TLS, Prometheus per-action telemetry, hierarchical timeouts, Ubuntu/RedHat Docker presets, Web Console, RBAC/PAT/Service Accounts, Declarative & SQL Plugins, MCP Server with trace retention, and SHA-256 hash-chained audit logging).
- **Changes**:
  - Added [`docs/assets/logo.svg`](assets/logo.svg), [`docs/assets/header-banner.svg`](assets/header-banner.svg), and [`docs/branding_test.go`](branding_test.go).
  - Updated [`README.md`](../README.md), [`docs/ACTION_LOGBOOK.md`](ACTION_LOGBOOK.md), and [`docs/RCA_REGISTER.md`](RCA_REGISTER.md).
- **Result**:
  - `go test -v -cover ./...` passing (`docs` 100.0%, `internal/api` 76.8%, `internal/auth` 85.1%, `internal/audit` 79.1%, `internal/core` 72.5%, `internal/mcp` 68.3%, `internal/plugins` 66.9%).

### `ACT-009` — Build Pure Web Administration Console for Commands, Presets, Auth, Plugins, DB, MCP, Audit & TLS
- **Timestamp (UTC)**: `2026-10-26T19:23:00Z`
- **GitHub Issue**: [#10](https://github.com/jmrenouard/api_executor/issues/10) (PR [#20](https://github.com/jmrenouard/api_executor/pull/20), commit `e93e078`)
- **Branch**: `feat/issue-10-web-administration-console`
- **Request**:
  - Build a pure Web Administration Console (`web/static/index.html`) covering all 8 functional domains: Command Executor (with per-call timeout override and cURL snippet generator), Ubuntu & RedHat OS Task Presets, RBAC Users & Personal Access Tokens (`gat_pat_...`), Third-Party Service Accounts (`gat_svc_...`), Extensible Plugins & Read-Only SQL Explorer (`db-exposure`), Interactive MCP Server Playground & Trace Inspector (`mcp_tr_...`), SHA-256 Hash-Chained Audit Trail & Logs, and HTTPS/TLS Certificate Manager.
- **Changes**:
  - Updated [`web/static/index.html`](../web/static/index.html) and [`internal/api/router.go`](../internal/api/router.go).
  - Added [`internal/api/web_console_test.go`](../internal/api/web_console_test.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/api` 76.8%).

### `ACT-008` — Implement Model Context Protocol (MCP) Server with Persistent Trace Retention
- **Timestamp (UTC)**: `2026-10-26T06:34:00Z`
- **GitHub Issue**: [#9](https://github.com/jmrenouard/api_executor/issues/9) (PR [#19](https://github.com/jmrenouard/api_executor/pull/19), commit `4f84ba2`)
- **Branch**: `feat/issue-9-mcp-server-and-trace-retention`
- **Request**:
  - Implement a complete JSON-RPC 2.0 Model Context Protocol (`2024-11-05`) server (`internal/mcp`) exposing tools, resources, and prompts with full request/response trace retention (`mcp_tr_<hex>`) linked to the SHA-256 hash-chained audit trail.
- **Changes**:
  - Added [`internal/mcp/server.go`](../internal/mcp/server.go), [`internal/mcp/server_test.go`](../internal/mcp/server_test.go), [`internal/api/mcp_handlers.go`](../internal/api/mcp_handlers.go), and [`internal/api/mcp_test.go`](../internal/api/mcp_test.go).
  - Updated [`internal/core/config.go`](../internal/core/config.go), [`internal/api/handlers.go`](../internal/api/handlers.go), [`internal/api/router.go`](../internal/api/router.go), and [`cmd/server/main.go`](../cmd/server/main.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/mcp` 68.3%, `internal/api` 76.8%).

### `ACT-007` — Add Extensible Plugin System with Declarative Modules and Read-Only Database Exposure
- **Timestamp (UTC)**: `2026-10-26T06:23:00Z`
- **GitHub Issue**: [#8](https://github.com/jmrenouard/api_executor/issues/8) (PR [#18](https://github.com/jmrenouard/api_executor/pull/18), commit `641bd54`)
- **Branch**: `feat/issue-8-extensible-plugins-and-db-exposure`
- **Request**:
  - Implement an extensible plugin system (`internal/plugins`) supporting both declarative YAML/JSON command modules with strict regex parameter sanitization and advanced native plugins (`db-exposure` for read-only database inspection/SELECT querying and `sys-diagnostics`).
- **Changes**:
  - Added [`internal/plugins/plugin.go`](../internal/plugins/plugin.go), [`internal/plugins/declarative.go`](../internal/plugins/declarative.go), [`internal/plugins/db_exposure.go`](../internal/plugins/db_exposure.go), [`internal/plugins/sys_diagnostics.go`](../internal/plugins/sys_diagnostics.go), [`internal/plugins/plugins_test.go`](../internal/plugins/plugins_test.go), [`plugins/network-audit.yaml`](../plugins/network-audit.yaml), [`internal/api/plugin_handlers.go`](../internal/api/plugin_handlers.go), and [`internal/api/plugin_test.go`](../internal/api/plugin_test.go).
  - Updated [`internal/core/config.go`](../internal/core/config.go), [`internal/api/handlers.go`](../internal/api/handlers.go), [`internal/api/router.go`](../internal/api/router.go), and [`cmd/server/main.go`](../cmd/server/main.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/plugins` 66.9%, `internal/api` 76.8%).

### `ACT-006` — Implement RBAC User Management, Personal Access Tokens, and Third-Party Service Accounts
- **Timestamp (UTC)**: `2026-10-26T06:15:00Z`
- **GitHub Issue**: [#7](https://github.com/jmrenouard/api_executor/issues/7) (PR [#17](https://github.com/jmrenouard/api_executor/pull/17), commit `02535c7`)
- **Branch**: `feat/issue-7-rbac-users-tokens-and-service-accounts`
- **Request**:
  - Add RBAC user management (`admin`, `operator`, `viewer`), Personal Access Tokens (`gat_pat_...`) for remote calls, and Third-Party Service Accounts (`gat_svc_...`) with action-level scoping (`allowed_actions` exact & prefix wildcards) and key rotation.
- **Changes**:
  - Added [`internal/auth/manager.go`](../internal/auth/manager.go), [`internal/auth/manager_test.go`](../internal/auth/manager_test.go), [`internal/api/auth_handlers.go`](../internal/api/auth_handlers.go), and [`internal/api/auth_test.go`](../internal/api/auth_test.go).
  - Updated [`internal/core/config.go`](../internal/core/config.go), [`internal/api/handlers.go`](../internal/api/handlers.go), [`internal/api/router.go`](../internal/api/router.go), and [`cmd/server/main.go`](../cmd/server/main.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/auth` 85.1%, `internal/api` 78.8%).

### `ACT-005` — Implement Tamper-Evident SHA-256 Hash-Chained Audit Trail and Structured Log Buffer
- **Timestamp (UTC)**: `2026-10-25T22:30:00Z`
- **GitHub Issue**: [#6](https://github.com/jmrenouard/api_executor/issues/6) (PR [#16](https://github.com/jmrenouard/api_executor/pull/16), commit `ab8e5ae`)
- **Branch**: `feat/issue-6-tamper-evident-audit-and-structured-logging`
- **Request**:
  - Implement a tamper-evident SHA-256 hash-chained audit trail (`internal/audit`) and a structured ring-buffer logger (`internal/core/logger.go`) with REST inspection endpoints (`/api/v1/audit/logs`, `/api/v1/audit/verify`, `/api/v1/logs`, `/api/v1/history`).
- **Changes**:
  - Added [`internal/audit/audit.go`](../internal/audit/audit.go), [`internal/audit/audit_test.go`](../internal/audit/audit_test.go), [`internal/api/audit_handlers.go`](../internal/api/audit_handlers.go), and [`internal/api/audit_test.go`](../internal/api/audit_test.go).
  - Updated [`internal/core/logger.go`](../internal/core/logger.go), [`internal/core/config.go`](../internal/core/config.go), [`internal/api/handlers.go`](../internal/api/handlers.go), [`internal/api/router.go`](../internal/api/router.go), and [`cmd/server/main.go`](../cmd/server/main.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/audit` 79.1%, `internal/api` 83.2%, `internal/core` 75.5%).

### `ACT-004` — Add Security Architecture Analysis and Docker-Testable Ubuntu & RedHat OS Task Presets
- **Timestamp (UTC)**: `2026-10-25T22:27:00Z`
- **GitHub Issue**: [#5](https://github.com/jmrenouard/api_executor/issues/5) (PR [#15](https://github.com/jmrenouard/api_executor/pull/15), commit `ee302b2`)
- **Branch**: `feat/issue-5-security-analysis-and-os-presets-docker`
- **Request**:
  - Document the security architecture and threat model (`docs/SECURITY_AND_ARCHITECTURE_ANALYSIS.md`) and provide predefined, Docker-testable OS administration task catalogs for Ubuntu (`ubuntu`) and RedHat (`redhat`) via `GET /api/v1/presets` and `POST /api/v1/presets/activate`.
- **Changes**:
  - Added [`docs/SECURITY_AND_ARCHITECTURE_ANALYSIS.md`](SECURITY_AND_ARCHITECTURE_ANALYSIS.md), [`internal/core/os_presets.go`](../internal/core/os_presets.go), [`internal/core/os_presets_test.go`](../internal/core/os_presets_test.go), [`internal/api/presets_handlers.go`](../internal/api/presets_handlers.go), [`internal/api/presets_test.go`](../internal/api/presets_test.go), [`configs/ubuntu-tasks.yaml`](../configs/ubuntu-tasks.yaml), [`configs/redhat-tasks.yaml`](../configs/redhat-tasks.yaml), [`docker/Dockerfile.ubuntu`](../docker/Dockerfile.ubuntu), [`docker/Dockerfile.redhat`](../docker/Dockerfile.redhat), and [`docker-compose.os-test.yml`](../docker-compose.os-test.yml).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/core` 72.5%, `internal/api` 84.1%).

### `ACT-003` — Enable HTTPS/TLS by Default with Automatic X.509 Certificate Lifecycle Management
- **Timestamp (UTC)**: `2026-10-25T22:25:00Z`
- **GitHub Issue**: [#4](https://github.com/jmrenouard/api_executor/issues/4) (PR [#14](https://github.com/jmrenouard/api_executor/pull/14), commit `cfc9ef5`)
- **Branch**: `feat/issue-4-default-https-tls-certificate-manager`
- **Request**:
  - Enable HTTPS/TLS 1.2+ by default with automatic ECDSA P-256 self-signed X.509 certificate generation, hot rotation (`POST /api/v1/tls/renew`), PEM download (`GET /api/v1/tls/certificate`), and metadata inspection (`GET /api/v1/tls/info`).
- **Changes**:
  - Added [`internal/core/tls.go`](../internal/core/tls.go), [`internal/core/tls_test.go`](../internal/core/tls_test.go), and [`internal/api/tls_test.go`](../internal/api/tls_test.go).
  - Updated [`internal/core/config.go`](../internal/core/config.go), [`internal/api/handlers.go`](../internal/api/handlers.go), [`internal/api/router.go`](../internal/api/router.go), [`internal/api/middleware.go`](../internal/api/middleware.go), and [`cmd/server/main.go`](../cmd/server/main.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/core` 72.5%, `internal/api` 84.0%).

### `ACT-002` — Add Per-Action Prometheus Metrics and Hierarchical Call Timeout System
- **Timestamp (UTC)**: `2026-10-25T22:23:00Z`
- **GitHub Issue**: [#3](https://github.com/jmrenouard/api_executor/issues/3) (PR [#13](https://github.com/jmrenouard/api_executor/pull/13), commit `9bd86b6`)
- **Branch**: `feat/issue-3-prometheus-action-metrics-and-timeouts`
- **Request**:
  - Enrich Prometheus telemetry with bounded per-action counters (`action_calls_total`, `action_calls_ok_total`, `action_calls_error_total`, `action_calls_failure_total`, `action_call_duration_seconds`) and implement a 4-tier hierarchical call timeout (`per-call > per-command > global default > 30s fallback`) with process-group termination.
- **Changes**:
  - Updated [`internal/core/config.go`](../internal/core/config.go), [`internal/core/executor.go`](../internal/core/executor.go), [`internal/api/metrics.go`](../internal/api/metrics.go), [`internal/api/handlers.go`](../internal/api/handlers.go), and [`docs/docs.go`](docs.go).
  - Added [`internal/core/executor_test.go`](../internal/core/executor_test.go), [`internal/core/process_unix.go`](../internal/core/process_unix.go), [`internal/core/process_windows.go`](../internal/core/process_windows.go), and [`internal/api/metrics_timeout_test.go`](../internal/api/metrics_timeout_test.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/core` 75.5%, `internal/api` 82.0%).

### `ACT-001` — Enforce English-Only Governance, Living Registers, and Strict Atomic Issue/PR/Merge Rules
- **Timestamp (UTC)**: `2026-10-25T22:20:00Z`
- **GitHub Issue**: [#2](https://github.com/jmrenouard/api_executor/issues/2) (PR [#12](https://github.com/jmrenouard/api_executor/pull/12), commit `64db254`)
- **Branch**: `docs/issue-2-atomic-governance-rules`
- **Request**:
  - Codify strict atomic GitHub workflow rules (`1 Item = 1 Issue = 1 Branch = 1 PR = 1 Merge`), mandatory English-only policy, and living governance registers (`docs/ACTION_LOGBOOK.md`, `docs/RCA_REGISTER.md`).
- **Changes**:
  - Added [`AGENTS.md`](../AGENTS.md), [`.agents/rules/atomic-workflow.md`](../.agents/rules/atomic-workflow.md), [`.agents/rules/english-only.md`](../.agents/rules/english-only.md), [`.agents/rules/git-workflow.md`](../.agents/rules/git-workflow.md), [`.agents/rules/github-workflow.md`](../.agents/rules/github-workflow.md), [`.agents/rules/project-governance.md`](../.agents/rules/project-governance.md), [`docs/ACTION_LOGBOOK.md`](ACTION_LOGBOOK.md), and [`docs/RCA_REGISTER.md`](RCA_REGISTER.md).
- **Result**:
  - Decomposed monolithic backlog into 10 atomic GitHub Issues (`#2`–`#11`) and verified `go test -v -cover ./...`.

