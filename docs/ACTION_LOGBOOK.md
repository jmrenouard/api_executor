# API Executor — Action Logbook (`ACTION_LOGBOOK.md`)

This living governance register tracks all ongoing and completed engineering actions on the **API Executor (`go-admin-tool`)** repository.
In accordance with [`AGENTS.md`](../AGENTS.md) and [`.agents/rules/atomic-workflow.md`](../.agents/rules/atomic-workflow.md), every distinct item is tracked atomically (**1 Item = 1 Issue = 1 Branch = 1 Pull Request = 1 Merge**).

---

## 1. Ongoing Actions (`IN PROGRESS`)

| Action ID | Timestamp (UTC) | Atomic Issue | Branch | Request Summary |
|---|---|---|---|---|
| `ACT-009` | `2026-10-25T22:20:00Z` | [#10](https://github.com/jmrenouard/api_executor/issues/10) | `feat/issue-10-web-administration-console` | Build pure Web Administration Console managing commands, OS presets, users, tokens, service accounts, plugins, DB, MCP, audit, and TLS. |
| `ACT-010` | `2026-10-25T22:20:00Z` | [#11](https://github.com/jmrenouard/api_executor/issues/11) | `docs/issue-11-svg-branding-and-english-readme` | Add custom vector SVG logo, panoramic header banner, and comprehensive English `README.md`. |

---

## 2. Completed Actions (`COMPLETED`)

### `ACT-008` — Implement Model Context Protocol (MCP) Server with Persistent Trace Retention
- **Timestamp (UTC)**: `2026-10-26T06:34:00Z`
- **GitHub Issue**: [#9](https://github.com/jmrenouard/api_executor/issues/9)
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
- **GitHub Issue**: [#6](https://github.com/jmrenouard/api_executor/issues/6)
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

### `ACT-003` — Enable HTTPS/TLS by Default with Automatic X.509 Certificate Lifecycle Management
- **Timestamp (UTC)**: `2026-10-25T22:25:00Z`
- **GitHub Issue**: [#4](https://github.com/jmrenouard/api_executor/issues/4) (PR [#14](https://github.com/jmrenouard/api_executor/pull/14), commit `cfc9ef5`)
- **Branch**: `feat/issue-4-default-https-tls-certificate-manager`

### `ACT-002` — Add Per-Action Prometheus Metrics and Hierarchical Call Timeout System
- **Timestamp (UTC)**: `2026-10-25T22:23:00Z`
- **GitHub Issue**: [#3](https://github.com/jmrenouard/api_executor/issues/3) (PR [#13](https://github.com/jmrenouard/api_executor/pull/13), commit `9bd86b6`)
- **Branch**: `feat/issue-3-prometheus-action-metrics-and-timeouts`

### `ACT-001` — Enforce English-Only Governance, Living Registers, and Strict Atomic Issue/PR/Merge Rules
- **Timestamp (UTC)**: `2026-10-25T22:20:00Z`
- **GitHub Issue**: [#2](https://github.com/jmrenouard/api_executor/issues/2) (PR [#12](https://github.com/jmrenouard/api_executor/pull/12), commit `64db254`)
- **Branch**: `docs/issue-2-atomic-governance-rules`
