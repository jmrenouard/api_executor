# API Executor — Action Logbook (`ACTION_LOGBOOK.md`)

This living governance register tracks all ongoing and completed engineering actions on the **API Executor (`go-admin-tool`)** repository.
In accordance with [`AGENTS.md`](../AGENTS.md) and [`.agents/rules/atomic-workflow.md`](../.agents/rules/atomic-workflow.md), every distinct item is tracked atomically (**1 Item = 1 Issue = 1 Branch = 1 Pull Request = 1 Merge**).

---

## 1. Ongoing Actions (`IN PROGRESS`)

| Action ID | Timestamp (UTC) | Atomic Issue | Branch | Request Summary |
|---|---|---|---|---|
| `ACT-003` | `2026-10-25T22:20:00Z` | [#4](https://github.com/jmrenouard/api_executor/issues/4) | `feat/issue-4-default-https-tls-certificate-manager` | Enable HTTPS/TLS by default with automatic X.509 self-signed certificate generation, reuse, renewal, and live rotation. |
| `ACT-004` | `2026-10-25T22:20:00Z` | [#5](https://github.com/jmrenouard/api_executor/issues/5) | `feat/issue-5-security-analysis-and-os-presets-docker` | Publish security/architecture analysis and add Docker-testable Ubuntu & RedHat predefined OS task catalogs. |
| `ACT-005` | `2026-10-25T22:20:00Z` | [#6](https://github.com/jmrenouard/api_executor/issues/6) | `feat/issue-6-tamper-evident-audit-and-structured-logging` | Implement tamper-evident SHA-256 hash-chained audit trail and structured ring-buffer logging. |
| `ACT-006` | `2026-10-25T22:20:00Z` | [#7](https://github.com/jmrenouard/api_executor/issues/7) | `feat/issue-7-rbac-users-tokens-and-service-accounts` | Implement RBAC user management, Personal Access Tokens (PAT), and Third-Party Service Accounts with action scoping. |
| `ACT-007` | `2026-10-25T22:20:00Z` | [#8](https://github.com/jmrenouard/api_executor/issues/8) | `feat/issue-8-extensible-plugins-and-db-exposure` | Add extensible plugin system supporting declarative YAML command modules and read-only SQLite database exposure. |
| `ACT-008` | `2026-10-25T22:20:00Z` | [#9](https://github.com/jmrenouard/api_executor/issues/9) | `feat/issue-9-mcp-server-and-trace-retention` | Implement complete JSON-RPC 2.0 Model Context Protocol (MCP) server with persistent trace retention. |
| `ACT-009` | `2026-10-25T22:20:00Z` | [#10](https://github.com/jmrenouard/api_executor/issues/10) | `feat/issue-10-web-administration-console` | Build pure Web Administration Console managing commands, OS presets, users, tokens, service accounts, plugins, DB, MCP, audit, and TLS. |
| `ACT-010` | `2026-10-25T22:20:00Z` | [#11](https://github.com/jmrenouard/api_executor/issues/11) | `docs/issue-11-svg-branding-and-english-readme` | Add custom vector SVG logo, panoramic header banner, and comprehensive English `README.md`. |

---

## 2. Completed Actions (`COMPLETED`)

### `ACT-002` — Add Per-Action Prometheus Metrics and Hierarchical Call Timeout System
- **Timestamp (UTC)**: `2026-10-25T22:23:00Z`
- **GitHub Issue**: [#3](https://github.com/jmrenouard/api_executor/issues/3)
- **Branch**: `feat/issue-3-prometheus-action-metrics-and-timeouts`
- **Request**:
  - Enrich Prometheus `/metrics` with per-action counters (`action_calls_total`, `action_calls_ok_total`, `action_calls_error_total`, `action_calls_failure_total`, `action_calls_timeout_total`, `action_calls_status_total`) and duration histogram (`action_call_duration_seconds`).
  - Add a default call timeout (`30s`) overridable per command and per API call (`timeout`, `timeout_seconds`, `timeout_ms` via JSON body or URL query).
- **Changes**:
  - Modified [`internal/core/config.go`](../internal/core/config.go), [`internal/core/executor.go`](../internal/core/executor.go), [`internal/core/executor_unix.go`](../internal/core/executor_unix.go), [`internal/core/executor_windows.go`](../internal/core/executor_windows.go), [`internal/api/router.go`](../internal/api/router.go), [`internal/api/handlers.go`](../internal/api/handlers.go), [`internal/database/db.go`](../internal/database/db.go), [`config.yaml`](../config.yaml), [`Dockerfile`](../Dockerfile), and Swagger specs (`docs/docs.go`, `docs/swagger.json`, `docs/swagger.yaml`).
  - Added [`internal/core/executor_test.go`](../internal/core/executor_test.go), [`internal/api/metrics_timeout_test.go`](../internal/api/metrics_timeout_test.go), and [`internal/database/db_test.go`](../internal/database/db_test.go).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/api` 82.9%, `internal/core` 76.2%, `internal/database` 26.6%).

### `ACT-001` — Enforce English-Only Governance, Living Registers, and Strict Atomic Issue/PR/Merge Rules
- **Timestamp (UTC)**: `2026-10-25T22:20:00Z`
- **GitHub Issue**: [#2](https://github.com/jmrenouard/api_executor/issues/2) (PR [#12](https://github.com/jmrenouard/api_executor/pull/12), commit `64db254`)
- **Branch**: `docs/issue-2-atomic-governance-rules`
- **Changes**: Added `AGENTS.md`, `.agents/rules/*.md`, `docs/ACTION_LOGBOOK.md`, and `docs/RCA_REGISTER.md` with strict atomic workflow rules.
