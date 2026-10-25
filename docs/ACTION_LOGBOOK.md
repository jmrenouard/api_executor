# API Executor — Action Logbook (`ACTION_LOGBOOK.md`)

This living governance register tracks all ongoing and completed engineering actions on the **API Executor (`go-admin-tool`)** repository.
In accordance with [`AGENTS.md`](../AGENTS.md) and [`.agents/rules/atomic-workflow.md`](../.agents/rules/atomic-workflow.md), every distinct item is tracked atomically (**1 Item = 1 Issue = 1 Branch = 1 Pull Request = 1 Merge**).

---

## 1. Ongoing Actions (`IN PROGRESS`)

| Action ID | Timestamp (UTC) | Atomic Issue | Branch | Request Summary |
|---|---|---|---|---|
| `ACT-004` | `2026-10-25T22:20:00Z` | [#5](https://github.com/jmrenouard/api_executor/issues/5) | `feat/issue-5-security-analysis-and-os-presets-docker` | Publish security/architecture analysis and add Docker-testable Ubuntu & RedHat predefined OS task catalogs. |
| `ACT-005` | `2026-10-25T22:20:00Z` | [#6](https://github.com/jmrenouard/api_executor/issues/6) | `feat/issue-6-tamper-evident-audit-and-structured-logging` | Implement tamper-evident SHA-256 hash-chained audit trail and structured ring-buffer logging. |
| `ACT-006` | `2026-10-25T22:20:00Z` | [#7](https://github.com/jmrenouard/api_executor/issues/7) | `feat/issue-7-rbac-users-tokens-and-service-accounts` | Implement RBAC user management, Personal Access Tokens (PAT), and Third-Party Service Accounts with action scoping. |
| `ACT-007` | `2026-10-25T22:20:00Z` | [#8](https://github.com/jmrenouard/api_executor/issues/8) | `feat/issue-8-extensible-plugins-and-db-exposure` | Add extensible plugin system supporting declarative YAML command modules and read-only SQLite database exposure. |
| `ACT-008` | `2026-10-25T22:20:00Z` | [#9](https://github.com/jmrenouard/api_executor/issues/9) | `feat/issue-9-mcp-server-and-trace-retention` | Implement complete JSON-RPC 2.0 Model Context Protocol (MCP) server with persistent trace retention. |
| `ACT-009` | `2026-10-25T22:20:00Z` | [#10](https://github.com/jmrenouard/api_executor/issues/10) | `feat/issue-10-web-administration-console` | Build pure Web Administration Console managing commands, OS presets, users, tokens, service accounts, plugins, DB, MCP, audit, and TLS. |
| `ACT-010` | `2026-10-25T22:20:00Z` | [#11](https://github.com/jmrenouard/api_executor/issues/11) | `docs/issue-11-svg-branding-and-english-readme` | Add custom vector SVG logo, panoramic header banner, and comprehensive English `README.md`. |

---

## 2. Completed Actions (`COMPLETED`)

### `ACT-003` — Enable HTTPS/TLS by Default with Automatic X.509 Certificate Lifecycle Management
- **Timestamp (UTC)**: `2026-10-25T22:25:00Z`
- **GitHub Issue**: [#4](https://github.com/jmrenouard/api_executor/issues/4)
- **Branch**: `feat/issue-4-default-https-tls-certificate-manager`
- **Request**:
  - Enable HTTPS/TLS by default with automatic ECDSA P-256 X.509 self-signed certificate generation, reuse, expiry auto-renewal, live rotation (`POST /api/v1/tls/renew`), PEM download (`GET /api/v1/tls/certificate`), metadata inspection (`GET /api/v1/tls/info`), optional mTLS client CA verification, and HSTS header injection.
- **Changes**:
  - Added [`internal/core/tls.go`](../internal/core/tls.go), [`internal/core/tls_test.go`](../internal/core/tls_test.go), and [`internal/api/tls_test.go`](../internal/api/tls_test.go).
  - Updated [`internal/core/config.go`](../internal/core/config.go), [`internal/api/handlers.go`](../internal/api/handlers.go), [`internal/api/router.go`](../internal/api/router.go), [`cmd/server/main.go`](../cmd/server/main.go), and [`config.yaml`](../config.yaml).
- **Result**:
  - `go test -v -cover ./...` passing (`internal/api` 84.2%, `internal/core` 79.1%).

### `ACT-002` — Add Per-Action Prometheus Metrics and Hierarchical Call Timeout System
- **Timestamp (UTC)**: `2026-10-25T22:23:00Z`
- **GitHub Issue**: [#3](https://github.com/jmrenouard/api_executor/issues/3) (PR [#13](https://github.com/jmrenouard/api_executor/pull/13), commit `9bd86b6`)
- **Branch**: `feat/issue-3-prometheus-action-metrics-and-timeouts`
- **Changes**: Per-action Prometheus counters/histograms and hierarchical call timeouts with process-group termination.

### `ACT-001` — Enforce English-Only Governance, Living Registers, and Strict Atomic Issue/PR/Merge Rules
- **Timestamp (UTC)**: `2026-10-25T22:20:00Z`
- **GitHub Issue**: [#2](https://github.com/jmrenouard/api_executor/issues/2) (PR [#12](https://github.com/jmrenouard/api_executor/pull/12), commit `64db254`)
- **Branch**: `docs/issue-2-atomic-governance-rules`
- **Changes**: Added `AGENTS.md`, `.agents/rules/*.md`, `docs/ACTION_LOGBOOK.md`, and `docs/RCA_REGISTER.md` with strict atomic workflow rules.
