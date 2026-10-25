# API Executor — Action Logbook (`ACTION_LOGBOOK.md`)

This living governance register tracks all ongoing and completed engineering actions on the **API Executor (`go-admin-tool`)** repository.
In accordance with [`AGENTS.md`](../AGENTS.md) and [`.agents/rules/atomic-workflow.md`](../.agents/rules/atomic-workflow.md), every distinct item is tracked atomically (**1 Item = 1 Issue = 1 Branch = 1 Pull Request = 1 Merge**).

---

## 1. Ongoing Actions (`IN PROGRESS`)

| Action ID | Timestamp (UTC) | Atomic Issue | Branch | Request Summary |
|---|---|---|---|---|
| `ACT-002` | `2026-10-25T22:20:00Z` | [#3](https://github.com/jmrenouard/api_executor/issues/3) | `feat/issue-3-prometheus-action-metrics-and-timeouts` | Enrich `/metrics` with per-action Prometheus counters/histograms and add default/overridable call timeout system. |
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

### `ACT-001` — Enforce English-Only Governance, Living Registers, and Strict Atomic Issue/PR/Merge Rules
- **Timestamp (UTC)**: `2026-10-25T22:20:00Z`
- **GitHub Issue**: [#2](https://github.com/jmrenouard/api_executor/issues/2)
- **Branch**: `docs/issue-2-atomic-governance-rules`
- **Request**:
  - Port the agent instructions and governance rules from `MicroLLM` to `api_executor` exclusively in English.
  - Enforce the strict rule: *"Une issue par élément de corrections à apporter. https://github.com/jmrenouard/api_executor/issues/2 à redécouper par éléments de corrections"* and *"Les PR, merge et issue doivent être atomiques et ne pas faire papa maman"* (1 distinct item = 1 Issue = 1 Branch = 1 Pull Request = 1 Merge).
- **Changes**:
  - Created [`AGENTS.md`](../AGENTS.md) with Section 1.1 (*Strict Atomicity Rule: 1 Item = 1 Issue = 1 Branch = 1 PR = 1 Merge*), full GitHub lifecycle, living register rules, and English-only policy.
  - Created [`.agents/rules/atomic-workflow.md`](../.agents/rules/atomic-workflow.md), [`.agents/rules/english-only.md`](../.agents/rules/english-only.md), [`.agents/rules/git-workflow.md`](../.agents/rules/git-workflow.md), [`.agents/rules/github-workflow.md`](../.agents/rules/github-workflow.md), and [`.agents/rules/project-governance.md`](../.agents/rules/project-governance.md).
  - Initialized [`docs/ACTION_LOGBOOK.md`](ACTION_LOGBOOK.md) and [`docs/RCA_REGISTER.md`](RCA_REGISTER.md).
  - Decomposed the former monolithic Issue #2 into 10 strictly atomic GitHub Issues ([#2](https://github.com/jmrenouard/api_executor/issues/2) through [#11](https://github.com/jmrenouard/api_executor/issues/11)).
- **Result**:
  - `go test -v -cover ./...` passing cleanly.
  - Issue [#2](https://github.com/jmrenouard/api_executor/issues/2) re-scoped to atomic governance & closed via atomic PR merge.
