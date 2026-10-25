# API Executor — Root Cause Analysis (RCA) & Technical Transparency Register (`RCA_REGISTER.md`)

This living governance register records all errors encountered, technical dead-ends, current approximations, and unimplemented roadmap ideas on the **API Executor (`go-admin-tool`)** project in accordance with [`AGENTS.md`](../AGENTS.md).

---

## 1. Errors & Bugs Encountered (`RCA-XXX`)

### `RCA-001` — Bundling Multiple Distinct Features into a Monolithic Issue #2 ("Kitchen-Sink / Papa-Maman" Anti-Pattern)
- **Date**: `2026-10-25`
- **Observed Symptom**:
  - Eight distinct engineering requests (Governance rules, Per-Action Prometheus Metrics & Timeouts, Default HTTPS/TLS, Security Analysis & Ubuntu/RedHat OS Presets, Tamper-Evident Audit & Logging, RBAC & Service Accounts, Declarative/DB Plugins, MCP Server & Web Admin Console, and SVG Branding/README) were initially grouped into a single catch-all GitHub Issue ([#2](https://github.com/jmrenouard/api_executor/issues/2)) and a single working branch.
- **Root Cause Analysis (5 Whys)**:
  1. *Why were multiple features grouped into Issue #2?* Because several historical user requests were consolidated for batch delivery.
  2. *Why did batch consolidation happen?* Because the governance rules in `AGENTS.md` and `.agents/rules/*.md` required an Issue and PR per request, but did not explicitly forbid bundling multiple distinct items into a single umbrella Issue/PR.
  3. *Why is an umbrella Issue/PR harmful?* It couples unrelated changes (governance docs, TLS, metrics, auth, plugins, MCP, UI), making code review, bisecting regressions, and independent rollbacks impossible.
- **Applied Change / Fix**:
  - Codified the **Strict Atomicity Rule** (`1 distinct item = 1 Issue = 1 Branch = 1 Pull Request = 1 Merge`) in [`AGENTS.md`](../AGENTS.md), [`.agents/rules/atomic-workflow.md`](../.agents/rules/atomic-workflow.md), [`.agents/rules/git-workflow.md`](../.agents/rules/git-workflow.md), and [`.agents/rules/github-workflow.md`](../.agents/rules/github-workflow.md).
  - Decomposed Issue #2 into 10 strictly atomic GitHub Issues (`#2` through `#11`), each delivered on its own dedicated branch and merged via its own atomic Pull Request.
- **Result & Non-Regression Check**:
  - Every issue (`#2`..`#11`) maps 1-to-1 to a single cohesive responsibility, a single branch, and a single merged PR.

---

## 2. Technical Dead-Ends & Abandoned Leads (`IMP-XXX`)

### `IMP-001` — Monolithic Catch-All Pull Requests
- **Context**: Attempting to deliver governance, TLS, metrics, auth, plugins, MCP, and UI changes in a single multi-thousand-line Pull Request.
- **Reason for Abandonment**: Violates atomic engineering discipline, obscures diffs per subsystem, and prevents granular traceability between issues and merges.

---

## 3. Current Approximations & Simplifying Assumptions (`APP-XXX`)

| ID | Module | Approximation / Assumption | Impact | Condition for Removal |
|---|---|---|---|---|
| `APP-001` | `internal/database` | SQLite local file storage (`history.db`) for command history. | Single-node persistence only; not shared across horizontally scaled replicas. | Introduce PostgreSQL driver adapter when deploying multi-replica clusters. |

---

## 4. Unimplemented Ideas & Future Roadmap (`IDEA-XXX`)

| ID | Priority | Target Module | Description |
|---|---|---|---|
| `IDEA-001` | `P2` | `internal/auth` | External OIDC / OAuth2 identity provider federation (Keycloak, Okta, GitHub OAuth) in addition to built-in RBAC users and service accounts. |
| `IDEA-002` | `P2` | `internal/core/tls` | Automatic ACME / Let's Encrypt certificate provisioning for public domain deployments alongside built-in X.509 self-signed and custom PEM modes. |
| `IDEA-003` | `P3` | `internal/audit` | Remote syslog / OpenTelemetry OTLP sink for real-time replication of the SHA-256 hash-chained audit log to an external SIEM. |
