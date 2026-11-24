# API Security Audit, Threat Mitigations & Automated Verification (`SECURITY.md`)

[![Automated API Security Suite](https://img.shields.io/badge/CI-Automated_API_Security_Suite-10b981?style=flat-square&logo=githubactions&logoColor=white)](.github/workflows/security.yml)
[![HTTPS/TLS 1.3 Default](https://img.shields.io/badge/Transport-TLS_1.2%2F1.3_%2B_HSTS-38bdf8?style=flat-square)](internal/core/tls.go)
[![Zero Shell Interpolation](https://img.shields.io/badge/Execution-Zero_Shell_Interpolation-a78bfa?style=flat-square)](internal/core/executor.go)
[![Tamper-Evident Audit](https://img.shields.io/badge/Audit-SHA--256_Hash_Chain-fbbf24?style=flat-square)](internal/audit/audit.go)

This document presents the **API Security Architecture, Threat Model, Audit Findings, Hardening Controls, and Automated Security Test Catalog** for **API Executor (`go-admin-tool`)**.

Every control documented below is continuously verified by deterministic unit, adversarial, and end-to-end tests in [`internal/api/security_audit_test.go`](internal/api/security_audit_test.go), [`internal/plugins/m2_adversarial_test.go`](internal/plugins/m2_adversarial_test.go), [`tests/e2e/`](tests/e2e/), and the GitHub Actions workflow [`.github/workflows/security.yml`](.github/workflows/security.yml).

---

## 1. Executive Summary & Audit Scope (`/repo-scan` + `/ponytail-audit`)

An end-to-end security review was performed across all **53 documented HTTP/REST routes** (49 static router handler mounts and JSON-RPC 2.0 MCP methods), authentication/authorization resolvers, the **Zero-Trust MCP Bastion** control plane (Human-in-the-Loop pre-execution approvals, pluggable `MicroLLM` System-1 gatekeeper, SHA-256 hash-chained & replayable MCP traces, read-only `CISBenchmarks` MCP audit preset), command and plugin execution engines, read-only SQLite exposure, and HTTP middleware layers.

### Key Security Guarantees Verified by Automated Tests

1. **Zero Unauthorized Access (`401 Unauthorized` & Fail-Closed Resolution)**:
   - Every protected API endpoint enforces authentication when `auth.require_auth: true`.
   - Missing credentials, malformed headers, forged tokens, revoked sessions/PATs, expired tokens, and disabled user/service-account credentials are systematically rejected with `401 Unauthorized`.
   - `resolvePrincipal` fails closed even if `AuthManager` is uninitialized or `auth.enabled` is misconfigured while `auth.require_auth: true`.
2. **Strict Anti-Privilege Escalation & Unauthorized Addition Prevention (`403 Forbidden`)**:
   - Non-admin principals (`anonymous`, `viewer`, `operator`, and `service_account`) **cannot** create, modify, or delete users (`POST/PATCH/DELETE /api/v1/auth/users`), mint admin/wildcard PATs (`POST /api/v1/auth/tokens`), create/rotate/delete service accounts (`/api/v1/auth/service-accounts*`), activate OS presets (`POST /api/v1/presets/activate`), dynamically register declarative plugins (`POST /api/v1/plugins/declarative`), renew X.509 TLS certificates (`POST /api/v1/tls/renew`), or clear MCP trace logs (`DELETE /api/v1/mcp/traces`).
   - Machine-to-machine `service_account` credentials (`gat_svc_...`) are strictly confined to their `allowed_actions` glob patterns across synchronous REST (`/api/v1/execute`, `/api/v1/plugins/execute`), asynchronous jobs (`POST /api/v1/jobs`), and MCP (`POST /api/v1/mcp` `tools/call`).
3. **Command, Plugin, Path & SQL Injection Confinement (`400` / `403` / `404`)**:
   - Arbitrary or unlisted command names are rejected (`404 Not Found`), and execution invokes `exec.CommandContext(ctx, cmd.Command, cmd.Args...)` directly without `sh -c` or `cmd /C` shell concatenation.
   - Declarative plugin parameters enforce strict scalar typing, regex validation (`^[a-zA-Z0-9._:/-]+$`), shell metacharacter blocking (`;&|$><` + backticks/newlines), and `../` path traversal rejection (`400 Bad Request`).
   - File downloads (`/api/v1/files/`) enforce `filepath.Base` normalization and `SecureDir` prefix confinement.
   - Database inspection (`/api/v1/db/query` and MCP `db_query`) enforces `ValidateReadOnlySQL`, blocking `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `ATTACH`, `DETACH`, `PRAGMA`, stacked queries (`;`), and SQL comments (`--`, `/* */`) with `403 Forbidden`.
4. **DDoS, Rate-Limiting & Resource Exhaustion Resilience (`413` / `429` / Timeouts / Cardinality Caps)**:
   - **Per-IP Token-Bucket Rate Limiting (`internal/api/security_middleware.go`)**: Throttles volumetric floods and credential brute-force attacks with `429 Too Many Requests`, `Retry-After: 1`, and `X-RateLimit-Limit` headers while bounding tracker memory (`MaxTrackedRateLimitIPs = 10000`) against spoofed-IP floods.
   - **Request Body Size Cap (`MaxRequestBodyBytes = 1 MiB`)**: Rejects oversized `Content-Length` and chunked request streams with `413 Request Entity Too Large` before JSON decoding can exhaust heap memory.
   - **Subprocess Timeout Ceilings & Process-Group Kill**: Enforces `executor.max_timeout_seconds` (`400 Bad Request` on excessive overrides) and kills entire process groups on timeout or job cancellation.
   - **Prometheus Cardinality Protection**: Normalizes dynamic HTTP path segments (`:id`, `:trace_id`), enforces closed-set `gatekeeper_decisions_total` / `gatekeeper_latency_seconds` labels, and caps dynamic action labels at `MaxDynamicActionLabels = 64` (falling back to `"unknown"`).
5. **Zero-Trust MCP Bastion Controls (HITL, System-1 Gatekeeper, Cryptographic Trace Replay & Read-Only CIS Audits)**:
   - **Human-in-the-Loop (HITL) Pre-Execution Gate (`internal/approval/`, `internal/api/approval_handlers.go`)**: Intercepts critical commands, plugins, async jobs, and MCP `tools/call` operations with a canonical SHA-256 payload digest (`PayloadSHA256`), enforces distinct-approver separation (`RequireDistinctApprover`), blocks TOCTOU payload tampering (`403 Forbidden`), and enforces atomic single-use approval consumption (`409 Conflict` on replay).
   - **Pluggable `MicroLLM` (`microllm.guard.v1`) System-1 Gatekeeper (`internal/gatekeeper/`)**: Evaluates requests in strict order (`Auth -> RBAC -> Pre-Approved approval_id -> Static HITL -> System-1 -> Execution`) over loopback-confined HTTP (`< 5 ms` target, `64 KiB` response cap, redirect-blocked) or non-root UID `10001` CLI subprocesses; escalates `x_abstain` / timeouts / invalid outputs fail-closed to HITL (or `403 Forbidden` when HITL is disabled) and forces fail-closed denial on `hijack_suspected: true`.
   - **Tamper-Evident MCP Trace Chain & Deterministic Replay (`internal/mcp/trace_integrity.go`, `internal/mcp/replay.go`)**: Chains every MCP trace via `PrevTraceHash -> TraceHash`, cross-links to `audit_entry_hash`, exposes `GET /api/v1/mcp/traces/verify` and `GET /api/v1/mcp/traces/{id}/verify`, and provides zero-side-effect `dry_run` replay plus strictly `admin`-gated `live` replay with `parent_trace_id` lineage.
   - **Read-Only `CISBenchmarks` (`cis.mcp.contract.v1`) MCP Audit Preset (`plugins/secops/cis-benchmarks-audit.yaml`, `configs/cis-benchmarks-audit.yaml`)**: Exposes 4 strictly read-only `audit-cis` presets (`cis_list_targets`, `cis_audit_json`, `cis_audit_sarif`, `cis_remediate_dry_run`), 18 canonical targets, directory-confined report/output regex allowlists, zero shell interpolation, `CIS_DB_PASSWORD` env-only credential boundary, and UID/GID `10001` (`keep-id`) sandbox enforcement.

---

## 2. Complete API Surface & RBAC Security Matrix (35 Logical Endpoint Groups; 53 Routes)

| # | Endpoint | Methods | Required Scope / Role | Anonymous (`require_auth: true`) | `viewer` | `operator` | `service_account` (Scoped) | `admin` | Security Controls & Confinement |
| :- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| 1 | `/health`, `/healthz`, `/readyz` | `GET` | Public liveness & readiness probes | `200` (`503` degraded) | `200` | `200` | `200` | `200` | Read-only liveness & subsystem checks (`database`, `tls`, `jobs`), zero secret/path exposure, rate-limited |
| 2 | `/api/v1/version`, `/api/v1/config/version` | `GET` | Public probes | `200` | `200` | `200` | `200` | `200` | Read-only version & config-version metadata, rate-limited, security headers |
| 3 | `/metrics` | `GET` | Public telemetry scrape | `200` | `200` | `200` | `200` | `200` | Bounded Prometheus label cardinality (`MaxDynamicActionLabels = 64`) |
| 4 | `/swagger/*` | `GET` | Public OpenAPI UI | `200` | `200` | `200` | `200` | `200` | Read-only embedded OpenAPI specification |
| 5 | `/` | `GET` | Public Web Console | `200` | `200` | `200` | `200` | `200` | Hardened headers (`X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`) |
| 6 | `/api/v1/auth/login` | `POST` | Public authentication | `200`/`401` | `200` | `200` | N/A | `200` | Per-IP rate-limited, `1 MiB` body cap, 10,000-round salted SHA-256 verification, SHA-256 audit log |
| 7 | `/api/v1/config`, `/api/v1/configs/{profile}` | `GET` | Public sanitized view | `200` | `200` | `200` | `200` | `200` | Returns sanitized active/profile config with secrets masked as `[REDACTED]` |
| 8 | `/api/v1/auth/me` | `GET` | Authenticated (`require_auth`) | `401` | `200` | `200` | `200` | `200` | Returns caller principal & effective scopes |
| 9 | `/api/v1/auth/users` | `GET`, `POST` | `users:manage` (`admin`) | `401` | `403` | `403` | `403` | `200`/`201` | Blocks unauthorized user creation or enumeration |
| 10 | `/api/v1/auth/users/{id}` | `PATCH`, `DELETE` | `users:manage` (`admin`) | `401` | `403` | `403` | `403` | `200` | Blocks horizontal/vertical role escalation & user deletion |
| 11 | `/api/v1/auth/tokens` | `GET`, `POST` | Authenticated + scope subset | `401` | Own scopes | Own scopes | `403` | All scopes | Rejects anonymous & service accounts; blocks scope elevation beyond caller |
| 12 | `/api/v1/auth/tokens/{id}` | `DELETE` | Owner or `admin` | `401` | Own only | Own only | `403` | Any | Prevents cross-user token revocation by non-admins |
| 13 | `/api/v1/auth/service-accounts` | `GET`, `POST` | `service_accounts:manage` (`admin`) | `401` | `403` | `403` | `403` | `200`/`201` | Only admins can provision machine-to-machine accounts |
| 14 | `/api/v1/auth/service-accounts/{id}` | `DELETE`, `POST .../rotate` | `service_accounts:manage` (`admin`) | `401` | `403` | `403` | `403` | `200` | Atomic secret rotation invalidates previous `gat_svc_` key |
| 15 | `/api/v1/commands` | `GET` | `commands:read` | `401` | `200` | `200` | `403` | `200` | Returns configured command allowlist |
| 16 | `/api/v1/execute` | `POST` | `commands:execute` + action allowlist | `401` | `403` | `200` | Allowlist only | `200` | Direct argv execution (`exec.CommandContext`), timeout ceiling, `1 MiB` output cap |
| 17 | `/api/v1/history` | `GET` | `commands:read` | `401` | `200` | `200` | `403` | `200` | Bounded to latest 100 execution records |
| 18 | `/api/v1/files/{name}` | `GET` | `files:read` | `401` | `200` | `200` | `403` | `200` | `filepath.Base` + `SecureDir` boundary verification (`400`/`403` on traversal) |
| 19 | `/api/v1/presets` | `GET` | `commands:read` | `401` | `200` | `200` | `403` | `200` | Lists predefined Ubuntu & RedHat OS task catalogs |
| 20 | `/api/v1/presets/activate` | `POST` | `admin` role required | `401` | `403` | `403` | `403` | `200` | Prevents non-admins from mutating active runtime command catalog |
| 21 | `/api/v1/plugins` | `GET` | `plugins:read` | `401` | `200` | `200` | `403` | `200` | Read-only catalog discovery & filtering |
| 22 | `/api/v1/plugins/execute` | `POST` | `plugins:execute` + action allowlist | `401` | `403` | `200` | Allowlist only | `200` | Strict regex & metacharacter parameter validation, timeout ceiling |
| 23 | `/api/v1/plugins/declarative` | `POST` | `admin` role required | `401` | `403` | `403` | `403` | `201` | Blocks arbitrary command registration by non-admin principals |
| 24 | `/api/v1/db/tables` | `GET` | `db:read` | `401` | `200` | `200` | Allowlist only | `200` | Read-only SQLite table & schema metadata |
| 25 | `/api/v1/db/query` | `POST` | `db:read` | `401` | `200` | `200` | Allowlist only | `200` | `ValidateReadOnlySQL` (`SELECT`/`WITH`/`EXPLAIN` only; `403` on DDL/DML/stacked SQL) |
| 26 | `/api/v1/audit/logs`, `/api/v1/audit/verify` | `GET` | `audit:read` | `401` | `200` | `200` | `403` | `200` | Cryptographic SHA-256 hash-chain verification (`GENESIS` -> head) |
| 27 | `/api/v1/tls/info`, `/api/v1/tls/certificate`, `/api/v1/tls/renew` | `GET`, `POST` | `tls:read` (`GET`), `tls:manage` / `admin` (`POST`) | `401` | `200` (`GET`) / `403` (`POST`) | `200` (`GET`) / `403` (`POST`) | `403` | `200` | Atomic ECDSA P-256 certificate inspection, public PEM download, and rotation restricted to `admin` |
| 28 | `/api/v1/mcp` (`GET`, `POST`), `/api/v1/mcp/traces*` (`GET`, `DELETE`) | `GET`, `POST`, `DELETE` | `mcp:access` (`GET`/`POST`), `admin` (`DELETE`) | `401` | `403` | `200` (`GET`/`POST`) / `403` (`DELETE`) | Allowlist only (`POST`) | `200` | Per-tool RBAC (`commands:execute`, `plugins:execute`, `db:read`, `tls:manage`), HITL & System-1 hooks |
| 29 | `/api/v1/jobs` (`POST`, `GET`), `/api/v1/jobs/{id}` (`GET`), `/logs` (`GET`), `/cancel` (`POST`) | `POST`, `GET` | `jobs:submit` + underlying action RBAC, `jobs:read`, `jobs:cancel` | `401` | `403` (`POST`) / `200` (`GET`) | `202`/`200` | Allowlist only (`POST`) | `202`/`200` | Dual authorization (job scope + command/plugin allowlist), HITL & System-1 gates, `429` queue backpressure |
| 30 | `/api/v1/jobs/{id}/stream` | `GET` | `jobs:read` (`viewer`+) | `401` | `200` | `200` | `403` | `200` | Real-time SSE job status & log stream, `?offset=` / `Last-Event-ID` resume, per-connection `WriteTimeout` clearing |
| 31 | `/api/v1/approvals`, `/api/v1/approvals/{id}` | `GET` | `approvals:read` (`admin` / scoped) | `401` | `403` | `403` | `403` | `200` | Bounded pending approval queue (`MaxPending`), canonical SHA-256 payload digest inspection |
| 32 | `/api/v1/approvals/{id}/approve`, `/api/v1/approvals/{id}/reject` | `POST` | `approvals:decide` (`admin`, distinct approver) | `401` | `403` | `403` | `403` | `200` (`403` self) | Distinct-approver enforcement (`RequireDistinctApprover`), atomic single-use consumption (`409` on replay) |
| 33 | `/api/v1/mcp/traces/verify` | `GET` | `mcp:access` | `401` | `403` | `200` | `403` | `200` | Cryptographic SHA-256 chain continuity verification (`GENESIS` -> head) across retained MCP traces |
| 34 | `/api/v1/mcp/traces/{trace_id}/verify` | `GET` | `mcp:access` | `401` | `403` | `200` | `403` | `200` | Recomputes request/response/trace SHA-256 digests and verifies cross-link to `audit_entry_hash` |
| 35 | `/api/v1/mcp/traces/{trace_id}/replay` | `POST` | `mcp:access` (`dry_run`), `admin` (`live`) | `401` | `403` | `200` (`dry_run`) / `403` (`live`) | `403` (`live`) | `200` | Zero-side-effect `dry_run` default; `live` replay enforces `admin`, SHA-256 determinism & `parent_trace_id` lineage |

---

## 3. Detailed Threat Mitigations & Hardening Architecture

### 3.1 Authentication & Unauthorized Access Prevention (`401 Unauthorized`)

- **Multi-Credential Resolution (`internal/api/auth_handlers.go`, `internal/auth/manager.go`)**:
  - Supports Bearer tokens (`Authorization: Bearer <token>`), `X-API-Token: <token>`, `X-API-Key: <token>`, and `X-Service-Key: <key>` (`ExtractTokenFromRequest`; raw `Authorization: Basic <base64>` strings are not decoded as Basic auth and fail with `401`).
  - Passwords and API tokens are never stored in cleartext: user passwords use `10,000-round` salted SHA-256 with `subtle.ConstantTimeCompare`, and PATs (`gat_pat_...`) / Service Account keys (`gat_svc_...`) are indexed by SHA-256 hash (`tokenByHash`, `serviceAccountByHash`) and compared in constant time.
- **Fail-Closed Enforcement**:
  - When `auth.require_auth: true`, `resolvePrincipal` immediately rejects unauthenticated requests (`401 Unauthorized`) before any handler logic runs—even if `auth.enabled` was accidentally set to `false` or `AuthManager` is `nil`.
  - Revoking a session/PAT, disabling a user account (`enabled: false`), disabling a service account, or rotating a service account key immediately invalidates prior credentials with `401 Unauthorized`.

### 3.2 Anti-Privilege Escalation & Unauthorized Additions (`403 Forbidden`)

- **Strict Role & Scope Separation (`internal/auth/manager.go`)**:
  - `viewer`: Read-only scopes (`commands:read`, `plugins:read`, `db:read`, `audit:read`, `tls:read`, `files:read`, `jobs:read`). Cannot execute commands/plugins, submit/cancel jobs, or invoke MCP tools.
  - `operator`: Operational execution scopes (`commands:execute`, `plugins:execute`, `mcp:access`, `jobs:submit`, `jobs:cancel`) plus read scopes. Cannot create/modify users, manage service accounts, register declarative plugins, activate OS presets, renew TLS certificates, or delete MCP traces.
  - `service_account`: Restricted to `commands:execute`, `plugins:execute`, `mcp:access`, and `jobs:submit`, and further constrained by `allowed_actions` glob matching (`matchActionPattern`).
- **Scope-Subset Enforcement on Token Minting (`POST /api/v1/auth/tokens`)**:
  - Non-admin users can only mint Personal Access Tokens containing a strict subset of their own role's scopes. Any attempt by a `viewer` or `operator` to request `["*"]`, `users:manage`, `service_accounts:manage`, or `commands:execute` (for a `viewer`) is blocked with `403 Forbidden`.
- **Cross-Subsystem Authorization Consistency**:
  - Submitting an asynchronous job (`POST /api/v1/jobs`) or calling an MCP tool (`POST /api/v1/mcp` with `tools/call`) performs the exact same secondary RBAC and `allowed_actions` check as direct synchronous REST execution (`/api/v1/execute` and `/api/v1/plugins/execute`). Neither `/api/v1/jobs` nor `/api/v1/mcp` can be used as a confused-deputy bypass.

### 3.3 Injection & Sandbox Confinement (`400` / `403` / `404`)

- **Command Execution Confinement (`internal/core/executor.go`)**:
  - Only commands explicitly pre-registered in `config.yaml` (or an admin-activated OS preset) can be executed. Unlisted commands return `404 Not Found`.
  - Subprocesses are spawned directly via `exec.CommandContext(ctx, cmdDef.Command, cmdDef.Args...)` with zero shell interpolation.
- **Declarative Plugin Parameter Sanitization (`internal/plugins/declarative.go`)**:
  - Non-scalar JSON types (arrays, objects) are rejected before string formatting.
  - Every parameter is validated against both its pre-compiled regex (`^[a-zA-Z0-9._:/-]+$` by default) and an explicit metacharacter/traversal blocklist (`;&|$><` + backticks, `\n`, `\r`, `../`, `..\`).
- **Read-Only SQL Guard (`internal/plugins/db_exposure.go`)**:
  - `ValidateReadOnlySQL` strips literals, rejects SQL comments (`--`, `/*`), blocks multi-statement semicolons (`;`), requires the statement to begin with `SELECT`, `WITH`, or `EXPLAIN`, and blocks all mutating or administrative SQLite keywords (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `REPLACE`, `TRUNCATE`, `ATTACH`, `DETACH`, `PRAGMA`, `VACUUM`, `REINDEX`, `ANALYZE`) with `403 Forbidden`.

### 3.4 Multi-Layer DDoS, Rate-Limiting & Resource Exhaustion Protection

| Layer | Threat Vector | Control Mechanism | Configuration / Threshold | HTTP Response on Violation |
| :--- | :--- | :--- | :--- | :--- |
| **L1: Network / IP Flood** | Volumetric HTTP DDoS & credential brute-force | Per-IP Token-Bucket Rate Limiter (`IPRateLimiter`) with bounded IP map (`MaxTrackedRateLimitIPs = 10000`) and stale-entry eviction | `server.rate_limit.requests_per_second: 500`, `burst: 2000` | `429 Too Many Requests` (`Retry-After: 1`, `X-RateLimit-Limit`) |
| **L2: HTTP Payload Bomb** | Multi-gigabyte JSON body / chunked stream OOM | `http.MaxBytesReader` + `maxBytesTrackingReader` in `securityMiddleware` | `server.max_request_body_bytes: 1048576` (`1 MiB`) | `413 Request Entity Too Large` |
| **L3: Slowloris / Socket Exhaustion** | Slow headers, stalled request bodies, idle keep-alives | Hardened `http.Server` socket timeouts (`cmd/server/main.go`) | `ReadHeaderTimeout: 5s`, `ReadTimeout: 15s`, `WriteTimeout: 30s`, `IdleTimeout: 60s` | Socket termination |
| **L4: Subprocess Hang / Fork Bomb** | Infinite command loops & orphan child processes | Hierarchical timeout ceiling + process-group kill (`Setpgid` / `taskkill /T /F`) | `executor.max_timeout_seconds: 300`, `default_timeout: 30s` | `400 Bad Request` (override > max) / `500` (`timed_out: true`) |
| **L5: Output Flood** | Subprocess writing gigabytes to stdout/stderr | `limitedOutputBuffer` (sync) & `JobLogBuffer` (async) truncation | `MaxCommandOutputBytes = 1 MiB`, `DefaultMaxLogBytes = 2 MiB` | Output safely truncated with flag |
| **L6: Async Job Queue Flood** | Submitting thousands of concurrent background jobs | Bounded priority heap capacity check (`Engine.Submit`) | `QueueCapacity = 1000` | `429 Too Many Requests` |
| **L7: Telemetry Cardinality DoS** | Fuzzing random URLs or action names to exhaust Prometheus RAM | Path segment normalization (`normalizeMetricPath`) + action label cap | `MaxDynamicActionLabels = 64` (overflow -> `"unknown"`) | Bounded time-series memory |

### 3.5 Zero-Trust MCP Bastion Controls (HITL, `MicroLLM` System-1, Trace Replay & `CISBenchmarks`)

- **Strict Pre-Execution Evaluation Pipeline (`internal/api/approval_handlers.go`, `internal/mcp/server.go`)**:
  - Every command, plugin, async job, and MCP tool invocation passes through: **Auth -> RBAC -> Pre-Approved `approval_id` (canonical SHA-256 match + atomic single-use consume) -> Static HITL Policy -> Pluggable `MicroLLM` System-1 Gatekeeper -> Non-Root UID `10001` Sandboxed Execution**.
  - Unauthenticated or unauthorized callers are rejected (`401`/`403`) before creating HITL challenges or invoking the System-1 gatekeeper, preventing unauthenticated queue-exhaustion or inference-flooding DoS.
- **Fail-Closed `MicroLLM` (`microllm.guard.v1`) Confinement (`internal/gatekeeper/`)**:
  - HTTP mode enforces loopback-only endpoints by default (`allow_remote: false`), disables HTTP redirects, caps response bodies at `64 KiB`, sends strict `extra="forbid"` request payloads, and redacts custom headers in `/api/v1/config`.
  - CLI mode invokes direct argv via `exec.CommandContext` with `ConfigureCommandProcessGroupAndSandbox` (UID/GID `10001`), zero shell interpolation, and strict exit-code cross-validation (`0`=allow, `2`=deny, `3`=x_abstain, `1`=error).
  - Any `hijack_suspected: true` flag overrides `allow` fail-closed; `x_abstain`, timeout, or malformed wire output escalates to HITL (or denies `403 Forbidden` when HITL is disabled).
- **Read-Only `CISBenchmarks` (`cis.mcp.contract.v1`) Audit Preset (`plugins/secops/cis-benchmarks-audit.yaml`, `configs/cis-benchmarks-audit.yaml`)**:
  - Exposes 4 strictly read-only `audit-cis` actions (`cis_list_targets`, `cis_audit_json`, `cis_audit_sarif`, `cis_remediate_dry_run`) with 11 pre-compiled regex allowlists (18 canonical targets, directory-confined `/tmp`/`/var/tmp`/`/var/log/cis` paths), zero `systemctl`, zero shell wrappers, and `CIS_DB_PASSWORD` env-only credential handling.
  - Exposes MCP resource `executor://cis-benchmarks/preset` and allowlist-validated prompt `cis-benchmark-audit`.

---

## 4. Catalog of Passing Security Tests

All security controls are validated by automated tests executed on every push and pull request.

### 4.1 API Security Audit Suite (`internal/api/security_audit_test.go`)

| Test Function | Security Domain Verified | Key Assertions |
| :--- | :--- | :--- |
| `TestAPISecurityAudit_UnauthorizedAccessMatrix` | **Unauthorized Access (`401`) & Fail-Closed Auth** | Verifies all 22 protected REST/MCP/Job operations reject unauthenticated requests, invalid Bearer tokens, invalid `X-API-Key` headers, wrong Basic Auth passwords, revoked PATs, disabled users, and rotated service account keys with `401 Unauthorized`. Verifies fail-closed `401` when `RequireAuth: true` even if `AuthManager == nil` or `Auth.Enabled == false`. |
| `TestAPISecurityAudit_PrivilegeEscalationAndForbiddenMutations` | **Anti-Privilege Escalation & Unauthorized Additions (`403`)** | Verifies `viewer`, `operator`, and `service_account` principals are blocked (`403 Forbidden`) from adding/editing/deleting users, minting elevated PATs, creating/rotating/deleting service accounts, activating OS presets, registering declarative plugins, renewing TLS certs, or clearing MCP traces. Verifies `service_account` allowlist confinement across REST, Async Jobs, and MCP `tools/call`, plus SHA-256 audit chain integrity (`VerifyChain`). |
| `TestAPISecurityAudit_InjectionAndConfinementPrevention` | **Command, Plugin, Path & SQL Injection Confinement** | Verifies unlisted commands return `404`; shell metacharacters (`;`, `$(...)`, backticks, `|`) and `../` in declarative plugins return `400`; file download path traversals return `400`/`403`; and 9 classes of mutating/stacked/commented SQL queries on `/api/v1/db/query` and MCP `db_query` return `403` / `isError: true`. |
| `TestAPISecurityAudit_DDoSRateLimitAndResourceExhaustion` | **DDoS, Per-IP Rate Limiting (`429`), Body Caps (`413`) & Cardinality** | Verifies defensive HTTP headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `X-Permitted-Cross-Domain-Policies`), `413 Request Entity Too Large` on `> 1 MiB` fixed and chunked bodies across 5 POST endpoints, per-IP token-bucket rate limiting (`429` + `Retry-After` + `X-RateLimit-Limit`) with independent IP isolation and `MaxTrackedRateLimitIPs` eviction, timeout ceiling enforcement (`400`), and Prometheus label cardinality caps. |

### 4.2 Authentication, RBAC & Adversarial Suites (`internal/api/`, `internal/plugins/`, `internal/audit/`, `tests/e2e/`)

| Test Suite / File | Coverage Summary |
| :--- | :--- |
| [`internal/api/auth_test.go`](internal/api/auth_test.go) | Session login, PAT lifecycle, Service Account glob matching (`ubuntu-*`), disabled principal rejection, and cross-user PAT revocation blocking. |
| [`internal/api/endpoint_auth_test.go`](internal/api/endpoint_auth_test.go) | Endpoint-level RBAC matrix for `/api/v1/commands`, `/api/v1/history`, `/api/v1/presets`, `/api/v1/files/`, and anonymous privilege escalation prevention (`TestAnonymousPrivilegeEscalationBlockedOnTokenAndPresetEndpoints`). |
| [`internal/plugins/m2_adversarial_test.go`](internal/plugins/m2_adversarial_test.go) | Adversarial security tests for JWT algorithm confusion (`alg: none`), HMAC secret brute-force resistance, non-scalar parameter injection, and SQL comment/stacked-query bypass attempts. |
| [`internal/plugins/plugins_test.go`](internal/plugins/plugins_test.go) | Read-only SQL validation (`TestDBExposureReadOnlyValidationAndExecution`) and declarative parameter regex sanitization. |
| [`internal/audit/audit_test.go`](internal/audit/audit_test.go) | Cryptographic SHA-256 hash chain verification (`GENESIS` linkage) and tamper detection when an SQLite audit row is altered. |
| [`internal/approval/approval_test.go`](internal/approval/approval_test.go) & [`internal/api/approval_gate_test.go`](internal/api/approval_gate_test.go) | HITL policy matching, canonical SHA-256 payload digests, distinct-approver enforcement, TOCTOU tamper rejection (`403`), atomic single-use consumption (`409` on replay), and SQLite reload persistence. |
| [`internal/gatekeeper/gatekeeper_test.go`](internal/gatekeeper/gatekeeper_test.go) & [`internal/api/gatekeeper_integration_test.go`](internal/api/gatekeeper_integration_test.go) | `microllm.guard.v1` HTTP/CLI contract validation, loopback SSRF rejection, `hijack_suspected` fail-closed override, `< 5 ms` localhost benchmark, `0 allocs/op` bounded Prometheus metrics, and `x_abstain` -> HITL escalation. |
| [`internal/mcp/trace_integrity_test.go`](internal/mcp/trace_integrity_test.go) & [`internal/mcp/replay_test.go`](internal/mcp/replay_test.go) | MCP trace SHA-256 hash chaining, audit cross-link verification, tamper detection, `dry_run` verification, and `admin`-only deterministic `live` replay with `parent_trace_id` lineage. |
| [`internal/plugins/cis_preset_test.go`](internal/plugins/cis_preset_test.go) & [`internal/api/cis_preset_test.go`](internal/api/cis_preset_test.go) | Read-only `CISBenchmarks` (`cis.mcp.contract.v1`) declarative loading, pre-compiled regex enforcement, forbidden remediation/credential flag smuggling rejection, UID `10001` sandbox validation, and scoped service-account RBAC isolation. |
| [`tests/e2e/tier2_boundary_test.go`](tests/e2e/tier2_boundary_test.go), [`tier3_cross_feature_test.go`](tests/e2e/tier3_cross_feature_test.go) & [`tier4_bastion_test.go`](tests/e2e/tier4_bastion_test.go) | Full-stack real HTTPS **TLS 1.3** boundary and Zero-Trust MCP Bastion E2E suites chaining `MicroLLM` -> `x_abstain` -> HITL approve -> single-use execute -> SHA-256 audit & trace verify -> deterministic replay -> read-only `CISBenchmarks` preset -> `/metrics` zero-ID-leak audit. |

---

## 5. Running the Security Suite Locally & in CI/CD

### Run All Automated Security Tests Locally

```bash
# 1. Run the comprehensive API Security Audit suite (with race detector)
go test -v -race ./internal/api -run "TestAPISecurityAudit|TestAuth|TestProtectedEndpoints|TestAnonymousPrivilegeEscalation"

# 2. Run the Adversarial Plugin & Read-Only SQL Confinement suite
go test -v ./internal/plugins -run "TestM2Adversarial|TestDBExposure|TestJWTTokenInspector"

# 3. Run the SHA-256 Tamper-Evident Audit Hash-Chain suite
go test -v -race ./internal/audit/...

# 4. Run the End-to-End Security Boundary, Cross-Feature & TLS 1.3 Zero-Trust Bastion suite
go test -v ./tests/e2e -run "TestTier2_Boundary|TestTier3_Combination|TestTier4_ZeroTrustMCPBastion"

# 5. Run the Zero-Trust Bastion HITL, Gatekeeper, MCP Replay & CIS Preset suites (with race detector)
go test -v -race ./internal/approval/... ./internal/gatekeeper/... ./internal/mcp/... ./internal/plugins/...
```

### Continuous Integration (`.github/workflows/security.yml`)

The GitHub Actions workflow [`.github/workflows/security.yml`](.github/workflows/security.yml) runs automatically on:
- Every `push` to `main`
- Every `pull_request` targeting `main`
- Weekly scheduled security regression audits (`cron: '0 4 * * 1'`)
- Manual on-demand dispatch (`workflow_dispatch`)

---

## 6. Reporting a Vulnerability

If you discover a security issue in **API Executor (`go-admin-tool`)**:
1. **Do not open a public issue containing live exploit payloads against production deployments.**
2. Use GitHub Security Advisories (**Security -> Report a vulnerability**) on the repository or open a sanitized tracking issue following the project's atomic governance workflow (`AGENTS.md`), accompanied by a deterministic reproduction test in `internal/api/security_audit_test.go`.
