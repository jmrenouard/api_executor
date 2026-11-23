# Error, Exit Code, and Alert Matrix

Authoritative reference mapping HTTP status codes, System-1 `MicroLLM` exit codes, CIS benchmark audit exit codes, SHA-256 verification failures, and operational alerts to remediation runbooks in **API Executor (`go-admin-tool`)**.

---

## HTTP Status Codes

| Code | Reason | Typical Trigger Condition | Client / Operator Action |
| :--- | :--- | :--- | :--- |
| `202 Accepted` | HITL challenge created (`pending_approval`) | Static HITL policy or `MicroLLM` `x_abstain` escalation minted a pending `apr_*` challenge (`X-Approval-ID` header + approve/reject URLs) | Have a distinct `admin` approve `POST /api/v1/approvals/{id}/approve`, then resubmit with `approval_id` |
| `400 Bad Request` | Malformed payload or invalid selector | Invalid JSON body, disallowed argument flag, invalid `sandbox` value, or invalid SQLite query syntax | Fix payload fields against the endpoint schema and resubmit |
| `401 Unauthorized` | Missing, malformed, or expired credentials | Missing bearer/API key header, unsupported `Authorization: Basic` header, invalid token hash, or expired PAT | Authenticate via `POST /api/v1/auth/login` or rotate key (`X-API-Key` / `Authorization: Bearer`) |
| `403 Forbidden` | Authorization, payload-binding, HITL, SQL, or `MicroLLM` block | RBAC role denial (`viewer` calling mutation endpoint), `ErrPayloadMismatch` (supplied `approval_id` canonical payload SHA-256 mismatch), `MicroLLM` `deny` verdict, `x_abstain` fail-closed rejection when HITL is disabled, self-approval attempt, forbidden SQL keywords (including `PRAGMA` / DML / DDL), or non-whitelisted `allowed_db_paths` target | Request a fresh `apr_*` approval matching the exact target payload, use read-only `SELECT` SQL, elevate role, or inspect gatekeeper decision |
| `404 Not Found` | Unknown route, resource, command, or job | Unmounted route, unknown command name, unknown `multi_config` profile, or missing job/trace/approval ID | Verify catalog endpoints (`/api/v1/commands`, `/api/v1/plugins`, `/api/v1/jobs`) |
| `405 Method Not Allowed` | Unsupported HTTP verb | Calling `GET` on a `POST`-only execution endpoint or unsupported method on `/api/v1/*` | Switch to the method listed in [`rest-mcp-endpoints-and-env.md`](../api-and-cli/rest-mcp-endpoints-and-env.md) |
| `409 Conflict` | Invalid resource state transition or trace integrity failure | Consuming an already-used, expired, rejected, or invalidly transitioned `apr_*` approval token (`ErrAlreadyConsumed`, `ErrExpired`, `ErrInvalidTransition`), tampered MCP trace replay (`ErrIntegrityFailed` on `POST /api/v1/mcp/traces/{trace_id}/replay`), or canceling a terminal job | Obtain a new `apr_*` approval or remediate trace ledger integrity before retrying |
| `413 Request Entity Too Large` | Request body exceeds server limit | Payload larger than `MaxRequestBodyBytes` (`1 MiB` / `1048576` bytes) or oversized gatekeeper response (`> 64 KiB`) | Split batch operations or reduce request body size below `1 MiB` |
| `429 Too Many Requests` | Rate limit or queue capacity exceeded | Client IP exceeds `server.rate_limit` token bucket (`requests_per_second: 500`, `burst: 2000`), pending approvals exceed `max_pending` (`500`), or job queue exceeds `QueueCapacity` (`1000`) | Apply exponential backoff or drain queued async jobs |
| `500 Internal Server Error` | Unhandled server, SQLite, TLS, or fail-closed guard error | Disk/SQLite I/O failure, TLS key generation error, command spawn failure, or fail-closed policy error | Inspect `/api/v1/logs`, host stderr, and audit chain integrity |

---

## System-1 `MicroLLM` CLI Exit Codes

Process exit contract enforced in [`internal/gatekeeper/cli_client.go`](../../../internal/gatekeeper/cli_client.go) (`microllm.guard.v1`):

| Exit Code | Gatekeeper Interpretation | Resulting Policy Behavior |
| :--- | :--- | :--- |
| `0` | `allow` | Evaluates `confidence >= min_confidence` (`0.70` default); allows execution when threshold passes |
| `1` | `error` / invalid input | Triggers `gatekeeper.fail_mode` (`escalate_hitl`, `deny`, or `block`) and records latency telemetry |
| `2` | `deny` / `block` | Rejects execution immediately with `403 Forbidden` regardless of `fail_mode` |
| `3` | `x_abstain` / escalate | Escalates request to Human-in-the-Loop (`apr_*` approval workflow) when `fail_mode == "escalate_hitl"` or blocks when fail-closed |

---

## CIS Benchmark Audit Exit Codes

Process exit codes documented in [`internal/mcp/cis_preset.go`](../../../internal/mcp/cis_preset.go):

| Exit Code | Meaning | Interpretation |
| :--- | :--- | :--- |
| `0` | `success` | Audit check completed cleanly (inspect structured stdout for per-control compliance findings) |
| `1` | `audit_or_runtime_error` | Target inspection command encountered permission, OS compatibility, or runtime errors |
| `2` | `invalid_cli_arguments` | Malformed audit preset invocation arguments |

---

## Audit Trail and MCP Trace Verification Failures

Verification checks performed by `GET /api/v1/audit/verify`, `GET /api/v1/mcp/traces/verify`, and `GET /api/v1/mcp/traces/{trace_id}/verify`:

| Failure Signature | Subsystem | Cryptographic Cause | Required Action |
| :--- | :--- | :--- | :--- |
| `prev_hash mismatch at index N` | Audit Ledger | Event `PrevHash` does not equal `GenesisHash` (index `0`) or entry `N-1` `EntryHash` | Isolate host and remediate suspected log truncation or tampering |
| `entry_hash mismatch at event_id` | Audit Ledger | Recomputed `ComputeEntryHash` SHA-256 differs from stored `EntryHash` | Quarantine audit store and verify backing file permissions (`0600`) |
| `prev_trace_hash mismatch` | MCP Trace Ledger | Trace `PrevTraceHash` breaks linkage from `MCPTraceGenesisHash` or preceding trace | Halt automated MCP agents and collect forensic snapshot |
| `trace_hash mismatch` | MCP Trace Ledger | Recomputed `ComputeTraceHash` SHA-256 differs from stored `TraceHash` | Trigger incident-response audit verification runbook |
| `request_sha256` / `response_sha256` mismatch | MCP Trace Ledger | `CanonicalJSONSHA256` over trace payload diverges from stored digest | Reject trace replay and audit process/memory integrity |
| Missing `audit_entry_hash` correlation | Cross-Ledger Bridge | MCP trace `AuditEventID` or `AuditEntryHash` cannot be matched in audit chain | Inspect concurrent writes and verify both JSONL/SQLite stores |

---

## Alert and Incident Remediation Matrix

| Alert Condition | Signal / Metric Source | Severity | Remediation Runbook |
| :--- | :--- | :--- | :--- |
| **Audit or MCP SHA-256 Chain Break** | `GET /api/v1/audit/verify` or `GET /api/v1/mcp/traces/verify` reports `valid: false` | Critical | [`remediate-audit-or-mcp-trace-tamper.md`](../../02-how-to-guides/incident-response/remediate-audit-or-mcp-trace-tamper.md) |
| **TLS Certificate Expiry / Weak Protocol / Key Exposure** | `GET /api/v1/tls/info` reports imminent expiry, TLS `< 1.2`/`1.3`, or compromised `gat_pat_*`/`gat_svc_*` key | High | [`rotate-tls-and-service-account-keys.md`](../../02-how-to-guides/security/rotate-tls-and-service-account-keys.md) |
| **Rootless Sandbox Violation / Container Privilege Drift** | Startup failure on UID/GID `0` or disallowed `userns: host` | Critical | [`deploy-rootless-docker-and-tls.md`](../../02-how-to-guides/deployment/deploy-rootless-docker-and-tls.md) |
| **Async Job Queue Saturation or Stalled Workers** | `job_queue_depth` approaches `1000` or `action_calls_timeout_total` spikes | High | [`manage-async-jobs-and-presets.md`](../../02-how-to-guides/operations/manage-async-jobs-and-presets.md) |
| **Gatekeeper Abstain Spike or HITL Backlog** | `gatekeeper_decisions_total{decision="x_abstain"}` rises or pending `apr_*` approaches `500` | Medium | [`configure-hitl-and-microllm-gatekeeper.md`](../../02-how-to-guides/operations/configure-hitl-and-microllm-gatekeeper.md) |

---

## Related Documentation

- **Configuration Schema & Profiles**: [`config-schema-and-profiles.md`](../configuration/config-schema-and-profiles.md)
- **REST, MCP & Environment Reference**: [`rest-mcp-endpoints-and-env.md`](../api-and-cli/rest-mcp-endpoints-and-env.md)
- **Cryptographic Hash Chains Deep-Dive**: [`concurrency-timeouts-and-cryptographic-chains.md`](../../04-explanation/deep-dives/concurrency-timeouts-and-cryptographic-chains.md)
