# Concurrency, Timeout Bounds, and Cryptographic Chains

Systems engineering analysis of bounded execution, timeout precedence, non-blocking credential lookups, pooled streaming buffers, bounded cardinality metrics, and dual SHA-256 tamper-evident chains in **API Executor (`go-admin-tool`)**.

---

## Four-Tier Timeout Resolution and Process-Group Termination

Every synchronous and asynchronous command enforces strict wall-clock isolation through `ExecutorConfig.ResolveTimeout(cmd, override)` ([`internal/core/config.go`](../../../internal/core/config.go)) and per-platform process-group supervision ([`internal/core/executor_unix.go`](../../../internal/core/executor_unix.go), [`internal/core/executor_windows.go`](../../../internal/core/executor_windows.go)).

### Timeout Precedence Hierarchy

Timeout selection evaluates four ordered tiers from most specific to global default, bounded optionally by `command_executor.max_timeout_seconds`:

1. **Tier 1 — Per-call override**: An explicit request timeout (`override > 0`) supersedes static YAML defaults.
2. **Tier 2 — Command definition**: `command_executor.commands[].timeout` (Go duration string such as `"10s"`) takes precedence; if unset, `timeout_seconds` (`> 0`) applies.
3. **Tier 3 — Executor default**: `ExecutorConfig.EffectiveDefaultTimeout()` resolves `command_executor.default_timeout` (falling back to `default_timeout_seconds`, with explicit `DefaultTimeoutSeconds` mutations honored when `default_timeout` remains `"30s"`).
4. **Tier 4 — Global constant fallback**: Empty or unparseable configs normalize cleanly to `DefaultCommandTimeout` (`30s`). When `command_executor.max_timeout_seconds > 0`, resolved durations are capped at that ceiling.

### Process-Group Cancellation on Deadline

Standard `exec.CommandContext` termination sends `SIGKILL` only to the direct child PID; spawned grandchild processes can survive and hold stdout/stderr pipes open indefinitely. To guarantee bounded cleanup within milliseconds of `context.DeadlineExceeded`:

- Commands execute inside an isolated OS process group (`executor_unix.go` / `executor_windows.go`).
- Context expiration or `POST /api/v1/jobs/{id}/cancel` tears down the entire descendant tree simultaneously, wrapping timeout errors so callers observe both `ErrCommandTimeout` (`IsCommandTimeout(err)`) and `context.DeadlineExceeded`.
- Execution telemetry distinguishes exit status semantics into orthogonal Prometheus series: non-zero process exit maps to `IsCommandFailure` (`action_calls_failure_total`), binary spawn errors map to `IsCommandSystemError` (`action_calls_error_total`), and deadline expirations increment `action_calls_timeout_total`.

---

## O(1) Authentication Indexing and Rate-Limiter Memory Bounds

Auth checks run on the hot path of every protected API and MCP request. Executing `10000`-round salted key derivation on every bearer token request would degrade CPU throughput under autonomous agent bursts.

### Asymmetric Auth Path Splitting

- **Interactive password login (`POST /api/v1/auth/login`)**: Enforces `10000`-round salted SHA-256 with a `16`-byte salt and `subtle.ConstantTimeCompare`.
- **Stateless API tokens and service accounts (`gat_pat_*`, `gat_svc_*`)**: Keys carry `20` and `24` cryptographically random bytes respectively. At registration and store load, `auth.Manager` builds `O(1)` SHA-256 lookup maps (`tokenByHash`, `serviceAccountByHash`), resolving per-request verification in a single SHA-256 digest and hash map lookup followed by constant-time equality verification.

### Rate-Limiter State Bounding

Inbound rate limiting (`requests_per_second: 500`, `burst: 2000`) bounds its client IP tracking table at `MaxTrackedRateLimitIPs = 10000` and evicts stale IP buckets after `2m` of inactivity ([`internal/api/security_middleware.go`](../../../internal/api/security_middleware.go)), preventing unbounded heap growth under distributed spoofed-source floods.

---

## Async Priority Queue, `sync.Pool` Log Buffers, and Metric Cardinality

Long-running diagnostics offload from synchronous HTTP handlers to the async engine ([`internal/jobs/engine.go`](../../../internal/jobs/engine.go), [`internal/jobs/queue.go`](../../../internal/jobs/queue.go), [`internal/jobs/buffer.go`](../../../internal/jobs/buffer.go)):

- **Priority max-heap and worker pool**: Incoming jobs enqueue into a bounded priority max-heap (`QueueCapacity = 1000`) drained concurrently by `WorkersCount = 4` worker goroutines.
- **Pooled ring output buffers**: Each job retains at most `DefaultMaxLogBytes` (`2 MiB`, `2097152` bytes) backed by `sync.Pool`-recycled fixed `[16384]byte` (`16 KiB`) chunks (`ChunkSize = 16384`), bounding heap churn while synchronous `ExecuteCommand` captures up to `MaxCommandOutputBytes` (`1 MiB`) in `limitedOutputBuffer`.
- **Bounded Prometheus label cardinality**: Dynamic `action` labels on `action_calls_*` and `action_mode_*` metrics are truncated at `MaxActionLabelLength = 64` and capped at `MaxDynamicActionLabels = 64` unique label values; unseen labels beyond the cap collapse into `"unknown"` to protect Prometheus TSDB memory against cardinality explosion.

---

## Cryptographic SHA-256 Chain Equations

**API Executor** maintains two linked append-only SHA-256 hash chains across [`internal/audit/audit.go`](../../../internal/audit/audit.go) and [`internal/mcp/trace_integrity.go`](../../../internal/mcp/trace_integrity.go).

### 1. Audit Ledger Hash Chain

The audit ledger anchors record $i = 1$ at the deterministic genesis constant:

$$
H_{\text{audit},0} = \text{GENESIS\_00000000000000000000000000000000000000000000000000000000}
$$

For every subsequent event $i \ge 1$, the chain enforces `PrevHash` linkage ($P_i = H_{\text{audit},i-1}$) and serializes the pipe-delimited canonical preimage in `ComputeEntryHash`:

$$
H_{\text{audit},i} = \text{SHA256}\Big(\text{ID}_i \,\|\, \text{EventID}_i \,\|\, \text{UTC}_{\text{RFC3339Nano}}(t_i) \,\|\, \text{TraceID}_i \,\|\, \text{Category}_i \,\|\, \text{Action}_i \,\|\, \text{ActorType}_i \,\|\, \text{ActorID}_i \,\|\, \text{Status}_i \,\|\, \text{DurationMs}_i \,\|\, \text{Summary}_i \,\|\, P_i\Big)
$$

where $\|$ denotes insertion of the literal ASCII `|` separator. Any historical deletion, reordering, or single-field edit invalidates $H_{\text{audit},i}$ and every subsequent $P_{j} = H_{\text{audit},j-1}$ for $j > i$.

### 2. MCP Trace Ledger and Canonical Payload Digests

The MCP trace chain anchors at `MCPTraceGenesisHash`:

$$
T_0 = \text{MCP\_TRACE\_GENESIS\_0000000000000000000000000000000000000000000000}
$$

Because JSON map key order varies across clients and Go maps, `CanonicalJSONSHA256` normalizes any JSON value $x$ by marshaling to JSON, unmarshaling into generic map/slice structures (`any`), and re-marshaling so `encoding/json` sorts all object keys lexicographically before computing the SHA-256 hex digest:

$$
D(x) = \text{SHA256}\big(\text{CanonicalJSON}(x)\big)
$$

Each MCP trace record $i \ge 1$ binds its request digest $D(\text{req}_i)$, response digest $D(\text{resp}_i)$, correlated audit identity (`AuditEventID`, `AuditEntryHash`), and `MicroLLM` guard telemetry (`GatekeeperDecision`, `GatekeeperRiskScore` formatted to $6$ decimal places, `GatekeeperLatencyMs` formatted to $3$ decimal places) into `ComputeTraceHash`:

$$
T_i = \text{SHA256}\Big(\text{TraceID}_i \,\|\, \text{ParentTraceID}_i \,\|\, \text{SessionID}_i \,\|\, \text{UTC}_{\text{RFC3339Nano}}(t_i) \,\|\, \text{Method}_i \,\|\, \text{ToolName}_i \,\|\, \text{Actor}_i \,\|\, \text{Status}_i \,\|\, \text{IsError}_i \,\|\, \text{DurationMs}_i \,\|\, D(\text{req}_i) \,\|\, D(\text{resp}_i) \,\|\, \text{AuditEventID}_i \,\|\, H_{\text{audit}}(i) \,\|\, \text{GatekeeperDecision}_i \,\|\, \text{GatekeeperRiskScore}_i \,\|\, \text{GatekeeperLatencyMs}_i \,\|\, T_{i-1}\Big)
$$

When `GET /api/v1/audit/verify` or `GET /api/v1/mcp/traces/verify` executes, the verifier recomputes every digest sequentially from $H_{\text{audit},0}$ and $T_0$ and reports the exact failing index and field on mismatch.

---

## Related Documentation

- **Zero-Trust Topology Overview**: [`zero-trust-mcp-bastion-topology.md`](../architecture-overview/zero-trust-mcp-bastion-topology.md)
- **Configuration & Job Engine Defaults**: [`config-schema-and-profiles.md`](../../03-reference/configuration/config-schema-and-profiles.md)
- **Audit / MCP Tamper Remediation Runbook**: [`remediate-audit-or-mcp-trace-tamper.md`](../../02-how-to-guides/incident-response/remediate-audit-or-mcp-trace-tamper.md)
- **Error & Verification Failure Matrix**: [`error-and-alert-matrix.md`](../../03-reference/troubleshooting-codes/error-and-alert-matrix.md)
