# ADR-001: Zero-Trust Direct Execution, Pure-Go Persistence, and Fail-Closed Gating

- **Status**: Accepted
- **Scope**: Execution Engine (`internal/core`), Persistence (`internal/database`, `internal/approval`), Security Gating (`internal/gatekeeper`, `internal/approval`)
- **Governance Context**: API Executor (`go-admin-tool`) v2.x Architecture

---

## Context

Exposing administrative diagnostics, OS remediation presets, and SQLite database inspection to autonomous LLM agents via REST and MCP creates three structural failure risks:

1. **Command injection via shell parsing**: Passing user or LLM arguments through `/bin/sh -c` enables metacharacter injection (`;`, `|`, `$()`, backticks) regardless of upstream prompt filtering.
2. **Deployment fragility under CGO dependencies**: Requiring native SQLite CGO toolchains complicates static cross-compilation (`CGO_ENABLED=0`), minimal rootless containers, and Windows/Linux test portability.
3. **Unsafe fail-open defaults in hybrid human/AI gating**: Ambiguous integration between local `MicroLLM` classifiers, Human-in-the-Loop (HITL) approval tokens, and elevated runtime privileges risks executing unsafe commands during classifier timeouts or container misconfiguration.

---

## Decision Drivers

- Eliminate entire classes of shell metacharacter injection at the OS process boundary.
- Ship reproducible static binaries and rootless `UID/GID 10001` container workloads with minimal host dependencies.
- Guarantee deterministic fail-closed semantics when semantic classifiers abstain, time out, or lack confidence, while preserving fast single-use HITL token consumption bound to exact request payloads.

---

## Decision Outcome

The architecture standardizes three foundational invariants:

1. **Direct Argv Subprocess Execution (`exec.CommandContext`)**: Every whitelisted command and declarative YAML plugin executes its target binary directly with an explicit argument array (`argv`), never invoking a host shell interpreter.
2. **Pure-Go SQLite with Automatic In-Memory Fallback**: Database initialization applies SQLite WAL mode (`journal_mode=WAL`, `busy_timeout=5000`, `MaxOpenConns=1`) when compiled with SQLite support, and automatically switches to pure-Go in-memory stores (`db.IsInMemory()`) for history, approvals, and credentials when built with `CGO_ENABLED=0`.
3. **Strict Precedence & Fail-Closed Guardrail Ordering**: Requests check RBAC first, then validate any supplied single-use `apr_*` token against its canonical payload SHA-256 (`ComputePayloadSHA256`), then enforce static HITL policies (`require_approval` / `critical_*`), and finally invoke System-1 `MicroLLM` (`microllm.guard.v1`) where any error, timeout (`5ms`), low confidence (`< 0.70`), or `x_abstain` triggers `fail_mode` (`escalate_hitl` or hard `deny`/`block`). Process sandboxes reject `UID/GID 0` and `userns: "host"`.

---

## Options and Trade-Offs

| Design Dimension | Chosen Option | Rejected Alternative | Trade-Off & Rationale |
| :--- | :--- | :--- | :--- |
| **Process Spawn Mechanism** | Direct binary `exec.CommandContext` with explicit `argv` array | Shell invocation via `/bin/sh -c` | Pipelines or shell globs require explicit command binaries or wrappers, but shell metacharacter injection becomes structurally impossible. |
| **Storage Engine** | Local SQLite WAL (`MaxOpenConns=1`) with pure-Go in-memory fallback (`CGO_ENABLED=0`) | Mandatory PostgreSQL/Redis or mandatory CGO SQLite | In-memory `CGO_ENABLED=0` state resets on process restart and does not span horizontal replicas (documented in `APP-022`), yet guarantees zero-dependency static builds and instant hermetic tests. |
| **Gating Precedence** | RBAC -> Single-use `approval_id` digest check -> Static HITL -> System-1 `MicroLLM` (`fail_mode`) | Running `MicroLLM` after execution or failing open on guard timeout | Checking canonical `ComputePayloadSHA256` before consumption prevents TOCTOU argument tampering, and failing closed adds safe HITL friction rather than silent bypass on guard outages. |
| **Privilege Model** | Mandatory non-root `UID/GID 10001`, `userns: "keep-id"`, `no_new_privileges`, `drop_caps` | Privileged container or configurable `UID 0` | Disables tasks requiring unprivileged host capabilities unless granted by controlled wrappers, eliminating accidental root container breakouts. |

---

## Consequences

- **Positive**: Shell injection surface is eliminated across static commands and YAML declarative plugins; CI and rootless containers operate identically with `CGO_ENABLED=0`; security failures degrade conservatively toward human review (`apr_*`) or rejection (`403` / `409`).
- **Constraints**: Multi-replica horizontal scaling with shared persistent HITL approvals requires future external distributed state (tracked in `APP-022`); multi-command diagnostic chains must be defined explicitly as declarative plugins or curated OS presets rather than ad-hoc shell pipelines.

---

## Related Documentation

- **Configuration Schema & Sandbox Keys**: [`config-schema-and-profiles.md`](../../03-reference/configuration/config-schema-and-profiles.md)
- **HTTP, MicroLLM & Audit Verification Codes**: [`error-and-alert-matrix.md`](../../03-reference/troubleshooting-codes/error-and-alert-matrix.md)
- **Deploy Rootless Container & TLS Guide**: [`deploy-rootless-docker-and-tls.md`](../../02-how-to-guides/deployment/deploy-rootless-docker-and-tls.md)
- **Configure HITL & MicroLLM Gatekeeper Guide**: [`configure-hitl-and-microllm-gatekeeper.md`](../../02-how-to-guides/operations/configure-hitl-and-microllm-gatekeeper.md)
