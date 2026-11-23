# Configure HITL and MicroLLM Gatekeeper

Refer to
[Configuration Schema and Profiles](../../03-reference/configuration/config-schema-and-profiles.md)
and
[Error and Alert Matrix](../../03-reference/troubleshooting-codes/error-and-alert-matrix.md)
before you modify bastion policies.

## Prerequisites

1. Prepare at least two separate accounts: one requester (`operator` or `admin`) and one distinct `admin` approver.
2. Prepare a loopback `MicroLLM` (`microllm.guard.v1`) HTTP endpoint or a local non-root `microllm-guard` CLI binary.
3. Confirm write access to `config.yaml` on the host.

## Safety Instructions

**CAUTION:** Keep `require_distinct_approver: true` and `fail_mode: "escalate_hitl"` in production.
Self-approval or permissive fail-open rules allow one compromised account to bypass dual control.

**CAUTION:** Keep `allow_remote_endpoint: false` unless an encrypted tunnel protects the remote gatekeeper link.
Plaintext remote inference leaks command payloads, parameters, and actor names on the network.

## Procedure

1. Open `config.yaml` and add the `approval:` Human-in-the-Loop block:

   ```yaml
   approval:
     enabled: true
     default_ttl: "10m"
     max_pending: 500
     require_distinct_approver: true
     critical_commands:
       - "disk-usage"
     critical_plugins:
       - "db-exposure:*"
     critical_mcp_tools:
       - "execute_command"
   ```

2. Add the `gatekeeper:` System-1 `MicroLLM` block in `http` or `cli` mode:

   ```yaml
   gatekeeper:
     enabled: true
     mode: "http"
     endpoint: "http://127.0.0.1:8000/v1/guard/evaluate"
     allow_remote_endpoint: false
     timeout: "5ms"
     min_confidence: 0.70
     fail_mode: "escalate_hitl"
     environment: "production"
   ```

3. Enforce `0600` file permissions on `config.yaml`, then restart `go-admin-tool`:

   ```bash
   chmod 0600 config.yaml
   ```

4. Submit a critical action as the requester and record `approval_id` from the HTTP `202` challenge:

   ```bash
   curl -k -X POST https://localhost:8080/api/v1/execute \
     -H "Authorization: Bearer ${REQUESTER_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"name":"disk-usage"}'
   ```

5. Inspect the open challenge and its `payload_sha256` digest with `GET /api/v1/approvals/{id}`:

   ```bash
   curl -k "https://localhost:8080/api/v1/approvals/${APPROVAL_ID}" \
     -H "Authorization: Bearer ${APPROVER_TOKEN}"
   ```

6. Approve the challenge as the second distinct `admin` with `POST /api/v1/approvals/{id}/approve`:

   ```bash
   curl -k -X POST "https://localhost:8080/api/v1/approvals/${APPROVAL_ID}/approve" \
     -H "Authorization: Bearer ${APPROVER_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"comment":"Reviewed payload digest"}'
   ```

7. Re-send the identical request with `"approval_id"` in the JSON body or in `X-Approval-ID`:

   ```bash
   curl -k -X POST https://localhost:8080/api/v1/execute \
     -H "Authorization: Bearer ${REQUESTER_TOKEN}" \
     -H "Content-Type: application/json" \
     -d "{\"name\":\"disk-usage\",\"approval_id\":\"${APPROVAL_ID}\"}"
   ```

**NOTE:** When `gatekeeper.mode` equals `"cli"`, `go-admin-tool` runs `cli_path` as UID/GID `10001` without a shell.
Exit codes `0`, `2`, `3`, and `1` map to `allow`, `deny`, `x_abstain`, and `error`.

## Verification

1. Call `GET /api/v1/config` and confirm `approval.enabled` and `gatekeeper.enabled` both equal `true`.
2. Confirm that any `gatekeeper.headers` values appear as `"[REDACTED]"` in `/api/v1/config`.
3. Confirm that self-approval returns HTTP `403` and duplicate replay of a consumed `approval_id` returns HTTP `409`.
4. Query `/metrics` and confirm `gatekeeper_decisions_total` and `gatekeeper_latency_seconds` appear.

## Rollback

If System-1 inference blocks valid traffic, do these steps:

1. Reject any unwanted open requests with `POST /api/v1/approvals/{id}/reject`.
2. Set `gatekeeper.enabled: false` in `config.yaml` while you keep `approval.enabled: true`.
3. Restart `go-admin-tool` and confirm normal command flow through static HITL policy.

## Related Documentation

- Reference: [Configuration Schema and Profiles](../../03-reference/configuration/config-schema-and-profiles.md)
- Reference: [Error and Alert Matrix](../../03-reference/troubleshooting-codes/error-and-alert-matrix.md)
- Explanation:
  [Zero-Trust MCP Bastion Topology](../../04-explanation/architecture-overview/zero-trust-mcp-bastion-topology.md)
- Explanation:
  [ADR-001: Zero-Trust Execution and Bastion](../../04-explanation/design-decisions/adr-001-zero-trust-execution-and-bastion.md)
