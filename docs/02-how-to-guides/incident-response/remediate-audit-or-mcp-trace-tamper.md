# Remediate Audit or MCP Trace Tamper

Refer to
[Error and Alert Matrix](../../03-reference/troubleshooting-codes/error-and-alert-matrix.md)
before you execute this runbook.

## Prerequisites

1. Make sure that you hold a valid `admin` Personal Access Token (`gat_pat_...`).
2. Confirm SSH or local terminal access to the affected API Executor host.
3. Locate the configured `database.path`, `audit.file_path`, and `mcp.trace_file_path` files.

## Safety Instructions

**WARNING:** Isolate the affected node from production traffic before you touch `history.db` or JSONL files.
Active writes during triage can overwrite forensic evidence or cause security incidents.

**CAUTION:** Do not call `DELETE /api/v1/mcp/traces` before you archive forensic copies of all databases and logs.
The `DELETE` call removes active memory and database trace records permanently.

## Procedure

1. Query `GET /api/v1/audit/verify` and record `valid`, `broken_at_id`, `last_hash`, and `reason`:

   ```bash
   curl -k https://localhost:8080/api/v1/audit/verify \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   ```

2. Query `GET /api/v1/mcp/traces/verify` and record `valid`, `broken_at_trace_id`, `audit_chain_valid`, and `reason`:

   ```bash
   curl -k https://localhost:8080/api/v1/mcp/traces/verify \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   ```

3. Inspect the suspect trace with `GET /api/v1/mcp/traces/{trace_id}/verify`:

   ```bash
   curl -k "https://localhost:8080/api/v1/mcp/traces/${TRACE_ID}/verify" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   ```

4. Stop `go-admin-tool` on the node and copy `history.db` plus JSONL logs to read-only forensic storage:

   ```bash
   mkdir -p /var/backups/forensics/incident-snapshot
   cp history.db audit.jsonl mcp-traces.jsonl /var/backups/forensics/incident-snapshot/
   sha256sum /var/backups/forensics/incident-snapshot/* > /var/backups/forensics/incident-snapshot/SHA256SUMS
   chmod -R 0400 /var/backups/forensics/incident-snapshot
   ```

5. Inspect audit and trace events around `broken_at_id` or `broken_at_trace_id`:

   ```bash
   curl -k "https://localhost:8080/api/v1/audit/logs?limit=200" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   curl -k "https://localhost:8080/api/v1/mcp/traces?limit=200" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   ```

6. Test intact traces with zero-side-effect `dry_run` replay through `POST /api/v1/mcp/traces/{trace_id}/replay`:

   ```bash
   curl -k -X POST "https://localhost:8080/api/v1/mcp/traces/${TRACE_ID}/replay" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"mode":"dry_run"}'
   ```

7. Rotate all active TLS certificates, Personal Access Tokens, and Service Account keys on the host.
8. Restore `history.db`, `audit.jsonl`, and `mcp-traces.jsonl` from the clean backup, then start `go-admin-tool`.

**NOTE:** Replay on a tampered trace returns HTTP `409 Conflict` (`ErrIntegrityFailed`).
`dry_run` mode checks request, response, and audit link digests with zero command execution.

## Verification

1. Call `GET /api/v1/audit/verify` and confirm `"valid": true`.
2. Call `GET /api/v1/mcp/traces/verify` and confirm `"valid": true` and `"audit_chain_valid": true`.
3. Confirm `GET /api/v1/audit/logs?limit=5` shows new post-recovery events chained from the valid `last_hash`.

## Rollback

If verification returns `"valid": false` after recovery, do these steps:

1. Stop `go-admin-tool` immediately on the host.
2. Keep the host detached from upstream load balancers and MCP clients.
3. Provision a fresh container or host from the last verified immutable backup and escalate to security response.

## Related Documentation

- Reference: [Error and Alert Matrix](../../03-reference/troubleshooting-codes/error-and-alert-matrix.md)
- Reference: [REST, MCP Endpoints, and Environment](../../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)
- Explanation:
  [Concurrency, Timeouts, and Cryptographic Chains](../../04-explanation/deep-dives/concurrency-timeouts-and-cryptographic-chains.md)
- Explanation:
  [Zero-Trust MCP Bastion Topology](../../04-explanation/architecture-overview/zero-trust-mcp-bastion-topology.md)
