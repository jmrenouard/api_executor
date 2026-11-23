# Tutorial 3: Zero-Trust Bastion & Async Jobs Lab

> **Learning Goal:** Exercise the complete **Zero-Trust MCP Bastion** execution loop in an isolated sandbox
> (`/tmp/apiexec-bastion`): route an operator's async job through a local loopback `MicroLLM` (`microllm.guard.v1`)
> returning `x_abstain`, enforce distinct-admin Human-in-the-Loop (HITL) approval (`require_distinct_approver: true`),
> stream live chunked job logs, and verify SHA-256 audit and MCP trace replay (`dry_run`).

> [!WARNING]
> **Isolated Local Sandbox Only:** This tutorial runs a disposable Python `MicroLLM` mock server on `127.0.0.1:18000`
> and disposable RBAC lab accounts inside `/tmp/apiexec-bastion`. Never deploy mock gatekeepers in production.

---

## Prerequisites

Make sure your environment meets these requirements:

- Go `1.24+` and cloned `api_executor` repository
- `python3` available on `PATH` (used only for the local `microllm.guard.v1` HTTP mock)
- Standard Unix shell (`bash`) with `curl` and `jq`
- Loopback ports `18445/tcp` and `18000/tcp` free

---

## What You Will Build

By the end of this tutorial, you will have:

1. Started a loopback HTTP System-1 mock responding with `microllm.guard.v1` JSON (`x_abstain` on `ps`, `allow` on
   `audit_verify`).
2. Launched `go-admin-tool` with `approval.enabled: true`, `require_distinct_approver: true`, and `gatekeeper.enabled:
   true`.
3. Provisioned an `operator` user (`op-alice`) and a second `admin` approver (`sec-bob`).
4. Triggered an HTTP `202` `pending_approval` challenge on `POST /api/v1/jobs`, confirmed self-approval blocks (`403`),
   and approved via `sec-bob`.
5. Enqueued the async job with `approval_id`, streamed chunked logs (`GET /api/v1/jobs/{id}/logs`), and verified
   `GET /api/v1/audit/verify` plus `dry_run` MCP trace replay.

---

## Step 1: Start the Loopback `MicroLLM` Mock and Bastion Sandbox

Create `/tmp/apiexec-bastion`, launch a local `microllm.guard.v1` evaluator on `127.0.0.1:18000`, and start
`go-admin-tool` on `127.0.0.1:18445`:

```bash
rm -rf /tmp/apiexec-bastion
mkdir -p /tmp/apiexec-bastion/certs
go build -o /tmp/apiexec-bastion/go-admin-tool ./cmd/server

cat <<'PY' > /tmp/apiexec-bastion/mock_microllm.py
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class GuardHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(length) or b"{}")
        cmd = req.get("command", "")
        if "ps" in cmd:
            resp = {
                "schema_version": "microllm.guard.v1",
                "decision": "x_abstain",
                "confidence": 0.48,
                "abstain": True,
                "risk_score": 0.62,
                "primary_threat": "process_enumeration",
                "hijack_suspected": False,
                "reason": "Borderline host process inspection; escalate to HITL",
                "latency_ms": 1.2,
            }
        else:
            resp = {
                "schema_version": "microllm.guard.v1",
                "decision": "allow",
                "confidence": 0.96,
                "abstain": False,
                "risk_score": 0.05,
                "hijack_suspected": False,
                "reason": "Low-risk read-only operation",
                "latency_ms": 0.8,
            }
        body = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

HTTPServer(("127.0.0.1", 18000), GuardHandler).serve_forever()
PY

python3 /tmp/apiexec-bastion/mock_microllm.py &
GK_PID=$!

cat <<'YAML' > /tmp/apiexec-bastion/bastion-lab.yaml
version: "2.2.0"

server:
  port: 18445
  host: "127.0.0.1"
  tls:
    enabled: true
    auto_generate: true
    cert_file: "/tmp/apiexec-bastion/certs/server.crt"
    key_file: "/tmp/apiexec-bastion/certs/server.key"
    min_version: "1.3"
    hosts: ["localhost", "127.0.0.1"]

database:
  path: "/tmp/apiexec-bastion/history.db"

command_executor:
  enabled: true
  default_timeout: "30s"
  max_timeout_seconds: 300
  commands:
    - name: "list-processes"
      command: "ps"
      args: ["aux"]
      timeout: "30s"
    - name: "disk-usage"
      command: "df"
      args: ["-h"]
      timeout: "15s"
      require_approval: true

auth:
  enabled: true
  require_auth: true
  bootstrap_username: "admin"
  bootstrap_password: "lab-admin-pass"

plugins:
  enabled: true
  enable_db_exposure: true
  enable_sys_diagnostics: true

mcp:
  enabled: true
  retain_traces: true
  trace_file_path: "/tmp/apiexec-bastion/mcp-traces.jsonl"

audit:
  enabled: true
  file_path: "/tmp/apiexec-bastion/audit.jsonl"

approval:
  enabled: true
  default_ttl: "10m"
  max_pending: 500
  require_distinct_approver: true
  critical_commands: ["disk-usage"]

gatekeeper:
  enabled: true
  mode: "http"
  endpoint: "http://127.0.0.1:18000/v1/guard/evaluate"
  timeout: "50ms"
  min_confidence: 0.70
  fail_mode: "escalate_hitl"
  environment: "development"

sandbox:
  enabled: true
  enforce_non_root: true
  uid: 10001
  gid: 10001
  userns: "keep-id"
YAML

CONFIG_PATH=/tmp/apiexec-bastion/bastion-lab.yaml /tmp/apiexec-bastion/go-admin-tool > /tmp/apiexec-bastion/server.out 2>&1 &
BASTION_PID=$!
sleep 2
```

---

## Step 2: Provision Distinct Requester and Approver Accounts

Create `op-alice` (`operator`) and `sec-bob` (`admin`), then log in as each account:

```bash
ADMIN_TOK=$(curl -sk -X POST https://127.0.0.1:18445/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"lab-admin-pass"}' | jq -r '.token')

curl -sk -X POST https://127.0.0.1:18445/api/v1/auth/users \
  -H "Authorization: Bearer ${ADMIN_TOK}" \
  -H "Content-Type: application/json" \
  -d '{"username":"op-alice","password":"alice-lab-pass","display_name":"Alice Operator","role":"operator"}' > /dev/null

curl -sk -X POST https://127.0.0.1:18445/api/v1/auth/users \
  -H "Authorization: Bearer ${ADMIN_TOK}" \
  -H "Content-Type: application/json" \
  -d '{"username":"sec-bob","password":"bob-lab-pass","display_name":"Bob Security Admin","role":"admin"}' > /dev/null

ALICE_TOK=$(curl -sk -X POST https://127.0.0.1:18445/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"op-alice","password":"alice-lab-pass"}' | jq -r '.token')

BOB_TOK=$(curl -sk -X POST https://127.0.0.1:18445/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"sec-bob","password":"bob-lab-pass"}' | jq -r '.token')
```

---

## Step 3: Trigger System-1 `x_abstain` Escalation and Approve as Distinct Admin

Submit `list-processes` as `op-alice` via `POST /api/v1/jobs`. Because `mock_microllm.py` returns `x_abstain`, the
server escalates fail-closed to a HITL approval challenge:

```bash
CHALLENGE=$(curl -sk -X POST https://127.0.0.1:18445/api/v1/jobs \
  -H "Authorization: Bearer ${ALICE_TOK}" \
  -H "Content-Type: application/json" \
  -d '{"type":"command","action":"list-processes","priority":"high","timeout":"10s"}')

echo "${CHALLENGE}" | jq .
APPROVAL_ID=$(echo "${CHALLENGE}" | jq -r '.approval_id')
```

Expected response (`202 Accepted`):

```json
{
  "status": "pending_approval",
  "approval_id": "apr_9e8d7c6b5a4f3e2d1c0b9a8f",
  "expires_at": "2026-11-23T19:55:00Z",
  "payload_sha256": "4c2d...",
  "message": "System-1 gatekeeper abstained (Borderline host process inspection; escalate to HITL); Human-in-the-Loop approval required",
  "approve_url": "/api/v1/approvals/apr_9e8d7c6b5a4f3e2d1c0b9a8f/approve",
  "reject_url": "/api/v1/approvals/apr_9e8d7c6b5a4f3e2d1c0b9a8f/reject",
  "gatekeeper_decision": "x_abstain",
  "risk_score": 0.62
}
```

Confirm that `op-alice` cannot self-approve (`403`), then approve via distinct admin `sec-bob`:

```bash
curl -sk -o /dev/null -w "self_approve_status=%{http_code}\n" \
  -X POST "https://127.0.0.1:18445/api/v1/approvals/${APPROVAL_ID}/approve" \
  -H "Authorization: Bearer ${ALICE_TOK}"

curl -sk -X POST "https://127.0.0.1:18445/api/v1/approvals/${APPROVAL_ID}/approve" \
  -H "Authorization: Bearer ${BOB_TOK}" \
  -H "Content-Type: application/json" \
  -d '{"comment":"Verified safe process inspection"}' | jq '{id,status,approver_id}'
```

Expected output:

```text
self_approve_status=403
```

```json
{
  "id": "apr_9e8d7c6b5a4f3e2d1c0b9a8f",
  "status": "approved",
  "approver_id": "sec-bob"
}
```

---

## Step 4: Enqueue the Approved Async Job and Stream Live Logs

Re-submit the exact payload including `"approval_id": "${APPROVAL_ID}"`. Notice that modifying `"timeout"` or `"action"`
would trigger a `403` `ErrPayloadMismatch`, and reusing the consumed ID later returns `409 Conflict`:

```bash
JOB_RESP=$(curl -sk -X POST https://127.0.0.1:18445/api/v1/jobs \
  -H "Authorization: Bearer ${ALICE_TOK}" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"command\",\"action\":\"list-processes\",\"priority\":\"high\",\"timeout\":\"10s\",\"approval_id\":\"${APPROVAL_ID}\"}")

echo "${JOB_RESP}" | jq .
JOB_ID=$(echo "${JOB_RESP}" | jq -r '.job_id')
sleep 1

curl -sk "https://127.0.0.1:18445/api/v1/jobs/${JOB_ID}/logs?offset=0" \
  -H "Authorization: Bearer ${ALICE_TOK}" | jq '{job_id,status,offset,next_offset,eof}'

curl -sk https://127.0.0.1:18445/api/v1/jobs/queue \
  -H "Authorization: Bearer ${ALICE_TOK}" | jq .
```

Expected `logs` response:

```json
{
  "job_id": "job_01j9a8b7c6d5e4f3a2b1c0d9",
  "status": "completed",
  "offset": 0,
  "next_offset": 1420,
  "eof": true
}
```

---

## Step 5: Verify SHA-256 Audit Chain and MCP `dry_run` Replay

Execute one MCP `audit_verify` call, verify the audit chain, and replay the MCP trace in `dry_run` mode:

```bash
TRACE_ID=$(curl -sk -X POST https://127.0.0.1:18445/api/v1/mcp \
  -H "Authorization: Bearer ${ALICE_TOK}" \
  -H "X-MCP-Session-ID: bastion-01" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"audit_verify","arguments":{}}}' | jq -r '.trace_id')

curl -sk https://127.0.0.1:18445/api/v1/audit/verify \
  -H "Authorization: Bearer ${ALICE_TOK}" | jq .

curl -sk -X POST "https://127.0.0.1:18445/api/v1/mcp/traces/${TRACE_ID}/replay" \
  -H "Authorization: Bearer ${ALICE_TOK}" \
  -H "Content-Type: application/json" \
  -d '{"mode":"dry_run"}' | jq '{original_trace_id,mode,integrity_valid,audit_chain_valid,policy_eligible}'
```

Expected replay report:

```json
{
  "original_trace_id": "mcp_tr_...",
  "mode": "dry_run",
  "integrity_valid": true,
  "audit_chain_valid": true,
  "policy_eligible": true
}
```

---

## Step 6: Clean Up the Sandbox

Terminate both background processes and delete `/tmp/apiexec-bastion`:

```bash
kill "${BASTION_PID}" "${GK_PID}" 2>/dev/null || true
wait "${BASTION_PID}" "${GK_PID}" 2>/dev/null || true
rm -rf /tmp/apiexec-bastion
```

---

## Next Steps

- Configure production HITL and System-1 `MicroLLM` rules:
  [Configure HITL and MicroLLM Gatekeeper](../02-how-to-guides/operations/configure-hitl-and-microllm-gatekeeper.md)
- Inspect HTTP `403`/`409`/`429` codes and alert matrices:
  [Error & Alert Matrix](../03-reference/troubleshooting-codes/error-and-alert-matrix.md)
- Study canonical SHA-256 digest equations, 4-tier timeouts, and `sync.Pool` log chunks:
  [Concurrency, Timeouts & Cryptographic Chains](../04-explanation/deep-dives/concurrency-timeouts-and-cryptographic-chains.md)
