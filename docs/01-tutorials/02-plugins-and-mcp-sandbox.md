# Tutorial 2: Plugins & MCP Sandbox

> **Learning Goal:** Explore **API Executor**'s 305+ plugins catalog (`GET /api/v1/plugins`), run native Go and
> declarative YAML plugins without shell interpolation, execute guarded read-only SQLite queries (`db-exposure`), and
> invoke JSON-RPC 2.0 Model Context Protocol (MCP) tools (`POST /api/v1/mcp`) with cryptographic SHA-256 trace checks.

> [!WARNING]
> **Isolated Local Sandbox Only:** Run all commands against `/tmp/apiexec-mcp-lab` on `127.0.0.1:18444`. Never pass
> production SQLite files or sensitive host paths into sandbox examples.

---

## Prerequisites

Make sure your environment meets these requirements:

- Go `1.24+` and cloned `api_executor` repository (with the `plugins/` directory at repository root)
- Standard Unix shell (`bash`) with `curl` and `jq`
- Port `18444/tcp` available on loopback `127.0.0.1`

---

## What You Will Build

By the end of this tutorial, you will have:

1. Launched an isolated server loading all 24 native Go plugins, 1 built-in declarative plugin (`ops-quick-tools`), and 282 declarative YAML plugins from `plugins/`.
2. Filtered plugins by domain category (`SysAdmin`, `WebUtils`) and implementation type (`native`, `declarative`).
3. Executed native (`sys-diagnostics`) and declarative (`crypto-sha256-file`) plugins safely via direct `argv`.
4. Queried SQLite tables (`GET /api/v1/db/tables`), executed a read-only `SELECT` query, and verified DDL/DML blocking
   (`403 Forbidden`).
5. Called JSON-RPC 2.0 MCP methods (`initialize`, `tools/list`, `tools/call`, `resources/read`) and verified the
   SHA-256 MCP trace chain (`GET /api/v1/mcp/traces/verify`).

---

## Step 1: Launch the Plugins & MCP Sandbox Server

Create `/tmp/apiexec-mcp-lab`, copy the `plugins/` directory, build `go-admin-tool`, and start the sandbox server:

```bash
rm -rf /tmp/apiexec-mcp-lab
mkdir -p /tmp/apiexec-mcp-lab/certs
cp -R plugins /tmp/apiexec-mcp-lab/plugins
printf 'hello zero-trust sandbox\n' > /tmp/apiexec-mcp-lab/sample.txt

go build -o /tmp/apiexec-mcp-lab/go-admin-tool ./cmd/server

cat <<'YAML' > /tmp/apiexec-mcp-lab/mcp-lab.yaml
version: "2.2.0"

server:
  port: 18444
  host: "127.0.0.1"
  tls:
    enabled: true
    auto_generate: true
    cert_file: "/tmp/apiexec-mcp-lab/certs/server.crt"
    key_file: "/tmp/apiexec-mcp-lab/certs/server.key"
    min_version: "1.3"
    hosts: ["localhost", "127.0.0.1"]

database:
  path: "/tmp/apiexec-mcp-lab/history.db"

command_executor:
  enabled: true
  default_timeout: "30s"
  max_timeout_seconds: 300
  commands:
    - name: "disk-usage"
      command: "df"
      args: ["-h"]
      timeout: "15s"

auth:
  enabled: true
  require_auth: true
  bootstrap_username: "admin"
  bootstrap_password: "lab-admin-pass"

plugins:
  enabled: true
  enable_db_exposure: true
  enable_sys_diagnostics: true
  declarative_dir: "/tmp/apiexec-mcp-lab/plugins"
  max_query_rows: 100

mcp:
  enabled: true
  server_name: "api-executor-mcp-lab"
  server_version: "2.2.0"
  retain_traces: true
  max_traces: 500
  trace_file_path: "/tmp/apiexec-mcp-lab/mcp-traces.jsonl"

audit:
  enabled: true
  file_path: "/tmp/apiexec-mcp-lab/audit.jsonl"

sandbox:
  enabled: true
  enforce_non_root: true
  uid: 10001
  gid: 10001
  userns: "keep-id"
YAML

CONFIG_PATH=/tmp/apiexec-mcp-lab/mcp-lab.yaml /tmp/apiexec-mcp-lab/go-admin-tool > /tmp/apiexec-mcp-lab/server.out 2>&1 &
MCP_PID=$!
sleep 2

TOKEN=$(curl -sk -X POST https://127.0.0.1:18444/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"lab-admin-pass"}' | jq -r '.token')
```

---

## Step 2: Filter and Execute Native and Declarative Plugins

Query the plugin catalog (`GET /api/v1/plugins`) using category, type, and keyword filters:

```bash
curl -sk "https://127.0.0.1:18444/api/v1/plugins?category=SysAdmin&type=native" \
  -H "Authorization: Bearer ${TOKEN}" | jq '.plugins | map(.id)'

curl -sk "https://127.0.0.1:18444/api/v1/plugins?category=WebUtils&q=sha256" \
  -H "Authorization: Bearer ${TOKEN}" | jq '.plugins | map(.id)'
```

Expected output:

```json
[
  "host-storage-stats",
  "process-tree-analyzer",
  "sys-diagnostics"
]
```

```json
[
  "crypto-sha256-file"
]
```

Execute native `sys-diagnostics` (`runtime_stats`) and declarative `crypto-sha256-file` (`sha256_hash`):

```bash
curl -sk -X POST https://127.0.0.1:18444/api/v1/plugins/execute \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"plugin_id":"sys-diagnostics","action":"runtime_stats","params":{}}' | jq '{plugin_id,action,status,data}'

curl -sk -X POST https://127.0.0.1:18444/api/v1/plugins/execute \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"plugin_id":"crypto-sha256-file","action":"sha256_hash","params":{"file":"/tmp/apiexec-mcp-lab/sample.txt"}}' | jq .
```

Expected `crypto-sha256-file` response:

```json
{
  "plugin_id": "crypto-sha256-file",
  "action": "sha256_hash",
  "status": "ok",
  "output": "2b86...  /tmp/apiexec-mcp-lab/sample.txt\n",
  "duration_ms": 4
}
```

Test shell metacharacter rejection (`400 Bad Request`) on declarative plugin parameters:

```bash
curl -sk -o /dev/null -w "injection_status=%{http_code}\n" \
  -X POST https://127.0.0.1:18444/api/v1/plugins/execute \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"plugin_id":"crypto-sha256-file","action":"sha256_hash","params":{"file":"/tmp/a;id"}}'
```

Expected output:

```text
injection_status=400
```

---

## Step 3: Query Guarded Read-Only Database Exposure (`db-exposure`)

First trigger one command so `action_history` has a row, then inspect exposed tables and run a guarded `SELECT`:

```bash
curl -sk -X POST https://127.0.0.1:18444/api/v1/execute \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"disk-usage"}' > /dev/null

curl -sk https://127.0.0.1:18444/api/v1/db/tables \
  -H "Authorization: Bearer ${TOKEN}" | jq .

curl -sk -X POST https://127.0.0.1:18444/api/v1/db/query \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"sql":"SELECT id, command, status FROM action_history ORDER BY id DESC LIMIT 5","max_rows":5}' | jq .
```

Verify that `ValidateReadOnlySQL` blocks DDL/DML statements with `403 Forbidden`:

```bash
curl -sk -o /dev/null -w "ddl_status=%{http_code}\n" \
  -X POST https://127.0.0.1:18444/api/v1/db/query \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"sql":"DROP TABLE action_history"}'
```

Expected output:

```text
ddl_status=403
```

---

## Step 4: Invoke MCP Tools, Read Resources, and Verify Traces

Initialize an MCP session (`protocolVersion: "2024-11-05"`), read the `executor://plugins/catalog` resource, and invoke
`execute_plugin` and `audit_verify` via the Meta-Tool pattern:

```bash
curl -sk -X POST https://127.0.0.1:18444/api/v1/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-MCP-Session-ID: lab-mcp-01" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' | jq .

curl -sk -X POST https://127.0.0.1:18444/api/v1/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-MCP-Session-ID: lab-mcp-01" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_plugin","arguments":{"plugin_id":"sys-diagnostics","action":"runtime_stats"}}}' | jq '{trace_id,isError:.result.isError}'

curl -sk -X POST https://127.0.0.1:18444/api/v1/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-MCP-Session-ID: lab-mcp-01" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"audit_verify","arguments":{}}}' | jq .
```

Verify the SHA-256 hash chain across all retained MCP traces:

```bash
curl -sk "https://127.0.0.1:18444/api/v1/mcp/traces/verify" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

Expected output:

```json
{
  "valid": true,
  "total_traces": 3,
  "last_trace_hash": "9a7f...",
  "audit_chain_valid": true
}
```

---

## Step 5: Clean Up the Sandbox

Stop the sandbox daemon and remove `/tmp/apiexec-mcp-lab`:

```bash
kill "${MCP_PID}"
wait "${MCP_PID}" 2>/dev/null || true
rm -rf /tmp/apiexec-mcp-lab
```

---

## Next Steps

- Continue to [Tutorial 3: Zero-Trust Bastion & Async Jobs Lab](03-zero-trust-bastion-and-async-jobs-lab.md)
- Activate OS task presets and manage async job queues in production:
  [Manage Async Jobs and Presets](../02-how-to-guides/operations/manage-async-jobs-and-presets.md)
- Inspect all 48 HTTP/REST and MCP endpoints and plugin parameters:
  [REST, MCP Endpoints & Environment](../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)
- Understand why direct `argv` execution and the Meta-Tool pattern eliminate shell injection and context bloat:
  [ADR-001: Zero-Trust Execution & Bastion](../04-explanation/design-decisions/adr-001-zero-trust-execution-and-bastion.md)
