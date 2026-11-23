# Tutorial 1: Local HTTPS Quickstart

> **Learning Goal:** Build and run **API Executor (`go-admin-tool`)** inside an isolated local sandbox
> (`/tmp/apiexec-lab`) with auto-generated ECDSA P-256 TLS 1.3, inspect public version probes, issue a Personal
> Access Token (`gat_pat_...`), execute a predefined command with a timeout override, and verify Prometheus `/metrics`.

> [!WARNING]
> **Isolated Local Sandbox Only:** Run every command in this tutorial inside `/tmp/apiexec-lab` on port `18443` with
> disposable lab credentials. Never reuse `lab-admin-pass` or self-signed certificates on production hosts.

---

## Prerequisites

Make sure your workstation meets these requirements before starting:

- Go `1.24+` installed on `PATH` (tested with `go 1.24.3`, `CGO_ENABLED=0` or CGO-enabled SQLite)
- Cloned `api_executor` repository (`cd api_executor`)
- Standard Unix shell (`bash`) with `curl`, `jq`, and `openssl`
- Port `18443/tcp` available on loopback `127.0.0.1`

Verify your Go toolchain and repository version:

```bash
go version
cat VERSION
```

Expected output:

```text
go version go1.24.3 linux/amd64
2.2.0
```

---

## What You Will Build

By the end of this tutorial, you will have:

1. Compiled a standalone `go-admin-tool` binary inside `/tmp/apiexec-lab`.
2. Created an isolated `sandbox-config.yaml` enforcing `auth.require_auth: true` and HTTPS TLS `1.3`.
3. Started the daemon and verified automatic ECDSA P-256 certificate generation (`certs/server.key` with `0600`).
4. Queried public probes (`GET /api/v1/version` and `GET /api/v1/config/version`).
5. Authenticated as `admin`, minted a scoped Personal Access Token, executed `disk-usage` with `"timeout": "5s"`, and
   observed `action_mode_calls_total` on `/metrics`.

---

## Step 1: Create the Sandbox Directory and Build `go-admin-tool`

Create `/tmp/apiexec-lab` and compile `./cmd/server` without touching the repository's default `config.yaml` or
`history.db`:

```bash
rm -rf /tmp/apiexec-lab
mkdir -p /tmp/apiexec-lab/certs /tmp/apiexec-lab/secure_files
go build -o /tmp/apiexec-lab/go-admin-tool ./cmd/server
```

Verify the binary built cleanly:

```bash
ls -lh /tmp/apiexec-lab/go-admin-tool
```

---

## Step 2: Write an Isolated `sandbox-config.yaml`

Write `/tmp/apiexec-lab/sandbox-config.yaml` with TLS `1.3`, strict `auth.require_auth: true`, and two safe predefined
commands (`list-processes` and `disk-usage`):

```bash
cat <<'YAML' > /tmp/apiexec-lab/sandbox-config.yaml
version: "2.2.0"

server:
  port: 18443
  host: "127.0.0.1"
  tls:
    enabled: true
    auto_generate: true
    cert_file: "/tmp/apiexec-lab/certs/server.crt"
    key_file: "/tmp/apiexec-lab/certs/server.key"
    organization: "API Executor Lab"
    validity_days: 30
    min_version: "1.3"
    hosts:
      - "localhost"
      - "127.0.0.1"

logging:
  level: "info"
  path: "/tmp/apiexec-lab/app.log"

database:
  path: "/tmp/apiexec-lab/history.db"

file_server:
  enabled: true
  secure_dir: "/tmp/apiexec-lab/secure_files"

command_executor:
  enabled: true
  default_timeout: "30s"
  default_timeout_seconds: 30
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

auth:
  enabled: true
  require_auth: true
  bootstrap_username: "admin"
  bootstrap_password: "lab-admin-pass"

plugins:
  enabled: false

mcp:
  enabled: false

audit:
  enabled: true
  file_path: "/tmp/apiexec-lab/audit.jsonl"
  max_memory_log: 1000

sandbox:
  enabled: true
  enforce_non_root: true
  uid: 10001
  gid: 10001
  userns: "keep-id"
YAML
```

Start the server in the background using `CONFIG_PATH`:

```bash
CONFIG_PATH=/tmp/apiexec-lab/sandbox-config.yaml /tmp/apiexec-lab/go-admin-tool > /tmp/apiexec-lab/server.out 2>&1 &
LAB_PID=$!
sleep 2
```

Verify the auto-generated ECDSA P-256 key permissions (`-rw-------` / `0600`) and TLS certificate subject:

```bash
ls -l /tmp/apiexec-lab/certs/
```

Expected output:

```text
-rw-r--r-- 1 user group  980 Nov 23 19:40 server.crt
-rw------- 1 user group  227 Nov 23 19:40 server.key
```

---

## Step 3: Probe Public Version and Unauthenticated Guardrails

Query the two public unauthenticated probes (`GET /api/v1/version` and `GET /api/v1/config/version`):

```bash
curl -sk https://127.0.0.1:18443/api/v1/version | jq .
curl -sk https://127.0.0.1:18443/api/v1/config/version | jq .
```

Expected `/api/v1/version` JSON:

```json
{
  "version": "2.2.0",
  "git_commit": "0123456789abcdef0123456789abcdef01234567",
  "build_date": "2026-11-23T19:40:00Z",
  "integrity_status": "clean",
  "integrity": "clean",
  "uptime": "3s",
  "uptime_seconds": 3.12,
  "go_version": "go1.24.3",
  "start_time": "2026-11-23T19:40:00Z",
  "os": "linux",
  "arch": "amd64",
  "compiler": "gc",
  "config_version": "2.2.0",
  "config_version_path": "/api/v1/config/version",
  "config_file": "/tmp/apiexec-lab/sandbox-config.yaml"
}
```

Confirm that protected execution routes fail closed with `401 Unauthorized` when called without credentials:

```bash
curl -sk -o /dev/null -w "http_status=%{http_code}\n" \
  -X POST https://127.0.0.1:18443/api/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"name":"disk-usage"}'
```

Expected output:

```text
http_status=401
```

---

## Step 4: Authenticate, Mint a PAT, and Execute a Command

Log in as `admin` to obtain a 24-hour session token, then mint a dedicated Personal Access Token (`gat_pat_...`):

```bash
SESSION_TOKEN=$(curl -sk -X POST https://127.0.0.1:18443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"lab-admin-pass"}' | jq -r '.token')

LAB_PAT=$(curl -sk -X POST https://127.0.0.1:18443/api/v1/auth/tokens \
  -H "Authorization: Bearer ${SESSION_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"admin","name":"quickstart-cli","scopes":["commands:read","commands:execute"],"ttl":"2h"}' \
  | jq -r '.token')

echo "Token prefix: ${LAB_PAT:0:12}"
```

Expected output:

```text
Token prefix: gat_pat_a1b2
```

Execute `disk-usage` with a `"5s"` per-call timeout override (`POST /api/v1/execute`):

```bash
curl -sk -X POST https://127.0.0.1:18443/api/v1/execute \
  -H "X-API-Token: ${LAB_PAT}" \
  -H "Content-Type: application/json" \
  -d '{"name":"disk-usage","timeout":"5s"}' | jq .
```

Expected output:

```json
{
  "output": "Filesystem      Size  Used Avail Use% Mounted on\n...",
  "timeout": "5s"
}
```

Inspect Prometheus metrics for `disk-usage` (`GET /metrics`):

```bash
curl -sk https://127.0.0.1:18443/metrics | grep 'action_.*disk-usage'
```

Expected output:

```text
action_call_duration_seconds_count{action="disk-usage"} 1
action_calls_ok_total{action="disk-usage"} 1
action_calls_status_total{action="disk-usage",status="ok"} 1
action_calls_total{action="disk-usage"} 1
action_mode_call_duration_seconds_count{action="disk-usage",mode="sync"} 1
action_mode_calls_total{action="disk-usage",mode="sync",status="ok"} 1
```

---

## Step 5: Clean Up the Sandbox

Stop the background server and remove `/tmp/apiexec-lab`:

```bash
kill "${LAB_PID}"
wait "${LAB_PID}" 2>/dev/null || true
rm -rf /tmp/apiexec-lab
```

---

## Next Steps

- Continue to [Tutorial 2: Plugins & MCP Sandbox](02-plugins-and-mcp-sandbox.md)
- Deploy rootless containers with TLS 1.3 in production:
  [Deploy Rootless Docker and TLS](../02-how-to-guides/deployment/deploy-rootless-docker-and-tls.md)
- Look up every configuration field and REST endpoint:
  [Configuration Schema & Profiles](../03-reference/configuration/config-schema-and-profiles.md) and
  [REST, MCP Endpoints & Environment](../03-reference/api-and-cli/rest-mcp-endpoints-and-env.md)
- Study the full security pipeline:
  [Zero-Trust MCP Bastion Topology](../04-explanation/architecture-overview/zero-trust-mcp-bastion-topology.md)
