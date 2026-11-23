# Tutorials

> [!NOTE]
> **Learning-Oriented Quadrant (`01-tutorials/`):** Follow these guided, self-contained sandbox labs to learn
> **API Executor (`go-admin-tool`)** safely in isolated temporary directories before deploying to production hosts.

Each tutorial uses an isolated workspace (`/tmp/apiexec-lab` or `/tmp/apiexec-bastion`), exact `config.yaml` and
`curl` commands, expected JSON payloads, and full cleanup steps at the end.

---

## Guided Learning Path

| Lesson | What You Will Practice | Key Endpoints & Subsystems |
| :--- | :--- | :--- |
| [1. Local HTTPS Quickstart](01-local-https-quickstart.md) | Launch `go-admin-tool` over auto-generated ECDSA P-256 HTTPS, query `/api/v1/version`, mint a PAT, execute `disk-usage`, and inspect `/metrics` | `CONFIG_PATH`, `/api/v1/version`, `/api/v1/auth/login`, `/api/v1/execute`, `/metrics` |
| [2. Plugins & MCP Sandbox](02-plugins-and-mcp-sandbox.md) | Filter 305+ plugins, invoke `sys-diagnostics` and `crypto-sha256-file`, query `db-exposure`, and call JSON-RPC 2.0 MCP tools with trace checks | `/api/v1/plugins`, `/api/v1/db/query`, `/api/v1/mcp`, `/api/v1/mcp/traces/verify` |
| [3. Zero-Trust Bastion & Async Jobs Lab](03-zero-trust-bastion-and-async-jobs-lab.md) | Wire HITL distinct-admin approvals with a loopback mock `MicroLLM` (`x_abstain`), run async jobs with live logs, and verify SHA-256 chains | `/api/v1/approvals`, `gatekeeper`, `/api/v1/jobs`, `/api/v1/audit/verify` |

---

## Next Steps

- Execute production deployment, operations, incident response, and security procedures:
  [How-To Guides](../02-how-to-guides/index.md)
- Look up exhaustive YAML schemas, all 33 REST/MCP endpoints, and error codes:
  [Reference](../03-reference/index.md)
- Study the Zero-Trust MCP Bastion topology, 4-tier timeouts, cryptographic hash chains, and ADRs:
  [Explanation](../04-explanation/index.md)
