# How-To Guides and Operational Runbooks

Follow these procedural runbooks to deploy, operate, and secure **API Executor (`go-admin-tool`)**.
All procedures follow **ASD-STE100 Issue 9** Simplified Technical English.

## Deployment

| Guide | Purpose |
| :--- | :--- |
| [Deploy Rootless Docker and TLS](deployment/deploy-rootless-docker-and-tls.md) | Deploy the multi-arch container image as UID/GID `10001` (`keep-id`) with HTTPS/TLS 1.3 and persistent volumes. |

## Operations

| Guide | Purpose |
| :--- | :--- |
| [Manage Async Jobs and Presets](operations/manage-async-jobs-and-presets.md) | Activate Ubuntu/RedHat OS task presets, switch config profiles, submit priority jobs, and stream or cancel logs. |
| [Configure HITL and MicroLLM Gatekeeper](operations/configure-hitl-and-microllm-gatekeeper.md) | Enable Human-in-the-Loop dual-admin approvals and System-1 `MicroLLM` (`microllm.guard.v1`) pre-execution gates. |

## Incident Response

| Guide | Purpose |
| :--- | :--- |
| [Remediate Audit or MCP Trace Tamper](incident-response/remediate-audit-or-mcp-trace-tamper.md) | Diagnose and remediate broken SHA-256 audit or MCP trace hash chains (`valid: false` or `409` replay failures). |

## Security

| Guide | Purpose |
| :--- | :--- |
| [Rotate TLS and Service Account Keys](security/rotate-tls-and-service-account-keys.md) | Perform zero-downtime ECDSA P-256 TLS rotation, revoke Personal Access Tokens, and rotate `gat_svc_` keys. |

## Other Documentation Quadrants

- [Documentation Portal](../index.md)
- [Tutorials](../01-tutorials/index.md)
- [Reference Specifications](../03-reference/index.md)
- [Architecture Explanation](../04-explanation/index.md)
