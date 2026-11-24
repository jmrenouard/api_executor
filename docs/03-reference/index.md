# Reference

Exhaustive technical specifications for **API Executor (`go-admin-tool`)** configuration keys, REST and MCP JSON-RPC 2.0 interfaces, environment variables, Prometheus/OTLP metrics, error codes, and operational alert matrices.

## Reference Specifications

| Specification | Scope | File |
| :--- | :--- | :--- |
| **Configuration Schema & Profiles** | `config.yaml` schema (`server`, `tls`, `rate_limit`, `logging`, `database`, `file_server`, `command_executor`, `auth`, `plugins`, `mcp`, `audit`, `approval`, `gatekeeper`, `jobs`, `multi_config`, `otlp_export`, `sandbox`) and built-in profiles (`default`, `ubuntu`, `redhat`, `cis-benchmarks`) | [`config-schema-and-profiles.md`](configuration/config-schema-and-profiles.md) |
| **REST, MCP, CLI & Environment Reference** | Complete REST & MCP JSON-RPC 2.0 endpoint catalog, authentication headers, profile selectors, MCP tools/resources/prompts, environment variables, `scripts/build_versioned_docs.py` CLI options, and Prometheus/OTLP metrics | [`rest-mcp-endpoints-and-env.md`](api-and-cli/rest-mcp-endpoints-and-env.md) |
| **Error & Alert Matrix** | HTTP status codes, `MicroLLM` exit codes (`0`–`3`), CIS benchmark exit codes, SHA-256 audit/MCP trace verification failures, and alert-to-runbook remediation matrix | [`error-and-alert-matrix.md`](troubleshooting-codes/error-and-alert-matrix.md) |

## Repository Specifications & Release Records

| Document | Scope | Link |
| :--- | :--- | :--- |
| **Security Architecture & Threat Matrix** | End-to-end TLS, RBAC, HITL, `MicroLLM`, sandbox, and endpoint authorization catalog | [`SECURITY.md`](../../SECURITY.md) |
| **Project Overview** | Core repository capabilities and component layout | [`PROJECT.md`](../../PROJECT.md) |
| **Release Notes (v2.1.0)** | Release baseline notes for `v2.1.0` | [`v2.1.0.md`](../releases/v2.1.0.md) |
| **Release Notes (v2.0.0)** | Release baseline notes for `v2.0.0` | [`release_notes_v2.0.0.md`](../release_notes_v2.0.0.md) |
| **Action Logbook** | Living chronological record of ongoing and completed repository actions (`ACT-XXX`) | [`ACTION_LOGBOOK.md`](../ACTION_LOGBOOK.md) |
| **RCA & Transparency Register** | Living registry of root-cause analyses (`RCA-XXX`), dead-ends (`IMP-XXX`), assumptions (`APP-XXX`), and roadmap items (`IDEA-XXX`) | [`RCA_REGISTER.md`](../RCA_REGISTER.md) |

## Cross-Quadrant Navigation

| Quadrant | Purpose | Entry Point |
| :--- | :--- | :--- |
| **Documentation Home** | Portal landing page and Diátaxis map | [`docs/index.md`](../index.md) |
| **Tutorials** | Guided, reproducible onboarding lessons | [`01-tutorials/index.md`](../01-tutorials/index.md) |
| **How-To Guides** | ASD-STE100 Issue 9 operational and incident-response procedures | [`02-how-to-guides/index.md`](../02-how-to-guides/index.md) |
| **Explanation** | Architecture topology, ADRs, concurrency internals, and cryptographic chains | [`04-explanation/index.md`](../04-explanation/index.md) |
