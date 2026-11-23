# Explanation

Architectural overviews, Architecture Decision Records (ADRs), and systems engineering analyses explaining the design choices behind **API Executor (`go-admin-tool`)**.

## Explanation Documents

| Document | Focus | File |
| :--- | :--- | :--- |
| **Zero-Trust MCP Bastion Topology** | End-to-end defense-in-depth pipeline from token extraction and RBAC through HITL, System-1 `MicroLLM`, non-root execution, and cryptographic trace chains | [`zero-trust-mcp-bastion-topology.md`](architecture-overview/zero-trust-mcp-bastion-topology.md) |
| **ADR-001: Zero-Trust Execution & Bastion** | Architectural decisions for direct argv invocation, pure-Go SQLite/in-memory storage, fail-closed gatekeeper/HITL ordering, and UID `10001` sandboxing | [`adr-001-zero-trust-execution-and-bastion.md`](design-decisions/adr-001-zero-trust-execution-and-bastion.md) |
| **ADR-002: Diátaxis & Versioned MkDocs Publishing** | Architectural decisions for 4-quadrant documentation separation, ASD-STE100 Issue 9 runbooks, immutable tag overlays (`v2.0.0`, `v2.1.0`), and IONOS SFTP publishing | [`adr-002-diataxis-versioned-mkdocs-publishing.md`](design-decisions/adr-002-diataxis-versioned-mkdocs-publishing.md) |
| **Concurrency, Timeouts & Cryptographic Chains** | Systems analysis of 4-tier timeout resolution, process-group termination, O(1) auth maps, `sync.Pool` chunking, Prometheus cardinality bounds, and SHA-256 chain equations | [`concurrency-timeouts-and-cryptographic-chains.md`](deep-dives/concurrency-timeouts-and-cryptographic-chains.md) |

## Supporting Architectural Analysis and Articles

| Document | Scope | Link |
| :--- | :--- | :--- |
| **Security and Architecture Analysis** | Detailed repository security posture review and architectural evaluation | [`SECURITY_AND_ARCHITECTURE_ANALYSIS.md`](../SECURITY_AND_ARCHITECTURE_ANALYSIS.md) |
| **High-Throughput Agentic Execution Deep-Dive** | Engineering analysis of O(1) hashing, pre-compiled regex/catalog caching, output bounding, and persistent I/O handles | [`2026-11-08-optimizing-api-executor-for-scale-and-mcp-workloads.en.md`](../articles/2026-11-08-optimizing-api-executor-for-scale-and-mcp-workloads.en.md) |
| **Action Logbook** | Chronological engineering ledger of delivered atomic changes (`ACT-XXX`) | [`ACTION_LOGBOOK.md`](../ACTION_LOGBOOK.md) |
| **RCA & Transparency Register** | Root-cause analyses (`RCA-XXX`), abandoned dead-ends (`IMP-XXX`), and architectural assumptions (`APP-XXX`) | [`RCA_REGISTER.md`](../RCA_REGISTER.md) |

## Cross-Quadrant Navigation

| Quadrant | Purpose | Entry Point |
| :--- | :--- | :--- |
| **Documentation Home** | Portal landing page and Diátaxis map | [`docs/index.md`](../index.md) |
| **Tutorials** | Guided, reproducible onboarding lessons | [`01-tutorials/index.md`](../01-tutorials/index.md) |
| **How-To Guides** | Goal-oriented operational and incident-response runbooks | [`02-how-to-guides/index.md`](../02-how-to-guides/index.md) |
| **Reference** | Schema tables, endpoint specs, environment variables, and error matrices | [`03-reference/index.md`](../03-reference/index.md) |
