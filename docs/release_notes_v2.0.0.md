## Overview

API Executor (`go-admin-tool` v2.0.0) is an enterprise zero-trust administration and Model Context Protocol (MCP) platform designed for secure remote command execution, container-testable OS preset management, and high-throughput AI agent orchestration.

This release consolidates comprehensive security hardening, a 305+ plugin ecosystem across 10 operational domains, and four major performance optimizations eliminating hot-path lock contention, memory bloat, and syscall overhead.

---

## 🚀 Key Performance Optimizations

1. **O(1) Credential Authentication Indexing (PR #77, Closes #76)**
   - Replaced linear O(N) credential scans under exclusive memory locks with O(1) secondary hash lookup maps (`tokenByHash` and `serviceAccountByHash`).
   - Maintains constant-time verification (`crypto/subtle.ConstantTimeCompare`) and synchronized lifecycle across user deletion, token revocation, and key rotation.

2. **Pre-Compiled Regexes & Sorted Plugin Catalog Caching (PR #79, Closes #78)**
   - Pre-compiles all declarative parameter validation regular expressions at initialization.
   - Caches the sorted `[]PluginInfo` catalog snapshot in `Registry` across 305 plugins, eliminating O(N log N) sorting overhead on catalog queries.
   - Rejects non-scalar composite parameter types and fixes character class ranges.

3. **Subprocess Output Buffer Bounding (PR #81, Closes #80)**
   - Replaced unbounded `cmd.CombinedOutput()` with a bounded `limitedOutputBuffer` capped at `MaxCommandOutputBytes = 1 << 20` (1 MiB).
   - Drains excess bytes safely without triggering `SIGPIPE` or broken pipe failures on child processes, preventing heap exhaustion (OOM) on runaway commands.

4. **Persistent File Handles, Lock Decoupling & Direct db.Exec (PR #83, Closes #82)**
   - Persists open file descriptors (`*os.File`) in `AuditLogger` and `mcp.Server`, eliminating per-event `os.OpenFile`/`Close` syscall storms.
   - Decoupled disk and SQLite I/O from the in-memory ring-buffer lock (`al.mu`), ensuring non-blocking reads for audit queries and chain verification.
   - Replaced per-insert `db.Prepare` with direct `db.Exec`.

---

## 🛡️ Core Capabilities

- **Zero-Trust Security**: HTTPS/TLS 1.3 by default with automatic ECDSA P-256 certificate generation, live zero-downtime certificate rotation (`POST /api/v1/tls/renew`), and optional mTLS client authentication.
- **Model Context Protocol (MCP)**: Full JSON-RPC 2.0 MCP server (`POST /api/v1/mcp`) implementing the Meta-Tool pattern (`execute_plugin` and `executor://plugins/catalog`) with immutable trace retention.
- **305+ Plugins Across 10 Domains**: 24 native pure-Go plugins + 281 declarative YAML plugins spanning `SysAdmin`, `NetOps`, `SecOps`, `ContainerOps`, `Kubernetes`, `DataOps`, `DevOps`, `SRE`, `AIOps`, and `WebUtils`.
- **Tamper-Evident Audit Trail**: Cryptographic SHA-256 hash chaining (`prev_hash` -> `entry_hash` from `GENESIS`) with verifiable integrity (`GET /api/v1/audit/verify`).
- **OS Task Presets**: Ready-to-run container-safe system inspection catalogs for Ubuntu 24.04 and RedHat UBI 9.
- **Web Administration Console**: Single-page 8-tab dark console with instant client-side catalog filtering, dynamic parameter forms, and telemetry monitoring.

---

## 🧪 Verification & Test Coverage

- **100% Test Pass Rate**: 339 unit and integration tests passing across all 10 packages.
- **Zero-CGO Pure-Go Fallback**: Tested and validated under both CGO-enabled SQLite and pure-Go in-memory modes.
- **Docker Hygiene**: Multi-stage builds for Ubuntu and RedHat UBI9 with optimal layer caching.
