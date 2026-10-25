# API Executor (`go-admin-tool`) — Security, Code Updates & Missing Capabilities Analysis

## 1. Executive Summary

This document presents the comprehensive security review, dependency/code modernization audit, and enterprise feature gap analysis for **API Executor (`go-admin-tool`)**, along with the implemented remediations across atomic Issues [#2](https://github.com/jmrenouard/api_executor/issues/2) through [#11](https://github.com/jmrenouard/api_executor/issues/11).

---

## 2. Security Audit & Applied Remediations

| Finding ID | Severity | Area | Initial Vulnerability / Risk | Applied Remediation |
|---|---|---|---|---|
| `SEC-01` | **CRITICAL** | Transport Security | Server listened only on cleartext HTTP (`http.ListenAndServe`), exposing credentials, tokens, and command output in transit. | Enabled **HTTPS/TLS 1.2+ by default** (`internal/core/tls.go`) with automatic ECDSA P-256 X.509 certificate generation (`0600` private key), live rotation (`POST /api/v1/tls/renew`), optional mTLS Client CA validation, and `Strict-Transport-Security` (HSTS) header injection (Issue [#4](https://github.com/jmrenouard/api_executor/issues/4)). |
| `SEC-02` | **CRITICAL** | Authentication & Authorization | API endpoints (`/api/v1/execute`, `/api/v1/files`) had no authentication, RBAC, or machine-to-machine scoping. | Implemented `internal/auth/manager.go` supporting RBAC roles (`admin`, `operator`, `viewer`, `service`), Personal Access Tokens (`gat_pat_...`), and Third-Party Service Accounts (`gat_svc_...`) with constant-time hash comparison and per-service `allowed_actions` allowlists (Issue [#7](https://github.com/jmrenouard/api_executor/issues/7)). |
| `SEC-03` | **HIGH** | Process Lifecycle & DoS | `exec.CommandContext` did not isolate child process groups; timed-out commands spawning grandchildren leaked processes and hung HTTP handlers. | Added OS-specific process-group isolation (`Setpgid` on Unix, `WaitDelay` on Unix/Windows) and hierarchical timeouts (`30s` default -> executor default -> per-command -> per-call override capped by `max_timeout_seconds`) (Issue [#3](https://github.com/jmrenouard/api_executor/issues/3)). |
| `SEC-04` | **HIGH** | Metrics Cardinality DoS | Unbounded caller-supplied command names could create arbitrary Prometheus time series. | Added `normalizeActionLabel` in `internal/api/router.go` bounding dynamic action labels to `MaxDynamicActionLabels = 64` and stripping control characters (Issue [#3](https://github.com/jmrenouard/api_executor/issues/3)). |
| `SEC-05` | **HIGH** | Non-Repudiation & Auditability | Action history stored in a mutable SQLite table without cryptographic integrity verification or caller attribution. | Implemented tamper-evident SHA-256 hash-chained audit logging (`internal/audit/audit.go`) linking every event from `GENESIS` (`prev_hash` -> `entry_hash`) with `/api/v1/audit/verify` verification (Issue [#6](https://github.com/jmrenouard/api_executor/issues/6)). |
| `SEC-06` | **HIGH** | Plugin & Database Exposure | Need to expose parameterized commands and SQLite database inspection without risking shell injection or destructive SQL statements. | Declarative plugins (`internal/plugins/declarative.go`) validate every `{{param}}` against strict regexes and execute via `os/exec` argument vectors (zero `sh -c`). `db-exposure` (`internal/plugins/db_exposure.go`) enforces read-only `SELECT` validation blocking `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `ATTACH`, `PRAGMA`, and multi-statement `;` queries (Issue [#8](https://github.com/jmrenouard/api_executor/issues/8)). |
| `SEC-07` | **MEDIUM** | Log File Permissions | Log files were opened with `0666` permissions (`os.O_CREATE`), allowing world-readable access on shared hosts. | Restricted log and audit file permissions to `0600` (`internal/core/logger.go`, `internal/audit/audit.go`) (Issue [#6](https://github.com/jmrenouard/api_executor/issues/6)). |

---

## 3. Code & Dependency Modernization

1. **Docker & Go Toolchain Alignment**:
   - Updated `Dockerfile` builder image from `golang:1.21-alpine` to `golang:1.24-alpine` to match `go.mod` (`go 1.24.0`).
   - Added dedicated multi-stage Dockerfiles for **Ubuntu 24.04 LTS** (`docker/Dockerfile.ubuntu`) and **RedHat UBI 9** (`docker/Dockerfile.redhat`) orchestrated via `docker-compose.os-test.yml`.
2. **Zero-CGO Portability**:
   - Enhanced `internal/database/db.go` with a thread-safe pure-Go in-memory fallback when compiled with `CGO_ENABLED=0` (as used in minimal container builds and Windows/CI environments without GCC).

---

## 4. Predefined OS Task Catalogs (Ubuntu & RedHat)

To make `api_executor` immediately usable across enterprise Linux fleets and testable in containers, two built-in OS preset catalogs are provided in `internal/core/os_presets.go` and `configs/{ubuntu,redhat}-tasks.yaml`:

- **Ubuntu / Debian (`ubuntu:24.04`)**:
  - `ubuntu-os-release`, `ubuntu-kernel-uname`, `ubuntu-dpkg-packages`, `ubuntu-apt-simulated-upgrade`, `ubuntu-apt-sources`, `ubuntu-disk-space`, `ubuntu-memory-stats`, `ubuntu-process-snapshot`, `ubuntu-network-sockets`, `ubuntu-passwd-accounts`.
- **RedHat / RHEL / Rocky / UBI 9 (`redhat/ubi9:latest`)**:
  - `redhat-os-release`, `redhat-system-release`, `redhat-rpm-qa`, `redhat-rpm-verify-crypto`, `redhat-dnf-repolist`, `redhat-disk-space`, `redhat-memory-stats`, `redhat-process-snapshot`, `redhat-kernel-uname`, `redhat-passwd-accounts`.
