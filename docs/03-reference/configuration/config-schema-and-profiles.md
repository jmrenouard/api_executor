# Configuration Schema and Profiles

Authoritative schema specification for `config.yaml`, runtime server limits, cryptographic and sandbox invariants, internal job engine defaults, and built-in multi-config profiles (`default`, `ubuntu`, `redhat`, `cis-benchmarks`) in **API Executor (`go-admin-tool`)**.

---

## Top-Level Configuration Keys

| Key | Type | Default (`DefaultConfig`) | Description |
| :--- | :--- | :--- | :--- |
| `version` | `string` | Config dependent | Configuration schema or manifest revision string |
| `config_version` | `string` | Config dependent | Logical configuration version exposed by version probe endpoints |
| `config_version_path` | `string` | `"/api/v1/config/version"` | Custom HTTP path (`DefaultConfigVersionPath`) for configuration version probing |
| `server` | `object` | See `server` below | HTTP/TLS listener, rate limiter, and request body bounds |
| `logging` | `object` | See `logging` below | Log verbosity, log file path, and memory ring buffer |
| `database` | `object` | See `database` below | SQLite persistence file path and WAL connection parameters |
| `file_server` | `object` | See `file_server` below | Read-only secure log file server settings |
| `command_executor` | `object` | See `command_executor` below | Whitelisted commands, OS presets, and timeout ceiling |
| `auth` | `object` | See `auth` below | Authentication bootstrap, token store, and RBAC settings |
| `plugins` | `object` | See `plugins` below | Built-in, declarative YAML, and SQLite DB exposure plugins |
| `mcp` | `object` | See `mcp` below | Model Context Protocol (MCP JSON-RPC 2.0) server and trace ring |
| `audit` | `object` | See `audit` below | SHA-256 hash-chained audit trail configuration |
| `approval` | `object` | See `approval` below | Single-use HITL approval workflow policy |
| `gatekeeper` | `object` | See `gatekeeper` below | System-1 `MicroLLM` pre-execution guard settings |
| `jobs` | `object` | See `jobs` below | Async job engine worker pool, queue capacity, log buffer, and retention policy |
| `multi_config` | `object` | See `multi_config` below | Multi-profile configuration switching settings |
| `otlp_export` | `object` | See `otlp_export` below | OpenTelemetry OTLP metrics export settings |
| `sandbox` | `object` | See `sandbox` below | Non-root execution UID/GID, user namespace, and capability drops |

---

## `server`, `server.tls`, and `server.rate_limit`

| Path | Type | Default (`DefaultConfig` / Runtime) | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `server.host` | `string` | `"0.0.0.0"` | Bind address for the API and Web Console listener |
| `server.port` | `int` | `8080` | TCP listener port |
| `server.max_request_body_bytes` | `int64` | `1048576` (`1 MiB`) | Middleware `MaxRequestBodyBytes` (`1 << 20`) cap on incoming payloads; oversized requests return `413` |
| `server.tls.enabled` | `bool` | `true` | Enables HTTPS TLS listener |
| `server.tls.auto_generate` | `bool` | `true` | Auto-generates ECDSA/TLS server keypair when certificate files are absent |
| `server.tls.cert_file` | `string` | `"certs/server.crt"` | Path to TLS server certificate |
| `server.tls.key_file` | `string` | `"certs/server.key"` | Path to TLS server private key |
| `server.tls.client_ca_file` | `string` | `""` | Optional client CA bundle for mTLS peer verification |
| `server.tls.organization` | `string` | `"Go Admin Tool"` | X.509 subject organization used for auto-generated certificates |
| `server.tls.validity_days` | `int` | `365` | Lifetime in days for auto-generated certificates |
| `server.tls.min_version` | `string` | `"1.2"` | Minimum TLS protocol version; accepts `"1.2"` or `"1.3"` (`cis-benchmarks` sets `"1.3"`) |
| `server.tls.hosts` | `[]string` | `["localhost", "127.0.0.1"]` | Subject Alternative Name (SAN) host/IP list for auto-generated certificates |
| `server.rate_limit.enabled` | `bool` | `true` | Enables per-IP token-bucket HTTP rate limiter |
| `server.rate_limit.requests_per_second` | `float64` | `500` | Sustained token refill rate per client IP |
| `server.rate_limit.burst` | `int` | `2000` | Maximum burst token capacity per client IP |

Runtime `http.Server` socket timeouts in [`cmd/server/main.go`](../../../cmd/server/main.go) and rate-limiter memory bounds in [`internal/api/security_middleware.go`](../../../internal/api/security_middleware.go):

| Runtime Constant | Value | Scope |
| :--- | :--- | :--- |
| `ReadHeaderTimeout` | `5s` | Maximum time to read HTTP request headers |
| `ReadTimeout` | `15s` | Maximum duration for reading the full request |
| `WriteTimeout` | `30s` | Maximum duration before timing out response writes |
| `IdleTimeout` | `60s` | Maximum keep-alive idle connection lifetime |
| `MaxTrackedRateLimitIPs` | `10000` | Maximum concurrent client IPs stored in rate-limiter map |
| Rate-limiter stale IP cutoff | `2m` | Inactive IP entries evicted after `2m` |

---

## `logging`, `database`, and `file_server`

| Path | Type | Default | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `logging.level` | `string` | `"info"` | Accepted levels: `debug`, `info`, `warn`, `error` |
| `logging.path` | `string` | `""` | Optional file log path written with `0600` permissions; empty logs to stdout only |
| `database.path` | `string` | `"history.db"` | SQLite database file path; falls back to pure-Go in-memory storage under `CGO_ENABLED=0` |
| `file_server.enabled` | `bool` | `false` (`true` in `config.yaml`) | Enables read-only file listing and bounded file downloads |
| `file_server.secure_dir` | `string` | `"/var/log/secure_files"` | Chrooted base directory enforced against path traversal |

Internal logging and SQLite defaults:

| Runtime Constant | Value | Description |
| :--- | :--- | :--- |
| `defaultLogBufferCapacity` | `500` | Maximum in-memory entries returned by `GET /api/v1/logs` |
| `DefaultMaxOpenConns` | `1` | SQLite single-writer open connection cap |
| `DefaultMaxIdleConns` | `1` | SQLite idle connection pool cap |
| `DefaultConnMaxLifetime` | `1h` | SQLite connection lifetime limit |
| `DefaultBusyTimeoutMs` | `5000` | SQLite busy wait timeout (`5000 ms`) |
| Applied SQLite `PRAGMA`s | `journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`, `foreign_keys=ON` | Enforced on SQLite initialization |

---

## `command_executor` and Command Definitions

| Path | Type | Default (`DefaultConfig`) | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `command_executor.enabled` | `bool` | `true` | Enables whitelisted command execution API and tools |
| `command_executor.default_timeout` | `string` | `"30s"` | Duration string overriding `default_timeout_seconds` when valid |
| `command_executor.default_timeout_seconds` | `int` | `30` | Legacy integer fallback default timeout in seconds |
| `command_executor.max_timeout_seconds` | `int` | `0` (`300` in `config.yaml`) | Global hard ceiling applied above profile/command timeouts (`0` disables upper clamp) |
| `command_executor.enable_os_presets` | `bool` | `false` | Enables built-in OS diagnostic preset merging |
| `command_executor.os_presets` | `[]string` | `[]` | Active preset families (for example `ubuntu`, `redhat`, `cis-benchmarks`) |
| `command_executor.commands` | `[]Command` | `[]` | Static whitelist of allowed `exec.CommandContext` definitions |

Each item inside `command_executor.commands[]`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `name` | `string` | Unique command identifier |
| `description` | `string` | Human-readable purpose returned by catalog endpoints and MCP |
| `os_family` | `string` | Target operating system family tag |
| `category` | `string` | Operational grouping label |
| `command` | `string` | Binary name or path executed directly without shell invocation |
| `args` | `[]string` | Static base argument vector |
| `timeout_seconds` | `int` | Per-command timeout override in seconds |
| `timeout` | `string` | Per-command Go duration string override (takes precedence over `timeout_seconds`) |
| `preset` | `bool` | Flags whether the command definition was merged dynamically from OS presets |
| `require_approval` | `bool` | Forces HITL approval gate regardless of global `approval.critical_commands` |
| `sandbox` | `object` | Optional per-command sandbox policy override |

Sync output cap in [`internal/core/executor.go`](../../../internal/core/executor.go): `MaxCommandOutputBytes = 1048576` (`1 MiB`, `1 << 20`) via `limitedOutputBuffer`.

---

## `auth`

| Path | Type | Default | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `auth.enabled` | `bool` | `true` | Initializes authentication manager, user accounts, PATs, and service accounts |
| `auth.require_auth` | `bool` | `false` | Enforces mandatory credential presentation across `/api/v1/*` routes |
| `auth.bootstrap_username` | `string` | `"admin"` | Initial administrator username created on empty stores |
| `auth.bootstrap_password` | `string` | `"admin-change-me"` | Initial administrator password; must be rotated outside local labs |
| `auth.bootstrap_token` | `string` | `""` | Optional static bootstrap token loaded into the auth store |
| `auth.store_path` | `string` | `""` | Optional persistent JSON credential store path; empty uses database/memory only |

Authentication cryptographic invariants in [`internal/auth/manager.go`](../../../internal/auth/manager.go):

| Mechanism | Specification |
| :--- | :--- |
| Password KDF | `10000`-round salted SHA-256 with `16`-byte random salt and `subtle.ConstantTimeCompare` |
| Personal Access Token (PAT) | Prefix `gat_pat_` + `20` random bytes hex-encoded; indexed by SHA-256 (`tokenByHash`) |
| Service Account Key | Prefix `gat_svc_` + `24` random bytes hex-encoded; indexed by SHA-256 (`serviceAccountByHash`) |
| Supported RBAC Roles | `admin`, `operator`, `viewer`, `service` |

---

## `plugins`, `mcp`, and `audit`

### `plugins`

| Path | Type | Default | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `plugins.enabled` | `bool` | `true` | Enables native and declarative plugin execution |
| `plugins.enable_db_exposure` | `bool` | `true` | Enables read-only SQLite inspection endpoints and MCP tools |
| `plugins.enable_sys_diagnostics` | `bool` | `true` | Enables built-in Go system diagnostic plugins |
| `plugins.declarative_dir` | `string` | `"plugins"` | Root directory recursively scanned for YAML declarative plugins |
| `plugins.allowed_db_paths` | `[]string` | `[]` | Reserved in single-DB mode; `db-exposure` queries the server's configured `database.path` SQLite store |
| `plugins.max_query_rows` | `int` | `200` | Maximum SQLite query rows returned; clamped to `<= 1000` |

Plugin inventory counts on the repository tree: `24` built-in Go native plugins + built-in `DefaultDeclarativeOpsPlugin()` (`ops-quick-tools`) loaded at startup + `282` declarative YAML plugin definitions under `plugins/` (`sysadmin`: 28, `netops`: 28, `secops`: 29 including `cis-benchmarks-audit.yaml`, `containerops`: 28, `kubernetes`: 28, `dataops`: 28, `devops`: 28, `sre`: 28, `aiops`: 28, `webutils`: 28, root `network-audit.yaml`: 1).

### `mcp`

| Path | Type | Default | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `mcp.enabled` | `bool` | `true` | Enables MCP JSON-RPC `2.0` server (protocol version `"2024-11-05"`) |
| `mcp.server_name` | `string` | `"api-executor-mcp"` | Reported MCP `serverInfo.name` |
| `mcp.server_version` | `string` | `"2.0.0"` | Reported MCP `serverInfo.version` |
| `mcp.retain_traces` | `bool` | `true` | Retains hash-chained MCP trace records for verification and replay |
| `mcp.max_traces` | `int` | `500` | Bounded ring capacity of retained MCP traces |
| `mcp.trace_file_path` | `string` | `""` | Optional persistent JSONL trace file path |

### `audit`

| Path | Type | Default | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `audit.enabled` | `bool` | `true` | Enables immutable SHA-256 hash-chained audit logging |
| `audit.file_path` | `string` | `""` | Optional append-only JSONL audit file written with `0600` mode |
| `audit.max_memory_log` | `int` | `1000` | Bounded in-memory audit event buffer size |
| Anchor Constant | `GenesisHash` | `"GENESIS_00000000000000000000000000000000000000000000000000000000"` | Root `PrevHash` anchor for audit chain entry `1` |

---

## `approval` and `gatekeeper`

### `approval`

| Path | Type | Default (`DefaultApprovalConfig`) | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `approval.enabled` | `bool` | `false` | Enables Human-in-the-Loop (HITL) pre-execution blocking |
| `approval.default_ttl` | `string` | `"10m"` | Approval token expiration duration |
| `approval.max_pending` | `int` | `500` | Bounded capacity for pending `apr_*` requests |
| `approval.require_distinct_approver` | `bool` | `true` | Rejects self-approval (`approver == requester`) |
| `approval.critical_commands` | `[]string` | `[]` | Command names requiring HITL approval |
| `approval.critical_plugins` | `[]string` | `[]` | Plugin names requiring HITL approval |
| `approval.critical_mcp_tools` | `[]string` | `[]` | MCP tool names requiring HITL approval |

### `gatekeeper` (`System-1 MicroLLM`)

| Path | Type | Default | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `gatekeeper.enabled` | `bool` | `false` | Enables pre-execution System-1 semantic guard evaluation |
| `gatekeeper.mode` | `string` | `"http"` | Guard transport mode: `"http"`, `"cli"`, or `"noop"` |
| `gatekeeper.endpoint` | `string` | `"http://127.0.0.1:8000/v1/guard/evaluate"` | Loopback HTTP endpoint for `microllm.guard.v1` JSON POSTs |
| `gatekeeper.allow_remote_endpoint` | `bool` | `false` | Must be `true` to permit non-loopback remote guard endpoints |
| `gatekeeper.insecure_skip_verify` | `bool` | `false` | Disables TLS verification on HTTPS guard endpoints |
| `gatekeeper.cli_path` | `string` | `""` | Binary path when `mode == "cli"` |
| `gatekeeper.cli_args` | `[]string` | `["--stdin", "--json"]` | Arguments passed to `cli_path` |
| `gatekeeper.timeout` | `string` | `"5ms"` | Guard evaluation latency budget |
| `gatekeeper.min_confidence` | `float64` | `0.70` | Minimum confidence threshold required before honoring guard decision |
| `gatekeeper.fail_mode` | `string` | `"escalate_hitl"` | Fallback policy on timeout, error, or low confidence: `"escalate_hitl"`, `"deny"`, or `"block"` |
| `gatekeeper.environment` | `string` | `"production"` | Environment context field sent in guard payload: `"production"`, `"staging"`, or `"development"` |
| `gatekeeper.headers` | `map[string]string` | `{}` | Optional HTTP headers (masked as `"[REDACTED]"` in `/api/v1/config`) |

Wire contract limits in [`internal/gatekeeper/`](../../../internal/gatekeeper/gatekeeper.go): schema version `"microllm.guard.v1"`, HTTP `MaxResponseBytes = 65536` (`64 * 1024`).

---

## `jobs`, `multi_config`, `otlp_export`, and `sandbox`

### `jobs`

| Path | Type | Default (`DefaultJobsConfig`) | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `jobs.workers_count` | `int` | `4` | Fixed worker goroutine pool size; non-positive values fall back to `4` |
| `jobs.queue_capacity` | `int` | `1000` | Bounded priority max-heap queue capacity; excess submissions return `429 Too Many Requests` |
| `jobs.max_log_bytes` | `int` | `2097152` (`2 MiB`) | Per-job `JobLogBuffer` ring retention cap in bytes |
| `jobs.prune_interval` | `string` | `"10m"` | Duration string between terminal job pruning sweeps (`ParseTimeoutDuration`) |
| `jobs.max_job_age` | `string` | `"168h"` (`7d`) | Maximum retention age for terminal jobs before pruning |
| `jobs.max_retained_jobs` | `int` | `10000` | Maximum number of terminal job records retained in the store |

Sanitized values are exposed at runtime under `jobs` on `GET /api/v1/config` (`SanitizedJobsConfig`).

### `multi_config`

| Path | Type | Default (`DefaultConfig`) | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `multi_config.enabled` | `bool` | `false` (`true` in `config.yaml`) | Enables profile lookup via `X-Config-Profile`, `?profile=`, and `/api/v1/configs/{profile}` |
| `multi_config.endpoint` | `string` | `"/api/v1/config"` | Base config inspection route prefix |
| `multi_config.version_path` | `string` | `"/api/v1/config/version"` | Version endpoint path for active profile |
| `multi_config.default_profile` | `string` | `"default"` | Default profile selected when no override is supplied |
| `multi_config.profiles` | `[]Profile` | `[]` | Array of `{name, path, description}` entries |

### `otlp_export`

| Path | Type | Default | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `otlp_export.enabled` | `bool` | `true` | Enables OTLP exporter state, `/api/v1/metrics/otlp` snapshot endpoint, and background `OTLPPusher` when `endpoint` is set |
| `otlp_export.endpoint` | `string` | `""` | Target OTLP/HTTP JSON receiver URL (`http://` or `https://` with non-empty host); empty disables outbound background pushes |
| `otlp_export.push_interval` | `string` | `"30s"` | Periodic outbound push interval duration string |
| `otlp_export.push_interval_seconds` | `int` | Config dependent | Legacy integer fallback interval in seconds |
| `otlp_export.headers` | `map[string]string` | `{}` | Outbound OTLP HTTP headers (masked as `"[REDACTED]"` in `/api/v1/config`) |
| `otlp_export.resource_attributes` | `map[string]string` | `{"service.name": "api-executor"}` | Resource attributes attached to exported telemetry |
| `otlp_export.timeout` | `string` | `"10s"` | HTTP push timeout duration string |
| `otlp_export.timeout_seconds` | `int` | Config dependent | Legacy integer fallback timeout in seconds |
| `otlp_export.insecure_skip_verify` | `bool` | `false` | Disables TLS verification for OTLP collector endpoint |

When `otlp_export.enabled` is `true` and `otlp_export.endpoint` is non-empty, `cmd/server/main.go` starts an active background `OTLPPusher` (`internal/api/metrics_otlp.go`) that gathers `prometheus.DefaultGatherer` metrics, translates them to OTLP/HTTP JSON (`OTLPExportMetricsRequest`), and POSTs on `EffectivePushInterval()` with TLS `MinVersion: 1.2` and non-HTTP(S) redirect blocking. Invalid `endpoint` values fail server startup; runtime push errors log a warning (`OTLP background metrics push failed`) without crashing the server, and `Close()` drains cleanly on shutdown.

### `sandbox`

| Path | Type | Default | Constraints & Behavior |
| :--- | :--- | :--- | :--- |
| `sandbox.enabled` | `bool` | `true` | Enables non-root execution sandbox metadata and enforcement |
| `sandbox.enforce_non_root` | `bool` | `true` | Rejects UID `0` or GID `0` execution policies |
| `sandbox.uid` | `int` | `10001` | Target execution user ID (`> 0` when `enforce_non_root` is true) |
| `sandbox.gid` | `int` | `10001` | Target execution group ID (`> 0` when `enforce_non_root` is true) |
| `sandbox.userns` | `string` | `"keep-id"` | Rootless container user namespace mode |
| `sandbox.userns_mode` | `string` | `"keep-id"` | Alias/runtime user namespace mode |
| `sandbox.drop_privileges` | `bool` | `true` | Drops ambient and effective privileges before exec |
| `sandbox.no_new_privileges` | `bool` | `true` | Sets `prctl(PR_SET_NO_NEW_PRIVS)` invariant |
| `sandbox.drop_caps` | `bool` | `true` | Drops Linux capabilities (`--cap-drop=ALL` alignment) |
| `sandbox.container_runtime` | `string` | `""` | Target runtime hint: `""`, `"podman"`, `"docker"`, or `"native"` |

Valid `sandbox.userns` / `sandbox.userns_mode` values: `"keep-id"`, `"auto"`, `"nomap"`, `"private"`, or `""`. Validation explicitly rejects `"host"`, negative IDs, and UID/GID `0` when `enforce_non_root` is enabled.

---

## Internal Async Job Engine Defaults

Defaults defined in `DefaultEngineConfig()` ([`internal/jobs/engine.go`](../../../internal/jobs/engine.go)) and overridden via top-level `jobs:` in `config.yaml` (`DefaultJobsConfig()`):

| Field | Default Value | Description |
| :--- | :--- | :--- |
| `WorkersCount` | `4` | Fixed background worker goroutine pool size |
| `QueueCapacity` | `1000` | Bounded priority max-heap queue capacity |
| `MaxLogBytes` | `2097152` (`2 MiB`) | Per-job `JobLogBuffer` ring retention ceiling (`DefaultMaxLogBytes`) |
| `ChunkSize` | `16384` (`16 KiB`) | `sync.Pool` fixed-size `[16384]byte` log chunk buffer |
| `PruneInterval` | `10m` | Interval between completed/failed/canceled job pruning sweeps |
| `MaxJobAge` | `168h` (`7d`) | Maximum age retained for terminal jobs |
| `MaxRetainedJobs` | `10000` | Maximum terminal job records kept in store |
| `DefaultJobTimeout` | `30s` | Fallback timeout when command and request specify no timeout |

---

## Built-In Configuration Profiles

| Profile | File Path | Static & Preset Commands | Notable Overrides |
| :--- | :--- | :--- | :--- |
| `default` | [`config.yaml`](../../../config.yaml) | Standard diagnostic command whitelist + presets disabled unless configured | `file_server.enabled: true`, `max_timeout_seconds: 300`, `multi_config.enabled: true` |
| `ubuntu` | [`configs/ubuntu-tasks.yaml`](../../../configs/ubuntu-tasks.yaml) | `4` YAML commands + `10` merged `ubuntu` OS presets | `enable_os_presets: true`, `os_presets: ["ubuntu"]` |
| `redhat` | [`configs/redhat-tasks.yaml`](../../../configs/redhat-tasks.yaml) | `4` YAML commands + `10` merged `redhat` OS presets | `enable_os_presets: true`, `os_presets: ["redhat"]` |
| `cis-benchmarks` | [`configs/cis-benchmarks-audit.yaml`](../../../configs/cis-benchmarks-audit.yaml) | `8` read-only `audit-cis` commands (`cis-benchmarks` preset) | `server.tls.min_version: "1.3"`, `command_executor.default_timeout: "120s"`, `file_server.enabled: false` |

---

## Related Documentation

- **API, MCP & CLI Specification**: [`rest-mcp-endpoints-and-env.md`](../api-and-cli/rest-mcp-endpoints-and-env.md)
- **Error & Alert Matrix**: [`error-and-alert-matrix.md`](../troubleshooting-codes/error-and-alert-matrix.md)
- **Rootless Container & TLS Guide**: [`deploy-rootless-docker-and-tls.md`](../../02-how-to-guides/deployment/deploy-rootless-docker-and-tls.md)
- **Async Jobs & Presets Guide**: [`manage-async-jobs-and-presets.md`](../../02-how-to-guides/operations/manage-async-jobs-and-presets.md)
- **HITL & MicroLLM Gatekeeper Guide**: [`configure-hitl-and-microllm-gatekeeper.md`](../../02-how-to-guides/operations/configure-hitl-and-microllm-gatekeeper.md)
- **ADR-001 Zero-Trust Execution**: [`adr-001-zero-trust-execution-and-bastion.md`](../../04-explanation/design-decisions/adr-001-zero-trust-execution-and-bastion.md)
