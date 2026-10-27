# Project: API Executor 300+ Plugins Ecosystem Expansion

## Architecture
The API Executor (`go-admin-tool`) plugin architecture uses a hybrid model combining high-performance native Go plugins with declarative YAML/JSON command plugins, exposed uniformly via REST API, MCP server, and a pure HTML5/Alpine.js Web Administration Console:

- **Core Plugin Engine (`internal/plugins/`)**:
  - `Registry`: Thread-safe registry (`sync.RWMutex`) with duplicate-detection, category-aware indexing, and in-memory multi-attribute filtering (`ListFiltered`).
  - `Plugin` Interface: Enriched with `Category() string` and `Type() string` (native vs declarative), while preserving backward compatibility with `Kind() PluginKind`.
  - `PluginInfo`: Serializes `id`, `name`, `version`, `kind`, `type`, `category`, `description`, `actions`.
  - Recursive Declarative Loader: Uses `filepath.WalkDir` to discover plugins across domain subdirectories (`plugins/<domain>/`), inferring default category from directory names when omitted.
  - Safe Subprocess Execution: Direct `exec.CommandContext` argv execution without shell interpreters (`sh`, `bash`, `cmd`), strictly validating parameter types, regex patterns, and metacharacter blacklists.
- **Native Go Plugins**: 24 distinct pure-Go plugins across 10 domains using standard library packages (`crypto/*`, `net`, `net/http`, `os`, `database/sql`, `regexp`, `time`), zero CGO dependencies.
- **Declarative Plugins Catalog (`plugins/`)**: 280 declarative YAML plugins organized across 10 operational domains (28 plugins per domain).
- **API & MCP Integration (`internal/api/`, `internal/mcp/`)**:
  - `GET /api/v1/plugins`: Supports query parameters `?category=...&q=...&type=...`.
  - `POST /api/v1/plugins/execute`: Uniform execution with RBAC, Prometheus metrics, and SHA-256 hash-chained audit logging.
  - `internal/mcp/`: Meta-Tool Pattern (`execute_plugin`) and `executor://plugins/catalog` resource, preventing LLM context-window token overflow.
- **Web Administration Console (`web/static/index.html`)**:
  - Tab 5 upgraded to a responsive Master-Detail layout featuring instant keyword search, 10 domain category pills, type toggles, pagination, and dynamic parameter forms.
- **Governance & Atomic Workflow**:
  - Strict 1 Item = 1 GitHub Issue = 1 Dedicated Branch = 1 PR = 1 Merge = Close Issue with summary comment.
  - English-only policy across code, comments, docs, commit messages, and PRs.
  - Living registers in `docs/ACTION_LOGBOOK.md` and `docs/RCA_REGISTER.md`.

---

## Feature Inventory

Every required feature from the survey and requirements is cataloged and assigned to a milestone:

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Category & Type Metadata in `PluginInfo` & `Plugin` | Enrich plugin metadata with `category` and `type` ("native" / "declarative") | M1 | Survey 1, 2, 3 |
| 2 | Recursive Declarative Directory Loader | Upgrade `LoadDeclarativeDirectory` to use `filepath.WalkDir` for domain subdirectories | M1 | Survey 2, 3 |
| 3 | Filtered Plugin Listing in Registry | Add `Registry.ListFiltered(category, q, pluginType)` with case-insensitive matching | M1 | Survey 1, 3 |
| 4 | API Query Parameter Filtering on `GET /api/v1/plugins` | Handle `?category=...`, `?q=...`, and `?type=...` in `PluginsListHandler` | M1 | Survey 3 |
| 5 | 24 Native Go Plugins Across 10 Domains | Implement 24 pure-Go plugins (zero CGO) across all 10 domains with unit tests | M1 | Survey 1 |
| 6 | SysAdmin Declarative Plugin Pack (28 plugins) | System, CPU, memory, storage, process, and kernel inspection plugins | M2 | Survey 2 |
| 7 | NetOps Declarative Plugin Pack (28 plugins) | Interfaces, routes, ARP, ping, traceroute, DNS, firewall, and curl plugins | M2 | Survey 2 |
| 8 | SecOps Declarative Plugin Pack (28 plugins) | Auth logs, sudo, SUID, permissions, AppArmor/SELinux, and audit plugins | M2 | Survey 2 |
| 9 | ContainerOps Declarative Plugin Pack (28 plugins) | Docker, containerd, crictl, Podman container, image, and network plugins | M2 | Survey 2 |
| 10 | Kubernetes Declarative Plugin Pack (28 plugins) | K8s nodes, pods, services, ingress, PVCs, events, and Helm releases | M2 | Survey 2 |
| 11 | DataOps Declarative Plugin Pack (28 plugins) | SQLite, PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, and backup checks | M3 | Survey 2 |
| 12 | DevOps & CI/CD Declarative Plugin Pack (28 plugins) | Git status, commits, tags, Go/Node/Python/Rust/Cargo/make/linters | M3 | Survey 2 |
| 13 | SRE & Observability Declarative Plugin Pack (28 plugins) | Prometheus scrape, Loki, OpenTelemetry, SLO latency, logs, FinOps | M3 | Survey 2 |
| 14 | AIOps & LLM/MCP Declarative Plugin Pack (28 plugins) | NVIDIA GPU, CUDA, Ollama, vLLM, TGI, MCP client, vector DBs, datasets | M3 | Survey 2 |
| 15 | Web & Crypto Utilities Declarative Pack (28 plugins) | HTTP latency, headers, SSL/TLS, X.509, SHA/MD5, JWT, base64, JSON/YAML | M3 | Survey 2 |
| 16 | Web Console Tab 5 Search, Filtering & Pagination | Upgrade Tab 5 in `web/static/index.html` with search, pills, pagination & forms | M4 | Survey 3 |
| 17 | MCP Catalog & Meta-Tool Compatibility | Verify `executor://plugins/catalog` and `execute_plugin` with 300+ plugins | M4 | Survey 3 |
| 18 | E2E Test Suite (Tiers 1-4) | Comprehensive opaque-box test suite for 300+ plugins, producing `TEST_READY.md` | E2E Track | Requirements |
| 19 | 100% E2E Pass & Test Coverage Verification | Pass 100% E2E tests, verify `>= 80%` statement coverage, and zero duplicate IDs | M5 | Requirements |
| 20 | Live MCP Playwright Web Console Validation | Automated browser verification of Tab 5 loading, filtering, and execution | M5 | Requirements |
| 21 | Governance Registers & Documentation | Update `docs/ACTION_LOGBOOK.md`, `docs/RCA_REGISTER.md`, and `README.md` | M5 | Governance |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core Engine & Native Go Plugins | Recursive loader, Category/Type metadata, API query filtering, 24 native Go plugins | none | DONE |
| M2 | Infrastructure & Systems Declarative Packs | 140 declarative plugins (SysAdmin, NetOps, SecOps, ContainerOps, Kubernetes) | M1 | DONE |
| M3 | Applications, Data & AIOps Declarative Packs | 140 declarative plugins (DataOps, DevOps, SRE, AIOps, Web/Crypto Utilities) | M1 | DONE |
| M4 | Web Console Tab 5 & MCP Integration | Search, domain pills, type filter, pagination, dynamic forms, MCP catalog verification | M1, M2, M3 | PLANNED |
| M5 | Final Verification, Playwright & Governance | 100% E2E test pass, Playwright browser test, registers & documentation updates | M1, M2, M3, M4, E2E | PLANNED |
| E2E | E2E Testing Track | Independent opaque-box test suite design (Tiers 1-4), harness, and `TEST_READY.md` | M1 interface | DONE |

---

## Interface Contracts

### `internal/plugins` ↔ `internal/api` & `internal/mcp`
- `PluginInfo`:
  ```go
  type PluginInfo struct {
      ID          string         `json:"id"`
      Name        string         `json:"name"`
      Version     string         `json:"version"`
      Kind        PluginKind     `json:"kind"`           // "declarative" | "advanced"
      Type        string         `json:"type"`           // "native" | "declarative"
      Category    string         `json:"category"`       // e.g. "SysAdmin", "NetOps", ...
      Description string         `json:"description"`
      Actions     []PluginAction `json:"actions"`
  }
  ```
- `Registry.ListFiltered`:
  ```go
  func (r *Registry) ListFiltered(category, query, pluginType string) []PluginInfo
  ```
- `GET /api/v1/plugins`:
  - Query parameters: `category` (string, case-insensitive substring/match), `q` (string, search in ID, Name, Description, Category, Action names), `type` (string, "native"|"declarative").
  - Response: `{"plugins": []PluginInfo}`

### Declarative Plugin Schema (`plugins/<domain>/<name>.yaml`)
- Structure:
  ```yaml
  id: "<domain-prefix>-<unique-slug>"
  name: "Human-Readable Plugin Name"
  version: "1.0.0"
  category: "<Operational Domain>"
  description: "Description of the plugin capability"
  os_family: "any" # or "linux", "windows"
  actions:
    - name: "<action-name>"
      description: "Action description"
      command: "<binary-name>"
      args: ["<arg1>", "<arg2>"]
      timeout: "5s"
      parameters:
        - name: "<param-name>"
          type: "string" # "string", "int", "bool"
          required: false
          default: "<default-value>"
          pattern: "^[a-zA-Z0-9._-]+$"
          description: "Parameter description"
  ```

---

## Code Layout

- `internal/plugins/`:
  - `plugin.go`: Core types (`PluginInfo`, `ActionParameter`, `PluginAction`, `Registry`).
  - `declarative.go`: `DeclarativePlugin`, recursive `LoadDeclarativeDirectory`, parameter validation.
  - `native_*.go`: 24 native Go plugins (e.g. `native_crypto.go`, `native_tls.go`, `native_net.go`, `native_system.go`, etc.).
  - `plugins_test.go`: Comprehensive unit tests for native and declarative plugins.
- `plugins/`:
  - `sysadmin/`: 28 SysAdmin declarative YAML manifests.
  - `netops/`: 28 NetOps declarative YAML manifests.
  - `secops/`: 28 SecOps declarative YAML manifests.
  - `containerops/`: 28 ContainerOps declarative YAML manifests.
  - `kubernetes/`: 28 Kubernetes declarative YAML manifests.
  - `dataops/`: 28 DataOps declarative YAML manifests.
  - `devops/`: 28 DevOps declarative YAML manifests.
  - `sre/`: 28 SRE & Observability declarative YAML manifests.
  - `aiops/`: 28 AIOps & LLM/MCP declarative YAML manifests.
  - `webutils/`: 28 Web, API & Crypto declarative YAML manifests.
- `internal/api/`:
  - `plugin_handlers.go`: `PluginsListHandler` with query parameter filtering, `PluginExecuteHandler`.
  - `plugin_handlers_test.go`: Unit tests for API filtering and execution.
- `web/static/`:
  - `index.html`: Upgraded Tab 5 with search, category pills, type filter, pagination, and parameter form generator.
- `docs/`:
  - `ACTION_LOGBOOK.md`: Ongoing and completed action logs.
  - `RCA_REGISTER.md`: Living register of root-cause analyses, dead ends, approximations, and ideas.
