# API Executor — End-to-End (E2E) Test Infrastructure Specification

This document defines the architecture, design principles, testing tiers, and runner specifications for the **API Executor (`go-admin-tool`)** End-to-End (E2E) test suite, covering the hybrid 300+ plugin ecosystem across REST and Model Context Protocol (MCP) surfaces.

---

## 1. Architectural Principles & Opaque-Box Methodology

The E2E test suite adheres to strict **opaque-box testing principles**:
1. **Public Protocol Surface Only**: All assertions and interactions execute exclusively across public HTTP endpoints (`GET /api/v1/plugins`, `POST /api/v1/plugins/execute`, `POST /api/v1/mcp`, `/api/v1/audit/*`, `/metrics`). The test suite never calls private internal methods to verify behavior; it exercises the system identically to external clients (cURL, Web Console, or LLM MCP clients).
2. **Deterministic Ephemeral Environments**: Each test initializes an isolated runtime environment using an ephemeral SQLite database (`t.TempDir()`), an isolated cryptographic SHA-256 audit logger, clean RBAC principals, and reset Prometheus metric counters via `api.ResetActionMetrics()`.
3. **Cross-Platform Portability**: Tests execute seamlessly on both Linux and Windows operating environments without requiring external daemon dependencies or root/Administrator privileges.
4. **Progressive Testability**: Tests verify baseline contracts and dynamically validate advanced features (such as multi-attribute query filtering and 300-plugin catalogs) as milestones are integrated, preventing regressions while enabling early CI/CD gating.

---

## 2. Four-Tier Testing Methodology

The E2E test harness is structured across four progressive testing tiers:

```text
┌─────────────────────────────────────────────────────────────────┐
│        Tier 4: Real-World Scenarios (End-to-End Workflows)       │
│   Multi-step SysAdmin, DB triage, LLM MCP agent simulation      │
├─────────────────────────────────────────────────────────────────┤
│        Tier 3: Cross-Feature Combinations & Integrations        │
│   Filtering + Exec, MCP + Audit chaining, RBAC & Service Accounts│
├─────────────────────────────────────────────────────────────────┤
│        Tier 2: Boundary, Corner Cases & Adversarial Stress      │
│   Empty inputs, regex injection, extreme timeouts, malformed JSON│
├─────────────────────────────────────────────────────────────────┤
│        Tier 1: Feature Coverage (>= 5 Tests per Core Feature)    │
│   Catalog discovery, filtering, native execution, declarative, MCP│
└─────────────────────────────────────────────────────────────────┘
```

### Tier 1: Feature Coverage (`tests/e2e/tier1_feature_test.go`)
Every core capability is validated with at least 5 distinct test cases covering primary happy paths:
- **Feature 1: Plugin Catalog Discovery (`GET /api/v1/plugins`)**
  - `TestTier1_F1_CatalogDiscovery_HappyPath`: Verify HTTP 200, valid `{"plugins": [...]}` JSON envelope.
  - `TestTier1_F1_PluginMetadataSchema_Validation`: Validate all required fields (`id`, `name`, `version`, `kind`, `description`, `actions`).
  - `TestTier1_F1_NativePlugins_Presence`: Assert presence and action schemas of core native plugins (`sys-diagnostics`, `db-exposure`).
  - `TestTier1_F1_DeclarativePlugins_Presence`: Assert presence and parameter schemas of declarative plugins.
  - `TestTier1_F1_PluginUniquenessAndSorting`: Verify zero duplicate plugin IDs and deterministic alphabetical ordering.
- **Feature 2: Catalog Filtering (`GET /api/v1/plugins?category=...&q=...&type=...`)**
  - `TestTier1_F2_FilterByCategory`: Verify category isolation (e.g. `SysAdmin`, `NetOps`, `DataOps`).
  - `TestTier1_F2_FilterByKeywordQuery`: Keyword search `?q=...` across ID, Name, Description, and Actions.
  - `TestTier1_F2_FilterByType`: Type toggle `?type=native` versus `?type=declarative`.
  - `TestTier1_F2_CombinedFilter_CategoryAndTypeAndQuery`: Multi-attribute compound filtering.
  - `TestTier1_F2_CaseInsensitiveFilter`: Case-insensitive category matching (e.g. `sysadmin` vs `SYSADMIN`).
- **Feature 3: Native Plugin Execution (`POST /api/v1/plugins/execute`)**
  - `TestTier1_F3_NativePlugin_SysDiagnostics_RuntimeStats`: Verify native Go memory and Goroutine telemetry execution.
  - `TestTier1_F3_NativePlugin_SysDiagnostics_NetworkInterfaces`: Verify network interface enumeration.
  - `TestTier1_F3_NativePlugin_SysDiagnostics_EnvSummary`: Verify sanitized environment variable inspection.
  - `TestTier1_F3_NativePlugin_DBExposure_ListTables`: Verify read-only database table listing.
  - `TestTier1_F3_NativePlugin_DBExposure_DBStats`: Verify database connection and row statistics.
- **Feature 4: Declarative Plugin Execution (`POST /api/v1/plugins/execute`)**
  - `TestTier1_F4_DeclarativePlugin_ProbeTarget_ValidParam`: Verify execution with explicitly provided parameter.
  - `TestTier1_F4_DeclarativePlugin_DefaultParameterFallback`: Verify parameter fallback to default values when omitted.
  - `TestTier1_F4_DeclarativePlugin_CustomTimeoutOverride`: Verify custom call timeout override enforcement.
  - `TestTier1_F4_DeclarativePlugin_DynamicRegistrationAndExecution`: Verify runtime declarative module registration via `POST /api/v1/plugins/declarative` and subsequent invocation.
  - `TestTier1_F4_DeclarativePlugin_CommandOutputAndExitStatus`: Verify structured output capture and status handling.
- **Feature 5: Model Context Protocol (MCP) Integration (`POST /api/v1/mcp`)**
  - `TestTier1_F5_MCP_InitializeProtocol`: Verify JSON-RPC `initialize` handshake and server capabilities.
  - `TestTier1_F5_MCP_ToolsList_ExecutePluginPresent`: Verify `tools/list` returns `execute_plugin` meta-tool with JSON schema.
  - `TestTier1_F5_MCP_ToolsCall_ExecutePlugin_Native`: Verify `tools/call` execution of native plugin (`sys-diagnostics:runtime_stats`).
  - `TestTier1_F5_MCP_ToolsCall_ExecutePlugin_Declarative`: Verify `tools/call` execution of declarative plugin.
  - `TestTier1_F5_MCP_ResourcesRead_PluginsCatalog`: Verify `resources/read` on `executor://plugins/catalog`.

### Tier 2: Boundary & Corner Cases (`tests/e2e/tier2_boundary_test.go`)
Adversarial verification and extreme boundary conditions:
- `TestTier2_Boundary_EmptyQueryParams`: Verify empty query strings (`?category=&q=&type=`) return full catalog gracefully.
- `TestTier2_Boundary_UnknownCategory`: Verify non-existent category query returns empty set without runtime error.
- `TestTier2_Boundary_UnknownSearchQuery`: Verify search for non-existent keywords returns empty set.
- `TestTier2_Boundary_MissingPluginID`: Verify HTTP 400 Bad Request when `plugin_id` is omitted.
- `TestTier2_Boundary_MissingAction`: Verify HTTP 400 Bad Request when `action` is omitted.
- `TestTier2_Boundary_NonExistentPluginID`: Verify HTTP 404 Not Found on unknown plugin.
- `TestTier2_Boundary_NonExistentActionOnExistingPlugin`: Verify HTTP 404 Not Found on unknown action.
- `TestTier2_Boundary_InvalidRegexParameterInjection`: Adversarial input testing shell metacharacters (`;&|$`><`, `$(whoami)`, `; rm -rf /`) rejected with 400 Bad Request.
- `TestTier2_Boundary_ParameterTypeMismatch`: Verify handling when parameter value does not conform to declared type.
- `TestTier2_Boundary_InvalidTimeoutString`: Verify HTTP 400 Bad Request on invalid timeout formats (e.g. `invalid`, `-5s`).
- `TestTier2_Boundary_ShortTimeoutExpiry`: Verify execution timeout aborts and returns `timed_out: true` when timeout is exceeded.
- `TestTier2_Boundary_LargePayloadStress`: Verify handling of large parameter payloads within memory constraints.
- `TestTier2_Boundary_SpecialCharactersAndUnicodeQuery`: Verify UTF-8, punctuation, and Unicode resilience in search queries.
- `TestTier2_Boundary_MalformedJSONRequestBody`: Verify HTTP 400 Bad Request on malformed JSON bodies across all POST endpoints.

### Tier 3: Cross-Feature Combinations (`tests/e2e/tier3_cross_feature_test.go`)
Integration contracts across multiple distinct subsystems:
- `TestTier3_Combination_APIFilterAndExecuteWorkflow`: Search catalog via `GET /api/v1/plugins`, select plugin, and execute via `POST /api/v1/plugins/execute`.
- `TestTier3_Combination_MCPExecution_WithSHA256AuditLoggingAndChainVerification`: Execute plugin via MCP `tools/call`, inspect recorded audit event via `GET /api/v1/audit/logs`, and cryptographically verify the hash chain via `GET /api/v1/audit/verify`.
- `TestTier3_Combination_RESTExecution_WithSHA256AuditLoggingAndChainVerification`: Execute plugin via REST API, verify audit event category `plugin`, actor identity, and SHA-256 integrity.
- `TestTier3_Combination_RBAC_AdminAllowed_ViewerForbidden`: Enforce RBAC permissions: admin PAT succeeds on plugin execution; viewer PAT receives HTTP 403 Forbidden.
- `TestTier3_Combination_ScopedServiceAccount_AllowedActionsEnforcement`: Scoped Service Account (`gat_svc_...`) with `allowed_actions: ["plugin:sys-diagnostics:*"]` successfully executes `sys-diagnostics` but is denied on other plugins.
- `TestTier3_Combination_PrometheusMetricCorrelation_OnPluginAction`: Verify `action_calls_total{action="plugin:..."}` counter increments on `/metrics` upon plugin execution.
- `TestTier3_Combination_DynamicDeclarativeRegistration_MCPAvailability`: Register new declarative plugin via REST, verify it instantly appears in MCP `resources/read executor://plugins/catalog` and executes via MCP `tools/call`.

### Tier 4: Real-World Scenarios (`tests/e2e/tier4_real_world_test.go`)
Multi-step, production-realistic operational and autonomous agent workflows:
- `TestTier4_Scenario_ComprehensiveSystemDiagnosticsWorkflow`: Multi-plugin host triage (runtime stats -> network interfaces -> environment telemetry -> audit verification).
- `TestTier4_Scenario_DatabaseHealthAndTableInspectionWorkflow`: Automated database discovery, table catalog inspection, DB connection stats, and guarded read-only SELECT query.
- `TestTier4_Scenario_MultiDomainTriageViaMCPAgentSimulation`: Full MCP client agent simulation (handshake -> resource catalog inspection -> diagnostic tool execution -> MCP trace audit inspection).
- `TestTier4_Scenario_DynamicOpsRemediationAndAuditLifecycle`: Incident response simulation: register emergency inspection module -> run parameter-checked triage -> verify metrics and tamper-evident audit record.

---

## 3. Test Harness Architecture & Helpers (`tests/e2e/setup_test.go`)

### Ephemeral Test Server Construction
```go
type e2eTestServer struct {
    ts            *httptest.Server
    baseURL       string
    client        *http.Client
    db            *database.DB
    auditLogger   *audit.AuditLogger
    authMgr       *auth.Manager
    pluginReg     *plugins.Registry
    adminPAT      string
    operatorPAT   string
    viewerPAT     string
    scopedSvcPAT  string
}
```

The test server wires all components together using production constructors, seeds standard authenticated identities, mounts all REST and MCP handlers onto a standard HTTP multiplexer, and starts a local loopback listener.

### Seeded Credentials Matrix
| Identity | Type | Token / Key | Role / Scope |
|---|---|---|---|
| Admin Operator | Personal Access Token | `gat_pat_e2e_admin_secret_token_12345` | `admin` (Full permissions) |
| Standard Operator | Personal Access Token | `gat_pat_e2e_operator_token_67890` | `operator` (Execute allowed) |
| Read-Only Viewer | Personal Access Token | `gat_pat_e2e_viewer_token_13579` | `viewer` (Read-only, execution 403) |
| Scoped Service Account | Third-Party Service Account | `gat_svc_e2e_sysdiag_scoped_token` | `allowed_actions: ["plugin:sys-diagnostics:*", "sys-diagnostics"]` |

---

## 4. Test Execution & Verification Commands

### Standard Test Execution
Execute the entire E2E test suite in verbose mode:
```powershell
go test -v ./tests/e2e/...
```

### Execution with Statement Coverage
```powershell
go test -v -count=1 -cover ./tests/e2e/...
```

### Full Repository Verification
```powershell
go test -v -count=1 -cover ./...
```
