package plugins

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go-admin-tool/internal/database"
)

type pluginMockDriver struct{}
type pluginMockConn struct{}
type pluginMockStmt struct{ query string }
type pluginMockRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (d *pluginMockDriver) Open(_ string) (driver.Conn, error) { return &pluginMockConn{}, nil }
func (c *pluginMockConn) Prepare(q string) (driver.Stmt, error) {
	return &pluginMockStmt{query: q}, nil
}
func (c *pluginMockConn) Close() error              { return nil }
func (c *pluginMockConn) Begin() (driver.Tx, error) { return nil, errors.New("unsupported") }
func (s *pluginMockStmt) Close() error              { return nil }
func (s *pluginMockStmt) NumInput() int             { return -1 }
func (s *pluginMockStmt) Exec(_ []driver.Value) (driver.Result, error) {
	return nil, errors.New("read-only")
}
func (s *pluginMockStmt) Query(_ []driver.Value) (driver.Rows, error) {
	q := strings.ToUpper(s.query)
	switch {
	case strings.Contains(q, "SQLITE_MASTER"):
		return &pluginMockRows{
			cols: []string{"name"},
			rows: [][]driver.Value{{"action_history"}, {"invalid-table!"}},
		}, nil
	case strings.Contains(q, "SELECT COUNT(*)"):
		return &pluginMockRows{
			cols: []string{"count"},
			rows: [][]driver.Value{{int64(2)}},
		}, nil
	case strings.Contains(q, "PRAGMA TABLE_INFO(EMPTY_TABLE)"):
		return &pluginMockRows{
			cols: []string{"cid", "name", "type", "notnull", "dflt_value", "pk"},
			rows: nil,
		}, nil
	case strings.Contains(q, "PRAGMA TABLE_INFO"):
		return &pluginMockRows{
			cols: []string{"cid", "name", "type", "notnull", "dflt_value", "pk"},
			rows: [][]driver.Value{
				{int64(0), "id", "INTEGER", int64(1), nil, int64(1)},
				{int64(1), "command", "TEXT", int64(1), nil, int64(0)},
			},
		}, nil
	default:
		return &pluginMockRows{
			cols: []string{"id", "command", "status", "raw_bytes"},
			rows: [][]driver.Value{
				{int64(1), "ubuntu-os-release", "success", []byte("Ubuntu 24.04")},
			},
		}, nil
	}
}

func (r *pluginMockRows) Columns() []string { return r.cols }
func (r *pluginMockRows) Close() error      { return nil }
func (r *pluginMockRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	for i := range dest {
		dest[i] = r.rows[r.idx][i]
	}
	r.idx++
	return nil
}

var registerPluginSQLOnce sync.Once

func TestDeclarativePluginExecutionAndInjectionPrevention(t *testing.T) {
	reg := NewRegistry()
	opsPlugin, err := DefaultDeclarativeOpsPlugin()
	if err != nil {
		t.Fatalf("DefaultDeclarativeOpsPlugin failed: %v", err)
	}
	if err := reg.Register(opsPlugin); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// 1. Valid execution with safe parameter
	res, err := reg.Execute(context.Background(), "ops-quick-tools", "probe-target", map[string]any{
		"target": "db-node-01.internal",
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("expected valid declarative plugin execution, got %v", err)
	}
	if res.Status != "ok" || !strings.Contains(res.Output, "db-node-01.internal") {
		t.Errorf("unexpected output: %+v", res)
	}

	// Default parameter value when nil params passed and timeout <= 0 fallback
	resDefault, err := reg.Execute(context.Background(), "ops-quick-tools", "probe-target", nil, 0)
	if err != nil || resDefault.Status != "ok" || !strings.Contains(resDefault.Output, "localhost") {
		t.Errorf("expected default parameter 'localhost', got err=%v res=%+v", err, resDefault)
	}

	// 2. Shell injection attempt in parameter is rejected before execution
	_, err = reg.Execute(context.Background(), "ops-quick-tools", "probe-target", map[string]any{
		"target": "localhost; rm -rf /",
	}, 5*time.Second)
	if err == nil {
		t.Errorf("expected shell injection attempt in declarative plugin parameter to be rejected")
	}

	// Unknown action in declarative plugin
	if _, err := reg.Execute(context.Background(), "ops-quick-tools", "unknown-act", nil, time.Second); !errors.Is(err, ErrActionNotFound) {
		t.Errorf("expected ErrActionNotFound for unknown declarative action, got %v", err)
	}

	// 3. Load declarative YAML and JSON modules from directory (plus ignored subdirectory & non-YAML file)
	tmpDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("ignored"), 0600)

	yamlSpec := `
id: "custom-yaml-module"
name: "Custom YAML Declarative Module"
version: "1.1.0"
description: "Loaded from YAML file"
actions:
  - name: "custom-check"
    description: "Run custom check"
    command: "whoami"
    timeout: "5s"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "custom.yaml"), []byte(yamlSpec), 0600); err != nil {
		t.Fatalf("failed to write custom.yaml: %v", err)
	}
	jsonSpec := `{
  "id": "custom-json-module",
  "actions": [
    {
      "name": "req-param-action",
      "command": "nonexistent_binary_xyz_999",
      "parameters": [
        {"name": "req_field", "type": "string", "required": true, "pattern": "^[a-z]+$"}
      ]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "custom.json"), []byte(jsonSpec), 0600); err != nil {
		t.Fatalf("failed to write custom.json: %v", err)
	}

	loaded, err := reg.LoadDeclarativeDirectory(tmpDir)
	if err != nil || loaded != 2 {
		t.Fatalf("expected 2 declarative plugins loaded from directory, got %d (err=%v)", loaded, err)
	}
	if _, ok := reg.Get("custom-yaml-module"); !ok {
		t.Errorf("expected custom-yaml-module to be registered")
	}

	// Missing required parameter on custom-json-module
	if _, err := reg.Execute(context.Background(), "custom-json-module", "req-param-action", nil, time.Second); err == nil {
		t.Errorf("expected error when required parameter is missing")
	}
	// Non-existent command execution returns system error status
	resFailBin, err := reg.Execute(context.Background(), "custom-json-module", "req-param-action", map[string]any{"req_field": "abc"}, time.Second)
	if err == nil || resFailBin.Status != "error" {
		t.Errorf("expected error status for non-existent binary, got res=%+v err=%v", resFailBin, err)
	}

	// Edge cases for LoadDeclarativeDirectory (empty dir, non-existent dir, malformed YAML)
	if n, err := reg.LoadDeclarativeDirectory("   "); err != nil || n != 0 {
		t.Errorf("expected (0, nil) for empty dir, got (%d, %v)", n, err)
	}
	if n, err := reg.LoadDeclarativeDirectory(filepath.Join(tmpDir, "does-not-exist")); err != nil || n != 0 {
		t.Errorf("expected (0, nil) for non-existent dir, got (%d, %v)", n, err)
	}
	badDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(badDir, "bad.yaml"), []byte(":::not_yaml"), 0600)
	if _, err := reg.LoadDeclarativeDirectory(badDir); err == nil {
		t.Errorf("expected error loading malformed YAML declarative plugin")
	}

	// Edge cases for NewDeclarativePlugin validation
	if _, err := NewDeclarativePlugin(DeclarativeModuleSpec{ID: "no-actions"}); err == nil {
		t.Errorf("expected error for declarative plugin without actions")
	}
	if _, err := NewDeclarativePlugin(DeclarativeModuleSpec{
		ID:      "empty-cmd",
		Actions: []DeclarativeActionSpec{{Name: "a1", Command: ""}},
	}); err == nil {
		t.Errorf("expected error for action with empty command")
	}
	if _, err := NewDeclarativePlugin(DeclarativeModuleSpec{
		ID: "bad-regex",
		Actions: []DeclarativeActionSpec{{
			Name:       "a1",
			Command:    "echo",
			Parameters: []ActionParameter{{Name: "p1", Pattern: "[unclosed"}},
		}},
	}); err == nil {
		t.Errorf("expected error for invalid parameter regex pattern")
	}
}

func TestDatabaseExposurePluginAndSQLGuardrails(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := database.NewDB(filepath.Join(tmpDir, "test_plugin.db"))
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init failed: %v", err)
	}

	_, _ = db.RecordAction("ubuntu-os-release", "success", "Ubuntu 24.04 LTS")
	_, _ = db.RecordAction("redhat-rpm-qa", "failure", "exit status 1")

	dbPlugin := NewDatabaseExposurePlugin(db, 0) // 0 defaults to 200
	sysPlugin := NewSystemDiagnosticsPlugin()
	reg := NewEmptyRegistry()
	_ = reg.Register(dbPlugin)
	_ = reg.Register(sysPlugin)

	// Verify Registry.List() and all plugin metadata getters
	listed := reg.List()
	if len(listed) != 2 || listed[0].ID != "db-exposure" || listed[1].ID != "sys-diagnostics" {
		t.Fatalf("unexpected Registry.List() result: %+v", listed)
	}

	// Verify nil DB error on DatabaseExposurePlugin
	nilDBPlugin := NewDatabaseExposurePlugin(nil, 5000)
	if _, err := nilDBPlugin.Execute(context.Background(), "list_tables", nil, time.Second); err == nil {
		t.Errorf("expected error when executing DatabaseExposurePlugin with nil DB")
	}

	// 1. list_tables
	resTables, err := reg.Execute(context.Background(), "db-exposure", "list_tables", nil, 5*time.Second)
	if err != nil || resTables.Status != "ok" {
		t.Fatalf("list_tables failed: %v (%+v)", err, resTables)
	}
	if !strings.Contains(resTables.Output, "action_history") {
		t.Errorf("expected action_history in list_tables output: %s", resTables.Output)
	}

	// 2. describe_table (valid, invalid identifier, and non-existent table)
	resDesc, err := reg.Execute(context.Background(), "db-exposure", "describe_table", map[string]any{"table": "action_history"}, 5*time.Second)
	if err != nil || resDesc.Status != "ok" {
		t.Fatalf("describe_table failed: %v", err)
	}
	if !strings.Contains(resDesc.Output, "command") {
		t.Errorf("expected column 'command' in describe_table output: %s", resDesc.Output)
	}
	if _, err := reg.Execute(context.Background(), "db-exposure", "describe_table", map[string]any{"table": "bad;table"}, time.Second); err == nil {
		t.Errorf("expected error for invalid table identifier in describe_table")
	}
	if _, err := reg.Execute(context.Background(), "db-exposure", "describe_table", map[string]any{"table": "unknown_table"}, time.Second); err == nil {
		t.Errorf("expected error for non-existent table in describe_table")
	}

	// 3. query_readonly valid SELECT with max_rows override
	resQuery, err := reg.Execute(context.Background(), "db-exposure", "query_readonly", map[string]any{
		"sql":      "SELECT id, command, status FROM action_history ORDER BY id DESC;",
		"max_rows": 10,
	}, 5*time.Second)
	if err != nil || resQuery.Status != "ok" {
		t.Fatalf("query_readonly valid SELECT failed: %v (%+v)", err, resQuery)
	}
	if !strings.Contains(resQuery.Output, "ubuntu-os-release") {
		t.Errorf("expected ubuntu-os-release in query_readonly output: %s", resQuery.Output)
	}

	// 4. query_readonly blocks empty SQL, SQL injection, DDL/DML, PRAGMA, comments, and multi-statements
	maliciousQueries := []string{
		"   ",
		"DROP TABLE action_history",
		"DELETE FROM action_history WHERE 1=1",
		"UPDATE action_history SET status='hacked'",
		"INSERT INTO action_history(command, status) VALUES('x','y')",
		"SELECT * FROM action_history; DROP TABLE action_history",
		"SELECT * FROM action_history -- comment",
		"SELECT * FROM action_history /* block comment */",
		"PRAGMA writable_schema = 1",
		"ATTACH DATABASE 'evil.db' AS evil",
	}
	for _, badSQL := range maliciousQueries {
		_, err := reg.Execute(context.Background(), "db-exposure", "query_readonly", map[string]any{"sql": badSQL}, 5*time.Second)
		if !errors.Is(err, ErrForbiddenSQL) {
			t.Errorf("expected ErrForbiddenSQL for %q, got %v", badSQL, err)
		}
	}

	// 5. db_stats and table_sample (valid, invalid table name, unknown table)
	resStats, err := reg.Execute(context.Background(), "db-exposure", "db_stats", nil, 5*time.Second)
	if err != nil || resStats.Status != "ok" {
		t.Fatalf("db_stats failed: %v", err)
	}
	if !strings.Contains(resStats.Output, "total_actions") {
		t.Errorf("expected total_actions in db_stats output: %s", resStats.Output)
	}

	resSample, err := reg.Execute(context.Background(), "db-exposure", "table_sample", map[string]any{"table": "action_history", "limit": 5}, 5*time.Second)
	if err != nil || resSample.Status != "ok" {
		t.Fatalf("table_sample failed: %v", err)
	}
	if _, err := reg.Execute(context.Background(), "db-exposure", "table_sample", map[string]any{"table": "bad;table"}, time.Second); err == nil {
		t.Errorf("expected error for invalid table name in table_sample")
	}
	if _, err := reg.Execute(context.Background(), "db-exposure", "table_sample", map[string]any{"table": "unknown_table"}, time.Second); err == nil {
		t.Errorf("expected error for non-existent table in table_sample")
	}

	// 6. Unknown plugin or unknown action returns appropriate sentinel errors
	if _, err := reg.Execute(context.Background(), "non-existent", "act", nil, time.Second); !errors.Is(err, ErrPluginNotFound) {
		t.Errorf("expected ErrPluginNotFound, got %v", err)
	}
	if _, err := reg.Execute(context.Background(), "db-exposure", "unknown_action", nil, time.Second); !errors.Is(err, ErrActionNotFound) {
		t.Errorf("expected ErrActionNotFound, got %v", err)
	}
	if err := reg.Register(nil); err == nil {
		t.Errorf("expected error registering nil plugin")
	}
	if _, err := NewDeclarativePlugin(DeclarativeModuleSpec{ID: ""}); err == nil {
		t.Errorf("expected error for empty declarative plugin ID")
	}
}

func TestDatabaseExposureSQLiteDriverExecution(t *testing.T) {
	registerPluginSQLOnce.Do(func() {
		sql.Register("plugin_sqlite_mock", &pluginMockDriver{})
	})
	rawSQL, err := sql.Open("plugin_sqlite_mock", "mock.db")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer rawSQL.Close()

	sqlBackedDB := &database.DB{DB: rawSQL}
	p := NewDatabaseExposurePlugin(sqlBackedDB, 50)

	if res, err := p.Execute(context.Background(), "list_tables", nil, time.Second); err != nil || res.Status != "ok" {
		t.Fatalf("SQLite list_tables failed: %v (%+v)", err, res)
	}
	if res, err := p.Execute(context.Background(), "describe_table", map[string]any{"table": "action_history"}, time.Second); err != nil || res.Status != "ok" {
		t.Fatalf("SQLite describe_table failed: %v (%+v)", err, res)
	}
	if _, err := p.Execute(context.Background(), "describe_table", map[string]any{"table": "empty_table"}, time.Second); err == nil {
		t.Errorf("expected error when SQLite PRAGMA table_info returns 0 columns")
	}
	if res, err := p.Execute(context.Background(), "table_sample", map[string]any{"table": "action_history", "limit": 5}, time.Second); err != nil || res.Status != "ok" {
		t.Fatalf("SQLite table_sample failed: %v (%+v)", err, res)
	}
	if res, err := p.Execute(context.Background(), "query_readonly", map[string]any{"sql": "SELECT id, command, status, raw_bytes FROM action_history"}, time.Second); err != nil || res.Status != "ok" {
		t.Fatalf("SQLite query_readonly failed: %v (%+v)", err, res)
	}
}

func TestSystemDiagnosticsPlugin(t *testing.T) {
	p := NewSystemDiagnosticsPlugin()
	for _, action := range []string{
		"runtime_stats", "runtime-stats",
		"network_interfaces", "network-interfaces",
		"env_summary", "env-summary",
	} {
		res, err := p.Execute(context.Background(), action, nil, 5*time.Second)
		if err != nil || res.Status != "ok" {
			t.Errorf("expected %s to succeed, got err=%v res=%+v", action, err, res)
		}
	}
	if _, err := p.Execute(context.Background(), "unknown", nil, time.Second); !errors.Is(err, ErrActionNotFound) {
		t.Errorf("expected ErrActionNotFound for unknown sys-diagnostics action, got %v", err)
	}
}

func TestRecursiveDeclarativeDirectoryLoaderAndCategoryInference(t *testing.T) {
	tmpDir := t.TempDir()

	// Create subdirectories for various domains
	sysadminDir := filepath.Join(tmpDir, "sysadmin")
	netopsDir := filepath.Join(tmpDir, "netops")
	customDir := filepath.Join(tmpDir, "custom_domain")
	for _, d := range []string{sysadminDir, netopsDir, customDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
	}

	// 1. SysAdmin manifest without explicit category (inferred)
	p1YAML := `id: "sys-cpu-probe"
name: "CPU Telemetry Probe"
version: "1.0.0"
actions:
  - name: "check-cpu"
    command: "echo"
    args: ["cpu=ok"]
`
	if err := os.WriteFile(filepath.Join(sysadminDir, "cpu.yaml"), []byte(p1YAML), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 2. NetOps manifest in JSON format without explicit category
	p2JSON := `{
  "id": "net-ping-probe",
  "name": "Network Ping Probe",
  "version": "1.0.0",
  "actions": [
    {
      "name": "ping",
      "command": "echo",
      "args": ["pong"]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(netopsDir, "ping.json"), []byte(p2JSON), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 3. Manifest with explicit category overriding inference
	p3YAML := `id: "custom-explicit"
name: "Explicit Category Plugin"
version: "1.0.0"
category: "CustomExplicitCategory"
actions:
  - name: "run"
    command: "echo"
    args: ["explicit"]
`
	if err := os.WriteFile(filepath.Join(customDir, "explicit.yml"), []byte(p3YAML), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 4. Non-plugin files to verify filtering
	_ = os.WriteFile(filepath.Join(customDir, "notes.txt"), []byte("not a plugin"), 0o644)

	reg := NewEmptyRegistry()
	count, err := reg.LoadDeclarativeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadDeclarativeDirectory failed: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 plugins loaded recursively, got %d", count)
	}

	p1, ok1 := reg.Get("sys-cpu-probe")
	if !ok1 || p1.Category() != "SysAdmin" {
		t.Errorf("expected p1 to have inferred category 'SysAdmin', got ok=%v, category=%s", ok1, p1.Category())
	}
	if p1.Type() != "declarative" {
		t.Errorf("expected type 'declarative', got %s", p1.Type())
	}

	p2, ok2 := reg.Get("net-ping-probe")
	if !ok2 || p2.Category() != "NetOps" {
		t.Errorf("expected p2 to have inferred category 'NetOps', got ok=%v, category=%s", ok2, p2.Category())
	}

	p3, ok3 := reg.Get("custom-explicit")
	if !ok3 || p3.Category() != "CustomExplicitCategory" {
		t.Errorf("expected p3 to retain explicit category 'CustomExplicitCategory', got %s", p3.Category())
	}

	// Test empty dir and non-existent dir
	emptyCount, err := reg.LoadDeclarativeDirectory("")
	if err != nil || emptyCount != 0 {
		t.Errorf("expected 0 for empty dir, got %d, err=%v", emptyCount, err)
	}
	missingCount, err := reg.LoadDeclarativeDirectory(filepath.Join(tmpDir, "does-not-exist"))
	if err != nil || missingCount != 0 {
		t.Errorf("expected 0 for missing dir, got %d, err=%v", missingCount, err)
	}
}

func TestPluginRegistryDuplicateDetectionAndFilters(t *testing.T) {
	reg := NewEmptyRegistry()

	// Nil plugin
	if err := reg.Register(nil); err == nil {
		t.Errorf("expected error registering nil plugin")
	}

	// Empty ID plugin
	emptyIDPlugin := &DeclarativePlugin{spec: DeclarativeModuleSpec{ID: "  "}}
	if err := reg.Register(emptyIDPlugin); err == nil {
		t.Errorf("expected error registering plugin with empty ID")
	}

	// Register initial plugin
	p1 := &DeclarativePlugin{spec: DeclarativeModuleSpec{
		ID:          "probe-alpha",
		Name:        "Alpha Probe",
		Category:    "NetOps",
		Description: "Diagnostic alpha probe for network",
		Actions: []DeclarativeActionSpec{
			{Name: "ping", Command: "echo", Args: []string{"pong"}},
		},
	}}
	if err := reg.Register(p1); err != nil {
		t.Fatalf("expected initial registration to succeed: %v", err)
	}

	// Duplicate registration must fail with ErrDuplicatePlugin
	p1Dup := &DeclarativePlugin{spec: DeclarativeModuleSpec{
		ID:          "probe-alpha",
		Name:        "Duplicate Alpha",
		Category:    "SysAdmin",
		Actions:     []DeclarativeActionSpec{{Name: "run", Command: "echo"}},
	}}
	err := reg.Register(p1Dup)
	if err == nil || !errors.Is(err, ErrDuplicatePlugin) {
		t.Fatalf("expected ErrDuplicatePlugin, got %v", err)
	}

	// RegisterOrReplace allows explicit overwrite
	if err := reg.RegisterOrReplace(p1Dup); err != nil {
		t.Fatalf("expected RegisterOrReplace to succeed: %v", err)
	}
	retrieved, _ := reg.Get("probe-alpha")
	if retrieved.Name() != "Duplicate Alpha" {
		t.Errorf("expected overwritten name, got %s", retrieved.Name())
	}

	// Unregister
	if !reg.Unregister("probe-alpha") {
		t.Errorf("expected Unregister to return true")
	}
	if reg.Unregister("probe-alpha") {
		t.Errorf("expected second Unregister to return false")
	}

	// Populate multiple plugins for filtering tests
	_ = reg.Register(&DeclarativePlugin{spec: DeclarativeModuleSpec{
		ID: "p-net-1", Name: "Net Tracer", Category: "NetOps", Description: "Packet trace",
		Actions: []DeclarativeActionSpec{{Name: "trace", Command: "echo"}},
	}})
	_ = reg.Register(&DeclarativePlugin{spec: DeclarativeModuleSpec{
		ID: "p-sys-1", Name: "Host Audit", Category: "SysAdmin", Description: "System audit",
		Actions: []DeclarativeActionSpec{{Name: "audit", Command: "echo"}},
	}})
	_ = reg.Register(&HostStorageStatsPlugin{})

	// 1. Filter by category
	netPlugins := reg.ListFiltered("NetOps", "", "")
	if len(netPlugins) != 1 || netPlugins[0].ID != "p-net-1" {
		t.Errorf("expected 1 NetOps plugin, got %d", len(netPlugins))
	}

	// 2. Filter by type (declarative vs native)
	nativePlugins := reg.ListFiltered("", "", "native")
	if len(nativePlugins) != 1 || nativePlugins[0].ID != "host-storage-stats" {
		t.Errorf("expected 1 native plugin, got %d", len(nativePlugins))
	}
	decPlugins := reg.ListFiltered("", "", "declarative")
	if len(decPlugins) != 2 {
		t.Errorf("expected 2 declarative plugins, got %d", len(decPlugins))
	}

	// 3. Filter by query
	queryPlugins := reg.ListFiltered("", "Storage", "")
	if len(queryPlugins) != 1 || queryPlugins[0].ID != "host-storage-stats" {
		t.Errorf("expected 1 plugin matching 'Storage', got %d", len(queryPlugins))
	}

	// 4. Combined filter
	combined := reg.ListFiltered("SysAdmin", "audit", "declarative")
	if len(combined) != 1 || combined[0].ID != "p-sys-1" {
		t.Errorf("expected 1 combined match, got %d", len(combined))
	}
}

func TestDefaultRegistryAll24NativePlugins(t *testing.T) {
	reg := NewRegistry()
	pluginsList := reg.List()

	if len(pluginsList) < 24 {
		t.Fatalf("expected at least 24 native plugins registered by default, got %d", len(pluginsList))
	}

	seenIDs := make(map[string]bool)
	seenCategories := make(map[string]bool)

	expectedDomains := []string{
		"SysAdmin",
		"NetOps",
		"SecOps",
		"ContainerOps",
		"Kubernetes",
		"DataOps",
		"DevOps",
		"SRE",
		"AIOps",
		"Web & Crypto Utilities",
	}

	for _, p := range pluginsList {
		if seenIDs[p.ID] {
			t.Errorf("duplicate plugin ID detected: %s", p.ID)
		}
		seenIDs[p.ID] = true
		seenCategories[p.Category] = true

		if p.Type != "native" {
			t.Errorf("plugin %s has type %q, expected 'native'", p.ID, p.Type)
		}
		if p.Name == "" || p.Version == "" || p.Description == "" {
			t.Errorf("plugin %s has empty metadata: %+v", p.ID, p)
		}
		if len(p.Actions) == 0 {
			t.Errorf("plugin %s defines 0 actions", p.ID)
		}
	}

	for _, domain := range expectedDomains {
		if !seenCategories[domain] {
			t.Errorf("expected domain %q to have at least one registered native plugin", domain)
		}
	}
}

func TestNativePluginsExecutionAllDomains(t *testing.T) {
	ctx := context.Background()
	reg := NewRegistry()

	// 1. HostStorageStatsPlugin
	res, err := reg.Execute(ctx, "host-storage-stats", "disk_usage", map[string]any{"path": "."}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("host-storage-stats disk_usage failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "host-storage-stats", "mount_points", nil, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("host-storage-stats mount_points failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "host-storage-stats", "dir_summary", map[string]any{"path": ".", "top_n": 3, "max_depth": 2}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("host-storage-stats dir_summary failed: %v (%+v)", err, res)
	}

	// 2. ProcessTreeAnalyzerPlugin
	res, err = reg.Execute(ctx, "process-tree-analyzer", "process_list", map[string]any{"limit": 5}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("process-tree-analyzer process_list failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "process-tree-analyzer", "process_info", map[string]any{"pid": os.Getpid()}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("process-tree-analyzer process_info failed: %v (%+v)", err, res)
	}

	// 3. TCPUDPPortProbePlugin (using loopback/mock addresses)
	res, _ = reg.Execute(ctx, "tcp-udp-port-probe", "tcp_ping", map[string]any{"host": "127.0.0.1", "port": 65534, "timeout_ms": 100}, time.Second)
	if res.PluginID != "tcp-udp-port-probe" {
		t.Errorf("unexpected pluginID: %s", res.PluginID)
	}
	res, _ = reg.Execute(ctx, "tcp-udp-port-probe", "port_scan", map[string]any{"host": "127.0.0.1", "ports": "80,443", "timeout_ms": 50}, time.Second)
	if res.Status != "ok" {
		t.Errorf("tcp-udp-port-probe port_scan failed: %+v", res)
	}

	// 4. DNSResolverAuditPlugin
	res, _ = reg.Execute(ctx, "dns-resolver-audit", "lookup_records", map[string]any{"domain": "localhost"}, 5*time.Second)
	if res.Status != "ok" {
		t.Errorf("dns-resolver-audit lookup_records failed: %+v", res)
	}
	res, _ = reg.Execute(ctx, "dns-resolver-audit", "reverse_lookup", map[string]any{"ip": "127.0.0.1"}, 5*time.Second)
	if res.Status != "ok" {
		t.Errorf("dns-resolver-audit reverse_lookup failed: %+v", res)
	}

	// 5. FileIntegrityCheckerPlugin
	tmpFile := filepath.Join(t.TempDir(), "integrity_sample.txt")
	_ = os.WriteFile(tmpFile, []byte("hello integrity check 2026"), 0o644)
	res, err = reg.Execute(ctx, "file-integrity-checker", "file_checksums", map[string]any{"path": tmpFile}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("file-integrity-checker file_checksums failed: %v (%+v)", err, res)
	}
	dataMap, _ := res.Data.(map[string]any)
	sha := dataMap["sha256"].(string)

	res, err = reg.Execute(ctx, "file-integrity-checker", "verify_manifest", map[string]any{"path": tmpFile, "expected_hash": sha, "algorithm": "sha256"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("file-integrity-checker verify_manifest failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "file-integrity-checker", "dir_hash_audit", map[string]any{"path": filepath.Dir(tmpFile)}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("file-integrity-checker dir_hash_audit failed: %v (%+v)", err, res)
	}

	// 6. PasswordPolicyAuditPlugin
	res, err = reg.Execute(ctx, "password-policy-audit", "evaluate_entropy", map[string]any{"password": "CorrectHorseBatteryStaple123!"}, time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("password-policy-audit evaluate_entropy failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "password-policy-audit", "nist_compliance", map[string]any{"password": "CorrectHorseBatteryStaple123!"}, time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("password-policy-audit nist_compliance failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "password-policy-audit", "character_dist", map[string]any{"password": "Abc123$#@"}, time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("password-policy-audit character_dist failed: %v (%+v)", err, res)
	}

	// 7. DockerSocketClientPlugin
	res, err = reg.Execute(ctx, "docker-socket-client", "ping_engine", nil, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("docker-socket-client ping_engine failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "docker-socket-client", "container_stats", map[string]any{"container_id": "c-123"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("docker-socket-client container_stats failed: %v (%+v)", err, res)
	}

	// 8. ContainerSpecValidatorPlugin
	dfContent := `FROM alpine:3.19
HEALTHCHECK CMD ping localhost
USER 1000
CMD ["echo", "ready"]
`
	res, err = reg.Execute(ctx, "container-spec-validator", "lint_dockerfile", map[string]any{"content": dfContent}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("container-spec-validator lint_dockerfile failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "container-spec-validator", "check_privileges", map[string]any{"spec_json": `{"securityContext": {"privileged": false}}`}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("container-spec-validator check_privileges failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "container-spec-validator", "verify_rootless", map[string]any{"user": "appuser"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("container-spec-validator verify_rootless failed: %v (%+v)", err, res)
	}

	// 9. K8sManifestLinterPlugin
	k8sYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-executor-deploy
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: app
          image: api-executor:latest
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
            requests:
              cpu: "100m"
              memory: "64Mi"
`
	res, err = reg.Execute(ctx, "k8s-manifest-linter", "lint_manifest", map[string]any{"manifest_yaml": k8sYAML}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("k8s-manifest-linter lint_manifest failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "k8s-manifest-linter", "check_api_versions", map[string]any{"manifest_yaml": k8sYAML}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("k8s-manifest-linter check_api_versions failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "k8s-manifest-linter", "validate_limits", map[string]any{"manifest_yaml": k8sYAML}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("k8s-manifest-linter validate_limits failed: %v (%+v)", err, res)
	}

	// 10. HelmChartInspectorPlugin
	chartYAML := `apiVersion: v2
name: api-executor
version: 1.2.3
appVersion: "2.0.0"
`
	res, err = reg.Execute(ctx, "helm-chart-inspector", "inspect_chart", map[string]any{"chart_yaml": chartYAML}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("helm-chart-inspector inspect_chart failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "helm-chart-inspector", "validate_values", map[string]any{"values_yaml": "replicaCount: 3\nimage: app:v1\nresources: {}\n"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("helm-chart-inspector validate_values failed: %v (%+v)", err, res)
	}

	// 11. SQLiteSchemaAnalyzerPlugin
	res, err = reg.Execute(ctx, "sqlite-schema-analyzer", "page_analysis", map[string]any{"db_path": "non_existent.db"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("sqlite-schema-analyzer page_analysis failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "sqlite-schema-analyzer", "integrity_check", map[string]any{"db_path": "non_existent.db"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("sqlite-schema-analyzer integrity_check failed: %v (%+v)", err, res)
	}

	// 12. RedisProtocolProbePlugin
	res, _ = reg.Execute(ctx, "redis-protocol-probe", "redis_ping", map[string]any{"host": "127.0.0.1", "port": 65533}, time.Second)
	if res.PluginID != "redis-protocol-probe" {
		t.Errorf("unexpected pluginID: %s", res.PluginID)
	}

	// 13. GitRepoInspectorPlugin
	res, err = reg.Execute(ctx, "git-repo-inspector", "repo_status", map[string]any{"repo_path": "."}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("git-repo-inspector repo_status failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "git-repo-inspector", "commit_history", map[string]any{"repo_path": ".", "limit": 3}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("git-repo-inspector commit_history failed: %v (%+v)", err, res)
	}

	// 14. SemverReleaseCheckerPlugin
	res, err = reg.Execute(ctx, "semver-release-checker", "validate_semver", map[string]any{"version": "v1.2.3-beta.1"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("semver-release-checker validate_semver failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "semver-release-checker", "compare_versions", map[string]any{"version_a": "1.2.4", "version_b": "1.2.3"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("semver-release-checker compare_versions failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "semver-release-checker", "next_version", map[string]any{"version": "1.2.3", "bump": "minor"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("semver-release-checker next_version failed: %v (%+v)", err, res)
	}

	// 15. PrometheusScraperPlugin
	promText := `# HELP test_metric A test gauge
# TYPE test_metric gauge
test_metric{env="prod"} 42.5
`
	res, err = reg.Execute(ctx, "prometheus-scraper", "scrape_metrics", map[string]any{"content": promText}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("prometheus-scraper scrape_metrics failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "prometheus-scraper", "find_metric", map[string]any{"content": promText, "metric_name": "test_metric"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("prometheus-scraper find_metric failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "prometheus-scraper", "cardinality_check", map[string]any{"content": promText}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("prometheus-scraper cardinality_check failed: %v (%+v)", err, res)
	}

	// 16. LogRegexAnalyzerPlugin
	logStream := `2026-10-26T12:00:00Z INFO Server started on port 8080
2026-10-26T12:01:00Z WARN High memory usage: 85%
2026-10-26T12:02:00Z ERROR Connection refused to db
`
	res, err = reg.Execute(ctx, "log-regex-analyzer", "parse_stream", map[string]any{"log_content": logStream}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("log-regex-analyzer parse_stream failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "log-regex-analyzer", "aggregate_levels", map[string]any{"log_content": logStream}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("log-regex-analyzer aggregate_levels failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "log-regex-analyzer", "match_pattern", map[string]any{"log_content": logStream, "pattern": "ERROR.*"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("log-regex-analyzer match_pattern failed: %v (%+v)", err, res)
	}

	// 17. MCPEndpointTesterPlugin
	res, _ = reg.Execute(ctx, "mcp-endpoint-tester", "ping_mcp", map[string]any{"endpoint": "http://127.0.0.1:65532/mcp"}, time.Second)
	if res.PluginID != "mcp-endpoint-tester" {
		t.Errorf("unexpected pluginID: %s", res.PluginID)
	}

	// 18. ModelArtifactVerifierPlugin
	res, err = reg.Execute(ctx, "model-artifact-verifier", "verify_checksum", map[string]any{"path": tmpFile}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("model-artifact-verifier verify_checksum failed: %v (%+v)", err, res)
	}

	// 19. CryptoHashUtilityPlugin
	res, err = reg.Execute(ctx, "crypto-hash-utility", "hash_string", map[string]any{"input": "api-executor-2026", "algorithm": "all"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("crypto-hash-utility hash_string failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "crypto-hash-utility", "verify_hmac", map[string]any{"input": "api-executor-2026", "key": "secret"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("crypto-hash-utility verify_hmac failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "crypto-hash-utility", "detect_algorithm", map[string]any{"hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("crypto-hash-utility detect_algorithm failed: %v (%+v)", err, res)
	}

	// 20. JWTTokenInspectorPlugin
	// Example valid unencrypted JWT (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5OTk5OTk5OTl9.signature)
	sampleJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5OTk5OTk5OTl9.4S8884_f-H"
	res, err = reg.Execute(ctx, "jwt-token-inspector", "inspect_header", map[string]any{"token": sampleJWT}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("jwt-token-inspector inspect_header failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "jwt-token-inspector", "decode_claims", map[string]any{"token": sampleJWT}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("jwt-token-inspector decode_claims failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "jwt-token-inspector", "verify_validity", map[string]any{"token": sampleJWT}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("jwt-token-inspector verify_validity failed: %v (%+v)", err, res)
	}
}

func TestPluginHelpersAndEdgeCases(t *testing.T) {
	// Test getStringParam
	p := map[string]any{
		"str":  "  hello  ",
		"num":  123,
		"bool": true,
	}
	if v := getStringParam(p, "str", "def"); v != "hello" {
		t.Errorf("expected 'hello', got %q", v)
	}
	if v := getStringParam(p, "missing", "def"); v != "def" {
		t.Errorf("expected 'def', got %q", v)
	}
	if v := getStringParam(nil, "str", "def"); v != "def" {
		t.Errorf("expected 'def', got %q", v)
	}

	// Test getIntParam
	params := map[string]any{
		"int":    42,
		"int64":  int64(84),
		"float":  float64(126),
		"strInt": " 168 ",
		"badStr": "notAnInt",
	}
	if v := getIntParam(params, "int", 0); v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
	if v := getIntParam(params, "int64", 0); v != 84 {
		t.Errorf("expected 84, got %d", v)
	}
	if v := getIntParam(params, "float", 0); v != 126 {
		t.Errorf("expected 126, got %d", v)
	}
	if v := getIntParam(params, "strInt", 0); v != 168 {
		t.Errorf("expected 168, got %d", v)
	}
	if v := getIntParam(params, "badStr", 99); v != 99 {
		t.Errorf("expected 99, got %d", v)
	}
	if v := getIntParam(nil, "missing", 5); v != 5 {
		t.Errorf("expected 5, got %d", v)
	}

	// Test getBoolParam
	boolParams := map[string]any{
		"bTrue":    true,
		"bFalse":   false,
		"sTrue":    "TRUE",
		"sFalse":   "FALSE",
		"s1":       "1",
		"s0":       "0",
		"sYes":     "yes",
		"sNo":      "no",
		"f1":       float64(1),
		"f0":       float64(0),
		"i1":       1,
		"i0":       0,
	}
	for _, k := range []string{"bTrue", "sTrue", "s1", "sYes", "f1", "i1"} {
		if !getBoolParam(boolParams, k, false) {
			t.Errorf("expected true for %s", k)
		}
	}
	for _, k := range []string{"bFalse", "sFalse", "s0", "sNo", "f0", "i0"} {
		if getBoolParam(boolParams, k, true) {
			t.Errorf("expected false for %s", k)
		}
	}
	if !getBoolParam(nil, "missing", true) {
		t.Errorf("expected default true")
	}

	// Test formatJSON
	jsonStr := formatJSON(map[string]string{"foo": "bar"})
	if !strings.Contains(jsonStr, `"foo": "bar"`) {
		t.Errorf("unexpected formatJSON output: %s", jsonStr)
	}
}

func TestNativePluginsDeepExecutionAndEdgeCases(t *testing.T) {
	ctx := context.Background()
	reg := NewRegistry()

	// 1. Live TLS Server for TLSCertInspectorPlugin and HTTPLatencyProbePlugin
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// tls-cert-inspector
	res, err := reg.Execute(ctx, "tls-cert-inspector", "inspect_cert", map[string]any{"host": host, "port": port}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("tls-cert-inspector inspect_cert failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "tls-cert-inspector", "check_expiration", map[string]any{"host": host, "port": port}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("tls-cert-inspector check_expiration failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "tls-cert-inspector", "verify_sans", map[string]any{"host": host, "port": port, "hostname": "example.com"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("tls-cert-inspector verify_sans failed: %v (%+v)", err, res)
	}

	// http-latency-probe
	res, err = reg.Execute(ctx, "http-latency-probe", "probe_endpoint", map[string]any{"url": ts.URL}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("http-latency-probe probe_endpoint failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "http-latency-probe", "inspect_headers", map[string]any{"url": ts.URL}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("http-latency-probe inspect_headers failed: %v (%+v)", err, res)
	}
	redirectTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/login")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer redirectTS.Close()

	res, err = reg.Execute(ctx, "http-latency-probe", "ssl_redirect_check", map[string]any{"url": redirectTS.URL}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("http-latency-probe ssl_redirect_check failed: %v (%+v)", err, res)
	}

	// 2. Mock MCP Server for MCPEndpointTesterPlugin
	mcpTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)

		switch method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": body["id"],
				"result": map[string]any{"protocolVersion": "2024-11-05"},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": body["id"],
				"result": map[string]any{"tools": []string{"tool1", "tool2"}},
			})
		case "resources/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": body["id"],
				"result": map[string]any{"resources": []string{"res1"}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mcpTS.Close()

	res, err = reg.Execute(ctx, "mcp-endpoint-tester", "ping_mcp", map[string]any{"endpoint": mcpTS.URL}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("mcp-endpoint-tester ping_mcp failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "mcp-endpoint-tester", "list_tools", map[string]any{"endpoint": mcpTS.URL}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("mcp-endpoint-tester list_tools failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "mcp-endpoint-tester", "list_resources", map[string]any{"endpoint": mcpTS.URL}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("mcp-endpoint-tester list_resources failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "mcp-endpoint-tester", "benchmark_call", map[string]any{"endpoint": mcpTS.URL}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("mcp-endpoint-tester benchmark_call failed: %v (%+v)", err, res)
	}

	// 3. ModelArtifactVerifierPlugin (SafeTensors & GGUF)
	tmpDir := t.TempDir()
	stFile := filepath.Join(tmpDir, "model.safetensors")
	stJSON := `{"weight": {"dtype": "F32", "shape": [10, 10]}}`
	var stBuf []byte
	lenBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBuf, uint64(len(stJSON)))
	stBuf = append(stBuf, lenBuf...)
	stBuf = append(stBuf, []byte(stJSON)...)
	_ = os.WriteFile(stFile, stBuf, 0o644)

	res, err = reg.Execute(ctx, "model-artifact-verifier", "inspect_safetensors", map[string]any{"path": stFile}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("model-artifact-verifier inspect_safetensors failed: %v (%+v)", err, res)
	}

	ggufFile := filepath.Join(tmpDir, "model.gguf")
	var ggufBuf []byte
	ggufBuf = append(ggufBuf, []byte("GGUF")...)
	verBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(verBuf, 2)
	ggufBuf = append(ggufBuf, verBuf...)
	cntBuf := make([]byte, 16)
	binary.LittleEndian.PutUint64(cntBuf[:8], 128)
	binary.LittleEndian.PutUint64(cntBuf[8:], 16)
	ggufBuf = append(ggufBuf, cntBuf...)
	_ = os.WriteFile(ggufFile, ggufBuf, 0o644)

	res, err = reg.Execute(ctx, "model-artifact-verifier", "inspect_gguf", map[string]any{"path": ggufFile}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("model-artifact-verifier inspect_gguf failed: %v (%+v)", err, res)
	}

	// 4. SQLiteSchemaAnalyzerPlugin
	sqliteFile := filepath.Join(tmpDir, "test_schema.db")
	header := make([]byte, 100)
	copy(header[:16], "SQLite format 3\x00")
	binary.BigEndian.PutUint16(header[16:18], 4096) // page size 4096
	header[18] = 1                                  // write version
	header[19] = 1                                  // read version
	binary.BigEndian.PutUint32(header[28:32], 10)   // page count 10
	_ = os.WriteFile(sqliteFile, header, 0o644)

	res, err = reg.Execute(ctx, "sqlite-schema-analyzer", "integrity_check", map[string]any{"db_path": sqliteFile}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("sqlite-schema-analyzer integrity_check failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "sqlite-schema-analyzer", "page_analysis", map[string]any{"db_path": sqliteFile}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("sqlite-schema-analyzer page_analysis failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "sqlite-schema-analyzer", "analyze_indexes", map[string]any{"db_path": sqliteFile}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("sqlite-schema-analyzer analyze_indexes failed: %v (%+v)", err, res)
	}

	// 5. TCP & UDP listeners for TCPUDPPortProbePlugin
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		defer tcpLn.Close()
		go func() {
			for {
				conn, err := tcpLn.Accept()
				if err != nil {
					return
				}
				_, _ = conn.Write([]byte("220 Ready Banner\r\n"))
				_ = conn.Close()
			}
		}()

		tHost, tPortStr, _ := net.SplitHostPort(tcpLn.Addr().String())
		tPort, _ := strconv.Atoi(tPortStr)

		res, err = reg.Execute(ctx, "tcp-udp-port-probe", "tcp_ping", map[string]any{"host": tHost, "port": tPort, "timeout_ms": 1000}, 5*time.Second)
		if err != nil || res.Status != "ok" {
			t.Errorf("tcp-udp-port-probe tcp_ping failed: %v (%+v)", err, res)
		}
		res, err = reg.Execute(ctx, "tcp-udp-port-probe", "tcp_banner", map[string]any{"host": tHost, "port": tPort, "timeout_ms": 1000}, 5*time.Second)
		if err != nil || res.Status != "ok" {
			t.Errorf("tcp-udp-port-probe tcp_banner failed: %v (%+v)", err, res)
		}
	}

	udpLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err == nil {
		defer udpLn.Close()
		uHost, uPortStr, _ := net.SplitHostPort(udpLn.LocalAddr().String())
		uPort, _ := strconv.Atoi(uPortStr)
		res, err = reg.Execute(ctx, "tcp-udp-port-probe", "udp_ping", map[string]any{"host": uHost, "port": uPort}, 5*time.Second)
		if err != nil || res.Status != "ok" {
			t.Errorf("tcp-udp-port-probe udp_ping failed: %v (%+v)", err, res)
		}
	}

	// 6. Mock Docker Engine HTTP Server
	dockerTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/_ping" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1.43/containers/json") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"Id": "c1", "Names": ["/test-container"]}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer dockerTS.Close()

	res, err = reg.Execute(ctx, "docker-socket-client", "ping_engine", map[string]any{"socket_path": dockerTS.URL}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("docker-socket-client ping_engine failed: %v (%+v)", err, res)
	}
	res, err = reg.Execute(ctx, "docker-socket-client", "list_containers", map[string]any{"socket_path": dockerTS.URL}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Errorf("docker-socket-client list_containers failed: %v (%+v)", err, res)
	}

	// 7. Mock Redis Server for RedisProtocolProbePlugin
	redisLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		defer redisLn.Close()
		go func() {
			for {
				conn, err := redisLn.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					buf := make([]byte, 1024)
					for {
						n, err := c.Read(buf)
						if err != nil {
							return
						}
						req := string(buf[:n])
						if strings.Contains(req, "PING") {
							_, _ = c.Write([]byte("+PONG\r\n"))
						} else if strings.Contains(req, "INFO") {
							infoPayload := "# Server\r\nredis_version:7.2.4\r\nuptime_in_seconds:3600\r\nused_memory_human:10M\r\n"
							_, _ = fmt.Fprintf(c, "$%d\r\n%s\r\n", len(infoPayload), infoPayload)
						} else if strings.Contains(req, "TYPE") {
							_, _ = c.Write([]byte("+string\r\n"))
						} else {
							_, _ = c.Write([]byte("-ERR unknown\r\n"))
						}
					}
				}(conn)
			}
		}()

		rHost, rPortStr, _ := net.SplitHostPort(redisLn.Addr().String())
		rPort, _ := strconv.Atoi(rPortStr)

		res, err = reg.Execute(ctx, "redis-protocol-probe", "redis_ping", map[string]any{"host": rHost, "port": rPort}, 5*time.Second)
		if err != nil || res.Status != "ok" {
			t.Errorf("redis-protocol-probe redis_ping failed: %v (%+v)", err, res)
		}
		res, err = reg.Execute(ctx, "redis-protocol-probe", "redis_info", map[string]any{"host": rHost, "port": rPort}, 5*time.Second)
		if err != nil || res.Status != "ok" {
			t.Errorf("redis-protocol-probe redis_info failed: %v (%+v)", err, res)
		}
		res, err = reg.Execute(ctx, "redis-protocol-probe", "redis_key_type", map[string]any{"host": rHost, "port": rPort, "key": "session:user"}, 5*time.Second)
		if err != nil || res.Status != "ok" {
			t.Errorf("redis-protocol-probe redis_key_type failed: %v (%+v)", err, res)
		}
	}
}
