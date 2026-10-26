package plugins

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"path/filepath"
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
	reg := NewRegistry()
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
