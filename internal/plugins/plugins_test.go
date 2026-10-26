package plugins

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/database"
)

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

	// 2. Shell injection attempt in parameter is rejected before execution
	_, err = reg.Execute(context.Background(), "ops-quick-tools", "probe-target", map[string]any{
		"target": "localhost; rm -rf /",
	}, 5*time.Second)
	if err == nil {
		t.Errorf("expected shell injection attempt in declarative plugin parameter to be rejected")
	}

	// 3. Load declarative YAML module from directory
	tmpDir := t.TempDir()
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
	loaded, err := reg.LoadDeclarativeDirectory(tmpDir)
	if err != nil || loaded != 1 {
		t.Fatalf("expected 1 declarative plugin loaded from directory, got %d (err=%v)", loaded, err)
	}
	if _, ok := reg.Get("custom-yaml-module"); !ok {
		t.Errorf("expected custom-yaml-module to be registered")
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

	dbPlugin := NewDatabaseExposurePlugin(db, 100)
	reg := NewRegistry()
	_ = reg.Register(dbPlugin)

	// 1. list_tables
	resTables, err := reg.Execute(context.Background(), "db-exposure", "list_tables", nil, 5*time.Second)
	if err != nil || resTables.Status != "ok" {
		t.Fatalf("list_tables failed: %v (%+v)", err, resTables)
	}
	if !strings.Contains(resTables.Output, "action_history") {
		t.Errorf("expected action_history in list_tables output: %s", resTables.Output)
	}

	// 2. describe_table
	resDesc, err := reg.Execute(context.Background(), "db-exposure", "describe_table", map[string]any{"table": "action_history"}, 5*time.Second)
	if err != nil || resDesc.Status != "ok" {
		t.Fatalf("describe_table failed: %v", err)
	}
	if !strings.Contains(resDesc.Output, "command") {
		t.Errorf("expected column 'command' in describe_table output: %s", resDesc.Output)
	}

	// 3. query_readonly valid SELECT
	resQuery, err := reg.Execute(context.Background(), "db-exposure", "query_readonly", map[string]any{
		"sql": "SELECT id, command, status FROM action_history ORDER BY id DESC",
	}, 5*time.Second)
	if err != nil || resQuery.Status != "ok" {
		t.Fatalf("query_readonly valid SELECT failed: %v (%+v)", err, resQuery)
	}
	if !strings.Contains(resQuery.Output, "ubuntu-os-release") {
		t.Errorf("expected ubuntu-os-release in query_readonly output: %s", resQuery.Output)
	}

	// 4. query_readonly blocks SQL injection, DDL/DML, PRAGMA, comments, and multi-statements
	maliciousQueries := []string{
		"DROP TABLE action_history",
		"DELETE FROM action_history WHERE 1=1",
		"UPDATE action_history SET status='hacked'",
		"INSERT INTO action_history(command, status) VALUES('x','y')",
		"SELECT * FROM action_history; DROP TABLE action_history",
		"SELECT * FROM action_history -- comment",
		"PRAGMA writable_schema = 1",
		"ATTACH DATABASE 'evil.db' AS evil",
	}
	for _, badSQL := range maliciousQueries {
		_, err := reg.Execute(context.Background(), "db-exposure", "query_readonly", map[string]any{"sql": badSQL}, 5*time.Second)
		if !errors.Is(err, ErrForbiddenSQL) {
			t.Errorf("expected ErrForbiddenSQL for %q, got %v", badSQL, err)
		}
	}

	// 5. db_stats and table_sample
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


