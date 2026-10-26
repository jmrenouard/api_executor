package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/plugins"
)

func TestPluginEndpointsDeclarativeRegistrationAndReadOnlyDBExposure(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false

	db, err := database.NewDB(filepath.Join(t.TempDir(), "plugin_api_test.db"))
	if err != nil {
		t.Fatalf("failed to create DB: %v", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init failed: %v", err)
	}
	_, _ = db.RecordAction("ubuntu-os-release", "success", "Ubuntu 24.04 LTS")

	reg := plugins.NewRegistry()
	if ops, err := plugins.DefaultDeclarativeOpsPlugin(); err == nil {
		_ = reg.Register(ops)
	}
	_ = reg.Register(plugins.NewDatabaseExposurePlugin(db, 100))
	_ = reg.Register(plugins.NewSystemDiagnosticsPlugin())

	env := &APIEnv{
		Config:         cfg,
		DB:             db,
		PluginRegistry: reg,
	}
	router := NewRouter(env)

	// 1. GET /api/v1/plugins lists registered modules
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	recList := httptest.NewRecorder()
	router.ServeHTTP(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/plugins, got %d", recList.Code)
	}
	var listResp struct {
		Plugins []plugins.PluginInfo `json:"plugins"`
	}
	if err := json.Unmarshal(recList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode /api/v1/plugins response: %v", err)
	}
	if len(listResp.Plugins) < 3 {
		t.Fatalf("expected at least 3 plugins registered, got %d", len(listResp.Plugins))
	}

	// 2. POST /api/v1/plugins/execute on declarative plugin
	execBody, _ := json.Marshal(map[string]any{
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
		"params":    map[string]any{"target": "node01.prod.local"},
		"timeout":   "5s",
	})
	reqExec := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/execute", bytes.NewReader(execBody))
	recExec := httptest.NewRecorder()
	router.ServeHTTP(recExec, reqExec)
	if recExec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/plugins/execute, got %d: %s", recExec.Code, recExec.Body.String())
	}
	if !strings.Contains(recExec.Body.String(), "node01.prod.local") {
		t.Errorf("expected probe-target output to include node01.prod.local, got %s", recExec.Body.String())
	}

	// 3. POST /api/v1/plugins/declarative registers a new declarative command module
	declBody, _ := json.Marshal(map[string]any{
		"id":          "runtime-decl-mod",
		"name":        "Runtime Declarative Module",
		"version":     "1.0.0",
		"description": "Dynamically registered declarative module",
		"actions": []map[string]any{
			{
				"name":        "check-user",
				"description": "Display current OS user",
				"command":     "whoami",
				"timeout":     "5s",
			},
		},
	})
	reqDecl := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/declarative", bytes.NewReader(declBody))
	recDecl := httptest.NewRecorder()
	router.ServeHTTP(recDecl, reqDecl)
	if recDecl.Code != http.StatusCreated {
		t.Fatalf("expected 201 from /api/v1/plugins/declarative, got %d: %s", recDecl.Code, recDecl.Body.String())
	}

	// 4. GET /api/v1/db/tables returns tables and stats
	reqTables := httptest.NewRequest(http.MethodGet, "/api/v1/db/tables", nil)
	recTables := httptest.NewRecorder()
	router.ServeHTTP(recTables, reqTables)
	if recTables.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/db/tables, got %d: %s", recTables.Code, recTables.Body.String())
	}
	if !strings.Contains(recTables.Body.String(), "action_history") {
		t.Errorf("expected action_history in /api/v1/db/tables response: %s", recTables.Body.String())
	}

	// 5. POST /api/v1/db/query executes valid SELECT and blocks DROP TABLE with 403
	validQueryBody, _ := json.Marshal(map[string]any{
		"sql":      "SELECT id, command, status FROM action_history",
		"max_rows": 10,
	})
	reqValidQuery := httptest.NewRequest(http.MethodPost, "/api/v1/db/query", bytes.NewReader(validQueryBody))
	recValidQuery := httptest.NewRecorder()
	router.ServeHTTP(recValidQuery, reqValidQuery)
	if recValidQuery.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid read-only SQL query, got %d: %s", recValidQuery.Code, recValidQuery.Body.String())
	}

	badQueryBody, _ := json.Marshal(map[string]any{
		"sql": "DROP TABLE action_history",
	})
	reqBadQuery := httptest.NewRequest(http.MethodPost, "/api/v1/db/query", bytes.NewReader(badQueryBody))
	recBadQuery := httptest.NewRecorder()
	router.ServeHTTP(recBadQuery, reqBadQuery)
	if recBadQuery.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for DROP TABLE query, got %d: %s", recBadQuery.Code, recBadQuery.Body.String())
	}
}
