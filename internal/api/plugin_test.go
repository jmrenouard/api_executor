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

	// 6. POST /api/v1/db/query with empty SQL defaults to table_sample
	sampleBody, _ := json.Marshal(map[string]any{"table": "action_history", "max_rows": 5})
	reqSample := httptest.NewRequest(http.MethodPost, "/api/v1/db/query", bytes.NewReader(sampleBody))
	recSample := httptest.NewRecorder()
	router.ServeHTTP(recSample, reqSample)
	if recSample.Code != http.StatusOK {
		t.Errorf("expected 200 for default table_sample in /api/v1/db/query, got %d", recSample.Code)
	}

	// 7. Error cases on /api/v1/plugins/execute (missing fields, bad timeout, unknown plugin)
	for _, tc := range []struct {
		body map[string]any
		code int
	}{
		{map[string]any{"plugin_id": ""}, http.StatusBadRequest},
		{map[string]any{"plugin_id": "ops-quick-tools", "action": "probe-target", "timeout": "bad"}, http.StatusBadRequest},
		{map[string]any{"plugin_id": "unknown-plugin", "action": "act"}, http.StatusNotFound},
		{map[string]any{"plugin_id": "db-exposure", "action": "query_readonly", "params": map[string]any{"sql": "DROP TABLE x"}}, http.StatusForbidden},
	} {
		b, _ := json.Marshal(tc.body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/execute", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Errorf("expected %d for body %v, got %d: %s", tc.code, tc.body, rec.Code, rec.Body.String())
		}
	}

	// 8. Fallback resolveDBExposurePlugin when PluginRegistry is nil, and 503 when both Registry and DB are nil
	fallbackEnv := &APIEnv{Config: cfg, DB: db}
	fallbackRouter := NewRouter(fallbackEnv)
	reqFbTables := httptest.NewRequest(http.MethodGet, "/api/v1/db/tables", nil)
	recFbTables := httptest.NewRecorder()
	fallbackRouter.ServeHTTP(recFbTables, reqFbTables)
	if recFbTables.Code != http.StatusOK {
		t.Errorf("expected 200 from fallback DBTablesHandler, got %d", recFbTables.Code)
	}

	emptyEnv := &APIEnv{Config: cfg}
	emptyRouter := NewRouter(emptyEnv)
	for _, tc := range []struct {
		method string
		path   string
		code   int
	}{
		{http.MethodGet, "/api/v1/plugins", http.StatusOK},
		{http.MethodPost, "/api/v1/plugins", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/plugins/execute", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/v1/plugins/execute", http.StatusServiceUnavailable},
		{http.MethodGet, "/api/v1/plugins/declarative", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/v1/plugins/declarative", http.StatusServiceUnavailable},
		{http.MethodPost, "/api/v1/db/tables", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/db/tables", http.StatusServiceUnavailable},
		{http.MethodGet, "/api/v1/db/query", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/v1/db/query", http.StatusServiceUnavailable},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		emptyRouter.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Errorf("expected %d for %s %s on emptyEnv, got %d", tc.code, tc.method, tc.path, rec.Code)
		}
	}
}

