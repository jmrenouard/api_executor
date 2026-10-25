package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-admin-tool/internal/core"
)

func TestPresetsEndpointsListAndActivate(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Executor.Enabled = true
	cfg.Executor.Commands = []core.CommandDefinition{
		{Name: "custom-cmd", Command: "echo", Args: []string{"ok"}},
	}

	env := &APIEnv{Config: cfg}
	router := NewRouter(env)

	// 1. GET /api/v1/presets
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/presets", nil)
	recList := httptest.NewRecorder()
	router.ServeHTTP(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/presets, got %d", recList.Code)
	}
	var listResp struct {
		DetectedOSFamily string                 `json:"detected_os_family"`
		Catalogs         []core.OSPresetCatalog `json:"catalogs"`
	}
	if err := json.Unmarshal(recList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode presets response: %v", err)
	}
	if len(listResp.Catalogs) < 2 {
		t.Fatalf("expected at least 2 OS preset catalogs (ubuntu, redhat), got %d", len(listResp.Catalogs))
	}

	// 2. POST /api/v1/presets/activate
	body, _ := json.Marshal(map[string]any{"families": []string{"ubuntu", "redhat"}})
	reqAct := httptest.NewRequest(http.MethodPost, "/api/v1/presets/activate", bytes.NewReader(body))
	recAct := httptest.NewRecorder()
	router.ServeHTTP(recAct, reqAct)
	if recAct.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/presets/activate, got %d: %s", recAct.Code, recAct.Body.String())
	}
	var actResp struct {
		AddedCount    int `json:"added_count"`
		TotalCommands int `json:"total_commands"`
	}
	if err := json.Unmarshal(recAct.Body.Bytes(), &actResp); err != nil {
		t.Fatalf("failed to decode activate response: %v", err)
	}
	if actResp.AddedCount < 20 {
		t.Fatalf("expected at least 20 Ubuntu+RedHat preset commands added, got %d", actResp.AddedCount)
	}
}
