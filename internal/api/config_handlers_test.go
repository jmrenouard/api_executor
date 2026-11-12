package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-admin-tool/internal/core"
)

func setupTestMultiConfigEnv(t *testing.T) *APIEnv {
	t.Helper()

	masterCfg := core.DefaultConfig()
	masterCfg.Server.Port = 8080
	masterCfg.Auth.BootstrapPassword = "super-secret-password"
	masterCfg.Auth.BootstrapToken = "super-secret-token"
	masterCfg.Executor.Commands = []core.CommandDefinition{
		{Name: "default-cmd-1", Command: "echo", Args: []string{"default1"}},
		{Name: "default-cmd-2", Command: "echo", Args: []string{"default2"}},
	}
	masterCfg.MultiConfig = core.MultiConfig{
		Enabled:        true,
		Endpoint:       "/api/v1/config",
		DefaultProfile: "default",
	}

	mgr, err := core.NewMultiConfigManager("config.yaml", masterCfg)
	if err != nil {
		t.Fatalf("failed to create MultiConfigManager: %v", err)
	}

	ubuntuCfg := core.DefaultConfig()
	ubuntuCfg.Server.Port = 8081
	ubuntuCfg.Executor.Commands = []core.CommandDefinition{
		{Name: "ubuntu-check", Command: "echo", Args: []string{"ubuntu"}},
		{Name: "ubuntu-pkg", Command: "echo", Args: []string{"pkg"}},
		{Name: "ubuntu-status", Command: "echo", Args: []string{"status"}},
	}
	mgr.RegisterProfile("ubuntu", "configs/ubuntu-tasks.yaml", "Ubuntu administration tasks", ubuntuCfg)

	return &APIEnv{
		Config:             masterCfg,
		MultiConfigManager: mgr,
	}
}

func TestConfigHandler_Default_Success(t *testing.T) {
	env := setupTestMultiConfigEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rec := httptest.NewRecorder()

	env.ConfigHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var view core.SanitizedConfigView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if view.ActiveProfile != "default" {
		t.Errorf("expected ActiveProfile 'default', got %q", view.ActiveProfile)
	}
	if view.Server.Port != 8080 {
		t.Errorf("expected server port 8080, got %d", view.Server.Port)
	}
	if view.Auth.BootstrapPassword != "[REDACTED]" {
		t.Errorf("expected redacted password, got %q", view.Auth.BootstrapPassword)
	}
	if view.Auth.BootstrapToken != "[REDACTED]" {
		t.Errorf("expected redacted token, got %q", view.Auth.BootstrapToken)
	}
	if len(view.Profiles) != 2 {
		t.Errorf("expected 2 profiles listed, got %d", len(view.Profiles))
	}
}

func TestConfigHandler_ProfileQuery_Success(t *testing.T) {
	env := setupTestMultiConfigEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config?profile=ubuntu", nil)
	rec := httptest.NewRecorder()

	env.ConfigHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var view core.SanitizedConfigView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if view.ActiveProfile != "ubuntu" {
		t.Errorf("expected ActiveProfile 'ubuntu', got %q", view.ActiveProfile)
	}
	if view.Server.Port != 8081 {
		t.Errorf("expected server port 8081, got %d", view.Server.Port)
	}
	if view.CommandExecutor.CommandsCount != 3 {
		t.Errorf("expected 3 commands for ubuntu profile, got %d", view.CommandExecutor.CommandsCount)
	}
}

func TestConfigHandler_ProfilePath_Success(t *testing.T) {
	env := setupTestMultiConfigEnv(t)

	// Testing /api/v1/configs/{profile}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/configs/ubuntu", nil)
	rec := httptest.NewRecorder()

	env.ConfigHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var view core.SanitizedConfigView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if view.ActiveProfile != "ubuntu" {
		t.Errorf("expected ActiveProfile 'ubuntu', got %q", view.ActiveProfile)
	}
}

func TestConfigHandler_ProfileHeader_Success(t *testing.T) {
	env := setupTestMultiConfigEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set("X-Config-Profile", "ubuntu")
	rec := httptest.NewRecorder()

	env.ConfigHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var view core.SanitizedConfigView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if view.ActiveProfile != "ubuntu" {
		t.Errorf("expected ActiveProfile 'ubuntu', got %q", view.ActiveProfile)
	}
}

func TestConfigHandler_NotFound(t *testing.T) {
	env := setupTestMultiConfigEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config?profile=nonexistent", nil)
	rec := httptest.NewRecorder()

	env.ConfigHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", rec.Code)
	}
}

func TestConfigHandler_MethodNotAllowed(t *testing.T) {
	env := setupTestMultiConfigEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config", nil)
	rec := httptest.NewRecorder()

	env.ConfigHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rec.Code)
	}
}

func TestConfigHandler_Fallback_WithoutManager(t *testing.T) {
	masterCfg := core.DefaultConfig()
	masterCfg.Server.Port = 7777
	env := &APIEnv{
		Config:             masterCfg,
		MultiConfigManager: nil, // Intentionally nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rec := httptest.NewRecorder()

	env.ConfigHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from fallback, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var view core.SanitizedConfigView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if view.Server.Port != 7777 {
		t.Errorf("expected port 7777, got %d", view.Server.Port)
	}
}

func TestListCommandsHandler_WithProfile(t *testing.T) {
	env := setupTestMultiConfigEnv(t)

	// 1. Unadorned -> default commands
	reqDef := httptest.NewRequest(http.MethodGet, "/api/v1/commands", nil)
	recDef := httptest.NewRecorder()
	env.ListCommandsHandler(recDef, reqDef)

	if recDef.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recDef.Code)
	}
	var respDef struct {
		Profile  string `json:"profile"`
		Commands []struct {
			Name string `json:"name"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(recDef.Body.Bytes(), &respDef); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(respDef.Commands) != 2 {
		t.Errorf("expected 2 default commands, got %d", len(respDef.Commands))
	}

	// 2. Query ?profile=ubuntu -> ubuntu commands
	reqUbuntu := httptest.NewRequest(http.MethodGet, "/api/v1/commands?profile=ubuntu", nil)
	recUbuntu := httptest.NewRecorder()
	env.ListCommandsHandler(recUbuntu, reqUbuntu)

	if recUbuntu.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recUbuntu.Code)
	}
	var respUbuntu struct {
		Profile  string `json:"profile"`
		Commands []struct {
			Name string `json:"name"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(recUbuntu.Body.Bytes(), &respUbuntu); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if respUbuntu.Profile != "ubuntu" {
		t.Errorf("expected profile 'ubuntu', got %q", respUbuntu.Profile)
	}
	if len(respUbuntu.Commands) != 3 {
		t.Errorf("expected 3 ubuntu commands, got %d", len(respUbuntu.Commands))
	}
}
