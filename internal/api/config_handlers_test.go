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

func TestConfigHandler_ConditionalVersionFields_FallbackAndMultiConfig(t *testing.T) {
	t.Run("fallback without version omits version fields", func(t *testing.T) {
		cfg := core.DefaultConfig()
		env := &APIEnv{
			Config:             cfg,
			MultiConfigManager: nil,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		rec := httptest.NewRecorder()
		env.ConfigHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("decode raw failed: %v", err)
		}
		for _, key := range []string{"version", "config_version", "config_version_path"} {
			if _, ok := raw[key]; ok {
				t.Errorf("expected %q omitted from unversioned fallback SanitizedConfigView, got %v", key, raw[key])
			}
		}

		var view core.SanitizedConfigView
		if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
			t.Fatalf("decode view failed: %v", err)
		}
		if len(view.Profiles) != 1 || view.Profiles[0].Version != "" || view.Profiles[0].VersionPath != "" {
			t.Errorf("expected empty profile version fields on unversioned fallback, got %+v", view.Profiles)
		}
	})

	t.Run("fallback with version and SourcePath populates version fields", func(t *testing.T) {
		cfg := core.DefaultConfig()
		cfg.Version = "2.2.0"
		cfg.SourcePath = "configs/custom-master.yaml"
		env := &APIEnv{
			Config:             cfg,
			MultiConfigManager: nil,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		rec := httptest.NewRecorder()
		env.ConfigHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		var view core.SanitizedConfigView
		if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
			t.Fatalf("decode view failed: %v", err)
		}
		if view.ConfigFile != "configs/custom-master.yaml" {
			t.Errorf("expected ConfigFile 'configs/custom-master.yaml', got %q", view.ConfigFile)
		}
		if view.Version != "2.2.0" || view.ConfigVersion != "2.2.0" || view.ConfigVersionPath != "/api/v1/config/version" {
			t.Errorf("unexpected SanitizedConfigView version fields: %+v", view)
		}
		if len(view.Profiles) != 1 || view.Profiles[0].Version != "2.2.0" || view.Profiles[0].VersionPath != "/api/v1/config/version" {
			t.Errorf("unexpected fallback Profiles[0] version fields: %+v", view.Profiles)
		}
	})

	t.Run("multi-config includes version fields only for versioned profiles", func(t *testing.T) {
		masterCfg := core.DefaultConfig()
		masterCfg.Version = "2.2.0"
		mgr, err := core.NewMultiConfigManager("config.yaml", masterCfg)
		if err != nil {
			t.Fatalf("NewMultiConfigManager failed: %v", err)
		}

		ubuntuCfg := core.DefaultConfig()
		ubuntuCfg.Version = "2.2.0"
		mgr.RegisterProfile("ubuntu", "configs/ubuntu-tasks.yaml", "Ubuntu", ubuntuCfg)

		legacyCfg := core.DefaultConfig()
		mgr.RegisterProfile("legacy", "configs/legacy.yaml", "Legacy", legacyCfg)

		env := &APIEnv{
			Config:             masterCfg,
			MultiConfigManager: mgr,
		}

		// Versioned ubuntu profile
		reqUbuntu := httptest.NewRequest(http.MethodGet, "/api/v1/configs/ubuntu", nil)
		recUbuntu := httptest.NewRecorder()
		env.ConfigHandler(recUbuntu, reqUbuntu)
		if recUbuntu.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", recUbuntu.Code)
		}
		var viewUbuntu core.SanitizedConfigView
		if err := json.Unmarshal(recUbuntu.Body.Bytes(), &viewUbuntu); err != nil {
			t.Fatalf("decode ubuntu view failed: %v", err)
		}
		if viewUbuntu.Version != "2.2.0" || viewUbuntu.ConfigVersion != "2.2.0" || viewUbuntu.ConfigVersionPath != "/api/v1/configs/ubuntu/version" {
			t.Errorf("unexpected ubuntu SanitizedConfigView version fields: %+v", viewUbuntu)
		}

		// Unversioned legacy profile
		reqLegacy := httptest.NewRequest(http.MethodGet, "/api/v1/configs/legacy", nil)
		recLegacy := httptest.NewRecorder()
		env.ConfigHandler(recLegacy, reqLegacy)
		if recLegacy.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", recLegacy.Code)
		}
		var rawLegacy map[string]any
		if err := json.Unmarshal(recLegacy.Body.Bytes(), &rawLegacy); err != nil {
			t.Fatalf("decode raw legacy failed: %v", err)
		}
		for _, key := range []string{"version", "config_version", "config_version_path"} {
			if _, ok := rawLegacy[key]; ok {
				t.Errorf("expected %q omitted from unversioned legacy SanitizedConfigView, got %v", key, rawLegacy[key])
			}
		}
	})
}

func TestConfigHandler_DelegatesVersionRoutes(t *testing.T) {
	masterCfg := core.DefaultConfig()
	masterCfg.Version = "2.2.0"
	mgr, err := core.NewMultiConfigManager("config.yaml", masterCfg)
	if err != nil {
		t.Fatalf("NewMultiConfigManager failed: %v", err)
	}
	ubuntuCfg := core.DefaultConfig()
	ubuntuCfg.Version = "2.2.0"
	mgr.RegisterProfile("ubuntu", "configs/ubuntu-tasks.yaml", "Ubuntu", ubuntuCfg)

	env := &APIEnv{
		Config:             masterCfg,
		MultiConfigManager: mgr,
	}

	for _, tc := range []struct {
		path        string
		wantProfile string
		wantPath    string
	}{
		{"/api/v1/config/version", "default", "/api/v1/config/version"},
		{"/api/v1/configs/version", "default", "/api/v1/config/version"},
		{"/api/v1/configs/ubuntu/version", "ubuntu", "/api/v1/configs/ubuntu/version"},
		{"/api/v1/config/ubuntu/version/", "ubuntu", "/api/v1/configs/ubuntu/version"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			env.ConfigHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 OK for %s via ConfigHandler delegation, got %d (body: %s)", tc.path, rec.Code, rec.Body.String())
			}

			var resp ConfigVersionResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode ConfigVersionResponse: %v", err)
			}
			if resp.Profile != tc.wantProfile || resp.Path != tc.wantPath || resp.Version != "2.2.0" {
				t.Errorf("unexpected delegated ConfigVersionResponse for %s: %+v", tc.path, resp)
			}
		})
	}
}

func TestConfigHandler_JobsConfig_MultiConfigAndFallback(t *testing.T) {
	t.Run("multi-config includes sanitized jobs configuration", func(t *testing.T) {
		masterCfg := core.DefaultConfig()
		masterCfg.Jobs = core.JobsConfig{
			WorkersCount:    6,
			QueueCapacity:   500,
			MaxLogBytes:     1048576,
			PruneInterval:   "5m",
			MaxJobAge:       "72h",
			MaxRetainedJobs: 2000,
		}
		mgr, err := core.NewMultiConfigManager("config.yaml", masterCfg)
		if err != nil {
			t.Fatalf("NewMultiConfigManager failed: %v", err)
		}
		env := &APIEnv{
			Config:             masterCfg,
			MultiConfigManager: mgr,
		}

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
		if view.Jobs.WorkersCount != 6 ||
			view.Jobs.QueueCapacity != 500 ||
			view.Jobs.MaxLogBytes != 1048576 ||
			view.Jobs.PruneInterval != "5m0s" ||
			view.Jobs.MaxJobAge != "72h0m0s" ||
			view.Jobs.MaxRetainedJobs != 2000 {
			t.Fatalf("unexpected view.Jobs in multi-config response: %+v", view.Jobs)
		}
	})

	t.Run("fallback view includes jobs config with invalid duration fallback", func(t *testing.T) {
		cfg := core.DefaultConfig()
		cfg.Jobs = core.JobsConfig{
			WorkersCount:    3,
			QueueCapacity:   120,
			MaxLogBytes:     0,
			PruneInterval:   "invalid",
			MaxJobAge:       "",
			MaxRetainedJobs: 0,
		}
		env := &APIEnv{
			Config:             cfg,
			MultiConfigManager: nil,
		}

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
		if view.Jobs.WorkersCount != 3 ||
			view.Jobs.QueueCapacity != 120 ||
			view.Jobs.MaxLogBytes != (2<<20) ||
			view.Jobs.PruneInterval != "10m0s" ||
			view.Jobs.MaxJobAge != "168h0m0s" ||
			view.Jobs.MaxRetainedJobs != 10000 {
			t.Fatalf("unexpected fallback view.Jobs: %+v", view.Jobs)
		}
	})
}
