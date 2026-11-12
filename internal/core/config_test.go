package core_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"go-admin-tool/internal/core"
)

func TestMultiConfig_DefaultConfig(t *testing.T) {
	cfg := core.DefaultConfig()
	if cfg.MultiConfig.Enabled {
		t.Errorf("expected MultiConfig.Enabled to be false by default, got true")
	}
	if cfg.MultiConfig.DefaultProfile != "default" {
		t.Errorf("expected DefaultProfile 'default', got %q", cfg.MultiConfig.DefaultProfile)
	}
	if cfg.MultiConfig.Endpoint != "/api/v1/config" {
		t.Errorf("expected Endpoint '/api/v1/config', got %q", cfg.MultiConfig.Endpoint)
	}
}

func TestMultiConfigManager_New_Defaults(t *testing.T) {
	masterCfg := core.DefaultConfig()
	mgr, err := core.NewMultiConfigManager("config.yaml", masterCfg)
	if err != nil {
		t.Fatalf("unexpected error creating MultiConfigManager: %v", err)
	}

	if mgr.DefaultProfile() != "default" {
		t.Errorf("expected default profile 'default', got %q", mgr.DefaultProfile())
	}

	profiles := mgr.ListProfiles()
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	if profiles[0].Name != "default" || !profiles[0].IsDefault {
		t.Errorf("expected default profile summary, got %+v", profiles[0])
	}
}

func TestMultiConfigManager_MultipleProfiles(t *testing.T) {
	tempDir := t.TempDir()

	// Master config
	masterYAML := `
server:
  port: 8080
  host: "0.0.0.0"
multi_config:
  enabled: true
  endpoint: "/api/v1/config"
  default_profile: "master"
  profiles:
    - name: "master"
      path: "master.yaml"
      description: "Master config"
    - name: "custom"
      path: "custom.yaml"
      description: "Custom profile config"
command_executor:
  enabled: true
  commands:
    - name: "master-cmd"
      command: "echo"
      args: ["master"]
`
	masterPath := filepath.Join(tempDir, "master.yaml")
	if err := os.WriteFile(masterPath, []byte(masterYAML), 0644); err != nil {
		t.Fatalf("failed to write master.yaml: %v", err)
	}

	// Custom config
	customYAML := `
server:
  port: 9090
  host: "127.0.0.1"
command_executor:
  enabled: true
  commands:
    - name: "custom-cmd-1"
      command: "echo"
      args: ["custom1"]
    - name: "custom-cmd-2"
      command: "echo"
      args: ["custom2"]
`
	customPath := filepath.Join(tempDir, "custom.yaml")
	if err := os.WriteFile(customPath, []byte(customYAML), 0644); err != nil {
		t.Fatalf("failed to write custom.yaml: %v", err)
	}

	masterCfg, err := core.LoadConfig(masterPath)
	if err != nil {
		t.Fatalf("failed to load master config: %v", err)
	}

	mgr, err := core.NewMultiConfigManager(masterPath, masterCfg)
	if err != nil {
		t.Fatalf("failed to initialize MultiConfigManager: %v", err)
	}

	if mgr.DefaultProfile() != "master" {
		t.Errorf("expected default profile 'master', got %q", mgr.DefaultProfile())
	}

	profiles := mgr.ListProfiles()
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}

	// Verify command counts
	for _, p := range profiles {
		if p.Name == "master" && p.CommandsCount != 1 {
			t.Errorf("expected master profile to have 1 command, got %d", p.CommandsCount)
		}
		if p.Name == "custom" && p.CommandsCount != 2 {
			t.Errorf("expected custom profile to have 2 commands, got %d", p.CommandsCount)
		}
	}

	// Verify ResolveConfig
	// 1. Unadorned request -> master
	reqEmpty, _ := http.NewRequest(http.MethodGet, "/api/v1/commands", nil)
	resolvedDefault := mgr.ResolveConfig(reqEmpty)
	if resolvedDefault == nil || resolvedDefault.Server.Port != 8080 {
		t.Errorf("expected master config (port 8080) for empty request")
	}

	// 2. Query param ?profile=custom -> custom
	reqQuery, _ := http.NewRequest(http.MethodGet, "/api/v1/commands?profile=custom", nil)
	resolvedCustom := mgr.ResolveConfig(reqQuery)
	if resolvedCustom == nil || resolvedCustom.Server.Port != 9090 {
		t.Errorf("expected custom config (port 9090) for ?profile=custom")
	}

	// 3. Header X-Config-Profile: custom -> custom
	reqHeader, _ := http.NewRequest(http.MethodGet, "/api/v1/commands", nil)
	reqHeader.Header.Set("X-Config-Profile", "custom")
	resolvedHeader := mgr.ResolveConfig(reqHeader)
	if resolvedHeader == nil || resolvedHeader.Server.Port != 9090 {
		t.Errorf("expected custom config (port 9090) for X-Config-Profile: custom")
	}

	// 4. Unknown profile -> fallback to default (master)
	reqUnknown, _ := http.NewRequest(http.MethodGet, "/api/v1/commands?profile=unknown-env", nil)
	resolvedFallback := mgr.ResolveConfig(reqUnknown)
	if resolvedFallback == nil || resolvedFallback.Server.Port != 8080 {
		t.Errorf("expected fallback to master config for unknown profile")
	}

	// Test SanitizedView
	view, err := mgr.SanitizedView("custom")
	if err != nil {
		t.Fatalf("unexpected error from SanitizedView: %v", err)
	}
	if view.ActiveProfile != "custom" {
		t.Errorf("expected ActiveProfile 'custom', got %q", view.ActiveProfile)
	}
	if view.Server.Port != 9090 {
		t.Errorf("expected server port 9090, got %d", view.Server.Port)
	}
	if view.Auth.BootstrapPassword != "[REDACTED]" {
		t.Errorf("expected redacted bootstrap password, got %q", view.Auth.BootstrapPassword)
	}
	if view.Auth.BootstrapToken != "[REDACTED]" {
		t.Errorf("expected redacted bootstrap token, got %q", view.Auth.BootstrapToken)
	}

	// Test SanitizedView with non-existent profile
	_, err = mgr.SanitizedView("non-existent")
	if err == nil {
		t.Errorf("expected error for non-existent profile view, got nil")
	}
}

func TestMultiConfigManager_RegisterProfile(t *testing.T) {
	mgr, err := core.NewMultiConfigManager("config.yaml", nil)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	dynCfg := core.DefaultConfig()
	dynCfg.Server.Port = 9999
	dynCfg.Executor.Commands = []core.CommandDefinition{
		{Name: "dyn-cmd", Command: "echo"},
	}

	mgr.RegisterProfile("dynamic", "dynamic.yaml", "Dynamic test profile", dynCfg)

	profileCfg, found := mgr.GetProfile("dynamic")
	if !found || profileCfg == nil {
		t.Fatalf("failed to retrieve registered profile")
	}
	if profileCfg.Server.Port != 9999 {
		t.Errorf("expected port 9999, got %d", profileCfg.Server.Port)
	}

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/commands", nil)
	req.URL.RawQuery = url.Values{"profile": []string{"dynamic"}}.Encode()
	resolved := mgr.ResolveConfig(req)
	if resolved.Server.Port != 9999 {
		t.Errorf("expected resolved port 9999, got %d", resolved.Server.Port)
	}
}
