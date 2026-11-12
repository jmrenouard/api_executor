package core_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestOTLPExport_DefaultConfig(t *testing.T) {
	cfg := core.DefaultConfig()
	if !cfg.OTLPExport.Enabled {
		t.Errorf("expected OTLPExport.Enabled to be true by default")
	}
	if cfg.OTLPExport.PushInterval != "30s" {
		t.Errorf("expected PushInterval '30s', got %q", cfg.OTLPExport.PushInterval)
	}
	if cfg.OTLPExport.Timeout != "10s" {
		t.Errorf("expected Timeout '10s', got %q", cfg.OTLPExport.Timeout)
	}
	if cfg.OTLPExport.EffectivePushInterval() != 30*time.Second {
		t.Errorf("expected EffectivePushInterval 30s, got %v", cfg.OTLPExport.EffectivePushInterval())
	}
	if cfg.OTLPExport.EffectiveTimeout() != 10*time.Second {
		t.Errorf("expected EffectiveTimeout 10s, got %v", cfg.OTLPExport.EffectiveTimeout())
	}
	if cfg.OTLPExport.ResourceAttributes["service.name"] != "api-executor" {
		t.Errorf("expected service.name 'api-executor', got %q", cfg.OTLPExport.ResourceAttributes["service.name"])
	}
}

func TestOTLPExport_EffectiveDurations(t *testing.T) {
	// Custom string duration
	c1 := core.OTLPExportConfig{
		PushInterval: "45s",
		Timeout:      "15s",
	}
	if c1.EffectivePushInterval() != 45*time.Second {
		t.Errorf("expected 45s, got %v", c1.EffectivePushInterval())
	}
	if c1.EffectiveTimeout() != 15*time.Second {
		t.Errorf("expected 15s, got %v", c1.EffectiveTimeout())
	}

	// Seconds integers
	c2 := core.OTLPExportConfig{
		PushIntervalSeconds: 60,
		TimeoutSeconds:      20,
	}
	if c2.EffectivePushInterval() != 60*time.Second {
		t.Errorf("expected 60s, got %v", c2.EffectivePushInterval())
	}
	if c2.EffectiveTimeout() != 20*time.Second {
		t.Errorf("expected 20s, got %v", c2.EffectiveTimeout())
	}

	// Fallback defaults on zero / empty
	c3 := core.OTLPExportConfig{}
	if c3.EffectivePushInterval() != 30*time.Second {
		t.Errorf("expected default 30s, got %v", c3.EffectivePushInterval())
	}
	if c3.EffectiveTimeout() != 10*time.Second {
		t.Errorf("expected default 10s, got %v", c3.EffectiveTimeout())
	}
}

func TestOTLPExport_SanitizedView_Redaction(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.OTLPExport = core.OTLPExportConfig{
		Enabled:      true,
		Endpoint:     "https://otlp.datadoghq.com/v1/metrics",
		PushInterval: "15s",
		Timeout:      "5s",
		Headers: map[string]string{
			"DD-API-KEY":    "secret-datadog-key-12345",
			"Authorization": "Bearer token-67890",
			"X-Custom-Env":  "prod",
		},
		ResourceAttributes: map[string]string{
			"service.name": "custom-service",
		},
	}

	mgr, err := core.NewMultiConfigManager("config.yaml", cfg)
	if err != nil {
		t.Fatalf("failed to create MultiConfigManager: %v", err)
	}

	view, err := mgr.SanitizedView("default")
	if err != nil {
		t.Fatalf("unexpected error from SanitizedView: %v", err)
	}

	if !view.OTLPExport.Enabled {
		t.Errorf("expected OTLPExport.Enabled true in view")
	}
	if view.OTLPExport.Endpoint != "https://otlp.datadoghq.com/v1/metrics" {
		t.Errorf("expected endpoint preserved, got %q", view.OTLPExport.Endpoint)
	}
	if view.OTLPExport.Headers["DD-API-KEY"] != "[REDACTED]" {
		t.Errorf("expected DD-API-KEY redacted, got %q", view.OTLPExport.Headers["DD-API-KEY"])
	}
	if view.OTLPExport.Headers["Authorization"] != "[REDACTED]" {
		t.Errorf("expected Authorization redacted, got %q", view.OTLPExport.Headers["Authorization"])
	}
	if view.OTLPExport.Headers["X-Custom-Env"] != "[REDACTED]" {
		t.Errorf("expected X-Custom-Env redacted, got %q", view.OTLPExport.Headers["X-Custom-Env"])
	}
	if view.OTLPExport.ResourceAttributes["service.name"] != "custom-service" {
		t.Errorf("expected service.name preserved, got %q", view.OTLPExport.ResourceAttributes["service.name"])
	}
}

func TestSandboxConfig_Defaults(t *testing.T) {
	cfg := core.DefaultConfig()
	if !cfg.Sandbox.Enabled {
		t.Errorf("expected Sandbox.Enabled to be true by default")
	}
	if cfg.Sandbox.UID != 10001 {
		t.Errorf("expected Sandbox.UID 10001, got %d", cfg.Sandbox.UID)
	}
	if cfg.Sandbox.GID != 10001 {
		t.Errorf("expected Sandbox.GID 10001, got %d", cfg.Sandbox.GID)
	}
	if cfg.Sandbox.UserNS != "keep-id" {
		t.Errorf("expected Sandbox.UserNS 'keep-id', got %q", cfg.Sandbox.UserNS)
	}
	if !cfg.Sandbox.NoNewPrivileges {
		t.Errorf("expected Sandbox.NoNewPrivileges to be true by default")
	}
	if !cfg.Sandbox.DropCaps {
		t.Errorf("expected Sandbox.DropCaps to be true by default")
	}
	if !cfg.Sandbox.DropPrivileges {
		t.Errorf("expected Sandbox.DropPrivileges to be true by default")
	}
}

func TestSandboxConfig_Validation(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*core.SandboxConfig)
		wantError bool
		errSubstr string
	}{
		{
			name:      "valid default sandbox",
			mutate:    func(s *core.SandboxConfig) {},
			wantError: false,
		},
		{
			name: "reject root UID 0",
			mutate: func(s *core.SandboxConfig) {
				s.UID = 0
			},
			wantError: true,
			errSubstr: "root execution",
		},
		{
			name: "reject root GID 0",
			mutate: func(s *core.SandboxConfig) {
				s.GID = 0
			},
			wantError: true,
			errSubstr: "root execution",
		},
		{
			name: "reject host userns",
			mutate: func(s *core.SandboxConfig) {
				s.UserNS = "host"
			},
			wantError: true,
			errSubstr: "userns",
		},
		{
			name: "accept auto userns",
			mutate: func(s *core.SandboxConfig) {
				s.UserNS = "auto"
			},
			wantError: false,
		},
		{
			name: "accept nomap userns",
			mutate: func(s *core.SandboxConfig) {
				s.UserNS = "nomap"
			},
			wantError: false,
		},
		{
			name: "allow disabled sandbox with root for edge test cases if explicit",
			mutate: func(s *core.SandboxConfig) {
				s.Enabled = false
				s.UID = 0
			},
			wantError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := core.DefaultSandboxConfig()
			tc.mutate(&sc)
			err := sc.Validate()
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tc.name)
				}
				if tc.errSubstr != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.errSubstr)) {
					t.Errorf("expected error containing %q, got %q", tc.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %s: %v", tc.name, err)
				}
			}
		})
	}
}

func TestSandboxConfig_SanitizedView(t *testing.T) {
	cfg := core.DefaultConfig()
	mgr, err := core.NewMultiConfigManager("config.yaml", cfg)
	if err != nil {
		t.Fatalf("failed to create MultiConfigManager: %v", err)
	}

	view, err := mgr.SanitizedView("default")
	if err != nil {
		t.Fatalf("unexpected error from SanitizedView: %v", err)
	}

	if !view.Sandbox.Enabled {
		t.Errorf("expected Sandbox.Enabled true in view")
	}
	if view.Sandbox.UID != 10001 {
		t.Errorf("expected Sandbox.UID 10001, got %d", view.Sandbox.UID)
	}
	if view.Sandbox.GID != 10001 {
		t.Errorf("expected Sandbox.GID 10001, got %d", view.Sandbox.GID)
	}
	if view.Sandbox.UserNS != "keep-id" {
		t.Errorf("expected Sandbox.UserNS 'keep-id', got %q", view.Sandbox.UserNS)
	}
	if !view.Sandbox.NoNewPrivileges {
		t.Errorf("expected Sandbox.NoNewPrivileges true in view")
	}
}
