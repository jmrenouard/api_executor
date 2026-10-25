package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOSPresetCatalogsUbuntuAndRedHat(t *testing.T) {
	catalogs := AllOSPresetCatalogs()
	if len(catalogs) != 2 {
		t.Fatalf("expected 2 OS preset catalogs (ubuntu, redhat), got %d", len(catalogs))
	}

	ubuntuCmds := UbuntuPresetCommands()
	if len(ubuntuCmds) < 8 {
		t.Errorf("expected at least 8 Ubuntu preset commands, got %d", len(ubuntuCmds))
	}
	for _, c := range ubuntuCmds {
		if c.Name == "" || c.Command == "" {
			t.Errorf("invalid Ubuntu preset command definition: %+v", c)
		}
		if c.OSFamily != "ubuntu" {
			t.Errorf("expected OSFamily='ubuntu' for %s, got %q", c.Name, c.OSFamily)
		}
		if !c.Preset {
			t.Errorf("expected Preset=true for %s", c.Name)
		}
		if c.EffectiveTimeout(DefaultCommandTimeout) <= 0 {
			t.Errorf("expected positive timeout for %s", c.Name)
		}
	}

	redhatCmds := RedHatPresetCommands()
	if len(redhatCmds) < 8 {
		t.Errorf("expected at least 8 RedHat preset commands, got %d", len(redhatCmds))
	}
	for _, c := range redhatCmds {
		if c.Name == "" || c.Command == "" {
			t.Errorf("invalid RedHat preset command definition: %+v", c)
		}
		if c.OSFamily != "redhat" {
			t.Errorf("expected OSFamily='redhat' for %s, got %q", c.Name, c.OSFamily)
		}
		if !c.Preset {
			t.Errorf("expected Preset=true for %s", c.Name)
		}
	}
}

func TestGetAndMergeOSPresets(t *testing.T) {
	ubuntuOnly := GetOSPresetCommands("ubuntu")
	if len(ubuntuOnly) != len(UbuntuPresetCommands()) {
		t.Errorf("expected %d ubuntu commands, got %d", len(UbuntuPresetCommands()), len(ubuntuOnly))
	}

	redhatOnly := GetOSPresetCommands("redhat")
	if len(redhatOnly) != len(RedHatPresetCommands()) {
		t.Errorf("expected %d redhat commands, got %d", len(RedHatPresetCommands()), len(redhatOnly))
	}

	custom := []CommandDefinition{
		{
			Name:    "ubuntu-os-release",
			Command: "custom-cat",
			Timeout: "99s",
		},
	}
	merged := MergeOSPresets(custom, "ubuntu", "redhat")
	expectedTotal := len(UbuntuPresetCommands()) + len(RedHatPresetCommands())
	if len(merged) != expectedTotal {
		t.Errorf("expected %d merged commands without duplicates, got %d", expectedTotal, len(merged))
	}
	if merged[0].Command != "custom-cat" || merged[0].EffectiveTimeout(DefaultCommandTimeout) != 99*time.Second {
		t.Errorf("expected user-defined command to take precedence over preset of same name, got %+v", merged[0])
	}
}

func TestLoadConfigWithOSPresetsEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(cfgPath, []byte(`
command_executor:
  enabled: true
  enable_os_presets: true
  os_presets:
    - ubuntu
    - redhat
  commands:
    - name: "custom-ping"
      command: "echo"
      args: ["pong"]
`), 0600)
	if err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	wantCount := 1 + len(UbuntuPresetCommands()) + len(RedHatPresetCommands())
	if len(cfg.Executor.Commands) != wantCount {
		t.Errorf("expected %d commands when enable_os_presets=true, got %d", wantCount, len(cfg.Executor.Commands))
	}
}

func TestDetectHostOSFamily(t *testing.T) {
	family := DetectHostOSFamily()
	if family == "" {
		t.Errorf("expected non-empty host OS family")
	}
}
