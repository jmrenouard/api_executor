package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/core"
)

func resolveRepoRootPath(t *testing.T, rel string) string {
	t.Helper()
	candidates := []string{rel, filepath.Join("..", "..", rel)}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("unable to locate %q from current test working directory", rel)
	return ""
}

func TestCISBenchmarksPreset_DeclarativeLoadAndRegexCompilation(t *testing.T) {
	pluginsDir := resolveRepoRootPath(t, "plugins")
	reg := NewEmptyRegistry()
	if _, err := reg.LoadDeclarativeDirectory(pluginsDir); err != nil {
		t.Fatalf("LoadDeclarativeDirectory failed: %v", err)
	}

	rawPlugin, ok := reg.Get("cis-benchmarks-audit")
	if !ok {
		t.Fatalf("expected declarative plugin 'cis-benchmarks-audit' to be loaded")
	}
	if rawPlugin.Category() != "SecOps" {
		t.Errorf("expected category 'SecOps', got %q", rawPlugin.Category())
	}
	if rawPlugin.Kind() != KindDeclarative {
		t.Errorf("expected KindDeclarative, got %q", rawPlugin.Kind())
	}

	decl, ok := rawPlugin.(*DeclarativePlugin)
	if !ok {
		t.Fatalf("expected *DeclarativePlugin, got %T", rawPlugin)
	}
	if decl.PrecompiledRegexCount() < 11 {
		t.Errorf("expected at least 11 pre-compiled parameter regexes across CIS actions, got %d", decl.PrecompiledRegexCount())
	}

	// Verify all 4 canonical read-only actions exist and never embed forbidden flags or systemctl.
	actions := make(map[string]DeclarativeActionSpec, len(decl.spec.Actions))
	for _, a := range decl.spec.Actions {
		actions[a.Name] = a
		if a.Command != "audit-cis" {
			t.Errorf("action %q must invoke 'audit-cis' directly without shell wrapper, got %q", a.Name, a.Command)
		}
		joined := strings.ToLower(a.Command + " " + strings.Join(a.Args, " "))
		for _, forbidden := range []string{"systemctl", "--apply", "--allow-ephemeral-apply", "--force", "--fix", "--password", "--db-password", " -p ", "--sync-cis", "--all", "--auto-detect", "--write"} {
			if strings.Contains(joined, forbidden) {
				t.Errorf("action %q contains forbidden token %q in args: %v", a.Name, forbidden, a.Args)
			}
		}
	}
	for _, expected := range []string{"cis_list_targets", "cis_audit_json", "cis_audit_sarif", "cis_remediate_dry_run"} {
		if _, exists := actions[expected]; !exists {
			t.Errorf("missing expected cis.mcp.contract.v1 action %q", expected)
		}
	}

	// Verify all 18 canonical targets match the compiled target regex.
	targetRe := decl.compiledRegex[regexCacheKey("cis_audit_json", "target")]
	if targetRe == nil {
		t.Fatalf("expected compiled regex for cis_audit_json.target")
	}
	canonicalTargets := []string{
		"mariadb106", "mariadb1011",
		"mysql80", "mysql-community84", "mysql-enterprise84", "mysql-community97", "mysql-enterprise97",
		"postgresql16", "postgresql17", "postgresql18",
		"mongodb7", "mongodb8",
		"cassandra40", "cassandra41", "cassandra50",
		"rhel8", "rhel9", "rhel10",
	}
	for _, tgt := range canonicalTargets {
		if !targetRe.MatchString(tgt) {
			t.Errorf("expected canonical target %q to match target allowlist regex", tgt)
		}
	}
}

func TestCISBenchmarksPreset_RejectsInjectionTraversalAndForbiddenFlagsFailClosed(t *testing.T) {
	pluginsDir := resolveRepoRootPath(t, "plugins")
	reg := NewEmptyRegistry()
	if _, err := reg.LoadDeclarativeDirectory(pluginsDir); err != nil {
		t.Fatalf("LoadDeclarativeDirectory failed: %v", err)
	}

	cases := []struct {
		name   string
		action string
		params map[string]any
	}{
		{name: "target_remediation_apply", action: "cis_audit_json", params: map[string]any{"target": "--apply"}},
		{name: "target_ephemeral_apply", action: "cis_audit_json", params: map[string]any{"target": "--allow-ephemeral-apply"}},
		{name: "target_fix_flag", action: "cis_audit_json", params: map[string]any{"target": "--fix"}},
		{name: "target_remediate_flag", action: "cis_audit_json", params: map[string]any{"target": "--remediate"}},
		{name: "target_force_flag", action: "cis_audit_json", params: map[string]any{"target": "--force"}},
		{name: "target_password_flag", action: "cis_audit_json", params: map[string]any{"target": "--password"}},
		{name: "target_db_password_flag", action: "cis_audit_json", params: map[string]any{"target": "--db-password"}},
		{name: "target_short_password", action: "cis_audit_json", params: map[string]any{"target": "-p"}},
		{name: "target_sync_cis", action: "cis_audit_json", params: map[string]any{"target": "--sync-cis"}},
		{name: "target_all_flag", action: "cis_audit_json", params: map[string]any{"target": "--all"}},
		{name: "target_auto_detect", action: "cis_audit_json", params: map[string]any{"target": "--auto-detect"}},
		{name: "target_write_flag", action: "cis_audit_json", params: map[string]any{"target": "--write"}},
		{name: "target_shell_injection", action: "cis_audit_json", params: map[string]any{"target": "rhel9; cat /etc/shadow"}},
		{name: "target_command_subst", action: "cis_audit_sarif", params: map[string]any{"target": "$(id)"}},
		{name: "target_unknown_benchmark", action: "cis_audit_sarif", params: map[string]any{"target": "ubuntu2204"}},
		{name: "lang_injection", action: "cis_audit_json", params: map[string]any{"target": "rhel9", "lang": "en --apply"}},
		{name: "mode_injection", action: "cis_audit_json", params: map[string]any{"target": "rhel9", "mode": "docker"}},
		{name: "output_path_traversal", action: "cis_audit_json", params: map[string]any{"target": "rhel9", "output_path": "/tmp/../etc/passwd.json"}},
		{name: "output_path_etc_write", action: "cis_audit_json", params: map[string]any{"target": "rhel9", "output_path": "/etc/cron.d/pwn.json"}},
		{name: "output_path_hidden_dotfile", action: "cis_audit_json", params: map[string]any{"target": "rhel9", "output_path": "/tmp/.hidden.json"}},
		{name: "output_path_flag_smuggle", action: "cis_audit_sarif", params: map[string]any{"target": "postgresql17", "output_path": "--apply"}},
		{name: "output_path_shell_pipe", action: "cis_audit_sarif", params: map[string]any{"target": "postgresql17", "output_path": "/tmp/out.sarif|id"}},
		{name: "dry_run_report_traversal", action: "cis_remediate_dry_run", params: map[string]any{"report_path": "/tmp/../etc/shadow.json"}},
		{name: "dry_run_report_outside_audit_dirs", action: "cis_remediate_dry_run", params: map[string]any{"report_path": "/etc/docker/daemon.json"}},
		{name: "dry_run_report_non_json", action: "cis_remediate_dry_run", params: map[string]any{"report_path": "/etc/passwd"}},
		{name: "dry_run_report_flag_smuggle", action: "cis_remediate_dry_run", params: map[string]any{"report_path": "--apply"}},
		{name: "dry_run_format_invalid", action: "cis_remediate_dry_run", params: map[string]any{"report_path": "/tmp/report.json", "remediation_format": "apply"}},
		{name: "dry_run_output_outside_tmp", action: "cis_remediate_dry_run", params: map[string]any{"report_path": "/tmp/report.json", "output_path": "/etc/cis.sh"}},
		{name: "whitespace_target_rejected", action: "cis_audit_json", params: map[string]any{"target": "   "}},
		{name: "whitespace_report_path_rejected", action: "cis_remediate_dry_run", params: map[string]any{"report_path": "   "}},
		{name: "composite_slice_param", action: "cis_audit_json", params: map[string]any{"target": []string{"rhel9", "--apply"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := reg.Execute(context.Background(), "cis-benchmarks-audit", tc.action, tc.params, 2*time.Second)
			if err == nil {
				t.Fatalf("expected security validation rejection for %s, got nil error (res=%+v)", tc.name, res)
			}
			if res.Status != "error" {
				t.Errorf("expected status='error' on pre-execution validation failure, got %q (err=%v)", res.Status, err)
			}
			if !strings.Contains(err.Error(), "security validation") &&
				!strings.Contains(err.Error(), "missing required parameter") &&
				!strings.Contains(err.Error(), "non-scalar composite type") {
				t.Errorf("expected pre-spawn validation error, got unexpected error: %v", err)
			}
		})
	}
}

func TestCISBenchmarksConfigProfile_VersionSandboxAndNoSystemctl(t *testing.T) {
	cfgPath := resolveRepoRootPath(t, filepath.Join("configs", "cis-benchmarks-audit.yaml"))
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig(%s) failed: %v", cfgPath, err)
	}
	if cfg.EffectiveVersion() != "2.2.0" {
		t.Errorf("expected version '2.2.0', got %q", cfg.EffectiveVersion())
	}
	if !cfg.Server.TLS.Enabled || cfg.Server.TLS.MinVersion != "1.3" {
		t.Errorf("expected TLS 1.3 enabled in CIS profile, got enabled=%v min_version=%q", cfg.Server.TLS.Enabled, cfg.Server.TLS.MinVersion)
	}
	if err := cfg.Sandbox.Validate(); err != nil {
		t.Fatalf("Sandbox.Validate() failed: %v", err)
	}
	if !cfg.Sandbox.EnforceNonRoot || cfg.Sandbox.UID != 10001 || cfg.Sandbox.GID != 10001 || cfg.Sandbox.UserNS != "keep-id" {
		t.Errorf("unexpected CIS sandbox settings: %+v", cfg.Sandbox)
	}
	if len(cfg.Executor.Commands) == 0 {
		t.Fatalf("expected read-only CIS command presets in %s", cfgPath)
	}
	for _, cmd := range cfg.Executor.Commands {
		if cmd.Command != "audit-cis" {
			t.Errorf("CIS config command %q must execute 'audit-cis', got %q", cmd.Name, cmd.Command)
		}
		joined := strings.ToLower(cmd.Command + " " + strings.Join(cmd.Args, " "))
		for _, forbidden := range []string{"systemctl", "--apply", "--allow-ephemeral-apply", "--force", "--fix", "--remediate ", "--password", "--db-password", "--write"} {
			if strings.Contains(joined, forbidden) {
				t.Errorf("CIS config command %q contains forbidden token %q: %v", cmd.Name, forbidden, cmd.Args)
			}
		}
	}

	// Verify root config.yaml registers the cis-benchmarks multi-config profile cleanly.
	rootCfgPath := resolveRepoRootPath(t, "config.yaml")
	rootCfg, err := core.LoadConfig(rootCfgPath)
	if err != nil {
		t.Fatalf("LoadConfig(%s) failed: %v", rootCfgPath, err)
	}
	mgr, err := core.NewMultiConfigManager(rootCfgPath, rootCfg)
	if err != nil {
		t.Fatalf("NewMultiConfigManager failed: %v", err)
	}
	if _, ok := mgr.GetProfile("cis-benchmarks"); !ok {
		t.Fatalf("expected 'cis-benchmarks' profile registered in root config.yaml")
	}
}
