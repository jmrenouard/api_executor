package plugins

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockChallengerPlugin is a controllable Plugin implementation for stress testing.
type mockChallengerPlugin struct {
	id          string
	name        string
	version     string
	kind        PluginKind
	pluginType  string
	category    string
	description string
	actions     []PluginAction
}

func (m *mockChallengerPlugin) ID() string          { return m.id }
func (m *mockChallengerPlugin) Name() string        { return m.name }
func (m *mockChallengerPlugin) Version() string     { return m.version }
func (m *mockChallengerPlugin) Kind() PluginKind    { return m.kind }
func (m *mockChallengerPlugin) Type() string        { return m.pluginType }
func (m *mockChallengerPlugin) Category() string    { return m.category }
func (m *mockChallengerPlugin) Description() string { return m.description }
func (m *mockChallengerPlugin) Actions() []PluginAction {
	if m.actions == nil {
		return []PluginAction{}
	}
	return m.actions
}
func (m *mockChallengerPlugin) Execute(_ context.Context, action string, _ map[string]any, _ time.Duration) (PluginResult, error) {
	return PluginResult{PluginID: m.id, Action: action, Status: "ok"}, nil
}

// ---------------------------------------------------------------------------
// 1. Stress Tests: Recursive Directory Discovery & Category Inference
// ---------------------------------------------------------------------------

func TestChallenger_RecursiveDirectoryDiscovery_DeepAndMixed(t *testing.T) {
	tmpDir := t.TempDir()

	// Create deep directory structure:
	// tmpDir/
	//   general.yaml
	//   sysadmin/
	//     a/b/c/d/deep.yaml
	//     notes.txt (ignored)
	//     README.md (ignored)
	//     backup.yaml.bak (ignored)
	//   netops/
	//     sub/network.yml
	//   secops/
	//     auth.json
	//   containerops/
	//     DOCKER.YAML (uppercase extension)
	//   kubernetes/
	//     PODS.JSON (uppercase extension)
	//   aiops/
	//     LLM.YML (uppercase extension)
	//   devops/
	//     build.yaml (explicit category override)

	dirs := []string{
		filepath.Join(tmpDir, "sysadmin", "a", "b", "c", "d"),
		filepath.Join(tmpDir, "netops", "sub"),
		filepath.Join(tmpDir, "secops"),
		filepath.Join(tmpDir, "containerops"),
		filepath.Join(tmpDir, "kubernetes"),
		filepath.Join(tmpDir, "aiops"),
		filepath.Join(tmpDir, "devops"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("failed to create dir %s: %v", d, err)
		}
	}

	files := map[string]string{
		// Root level file -> should infer "General"
		filepath.Join(tmpDir, "general.yaml"): `
id: root-plugin
name: Root Plugin
actions:
  - name: ping
    command: echo
`,
		// Deeply nested -> should infer "SysAdmin"
		filepath.Join(tmpDir, "sysadmin", "a", "b", "c", "d", "deep.yaml"): `
id: deep-sysadmin
name: Deep SysAdmin Plugin
actions:
  - name: check
    command: echo
`,
		// Non-manifest files that must be ignored:
		filepath.Join(tmpDir, "sysadmin", "notes.txt"):        `This is a note file and not a plugin`,
		filepath.Join(tmpDir, "sysadmin", "README.md"):        `# Readme markdown`,
		filepath.Join(tmpDir, "sysadmin", "backup.yaml.bak"):  `id: ignored-bak`,
		filepath.Join(tmpDir, "sysadmin", "config.xml"):       `<config></config>`,

		// .yml extension -> should infer "NetOps"
		filepath.Join(tmpDir, "netops", "sub", "network.yml"): `
id: netops-probe
name: NetOps Probe
actions:
  - name: probe
    command: echo
`,
		// .json extension -> should infer "SecOps"
		filepath.Join(tmpDir, "secops", "auth.json"): `{
  "id": "secops-auth",
  "name": "SecOps Auth",
  "actions": [
    {"name": "audit", "command": "echo"}
  ]
}`,
		// Uppercase .YAML extension -> should infer "ContainerOps"
		filepath.Join(tmpDir, "containerops", "DOCKER.YAML"): `
id: container-docker
name: Container Docker
actions:
  - name: ps
    command: echo
`,
		// Uppercase .JSON extension -> should infer "Kubernetes"
		filepath.Join(tmpDir, "kubernetes", "PODS.JSON"): `{
  "id": "k8s-pods",
  "name": "K8s Pods",
  "actions": [
    {"name": "list", "command": "echo"}
  ]
}`,
		// Uppercase .YML extension -> should infer "AIOps"
		filepath.Join(tmpDir, "aiops", "LLM.YML"): `
id: aiops-llm
name: AIOps LLM
actions:
  - name: status
    command: echo
`,
		// Explicit category in manifest should NOT be overwritten by path
		filepath.Join(tmpDir, "devops", "build.yaml"): `
id: devops-custom-cat
name: DevOps Custom Cat
category: CustomCategoryOverride
actions:
  - name: build
    command: echo
`,
	}

	for path, content := range files {
		if err := os.WriteFile(path, []byte(strings.TrimSpace(content)), 0o644); err != nil {
			t.Fatalf("failed to write test file %s: %v", path, err)
		}
	}

	// Try symlink test if supported by host OS
	symlinkTarget := filepath.Join(tmpDir, "sysadmin", "a", "b", "c", "d", "deep.yaml")
	symlinkPath := filepath.Join(tmpDir, "netops", "symlinked.yaml")
	_ = os.Symlink(symlinkTarget, symlinkPath) // Ignore error if OS/privileges disallow symlink

	reg := NewEmptyRegistry()
	loaded, err := reg.LoadDeclarativeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadDeclarativeDirectory failed unexpectedly: %v", err)
	}

	// We expect at least the 7 valid plugin files to be loaded
	if loaded < 7 {
		t.Errorf("expected at least 7 plugins loaded, got %d", loaded)
	}

	// Verify categories
	expectedCategories := map[string]string{
		"root-plugin":        "General",
		"deep-sysadmin":      "SysAdmin",
		"netops-probe":       "NetOps",
		"secops-auth":        "SecOps",
		"container-docker":   "ContainerOps",
		"k8s-pods":           "Kubernetes",
		"aiops-llm":          "AIOps",
		"devops-custom-cat":  "CustomCategoryOverride",
	}

	for id, expectedCat := range expectedCategories {
		p, exists := reg.Get(id)
		if !exists {
			t.Errorf("plugin %q was not loaded into registry", id)
			continue
		}
		if p.Category() != expectedCat {
			t.Errorf("plugin %q: expected category %q, got %q", id, expectedCat, p.Category())
		}
	}
}

func TestChallenger_RecursiveDirectoryDiscovery_MalformedFiles(t *testing.T) {
	// Subtest 1: Corrupted YAML
	t.Run("MalformedYAML", func(t *testing.T) {
		tmpDir := t.TempDir()
		badYaml := filepath.Join(tmpDir, "bad.yaml")
		_ = os.WriteFile(badYaml, []byte("id: [unclosed yaml syntax: :::"), 0o644)

		reg := NewEmptyRegistry()
		_, err := reg.LoadDeclarativeDirectory(tmpDir)
		if err == nil {
			t.Errorf("expected error when loading malformed YAML file, got nil")
		} else if !strings.Contains(err.Error(), "failed to parse declarative plugin") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	// Subtest 2: Corrupted JSON
	t.Run("MalformedJSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		badJSON := filepath.Join(tmpDir, "bad.json")
		_ = os.WriteFile(badJSON, []byte("{not a json}"), 0o644)

		reg := NewEmptyRegistry()
		_, err := reg.LoadDeclarativeDirectory(tmpDir)
		if err == nil {
			t.Errorf("expected error when loading malformed JSON file, got nil")
		} else if !strings.Contains(err.Error(), "failed to parse declarative plugin") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	// Subtest 3: Invalid plugin spec (no actions)
	t.Run("InvalidPluginSpecNoActions", func(t *testing.T) {
		tmpDir := t.TempDir()
		specNoActions := filepath.Join(tmpDir, "no_actions.yaml")
		_ = os.WriteFile(specNoActions, []byte("id: no-actions\nname: No Actions"), 0o644)

		reg := NewEmptyRegistry()
		_, err := reg.LoadDeclarativeDirectory(tmpDir)
		if err == nil {
			t.Errorf("expected error when loading declarative plugin with no actions, got nil")
		}
	})

	// Subtest 4: Non-existent directory
	t.Run("NonExistentDir", func(t *testing.T) {
		reg := NewEmptyRegistry()
		loaded, err := reg.LoadDeclarativeDirectory(filepath.Join(t.TempDir(), "non_existent_folder_xyz"))
		if err != nil {
			t.Errorf("expected nil error for non-existent dir, got: %v", err)
		}
		if loaded != 0 {
			t.Errorf("expected 0 loaded plugins, got %d", loaded)
		}
	})

	// Subtest 5: Empty directory
	t.Run("EmptyDir", func(t *testing.T) {
		reg := NewEmptyRegistry()
		loaded, err := reg.LoadDeclarativeDirectory(t.TempDir())
		if err != nil {
			t.Errorf("expected nil error for empty dir, got: %v", err)
		}
		if loaded != 0 {
			t.Errorf("expected 0 loaded plugins, got %d", loaded)
		}
	})
}

func TestChallenger_RecursiveDirectoryDiscovery_FileCollision(t *testing.T) {
	tmpDir := t.TempDir()
	d1 := filepath.Join(tmpDir, "dir1")
	d2 := filepath.Join(tmpDir, "dir2")
	_ = os.MkdirAll(d1, 0o755)
	_ = os.MkdirAll(d2, 0o755)

	manifestContent := `
id: colliding-manifest-id
name: Collision Test Plugin
actions:
  - name: test
    command: echo
`
	_ = os.WriteFile(filepath.Join(d1, "p1.yaml"), []byte(manifestContent), 0o644)
	_ = os.WriteFile(filepath.Join(d2, "p2.yaml"), []byte(manifestContent), 0o644)

	reg := NewEmptyRegistry()
	_, err := reg.LoadDeclarativeDirectory(tmpDir)
	if err == nil {
		t.Fatalf("expected collision error when two files define identical plugin ID, got nil")
	}
	if !errors.Is(err, ErrDuplicatePlugin) {
		t.Errorf("expected error to wrap ErrDuplicatePlugin, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2. Stress Tests: Duplicate Plugin ID Registration & Collision Detection
// ---------------------------------------------------------------------------

func TestChallenger_DuplicateRegistration_CaseSensitivity(t *testing.T) {
	reg := NewEmptyRegistry()
	p1 := &mockChallengerPlugin{id: "my-test-plugin", name: "Lowercase ID"}
	p2 := &mockChallengerPlugin{id: "MY-TEST-PLUGIN", name: "Uppercase ID"}

	if err := reg.Register(p1); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	err := reg.Register(p2)
	t.Logf("Registering MY-TEST-PLUGIN when my-test-plugin exists: err=%v", err)
	if err == nil {
		t.Logf("OBSERVATION: Registry treats IDs as case-sensitive: my-test-plugin and MY-TEST-PLUGIN can both be registered!")
	}
}

func TestChallenger_DuplicateRegistration_CollisionDetection(t *testing.T) {
	reg := NewEmptyRegistry()

	p1 := &mockChallengerPlugin{id: "test-plug-id", name: "Original Plugin"}
	if err := reg.Register(p1); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// 1. Direct collision with identical ID
	p2 := &mockChallengerPlugin{id: "test-plug-id", name: "Duplicate Plugin"}
	err := reg.Register(p2)
	if err == nil {
		t.Fatalf("expected ErrDuplicatePlugin on registering duplicate ID, got nil")
	}
	if !errors.Is(err, ErrDuplicatePlugin) {
		t.Errorf("expected error to wrap ErrDuplicatePlugin, got %v", err)
	}

	// 2. Whitespace padded ID collision
	p3 := &mockChallengerPlugin{id: "  test-plug-id  ", name: "Padded Duplicate Plugin"}
	err = reg.Register(p3)
	if err == nil {
		t.Fatalf("expected ErrDuplicatePlugin on whitespace-padded ID, got nil")
	}
	if !errors.Is(err, ErrDuplicatePlugin) {
		t.Errorf("expected error to wrap ErrDuplicatePlugin, got %v", err)
	}

	// 3. Empty ID rejection
	pEmpty := &mockChallengerPlugin{id: "   ", name: "Empty ID Plugin"}
	if err := reg.Register(pEmpty); err == nil {
		t.Errorf("expected error registering empty ID, got nil")
	}

	// 4. Nil plugin rejection
	if err := reg.Register(nil); err == nil {
		t.Errorf("expected error registering nil plugin, got nil")
	}

	// 5. RegisterOrReplace should overwrite cleanly
	pReplace := &mockChallengerPlugin{id: "test-plug-id", name: "Replaced Plugin"}
	if err := reg.RegisterOrReplace(pReplace); err != nil {
		t.Fatalf("RegisterOrReplace failed: %v", err)
	}
	retrieved, ok := reg.Get("test-plug-id")
	if !ok || retrieved.Name() != "Replaced Plugin" {
		t.Errorf("expected replaced plugin name, got %v (ok=%v)", retrieved, ok)
	}

	// 6. Unregister and re-register
	if !reg.Unregister("test-plug-id") {
		t.Errorf("Unregister returned false for existing plugin")
	}
	if reg.Unregister("test-plug-id") {
		t.Errorf("second Unregister returned true for non-existent plugin")
	}
	// Re-registering after unregister should succeed
	if err := reg.Register(p1); err != nil {
		t.Errorf("re-register after unregister failed: %v", err)
	}
}

func TestChallenger_DuplicateRegistration_ConcurrentStampede(t *testing.T) {
	reg := NewEmptyRegistry()
	const concurrency = 100
	const targetID = "concurrent-stampede-plugin"

	var wg sync.WaitGroup
	wg.Add(concurrency)

	successCount := 0
	duplicateCount := 0
	var countMu sync.Mutex

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			p := &mockChallengerPlugin{
				id:   targetID,
				name: fmt.Sprintf("Plugin-%d", idx),
			}
			err := reg.Register(p)

			countMu.Lock()
			defer countMu.Unlock()
			if err == nil {
				successCount++
			} else if errors.Is(err, ErrDuplicatePlugin) {
				duplicateCount++
			}
		}(i)
	}

	wg.Wait()

	if successCount != 1 {
		t.Errorf("expected exactly 1 successful registration in stampede, got %d", successCount)
	}
	if duplicateCount != concurrency-1 {
		t.Errorf("expected %d duplicate errors in stampede, got %d", concurrency-1, duplicateCount)
	}
}

func TestChallenger_ImpostorNativePluginOverwrites(t *testing.T) {
	reg := NewRegistry() // Contains default 24 native plugins including sys-diagnostics & db-exposure

	// An impostor declarative plugin attempting to register with ID "sys-diagnostics"
	impostorSys := &mockChallengerPlugin{
		id:   "sys-diagnostics",
		name: "Malicious Sys Diagnostics Impostor",
	}
	err := reg.Register(impostorSys)
	if err == nil {
		t.Errorf("expected ErrDuplicatePlugin when registering impostor for sys-diagnostics, got nil")
	} else if !errors.Is(err, ErrDuplicatePlugin) {
		t.Errorf("expected ErrDuplicatePlugin, got %v", err)
	}

	// An impostor attempting to overwrite "db-exposure"
	impostorDB := &mockChallengerPlugin{
		id:   "db-exposure",
		name: "Malicious DB Exposure Impostor",
	}
	err = reg.Register(impostorDB)
	if err == nil {
		t.Errorf("expected ErrDuplicatePlugin when registering impostor for db-exposure, got nil")
	} else if !errors.Is(err, ErrDuplicatePlugin) {
		t.Errorf("expected ErrDuplicatePlugin, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// 3. Stress Tests: ListFiltered Edge Cases, Regex, and Concurrency
// ---------------------------------------------------------------------------

func TestChallenger_ListFiltered_EdgeCases(t *testing.T) {
	reg := NewEmptyRegistry()

	_ = reg.Register(&mockChallengerPlugin{
		id:          "sys-storage-stats",
		name:        "Storage Capacity Prober",
		pluginType:  "native",
		category:    "SysAdmin",
		description: "Monitors disk partitions and inode usage",
		actions: []PluginAction{
			{Name: "inspect-disks", Description: "Probe disk mount points and capacities"},
		},
	})
	_ = reg.Register(&mockChallengerPlugin{
		id:          "net-dns-audit",
		name:        "DNS Resolution Auditor",
		pluginType:  "native",
		category:    "NetOps",
		description: "Verifies recursive DNS lookups and latency",
		actions: []PluginAction{
			{Name: "resolve-host", Description: "Lookup domain records [A, AAAA, MX]"},
		},
	})
	_ = reg.Register(&mockChallengerPlugin{
		id:          "sec-crypto-validator",
		name:        "Security & Cryptography Validator",
		pluginType:  "declarative",
		category:    "SecOps",
		description: "Validates regex pattern ^[a-z0-9]+$ on tokens",
		actions: []PluginAction{
			{Name: "check-hash", Description: "Computes SHA-256 and HMAC.* token digests"},
		},
	})

	tests := []struct {
		name         string
		category     string
		query        string
		pluginType   string
		expectedIDs  []string
		expectedLen  int
		shouldNotErr bool
	}{
		{
			name:        "Empty parameters returns all plugins",
			category:    "",
			query:       "",
			pluginType:  "",
			expectedLen: 3,
		},
		{
			name:        "Category 'all' (mixed case, whitespace) returns all",
			category:    "  ALL  ",
			query:       "",
			pluginType:  "",
			expectedLen: 3,
		},
		{
			name:        "Case-insensitive category filter",
			category:    "sYsAdMiN",
			query:       "",
			pluginType:  "",
			expectedIDs: []string{"sys-storage-stats"},
			expectedLen: 1,
		},
		{
			name:        "Category substring match",
			category:    "sec",
			query:       "",
			pluginType:  "",
			expectedIDs: []string{"sec-crypto-validator"},
			expectedLen: 1,
		},
		{
			name:        "Non-existent category returns empty slice",
			category:    "NonExistentCategoryXYZ",
			query:       "",
			pluginType:  "",
			expectedLen: 0,
		},
		{
			name:        "Filter type native (case insensitive)",
			category:    "",
			query:       "",
			pluginType:  "NATIVE",
			expectedLen: 2,
		},
		{
			name:        "Filter type declarative",
			category:    "",
			query:       "",
			pluginType:  "declarative",
			expectedIDs: []string{"sec-crypto-validator"},
			expectedLen: 1,
		},
		{
			name:        "Filter type advanced maps to native",
			category:    "",
			query:       "",
			pluginType:  "advanced",
			expectedLen: 2,
		},
		{
			name:        "Filter type all",
			category:    "",
			query:       "",
			pluginType:  "all",
			expectedLen: 3,
		},
		{
			name:        "Non-existent type returns empty slice",
			category:    "",
			query:       "",
			pluginType:  "bogus-type",
			expectedLen: 0,
		},
		{
			name:        "Search query matching action name",
			category:    "",
			query:       "resolve-host",
			pluginType:  "",
			expectedIDs: []string{"net-dns-audit"},
			expectedLen: 1,
		},
		{
			name:        "Search query matching action description",
			category:    "",
			query:       "inode usage",
			pluginType:  "",
			expectedIDs: []string{"sys-storage-stats"},
			expectedLen: 1,
		},
		{
			name:        "Search query with regex metacharacters (must match as literal substring without panic)",
			category:    "",
			query:       "^[a-z0-9]+$",
			pluginType:  "",
			expectedIDs: []string{"sec-crypto-validator"},
			expectedLen: 1,
		},
		{
			name:        "Search query with unclosed regex brackets (must not panic)",
			category:    "",
			query:       "[A, AAAA",
			pluginType:  "",
			expectedIDs: []string{"net-dns-audit"},
			expectedLen: 1,
		},
		{
			name:        "Search query with regex wildcard .* (must match literal substring)",
			category:    "",
			query:       "HMAC.*",
			pluginType:  "",
			expectedIDs: []string{"sec-crypto-validator"},
			expectedLen: 1,
		},
		{
			name:        "Search query with SQL injection string (must not crash)",
			category:    "",
			query:       "' OR '1'='1",
			pluginType:  "",
			expectedLen: 0,
		},
		{
			name:        "Search query with XSS HTML payload (must not crash)",
			category:    "",
			query:       "<script>alert(1)</script>",
			pluginType:  "",
			expectedLen: 0,
		},
		{
			name:        "Search query with 50,000 characters (stress test string length)",
			category:    "",
			query:       strings.Repeat("q", 50000),
			pluginType:  "",
			expectedLen: 0,
		},
		{
			name:        "Search query with unicode emoji",
			category:    "",
			query:       "🚀🔥",
			pluginType:  "",
			expectedLen: 0,
		},
		{
			name:        "Search query with null byte",
			category:    "",
			query:       "\x00",
			pluginType:  "",
			expectedLen: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := reg.ListFiltered(tc.category, tc.query, tc.pluginType)
			if len(res) != tc.expectedLen {
				t.Fatalf("ListFiltered(%q, %q, %q) returned %d results, expected %d",
					tc.category, tc.query, tc.pluginType, len(res), tc.expectedLen)
			}
			if len(tc.expectedIDs) > 0 {
				for i, expectedID := range tc.expectedIDs {
					if res[i].ID != expectedID {
						t.Errorf("result[%d]: expected ID %q, got %q", i, expectedID, res[i].ID)
					}
				}
			}
		})
	}
}

func TestChallenger_ListFiltered_ConcurrentStress(t *testing.T) {
	reg := NewRegistry() // 24 default native plugins
	const numGoroutines = 50
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// 50 Reader goroutines
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			queries := []string{"storage", "dns", "crypto", "k8s", "sys", "all", "", "non-existent"}
			for j := 0; j < iterations; j++ {
				q := queries[j%len(queries)]
				list := reg.ListFiltered("", q, "")
				if len(list) < 0 {
					t.Errorf("impossible result")
				}
			}
		}(i)
	}

	// 50 Writer goroutines (registering and unregistering unique plugin IDs)
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			pluginID := fmt.Sprintf("dynamic-worker-%d", workerID)
			p := &mockChallengerPlugin{
				id:          pluginID,
				name:        fmt.Sprintf("Dynamic Worker %d", workerID),
				category:    "SysAdmin",
				description: "Temporary dynamic plugin",
			}
			for j := 0; j < iterations; j++ {
				_ = reg.RegisterOrReplace(p)
				_ = reg.Unregister(pluginID)
			}
		}(i)
	}

	wg.Wait()
}
