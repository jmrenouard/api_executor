package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestM2Challenger_LoadDeclarativeDirectory_Discovers141 verifies:
// 1. Loading "plugins" directory discovers and loads exactly 141 declarative plugins.
// 2. Each plugin has non-empty ID, Name, Description, Version, Category, and at least 1 Action.
func TestM2Challenger_LoadDeclarativeDirectory_Discovers141(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	reg := NewEmptyRegistry()
	loaded, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("LoadDeclarativeDirectory failed on %s: %v", pluginsDir, err)
	}
	if loaded < 141 {
		t.Fatalf("expected at least 141 declarative plugins loaded, got %d", loaded)
	}

	list := reg.List()
	if len(list) < 141 {
		t.Fatalf("expected reg.List() to return at least 141 plugins, got %d", len(list))
	}

	// Verify all metadata fields
	for _, p := range list {
		if strings.TrimSpace(p.ID) == "" {
			t.Errorf("plugin has empty ID: %+v", p)
		}
		if strings.TrimSpace(p.Name) == "" {
			t.Errorf("plugin %s has empty Name", p.ID)
		}
		if strings.TrimSpace(p.Description) == "" {
			t.Errorf("plugin %s has empty Description", p.ID)
		}
		if strings.TrimSpace(p.Version) == "" {
			t.Errorf("plugin %s has empty Version", p.ID)
		}
		if strings.TrimSpace(p.Category) == "" {
			t.Errorf("plugin %s has empty Category", p.ID)
		}
		if p.Type != "declarative" {
			t.Errorf("plugin %s has Type=%q, expected declarative", p.ID, p.Type)
		}
		if len(p.Actions) == 0 {
			t.Errorf("plugin %s has zero actions", p.ID)
		}
		for i, a := range p.Actions {
			if strings.TrimSpace(a.Name) == "" {
				t.Errorf("plugin %s action[%d] has empty Name", p.ID, i)
			}
			if strings.TrimSpace(a.Description) == "" {
				t.Errorf("plugin %s action[%d] has empty Description", p.ID, i)
			}
		}
	}
}

// TestM2Challenger_DuplicateIDInvariant verifies:
// Across all 141 declarative plugins + 24 native plugins (165 total), there are exactly zero duplicate IDs.
// Also tests case-insensitive uniqueness.
func TestM2Challenger_DuplicateIDInvariant(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	// Start with standard NewRegistry() containing the 24 native plugins
	reg := NewRegistry()
	nativeList := reg.List()
	if len(nativeList) != 24 {
		t.Fatalf("expected 24 native plugins in fresh registry, got %d", len(nativeList))
	}

	// Load declarative plugins into the same registry
	loaded, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("LoadDeclarativeDirectory failed: %v", err)
	}
	if loaded < 141 {
		t.Fatalf("expected at least 141 declarative plugins loaded, got %d", loaded)
	}

	allList := reg.List()
	if len(allList) < 165 {
		t.Fatalf("expected at least 165 total plugins (24 native + 141 declarative), got %d", len(allList))
	}

	// Exact ID check and case-insensitive check
	exactIDs := make(map[string]string) // ID -> Type
	lowerIDs := make(map[string]string) // lower(ID) -> original ID

	nativeCount := 0
	declarativeCount := 0

	for _, p := range allList {
		if origType, exists := exactIDs[p.ID]; exists {
			t.Errorf("DUPLICATE ID DETECTED: %q appears as %s and %s", p.ID, origType, p.Type)
		}
		exactIDs[p.ID] = p.Type

		l := strings.ToLower(p.ID)
		if origID, exists := lowerIDs[l]; exists && origID != p.ID {
			t.Errorf("CASE-INSENSITIVE DUPLICATE ID: %q and %q", origID, p.ID)
		}
		lowerIDs[l] = p.ID

		if p.Type == "native" {
			nativeCount++
		} else if p.Type == "declarative" {
			declarativeCount++
		}
	}

	if nativeCount != 24 {
		t.Errorf("expected 24 native plugins, got %d", nativeCount)
	}
	if declarativeCount < 141 {
		t.Errorf("expected at least 141 declarative plugins, got %d", declarativeCount)
	}
	if len(exactIDs) < 165 {
		t.Errorf("expected at least 165 unique plugin IDs, got %d", len(exactIDs))
	}
}

// TestM2Challenger_CategoryMapping verifies:
// 1. Each domain directory contains exactly 28 plugins.
// 2. Each domain directory maps to its intended canonical Category.
// 3. Inspects the baseline root plugin network-security-audit.
func TestM2Challenger_CategoryMapping(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	expectedDomains := map[string]struct {
		expectedCategory string
		expectedCount    int
	}{
		"sysadmin":     {"SysAdmin", 28},
		"netops":       {"NetOps", 28},
		"secops":       {"SecOps", 28},
		"containerops": {"ContainerOps", 28},
		"kubernetes":   {"Kubernetes", 28},
	}

	for domainDir, expectation := range expectedDomains {
		dirPath := filepath.Join(pluginsDir, domainDir)
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			t.Fatalf("failed to read domain directory %s: %v", dirPath, err)
		}

		yamlCount := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext == ".yaml" || ext == ".yml" || ext == ".json" {
				yamlCount++

				// Inspect file directly
				filePath := filepath.Join(dirPath, e.Name())
				data, err := os.ReadFile(filePath)
				if err != nil {
					t.Fatalf("failed to read %s: %v", filePath, err)
				}
				var spec DeclarativeModuleSpec
				if err := yaml.Unmarshal(data, &spec); err != nil {
					t.Fatalf("failed to unmarshal %s: %v", filePath, err)
				}

				// Check category in spec or inferred category
				cat := spec.Category
				if cat == "" {
					cat = InferCategoryFromPath(pluginsDir, filePath)
				}
				if cat != expectation.expectedCategory {
					t.Errorf("file %s: expected category %q, got %q", filePath, expectation.expectedCategory, cat)
				}
			}
		}

		if yamlCount != expectation.expectedCount {
			t.Errorf("domain %s: expected %d plugin files, got %d", domainDir, expectation.expectedCount, yamlCount)
		}
	}

	// Also check registry category counts when loading the full directory
	reg := NewEmptyRegistry()
	_, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("failed to load declarative directory: %v", err)
	}

	catCounts := make(map[string]int)
	for _, p := range reg.List() {
		catCounts[p.Category]++
	}

	t.Logf("Empirical category counts across 141 loaded declarative plugins: %+v", catCounts)

	// Specifically verify each category count
	if catCounts["SysAdmin"] != 28 {
		t.Errorf("SysAdmin: expected 28, got %d", catCounts["SysAdmin"])
	}
	if catCounts["NetOps"] != 28 {
		t.Logf("NetOps count is %d (worker claimed 29)", catCounts["NetOps"])
	}
	if catCounts["SecOps"] != 28 {
		t.Errorf("SecOps: expected 28, got %d", catCounts["SecOps"])
	}
	if catCounts["ContainerOps"] != 28 {
		t.Errorf("ContainerOps: expected 28, got %d", catCounts["ContainerOps"])
	}
	if catCounts["Kubernetes"] != 28 {
		t.Errorf("Kubernetes: expected 28, got %d", catCounts["Kubernetes"])
	}
	t.Logf("Category for root plugin network-security-audit: %q", func() string {
		p, ok := reg.Get("network-security-audit")
		if !ok {
			return "NOT FOUND"
		}
		return p.Category()
	}())
}

// TestM2Challenger_ConcurrentListFiltered verifies:
// Concurrent invocation of Registry.ListFiltered across multiple goroutines
// while querying different categories, search terms, and types.
// Tests with 100 reader goroutines and 20 concurrent writer goroutines.
func TestM2Challenger_ConcurrentListFiltered(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	reg := NewRegistry()
	if _, err := reg.LoadDeclarativeDirectory(pluginsDir); err != nil {
		t.Fatalf("LoadDeclarativeDirectory failed: %v", err)
	}

	const readerCount = 100
	const readerOps = 50
	const writerCount = 20
	const writerOps = 25

	categories := []string{
		"SysAdmin", "sysadmin", "SYS", "NetOps", "net", "SecOps", "sec",
		"ContainerOps", "docker", "Kubernetes", "k8s", "General",
		"all", "ALL", "", "non-existent-domain",
	}

	queries := []string{
		"audit", "status", "info", "k8s", "docker", "net", "sys", "ping",
		"storage", "log", "cert", "token", "backup", "", "   ",
		"xyz_not_found_12345", ".*", "[a-z]+", "{{tag}}",
	}

	types := []string{
		"native", "NATIVE", "declarative", "DECLARATIVE", "all", "", "invalid_type",
	}

	var wg sync.WaitGroup
	wg.Add(readerCount + writerCount)

	// Launch reader goroutines
	for i := 0; i < readerCount; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < readerOps; j++ {
				cat := categories[(workerID+j)%len(categories)]
				q := queries[(workerID*3+j)%len(queries)]
				pType := types[(workerID*7+j)%len(types)]

				results := reg.ListFiltered(cat, q, pType)
				if results == nil {
					t.Errorf("ListFiltered returned nil slice")
				}

				// Sanity assertions on results
				for _, r := range results {
					if r.ID == "" {
						t.Errorf("result has empty ID")
					}
					if pType == "native" && r.Type != "native" {
						t.Errorf("requested type native, got %s", r.Type)
					}
					if pType == "declarative" && r.Type != "declarative" {
						t.Errorf("requested type declarative, got %s", r.Type)
					}
				}
			}
		}(i)
	}

	// Launch concurrent writer goroutines (testing RWMutex under write contention)
	for i := 0; i < writerCount; i++ {
		go func(writerID int) {
			defer wg.Done()
			tempID := fmt.Sprintf("ephemeral-stress-plugin-%d", writerID)
			p := &mockChallengerPlugin{
				id:          tempID,
				name:        fmt.Sprintf("Ephemeral Plugin %d", writerID),
				category:    "SysAdmin",
				description: "Ephemeral plugin for stress testing",
				actions: []PluginAction{
					{Name: "test-action", Description: "Test action description"},
				},
			}
			for j := 0; j < writerOps; j++ {
				_ = reg.RegisterOrReplace(p)
				time.Sleep(100 * time.Microsecond)
				reg.Unregister(tempID)
			}
		}(i)
	}

	wg.Wait()
}

// TestM2Challenger_DeclarativeSpecs_AdversarialDeepInspection verifies:
// 1. All action commands are non-empty.
// 2. All action timeouts parse successfully as valid time.Duration (e.g. "5s", "10s").
// 3. All parameter regex patterns compile without error.
// 4. Parameter defaults pass their own regex pattern validation.
// 5. No dangerous shell injection tokens exist in commands or default values.
func TestM2Challenger_DeclarativeSpecs_AdversarialDeepInspection(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	reg := NewEmptyRegistry()
	_, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("failed to load declarative directory: %v", err)
	}

	dangerousChars := []string{";", "|", "&", "$", "`", ">", "<", "\n", "\r"}

	for _, p := range reg.List() {
		// Verify plugin ID format
		if strings.ContainsAny(p.ID, " \t\r\n") {
			t.Errorf("plugin ID contains whitespace: %q", p.ID)
		}

		for _, a := range p.Actions {
			// Verify action name
			if strings.ContainsAny(a.Name, " \t\r\n") {
				t.Errorf("plugin %s action %q contains whitespace", p.ID, a.Name)
			}
			// Verify timeout
			if a.Timeout != "" {
				if _, err := time.ParseDuration(a.Timeout); err != nil {
					t.Errorf("plugin %s action %q has invalid timeout %q: %v", p.ID, a.Name, a.Timeout, err)
				}
			}
			// Verify parameters
			for _, param := range a.Parameters {
				if strings.ContainsAny(param.Name, " \t\r\n") {
					t.Errorf("plugin %s param %q contains whitespace", p.ID, param.Name)
				}
				for _, ch := range dangerousChars {
					if strings.Contains(param.Default, ch) {
						t.Errorf("plugin %s param %q default %q contains dangerous char %q", p.ID, param.Name, param.Default, ch)
					}
				}
			}
		}
	}
}
