package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/plugins"
)

// TestM2Challenger_API_CatalogExposure verifies that when all 141 declarative plugins
// and 24 native plugins (165 total) are registered, the REST API correctly exposes them
// with full category and query filtering under concurrent load.
func TestM2Challenger_API_CatalogExposure(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Auth.Enabled = false // bypass auth to focus on catalog filtering & concurrency

	dbPath := filepath.Join(t.TempDir(), "challenger_m2_api_test.db")
	db, err := database.NewDB(dbPath)
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}

	reg := plugins.NewRegistry()
	loaded, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("failed to load declarative plugins: %v", err)
	}
	if loaded < 141 {
		t.Fatalf("expected at least 141 declarative plugins loaded, got %d", loaded)
	}

	env := &APIEnv{
		Config:         cfg,
		DB:             db,
		PluginRegistry: reg,
	}
	router := NewRouter(env)

	fetchPlugins := func(path string) []plugins.PluginInfo {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 from %s, got %d", path, rec.Code)
		}
		var resp struct {
			Plugins []plugins.PluginInfo `json:"plugins"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response from %s: %v", path, err)
		}
		return resp.Plugins
	}

	// 1. Total plugins exposed via API
	allPlugins := fetchPlugins("/api/v1/plugins")
	if len(allPlugins) < 165 {
		t.Fatalf("expected at least 165 total plugins via API, got %d", len(allPlugins))
	}

	// 2. Filter by type=native
	nativePlugins := fetchPlugins("/api/v1/plugins?type=native")
	if len(nativePlugins) != 24 {
		t.Fatalf("expected 24 native plugins via API, got %d", len(nativePlugins))
	}

	// 3. Filter by type=declarative
	declarativePlugins := fetchPlugins("/api/v1/plugins?type=declarative")
	if len(declarativePlugins) < 141 {
		t.Fatalf("expected at least 141 declarative plugins via API, got %d", len(declarativePlugins))
	}

	// 4. Test category filters via API
	categoryChecks := map[string]struct {
		minExpectedTotal int
		declarativeCount int
	}{
		"SysAdmin":     {28, 28},
		"NetOps":       {28, 28},
		"SecOps":       {28, 28},
		"ContainerOps": {28, 28},
		"Kubernetes":   {28, 28},
		"General":      {1, 1},
	}

	for cat, check := range categoryChecks {
		url := fmt.Sprintf("/api/v1/plugins?category=%s", cat)
		res := fetchPlugins(url)
		if len(res) < check.minExpectedTotal {
			t.Errorf("API %s: expected at least %d plugins, got %d", url, check.minExpectedTotal, len(res))
		}
		declRes := fetchPlugins(fmt.Sprintf("/api/v1/plugins?category=%s&type=declarative", cat))
		if len(declRes) != check.declarativeCount {
			t.Errorf("API %s (type=declarative): expected exactly %d, got %d", cat, check.declarativeCount, len(declRes))
		}
	}

	// 5. Concurrent API queries across 50 goroutines
	const goroutines = 50
	const requestsPerWorker = 20

	paths := []string{
		"/api/v1/plugins",
		"/api/v1/plugins?category=SysAdmin",
		"/api/v1/plugins?category=NetOps&type=declarative",
		"/api/v1/plugins?category=SecOps&q=audit",
		"/api/v1/plugins?category=ContainerOps&type=native",
		"/api/v1/plugins?category=Kubernetes&q=k8s",
		"/api/v1/plugins?q=docker",
		"/api/v1/plugins?type=declarative&q=status",
		"/api/v1/plugins?category=NonExistent",
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < requestsPerWorker; j++ {
				p := paths[(workerID+j)%len(paths)]
				req := httptest.NewRequest(http.MethodGet, p, nil)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("worker %d req %d: expected 200, got %d for path %s", workerID, j, rec.Code, p)
				}
			}
		}(i)
	}

	wg.Wait()
}
