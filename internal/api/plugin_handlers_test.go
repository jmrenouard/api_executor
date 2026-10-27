package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/plugins"
)

func TestPluginsListHandlerQueryFiltering(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false

	db, err := database.NewDB(filepath.Join(t.TempDir(), "api_plugins_filter_test.db"))
	if err != nil {
		t.Fatalf("failed to create DB: %v", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init failed: %v", err)
	}

	reg := plugins.NewRegistry()
	if ops, err := plugins.DefaultDeclarativeOpsPlugin(); err == nil {
		_ = reg.Register(ops)
	}

	env := &APIEnv{
		Config:         cfg,
		DB:             db,
		PluginRegistry: reg,
	}
	router := NewRouter(env)

	// Helper to perform GET request and decode plugins list
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

	// 1. Unfiltered request returns all plugins (>= 24 native + 1 declarative ops)
	all := fetchPlugins("/api/v1/plugins")
	if len(all) < 25 {
		t.Fatalf("expected at least 25 plugins, got %d", len(all))
	}

	// 2. Filter by category=SysAdmin
	sysPlugins := fetchPlugins("/api/v1/plugins?category=sysadmin")
	if len(sysPlugins) == 0 {
		t.Fatalf("expected at least one SysAdmin plugin")
	}
	for _, p := range sysPlugins {
		if p.Category != "SysAdmin" {
			t.Errorf("expected category 'SysAdmin', got %q for plugin %s", p.Category, p.ID)
		}
	}

	// 3. Filter by domain=NetOps alias
	netPlugins := fetchPlugins("/api/v1/plugins?domain=netops")
	if len(netPlugins) == 0 {
		t.Fatalf("expected at least one NetOps plugin")
	}
	for _, p := range netPlugins {
		if p.Category != "NetOps" {
			t.Errorf("expected category 'NetOps', got %q for plugin %s", p.Category, p.ID)
		}
	}

	// 4. Filter by type=native
	nativePlugins := fetchPlugins("/api/v1/plugins?type=native")
	if len(nativePlugins) < 24 {
		t.Errorf("expected at least 24 native plugins, got %d", len(nativePlugins))
	}
	for _, p := range nativePlugins {
		if p.Type != "native" {
			t.Errorf("expected type 'native', got %q for plugin %s", p.Type, p.ID)
		}
	}

	// 5. Filter by type=declarative
	decPlugins := fetchPlugins("/api/v1/plugins?type=declarative")
	if len(decPlugins) != 1 || decPlugins[0].ID != "ops-quick-tools" {
		t.Errorf("expected 1 declarative plugin (ops-quick-tools), got %d (%+v)", len(decPlugins), decPlugins)
	}

	// 6. Search query q=storage
	storagePlugins := fetchPlugins("/api/v1/plugins?q=storage")
	if len(storagePlugins) == 0 {
		t.Fatalf("expected at least 1 plugin matching 'storage'")
	}
	foundStorage := false
	for _, p := range storagePlugins {
		if p.ID == "host-storage-stats" {
			foundStorage = true
			break
		}
	}
	if !foundStorage {
		t.Errorf("expected host-storage-stats in search results for 'storage'")
	}

	// 7. Combined filter: category=SecOps & type=native & q=integrity
	combined := fetchPlugins("/api/v1/plugins?category=SecOps&type=native&q=integrity")
	if len(combined) != 1 || combined[0].ID != "file-integrity-checker" {
		t.Errorf("expected exactly 1 match (file-integrity-checker), got %d (%+v)", len(combined), combined)
	}

	// 8. Non-existent category returns empty array
	none := fetchPlugins("/api/v1/plugins?category=NonExistentCategory12345")
	if len(none) != 0 {
		t.Errorf("expected 0 plugins for non-existent category, got %d", len(none))
	}
}
