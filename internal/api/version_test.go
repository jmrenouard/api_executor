package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/core"
	"go-admin-tool/internal/version"
)

func TestVersionHandler_Success(t *testing.T) {
	startTime := time.Now().Add(-10 * time.Second)
	env := &APIEnv{
		StartTime: startTime,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rec := httptest.NewRecorder()

	env.VersionHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var resp version.VersionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode version response: %v", err)
	}

	if resp.Version != "2.2.0" {
		t.Errorf("expected Version '2.2.0', got %q", resp.Version)
	}
	hex40 := regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	if !hex40.MatchString(resp.GitCommit) {
		t.Errorf("expected 40-char hex GitCommit in repo, got %q", resp.GitCommit)
	}
	if resp.BuildDate == "" {
		t.Errorf("expected non-empty BuildDate in response")
	}
	if resp.IntegrityStatus == "" || resp.Integrity == "" {
		t.Errorf("expected non-empty IntegrityStatus and Integrity in response")
	}
	if resp.Uptime == "" {
		t.Errorf("expected non-empty Uptime in response")
	}
	if resp.UptimeSeconds < 9.0 || resp.UptimeSeconds > 20.0 {
		t.Errorf("expected ~10s UptimeSeconds, got %f", resp.UptimeSeconds)
	}
	if resp.GoVersion == "" {
		t.Errorf("expected non-empty GoVersion in response")
	}
	if resp.StartTime == "" {
		t.Errorf("expected non-empty StartTime in response")
	}
}

func TestVersionHandler_MethodNotAllowed(t *testing.T) {
	env := &APIEnv{}

	disallowedMethods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, method := range disallowedMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/version", nil)
			rec := httptest.NewRecorder()

			env.VersionHandler(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected status 405 Method Not Allowed for %s, got %d", method, rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != "GET" {
				t.Errorf("expected Allow: GET header for %s, got %q", method, allow)
			}
		})
	}
}

func TestVersionHandler_PublicUnauthenticatedAccessWhenRequireAuthTrue(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true

	env := &APIEnv{
		Config:    cfg,
		StartTime: time.Now(),
	}

	router := NewRouter(env)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for public unauthenticated /api/v1/version even when RequireAuth=true, got %d", rec.Code)
	}
}

func TestVersionHandler_StaticPathPreservedInMetrics(t *testing.T) {
	normalized := normalizeMetricPath("/api/v1/version")
	if normalized != "/api/v1/version" {
		t.Errorf("expected /api/v1/version to be preserved in normalizeMetricPath, got %s", normalized)
	}

	normalizedTrailing := normalizeMetricPath("/api/v1/version/")
	if normalizedTrailing != "/api/v1/version" {
		t.Errorf("expected /api/v1/version/ to normalize to /api/v1/version, got %s", normalizedTrailing)
	}
}

func TestVersionHandler_ConditionalConfigVersionFields(t *testing.T) {
	t.Run("omits config version fields when config has no version", func(t *testing.T) {
		cfg := core.DefaultConfig()
		env := &APIEnv{
			Config:    cfg,
			StartTime: time.Now().Add(-5 * time.Second),
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
		rec := httptest.NewRecorder()
		env.VersionHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}

		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("failed to decode JSON: %v", err)
		}
		for _, field := range []string{"config_version", "config_version_path", "config_file"} {
			if _, present := raw[field]; present {
				t.Errorf("expected %q to be omitted when no config version is defined, got %v", field, raw[field])
			}
		}
	})

	t.Run("includes config version fields for fallback and named profiles", func(t *testing.T) {
		masterCfg := core.DefaultConfig()
		masterCfg.Version = "2.2.0"
		masterCfg.SourcePath = "config.yaml"

		mgr, err := core.NewMultiConfigManager("config.yaml", masterCfg)
		if err != nil {
			t.Fatalf("failed to create MultiConfigManager: %v", err)
		}

		ubuntuCfg := core.DefaultConfig()
		ubuntuCfg.Version = "2.2.0"
		mgr.RegisterProfile("ubuntu", "configs/ubuntu-tasks.yaml", "Ubuntu tasks", ubuntuCfg)

		unversionedCfg := core.DefaultConfig()
		mgr.RegisterProfile("legacy", "configs/legacy.yaml", "Legacy unversioned", unversionedCfg)

		env := &APIEnv{
			Config:             masterCfg,
			MultiConfigManager: mgr,
			StartTime:          time.Now().Add(-5 * time.Second),
		}

		// Default profile
		reqDef := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
		recDef := httptest.NewRecorder()
		env.VersionHandler(recDef, reqDef)
		if recDef.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", recDef.Code)
		}
		var respDef version.VersionResponse
		if err := json.Unmarshal(recDef.Body.Bytes(), &respDef); err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if respDef.ConfigVersion != "2.2.0" || respDef.ConfigVersionPath != "/api/v1/config/version" || respDef.ConfigFile != "config.yaml" {
			t.Errorf("unexpected default config fields: %+v", respDef)
		}

		// ?profile=ubuntu
		reqQuery := httptest.NewRequest(http.MethodGet, "/api/v1/version?profile=ubuntu", nil)
		recQuery := httptest.NewRecorder()
		env.VersionHandler(recQuery, reqQuery)
		var respQuery version.VersionResponse
		if err := json.Unmarshal(recQuery.Body.Bytes(), &respQuery); err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if respQuery.ConfigVersion != "2.2.0" || respQuery.ConfigVersionPath != "/api/v1/configs/ubuntu/version" || respQuery.ConfigFile != "configs/ubuntu-tasks.yaml" {
			t.Errorf("unexpected ?profile=ubuntu config fields: %+v", respQuery)
		}

		// X-Config-Profile: ubuntu
		reqHdr := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
		reqHdr.Header.Set("X-Config-Profile", "ubuntu")
		recHdr := httptest.NewRecorder()
		env.VersionHandler(recHdr, reqHdr)
		var respHdr version.VersionResponse
		if err := json.Unmarshal(recHdr.Body.Bytes(), &respHdr); err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if respHdr.ConfigVersion != "2.2.0" || respHdr.ConfigVersionPath != "/api/v1/configs/ubuntu/version" || respHdr.ConfigFile != "configs/ubuntu-tasks.yaml" {
			t.Errorf("unexpected X-Config-Profile ubuntu config fields: %+v", respHdr)
		}

		// ?profile=legacy (unversioned) omits config fields
		reqLegacy := httptest.NewRequest(http.MethodGet, "/api/v1/version?profile=legacy", nil)
		recLegacy := httptest.NewRecorder()
		env.VersionHandler(recLegacy, reqLegacy)
		var rawLegacy map[string]any
		if err := json.Unmarshal(recLegacy.Body.Bytes(), &rawLegacy); err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		for _, field := range []string{"config_version", "config_version_path", "config_file"} {
			if _, present := rawLegacy[field]; present {
				t.Errorf("expected %q omitted for unversioned profile, got %v", field, rawLegacy[field])
			}
		}
	})
}

func TestConfigVersionHandler_SuccessAndProfileResolution(t *testing.T) {
	masterCfg := core.DefaultConfig()
	masterCfg.Server.TLS.Enabled = false
	masterCfg.Version = "2.2.0"

	mgr, err := core.NewMultiConfigManager("config.yaml", masterCfg)
	if err != nil {
		t.Fatalf("failed to create MultiConfigManager: %v", err)
	}

	ubuntuCfg := core.DefaultConfig()
	ubuntuCfg.Version = "2.2.0"
	mgr.RegisterProfile("ubuntu", "configs/ubuntu-tasks.yaml", "Ubuntu tasks", ubuntuCfg)

	customProfileCfg := core.DefaultConfig()
	customProfileCfg.ConfigVersion = "3.1.0"
	customProfileCfg.ConfigVersionPath = "/api/v1/custom-config-version"
	mgr.RegisterProfile("custom", "configs/custom.yaml", "Custom version path profile", customProfileCfg)

	env := &APIEnv{
		Config:             masterCfg,
		MultiConfigManager: mgr,
		StartTime:          time.Now(),
	}
	router := NewRouter(env)

	cases := []struct {
		name           string
		url            string
		headers        map[string]string
		wantVersion    string
		wantProfile    string
		wantConfigFile string
		wantPath       string
	}{
		{
			name:           "default /api/v1/config/version",
			url:            "/api/v1/config/version",
			wantVersion:    "2.2.0",
			wantProfile:    "default",
			wantConfigFile: "config.yaml",
			wantPath:       "/api/v1/config/version",
		},
		{
			name:           "default /api/v1/configs/version",
			url:            "/api/v1/configs/version",
			wantVersion:    "2.2.0",
			wantProfile:    "default",
			wantConfigFile: "config.yaml",
			wantPath:       "/api/v1/config/version",
		},
		{
			name:           "query ?profile=ubuntu",
			url:            "/api/v1/config/version?profile=ubuntu",
			wantVersion:    "2.2.0",
			wantProfile:    "ubuntu",
			wantConfigFile: "configs/ubuntu-tasks.yaml",
			wantPath:       "/api/v1/configs/ubuntu/version",
		},
		{
			name:           "header X-Config-Profile ubuntu",
			url:            "/api/v1/config/version",
			headers:        map[string]string{"X-Config-Profile": "ubuntu"},
			wantVersion:    "2.2.0",
			wantProfile:    "ubuntu",
			wantConfigFile: "configs/ubuntu-tasks.yaml",
			wantPath:       "/api/v1/configs/ubuntu/version",
		},
		{
			name:           "header X-API-Config ubuntu",
			url:            "/api/v1/config/version",
			headers:        map[string]string{"X-API-Config": "ubuntu"},
			wantVersion:    "2.2.0",
			wantProfile:    "ubuntu",
			wantConfigFile: "configs/ubuntu-tasks.yaml",
			wantPath:       "/api/v1/configs/ubuntu/version",
		},
		{
			name:           "path /api/v1/configs/ubuntu/version",
			url:            "/api/v1/configs/ubuntu/version",
			wantVersion:    "2.2.0",
			wantProfile:    "ubuntu",
			wantConfigFile: "configs/ubuntu-tasks.yaml",
			wantPath:       "/api/v1/configs/ubuntu/version",
		},
		{
			name:           "path /api/v1/config/ubuntu/version",
			url:            "/api/v1/config/ubuntu/version",
			wantVersion:    "2.2.0",
			wantProfile:    "ubuntu",
			wantConfigFile: "configs/ubuntu-tasks.yaml",
			wantPath:       "/api/v1/configs/ubuntu/version",
		},
		{
			name:           "custom ConfigVersionPath mounted on router",
			url:            "/api/v1/custom-config-version",
			wantVersion:    "3.1.0",
			wantProfile:    "custom",
			wantConfigFile: "configs/custom.yaml",
			wantPath:       "/api/v1/custom-config-version",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 OK for %s, got %d (body: %s)", tc.url, rec.Code, rec.Body.String())
			}

			var resp ConfigVersionResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode ConfigVersionResponse: %v", err)
			}
			if resp.Version != tc.wantVersion || resp.ConfigVersion != tc.wantVersion {
				t.Errorf("expected version/config_version %q, got version=%q config_version=%q", tc.wantVersion, resp.Version, resp.ConfigVersion)
			}
			if resp.Profile != tc.wantProfile {
				t.Errorf("expected profile %q, got %q", tc.wantProfile, resp.Profile)
			}
			if resp.ConfigFile != tc.wantConfigFile {
				t.Errorf("expected config_file %q, got %q", tc.wantConfigFile, resp.ConfigFile)
			}
			if resp.Path != tc.wantPath {
				t.Errorf("expected path %q, got %q", tc.wantPath, resp.Path)
			}
			if resp.AppVersion != "2.2.0" {
				t.Errorf("expected app_version '2.2.0', got %q", resp.AppVersion)
			}
		})
	}
}

func TestConfigVersionHandler_ConditionalNotFound(t *testing.T) {
	t.Run("fallback without manager and no version returns 404 and custom path is not mounted", func(t *testing.T) {
		cfg := core.DefaultConfig()
		cfg.Server.TLS.Enabled = false
		cfg.ConfigVersionPath = "/api/v1/custom-config-version"

		env := &APIEnv{
			Config:    cfg,
			StartTime: time.Now(),
		}
		router := NewRouter(env)

		for _, path := range []string{"/api/v1/config/version", "/api/v1/configs/version", "/api/v1/custom-config-version"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("expected 404 Not Found for %s when no version exists, got %d (body: %s)", path, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("unversioned profile and unknown profile return 404", func(t *testing.T) {
		masterCfg := core.DefaultConfig()
		masterCfg.Server.TLS.Enabled = false
		masterCfg.Version = "2.2.0"

		mgr, err := core.NewMultiConfigManager("config.yaml", masterCfg)
		if err != nil {
			t.Fatalf("failed to create MultiConfigManager: %v", err)
		}

		unversionedCfg := core.DefaultConfig()
		unversionedCfg.ConfigVersionPath = "/api/v1/unmounted-custom-version"
		mgr.RegisterProfile("unversioned", "configs/unversioned.yaml", "No version", unversionedCfg)

		env := &APIEnv{
			Config:             masterCfg,
			MultiConfigManager: mgr,
			StartTime:          time.Now(),
		}
		router := NewRouter(env)

		for _, path := range []string{
			"/api/v1/config/version?profile=unversioned",
			"/api/v1/configs/unversioned/version",
			"/api/v1/config/version?profile=unknown-prof",
			"/api/v1/configs/unknown-prof/version",
			"/api/v1/unmounted-custom-version",
		} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("expected 404 Not Found for %s, got %d (body: %s)", path, rec.Code, rec.Body.String())
			}
		}
	})
}

func TestVersionAndConfigVersionHandlers_MethodNotAllowed(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Version = "2.2.0"

	env := &APIEnv{
		Config:    cfg,
		StartTime: time.Now(),
	}
	router := NewRouter(env)

	disallowedMethods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, ep := range []string{"/api/v1/version", "/api/v1/config/version"} {
		for _, method := range disallowedMethods {
			t.Run(method+"_"+ep, func(t *testing.T) {
				req := httptest.NewRequest(method, ep, nil)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)

				if rec.Code != http.StatusMethodNotAllowed {
					t.Errorf("expected 405 Method Not Allowed for %s %s, got %d", method, ep, rec.Code)
				}
				if allow := rec.Header().Get("Allow"); allow != "GET" {
					t.Errorf("expected Allow: GET for %s %s, got %q", method, ep, allow)
				}
			})
		}
	}
}

func TestConfigVersionHandler_PublicUnauthenticatedAccessWhenRequireAuthTrue(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true
	cfg.Version = "2.2.0"

	mgr, err := core.NewMultiConfigManager("config.yaml", cfg)
	if err != nil {
		t.Fatalf("failed to create MultiConfigManager: %v", err)
	}
	ubuntuCfg := core.DefaultConfig()
	ubuntuCfg.Version = "2.2.0"
	mgr.RegisterProfile("ubuntu", "configs/ubuntu-tasks.yaml", "Ubuntu", ubuntuCfg)

	env := &APIEnv{
		Config:             cfg,
		MultiConfigManager: mgr,
		StartTime:          time.Now(),
	}
	router := NewRouter(env)

	for _, ep := range []string{"/api/v1/version", "/api/v1/config/version", "/api/v1/configs/ubuntu/version"} {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for public unauthenticated %s when RequireAuth=true, got %d (body: %s)", ep, rec.Code, rec.Body.String())
		}
	}
}

func TestNormalizeMetricPath_VersionAndConfigVersionRoutes(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/api/v1/version", "/api/v1/version"},
		{"/api/v1/version/", "/api/v1/version"},
		{"/api/v1/config/version", "/api/v1/config/version"},
		{"/api/v1/config/version/", "/api/v1/config/version"},
		{"/api/v1/configs/version", "/api/v1/config/version"},
		{"/api/v1/configs/version/", "/api/v1/config/version"},
		{"/api/v1/configs/ubuntu/version", "/api/v1/config/:profile/version"},
		{"/api/v1/config/ubuntu/version", "/api/v1/config/:profile/version"},
		{"/api/v1/configs/ubuntu/version/", "/api/v1/config/:profile/version"},
		{"/api/v1/config/ubuntu", "/api/v1/config/:profile"},
		{"/api/v1/configs/ubuntu", "/api/v1/config/:profile"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeMetricPath(tc.input)
			if got != tc.want {
				t.Errorf("normalizeMetricPath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}

	if got := normalizeMetricPath("/api/v1/config/version"); got == "/api/v1/config/:profile" {
		t.Errorf("/api/v1/config/version must not collapse into /api/v1/config/:profile")
	}
	if _, ok := knownStaticPaths["/api/v1/config/version"]; !ok {
		t.Errorf("expected /api/v1/config/version in knownStaticPaths")
	}
	if _, ok := knownStaticPaths["/api/v1/configs/version"]; !ok {
		t.Errorf("expected /api/v1/configs/version in knownStaticPaths")
	}
}

func TestVersionEndpoints_FullHTTPIntegrationWithRepoConfigs(t *testing.T) {
	cfg, err := core.LoadConfig("../../config.yaml")
	if err != nil {
		t.Fatalf("failed to load ../../config.yaml: %v", err)
	}
	cfg.Server.TLS.Enabled = false

	mgr, err := core.NewMultiConfigManager("../../config.yaml", cfg)
	if err != nil {
		t.Fatalf("failed to create MultiConfigManager from ../../config.yaml: %v", err)
	}

	env := &APIEnv{
		Config:             cfg,
		MultiConfigManager: mgr,
		StartTime:          time.Now().Add(-2 * time.Second),
	}

	ts := httptest.NewServer(NewRouter(env))
	defer ts.Close()

	// 1. GET /api/v1/version
	resVer, err := ts.Client().Get(ts.URL + "/api/v1/version")
	if err != nil {
		t.Fatalf("GET /api/v1/version failed: %v", err)
	}
	defer resVer.Body.Close()
	if resVer.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for /api/v1/version, got %d", resVer.StatusCode)
	}
	verRaw, err := io.ReadAll(resVer.Body)
	if err != nil {
		t.Fatalf("read /api/v1/version body failed: %v", err)
	}
	t.Logf("sample GET /api/v1/version JSON: %s", strings.TrimSpace(string(verRaw)))
	var verPayload version.VersionResponse
	if err := json.Unmarshal(verRaw, &verPayload); err != nil {
		t.Fatalf("decode /api/v1/version failed: %v", err)
	}
	if verPayload.Version != "2.2.0" || verPayload.ConfigVersion != "2.2.0" || verPayload.ConfigVersionPath != "/api/v1/config/version" || verPayload.ConfigFile != "config.yaml" {
		t.Errorf("unexpected /api/v1/version payload: %+v", verPayload)
	}
	hex40 := regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	if !hex40.MatchString(verPayload.GitCommit) {
		t.Errorf("expected 40-char hex git_commit, got %q", verPayload.GitCommit)
	}

	// 2. GET /api/v1/config/version, /api/v1/configs/ubuntu/version, /api/v1/configs/redhat/version
	profileChecks := []struct {
		path       string
		profile    string
		configFile string
		wantPath   string
	}{
		{"/api/v1/config/version", "default", "config.yaml", "/api/v1/config/version"},
		{"/api/v1/configs/ubuntu/version", "ubuntu", "configs/ubuntu-tasks.yaml", "/api/v1/configs/ubuntu/version"},
		{"/api/v1/configs/redhat/version", "redhat", "configs/redhat-tasks.yaml", "/api/v1/configs/redhat/version"},
	}

	for _, pc := range profileChecks {
		resp, err := ts.Client().Get(ts.URL + pc.path)
		if err != nil {
			t.Fatalf("GET %s failed: %v", pc.path, err)
		}
		bodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read %s body failed: %v", pc.path, readErr)
		}
		t.Logf("sample GET %s JSON: %s", pc.path, strings.TrimSpace(string(bodyBytes)))
		var payload ConfigVersionResponse
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			t.Fatalf("decode %s failed: %v", pc.path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK for %s, got %d", pc.path, resp.StatusCode)
		}
		if payload.Version != "2.2.0" || payload.ConfigVersion != "2.2.0" || payload.Profile != pc.profile ||
			payload.ConfigFile != pc.configFile || payload.Path != pc.wantPath || payload.AppVersion != "2.2.0" {
			t.Errorf("unexpected payload for %s: %+v", pc.path, payload)
		}
	}
}
