package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	if resp.Version == "" {
		t.Errorf("expected non-empty Version in response")
	}
	if resp.GitCommit == "" {
		t.Errorf("expected non-empty GitCommit in response")
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
