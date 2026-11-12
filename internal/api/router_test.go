package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go-admin-tool/internal/core"
)

func setupTestRouterForMetrics(t *testing.T) http.Handler {
	t.Helper()
	logger, err := core.NewLogger(core.LoggingConfig{Level: "error"})
	if err != nil {
		t.Fatalf("failed to initialize test logger: %v", err)
	}
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Executor.Enabled = true
	env := &APIEnv{
		Config: cfg,
		Logger: logger,
	}
	return NewRouter(env)
}

func getGatheredPathLabels(t *testing.T, metricName string) map[string]int {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("failed to gather prometheus metrics: %v", err)
	}
	paths := make(map[string]int)
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "path" {
					paths[lp.GetValue()]++
				}
			}
		}
	}
	return paths
}

func TestNormalizeMetricPath(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		// 1. Dynamic routes
		{"files dynamic with filename", "/api/v1/files/secret.pdf", "/api/v1/files/:filename"},
		{"files dynamic nested", "/api/v1/files/sub/file.txt", "/api/v1/files/:filename"},
		{"files trailing slash", "/api/v1/files/", "/api/v1/files/:filename"},
		{"mcp traces dynamic uuid", "/api/v1/mcp/traces/uuid-999", "/api/v1/mcp/traces/:trace_id"},
		{"mcp traces dynamic custom", "/api/v1/mcp/traces/trace-session-42", "/api/v1/mcp/traces/:trace_id"},

		// 2. Exact static routes
		{"root path", "/", "/"},
		{"index html", "/index.html", "/index.html"},
		{"health endpoint", "/health", "/health"},
		{"metrics endpoint", "/metrics", "/metrics"},
		{"otlp metrics endpoint", "/api/v1/metrics/otlp", "/api/v1/metrics/otlp"},
		{"swagger base", "/swagger", "/swagger"},
		{"swagger trailing slash", "/swagger/", "/swagger"},
		{"swagger doc json", "/swagger/doc.json", "/swagger"},
		{"swagger index html", "/swagger/index.html", "/swagger"},
		{"commands static", "/api/v1/commands", "/api/v1/commands"},
		{"execute static", "/api/v1/execute", "/api/v1/execute"},
		{"presets static", "/api/v1/presets", "/api/v1/presets"},
		{"presets activate static", "/api/v1/presets/activate", "/api/v1/presets/activate"},
		{"files static list", "/api/v1/files", "/api/v1/files"},
		{"tls info static", "/api/v1/tls/info", "/api/v1/tls/info"},
		{"tls certificate static", "/api/v1/tls/certificate", "/api/v1/tls/certificate"},
		{"tls renew static", "/api/v1/tls/renew", "/api/v1/tls/renew"},
		{"tls certificate renew static", "/api/v1/tls/certificate/renew", "/api/v1/tls/certificate/renew"},
		{"audit logs static", "/api/v1/audit/logs", "/api/v1/audit/logs"},
		{"audit verify static", "/api/v1/audit/verify", "/api/v1/audit/verify"},
		{"logs static", "/api/v1/logs", "/api/v1/logs"},
		{"history static", "/api/v1/history", "/api/v1/history"},
		{"auth login static", "/api/v1/auth/login", "/api/v1/auth/login"},
		{"auth me static", "/api/v1/auth/me", "/api/v1/auth/me"},
		{"auth users static", "/api/v1/auth/users", "/api/v1/auth/users"},
		{"auth tokens static", "/api/v1/auth/tokens", "/api/v1/auth/tokens"},
		{"auth credentials static", "/api/v1/auth/credentials", "/api/v1/auth/credentials"},
		{"auth service accounts static", "/api/v1/auth/service-accounts", "/api/v1/auth/service-accounts"},
		{"auth service accounts rotate static", "/api/v1/auth/service-accounts/rotate", "/api/v1/auth/service-accounts/rotate"},
		{"plugins static", "/api/v1/plugins", "/api/v1/plugins"},
		{"plugins catalog static", "/api/v1/plugins/catalog", "/api/v1/plugins/catalog"},
		{"plugins execute static", "/api/v1/plugins/execute", "/api/v1/plugins/execute"},
		{"plugins declarative static", "/api/v1/plugins/declarative", "/api/v1/plugins/declarative"},
		{"db tables static", "/api/v1/db/tables", "/api/v1/db/tables"},
		{"db query static", "/api/v1/db/query", "/api/v1/db/query"},
		{"mcp base static", "/api/v1/mcp", "/api/v1/mcp"},
		{"mcp tools static", "/api/v1/mcp/tools", "/api/v1/mcp/tools"},
		{"mcp resources static", "/api/v1/mcp/resources", "/api/v1/mcp/resources"},
		{"mcp traces static list", "/api/v1/mcp/traces", "/api/v1/mcp/traces"},
		{"jobs static base", "/api/v1/jobs", "/api/v1/jobs"},
		{"jobs queue static", "/api/v1/jobs/queue", "/api/v1/jobs/queue"},

		// 3. Static routes with trailing slashes
		{"health with trailing slash", "/health/", "/health"},
		{"commands with trailing slash", "/api/v1/commands/", "/api/v1/commands"},
		{"metrics with trailing slash", "/metrics/", "/metrics"},
		{"otlp metrics with trailing slash", "/api/v1/metrics/otlp/", "/api/v1/metrics/otlp"},
		{"jobs with trailing slash", "/api/v1/jobs/", "/api/v1/jobs"},
		{"jobs queue with trailing slash", "/api/v1/jobs/queue/", "/api/v1/jobs/queue"},

		// Dynamic jobs routes
		{"jobs dynamic id", "/api/v1/jobs/job_123456", "/api/v1/jobs/:id"},
		{"jobs dynamic id trailing slash", "/api/v1/jobs/job_123456/", "/api/v1/jobs/:id"},
		{"jobs dynamic id logs", "/api/v1/jobs/job_123456/logs", "/api/v1/jobs/:id/logs"},
		{"jobs dynamic id logs trailing slash", "/api/v1/jobs/job_123456/logs/", "/api/v1/jobs/:id/logs"},
		{"jobs dynamic id cancel", "/api/v1/jobs/job_123456/cancel", "/api/v1/jobs/:id/cancel"},
		{"jobs dynamic id cancel trailing slash", "/api/v1/jobs/job_123456/cancel/", "/api/v1/jobs/:id/cancel"},
		{"jobs invalid deep subpath", "/api/v1/jobs/a/b/c", "other"},

		// 4. Unrecognized or random 404 paths
		{"random 1", "/random-1", "other"},
		{"random 2", "/random-2", "other"},
		{"fuzz 3", "/fuzz-3", "other"},
		{"unknown api path", "/api/v2/users", "other"},
		{"empty path", "", "other"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeMetricPath(tc.input)
			if got != tc.expected {
				t.Errorf("normalizeMetricPath(%q) = %q, expected %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestPrometheusMetricDynamicRouteNormalization(t *testing.T) {
	ResetHTTPMetrics()
	router := setupTestRouterForMetrics(t)

	// Send requests to dynamic file routes
	fileUrls := []string{
		"/api/v1/files/secret.pdf",
		"/api/v1/files/another-file.png",
	}
	for _, url := range fileUrls {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}

	// Send requests to dynamic mcp trace routes
	traceUrls := []string{
		"/api/v1/mcp/traces/uuid-999",
		"/api/v1/mcp/traces/trace-alpha-001",
	}
	for _, url := range traceUrls {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}

	// Verify Prometheus label values collapsed to template paths
	pathLabels := getGatheredPathLabels(t, "http_requests_total")

	if _, found := pathLabels["/api/v1/files/:filename"]; !found {
		t.Errorf("expected metric path label '/api/v1/files/:filename' to be present")
	}
	if _, found := pathLabels["/api/v1/mcp/traces/:trace_id"]; !found {
		t.Errorf("expected metric path label '/api/v1/mcp/traces/:trace_id' to be present")
	}

	// Verify unnormalized dynamic URLs were NEVER created as raw labels
	for _, rawURL := range append(fileUrls, traceUrls...) {
		if _, found := pathLabels[rawURL]; found {
			t.Errorf("unnormalized dynamic URL %q was improperly registered as a Prometheus path label", rawURL)
		}
	}
}

func TestPrometheusMetricJobRouteNormalization(t *testing.T) {
	ResetHTTPMetrics()
	router := setupTestRouterForMetrics(t)

	jobUrls := []string{
		"/api/v1/jobs/job_123",
		"/api/v1/jobs/job_456",
		"/api/v1/jobs/job_789/logs",
		"/api/v1/jobs/job_789/cancel",
	}
	for _, url := range jobUrls {
		method := http.MethodGet
		if strings.HasSuffix(url, "/cancel") {
			method = http.MethodPost
		}
		req := httptest.NewRequest(method, url, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}

	pathLabels := getGatheredPathLabels(t, "http_requests_total")

	if _, found := pathLabels["/api/v1/jobs/:id"]; !found {
		t.Errorf("expected metric path label '/api/v1/jobs/:id' to be present")
	}
	if _, found := pathLabels["/api/v1/jobs/:id/logs"]; !found {
		t.Errorf("expected metric path label '/api/v1/jobs/:id/logs' to be present")
	}
	if _, found := pathLabels["/api/v1/jobs/:id/cancel"]; !found {
		t.Errorf("expected metric path label '/api/v1/jobs/:id/cancel' to be present")
	}

	for _, rawURL := range jobUrls {
		if _, found := pathLabels[rawURL]; found {
			t.Errorf("unnormalized dynamic URL %q was improperly registered as a Prometheus path label", rawURL)
		}
	}
}

func TestPrometheusMetricPathCardinalityBounding(t *testing.T) {
	ResetHTTPMetrics()
	router := setupTestRouterForMetrics(t)

	const fuzzRequests = 50
	for i := 0; i < fuzzRequests; i++ {
		randomPath := fmt.Sprintf("/random-%d", i)
		req := httptest.NewRequest(http.MethodGet, randomPath, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404 for random path %s, got %d", randomPath, rec.Code)
		}
	}

	// Also send random fuzz paths with multiple segments
	extraFuzz := []string{"/fuzz-3", "/attacker/sqli-test", "/probe/v2/debug"}
	for _, p := range extraFuzz {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}

	totalOther := float64(fuzzRequests + len(extraFuzz))

	// Verify that all arbitrary paths collapsed under the single label "other"
	otherCounter := httpRequestsTotal.WithLabelValues(http.MethodGet, "other", strconv.Itoa(http.StatusNotFound))
	var m dto.Metric
	if err := otherCounter.Write(&m); err != nil || m.Counter == nil {
		t.Fatalf("failed to read other counter value: %v", err)
	}
	if m.Counter.GetValue() != totalOther {
		t.Errorf("expected 'other' counter value %v, got %v", totalOther, m.Counter.GetValue())
	}

	// Gather all metric families and inspect path labels
	pathLabels := getGatheredPathLabels(t, "http_requests_total")

	if _, found := pathLabels["other"]; !found {
		t.Errorf("expected 'other' path label to be recorded in Prometheus")
	}

	// Ensure NONE of the fuzz paths exist as individual time series
	for i := 0; i < fuzzRequests; i++ {
		randomPath := fmt.Sprintf("/random-%d", i)
		if _, found := pathLabels[randomPath]; found {
			t.Errorf("cardinality explosion detected: raw path %q created an individual time series", randomPath)
		}
	}
	for _, p := range extraFuzz {
		if _, found := pathLabels[p]; found {
			t.Errorf("cardinality explosion detected: raw path %q created an individual time series", p)
		}
	}
}

func TestPrometheusMetricStaticRoutesPreserved(t *testing.T) {
	ResetHTTPMetrics()
	router := setupTestRouterForMetrics(t)

	staticEndpoints := []string{
		"/api/v1/commands",
		"/api/v1/history",
		"/metrics",
	}

	for _, ep := range staticEndpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}

	pathLabels := getGatheredPathLabels(t, "http_requests_total")
	for _, ep := range staticEndpoints {
		if _, found := pathLabels[ep]; !found {
			t.Errorf("expected static route %q to be preserved in Prometheus path labels", ep)
		}
	}
}
