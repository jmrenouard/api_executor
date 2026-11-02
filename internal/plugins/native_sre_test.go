package plugins

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPrometheusScraperPlugin_Metadata(t *testing.T) {
	p := &PrometheusScraperPlugin{}

	if p.ID() != "prometheus-scraper" {
		t.Fatalf("expected ID 'prometheus-scraper', got %q", p.ID())
	}
	if p.Name() != "Prometheus Metric Scraper & Exposition Parser" {
		t.Fatalf("unexpected Name: %q", p.Name())
	}
	if p.Version() != "1.0.0" {
		t.Fatalf("unexpected Version: %q", p.Version())
	}
	if p.Kind() != KindAdvanced {
		t.Fatalf("expected KindAdvanced, got %q", p.Kind())
	}
	if p.Type() != "native" {
		t.Fatalf("expected Type 'native', got %q", p.Type())
	}
	if p.Category() != "SRE" {
		t.Fatalf("expected Category 'SRE', got %q", p.Category())
	}
	if p.Description() == "" {
		t.Fatalf("expected non-empty Description")
	}

	actions := p.Actions()
	if len(actions) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(actions))
	}

	actionMap := make(map[string]PluginAction)
	for _, a := range actions {
		actionMap[a.Name] = a
	}

	for _, name := range []string{"scrape_metrics", "find_metric", "cardinality_check"} {
		action, exists := actionMap[name]
		if !exists {
			t.Fatalf("missing expected action: %s", name)
		}
		var hasAllowMock bool
		for _, param := range action.Parameters {
			if param.Name == "allow_mock" {
				hasAllowMock = true
				if param.Type != "bool" || param.Default != "false" {
					t.Errorf("action %s allow_mock parameter has unexpected type/default: %+v", name, param)
				}
			}
		}
		if !hasAllowMock {
			t.Errorf("action %s missing 'allow_mock' parameter", name)
		}
	}
}

func TestPrometheusScraperPlugin_RealScrapeSuccess(t *testing.T) {
	promPayload := `# HELP go_goroutines Number of goroutines
# TYPE go_goroutines gauge
go_goroutines 38
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{code="200",method="GET"} 1420
http_requests_total{code="500",method="POST"} 3
# HELP http_requests_duration_seconds Request duration
# TYPE http_requests_duration_seconds summary
http_requests_duration_seconds{quantile="0.99"} 0.052
`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(promPayload))
	}))
	defer ts.Close()

	p := &PrometheusScraperPlugin{}
	ctx := context.Background()

	// 1. scrape_metrics
	res, err := p.Execute(ctx, "scrape_metrics", map[string]any{"url": ts.URL}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error scraping real server: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("expected status 'ok', got %q (%s)", res.Status, res.Error)
	}
	dataMap, ok := res.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected res.Data to be map[string]any, got %T", res.Data)
	}
	totalSamples, ok := dataMap["total_samples"].(int)
	if !ok || totalSamples != 4 {
		t.Fatalf("expected total_samples=4, got %v", dataMap["total_samples"])
	}

	// 2. find_metric
	res, err = p.Execute(ctx, "find_metric", map[string]any{"url": ts.URL, "metric_name": "http_requests_total"}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error finding metric: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("expected status 'ok', got %q (%s)", res.Status, res.Error)
	}
	dataMap, ok = res.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected res.Data to be map[string]any, got %T", res.Data)
	}
	matchCount, ok := dataMap["match_count"].(int)
	if !ok || matchCount != 2 {
		t.Fatalf("expected match_count=2, got %v", dataMap["match_count"])
	}

	// 3. cardinality_check
	res, err = p.Execute(ctx, "cardinality_check", map[string]any{"url": ts.URL}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error in cardinality_check: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("expected status 'ok', got %q (%s)", res.Status, res.Error)
	}
	dataMap, ok = res.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected res.Data to be map[string]any, got %T", res.Data)
	}
	uniqueNames, ok := dataMap["unique_metric_names"].(int)
	if !ok || uniqueNames != 3 {
		t.Fatalf("expected unique_metric_names=3, got %v", dataMap["unique_metric_names"])
	}
	sampleCounts, ok := dataMap["sample_counts"].(map[string]int)
	if !ok || sampleCounts["http_requests_total"] != 2 {
		t.Fatalf("expected sample_counts['http_requests_total']=2, got %v", dataMap["sample_counts"])
	}
}

func TestPrometheusScraperPlugin_UnreachableTargetGenuineError(t *testing.T) {
	p := &PrometheusScraperPlugin{}
	ctx := context.Background()

	// Pick a non-existent port on localhost where nothing is listening
	unreachableURL := "http://127.0.0.1:59998/metrics"

	for _, action := range []string{"scrape_metrics", "find_metric", "cardinality_check"} {
		params := map[string]any{
			"url": unreachableURL,
		}
		if action == "find_metric" {
			params["metric_name"] = "go_goroutines"
		}

		res, err := p.Execute(ctx, action, params, 5*time.Second)
		if err == nil {
			t.Fatalf("action %s: expected genuine error for unreachable URL, got nil error", action)
		}
		if res.Status != "error" {
			t.Fatalf("action %s: expected status 'error', got %q", action, res.Status)
		}
		if !strings.Contains(res.Error, "prometheus scrape failed for") {
			t.Fatalf("action %s: expected error message mentioning 'prometheus scrape failed for', got %q", action, res.Error)
		}
		// Confirm zero hardcoded fake metrics were returned
		if strings.Contains(res.Output, "api_executor_actions_total") || strings.Contains(res.Output, "8452100") {
			t.Fatalf("action %s: violation! Fake mock metrics leaked in output on failure: %q", action, res.Output)
		}
		if res.Data != nil {
			t.Fatalf("action %s: expected nil Data on error, got %+v", action, res.Data)
		}
	}
}

func TestPrometheusScraperPlugin_HTTP500GenuineError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error in metrics exporter", http.StatusInternalServerError)
	}))
	defer ts.Close()

	p := &PrometheusScraperPlugin{}
	ctx := context.Background()

	res, err := p.Execute(ctx, "scrape_metrics", map[string]any{"url": ts.URL}, 5*time.Second)
	if err == nil {
		t.Fatalf("expected error for HTTP 500 response, got nil")
	}
	if res.Status != "error" {
		t.Fatalf("expected status 'error', got %q", res.Status)
	}
	if !strings.Contains(res.Error, "non-2xx status code 500") {
		t.Fatalf("expected error message to mention 'non-2xx status code 500', got %q", res.Error)
	}
	if strings.Contains(res.Output, "api_executor_actions_total") {
		t.Fatalf("violation: mock metrics returned when HTTP 500 encountered: %s", res.Output)
	}
}

func TestPrometheusScraperPlugin_HTTP404GenuineError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	p := &PrometheusScraperPlugin{}
	ctx := context.Background()

	res, err := p.Execute(ctx, "scrape_metrics", map[string]any{"url": ts.URL}, 5*time.Second)
	if err == nil {
		t.Fatalf("expected error for HTTP 404 response, got nil")
	}
	if res.Status != "error" {
		t.Fatalf("expected status 'error', got %q", res.Status)
	}
	if !strings.Contains(res.Error, "non-2xx status code 404") {
		t.Fatalf("expected error to mention 'non-2xx status code 404', got %q", res.Error)
	}
}

func TestPrometheusScraperPlugin_InvalidURLGenuineError(t *testing.T) {
	p := &PrometheusScraperPlugin{}
	ctx := context.Background()

	res, err := p.Execute(ctx, "scrape_metrics", map[string]any{"url": "http://[::1]:namedport"}, 5*time.Second)
	if err == nil {
		t.Fatalf("expected error for invalid URL, got nil")
	}
	if res.Status != "error" {
		t.Fatalf("expected status 'error', got %q", res.Status)
	}
	if !strings.Contains(res.Error, "invalid prometheus scrape request") {
		t.Fatalf("expected error to mention 'invalid prometheus scrape request', got %q", res.Error)
	}
}

func TestPrometheusScraperPlugin_ExplicitAllowMock(t *testing.T) {
	p := &PrometheusScraperPlugin{}
	ctx := context.Background()
	unreachableURL := "http://127.0.0.1:59998/metrics"

	// 1. With allow_mock: true, mock metrics are returned as explicit fallback
	res, err := p.Execute(ctx, "scrape_metrics", map[string]any{
		"url":        unreachableURL,
		"allow_mock": true,
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("expected no error when allow_mock=true, got: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("expected status 'ok' when allow_mock=true, got %q", res.Status)
	}
	dataMap, ok := res.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected res.Data to be map[string]any, got %T", res.Data)
	}
	totalSamples, ok := dataMap["total_samples"].(int)
	if !ok || totalSamples == 0 {
		t.Fatalf("expected non-zero samples when allow_mock=true, got %v", dataMap["total_samples"])
	}
	if !strings.Contains(res.Output, "api_executor_actions_total") {
		t.Fatalf("expected mock metrics in output when allow_mock=true, got %s", res.Output)
	}

	// 2. Also with allow_mock: "true" (string boolean)
	res, err = p.Execute(ctx, "scrape_metrics", map[string]any{
		"url":        unreachableURL,
		"allow_mock": "true",
	}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Fatalf("expected success with allow_mock='true', got err=%v, status=%s", err, res.Status)
	}

	// 3. With allow_mock: false, genuine error is returned and NO mock metrics
	res, err = p.Execute(ctx, "scrape_metrics", map[string]any{
		"url":        unreachableURL,
		"allow_mock": false,
	}, 5*time.Second)
	if err == nil {
		t.Fatalf("expected error when allow_mock=false, got nil")
	}
	if res.Status != "error" {
		t.Fatalf("expected status 'error' when allow_mock=false, got %q", res.Status)
	}
	if strings.Contains(res.Output, "api_executor_actions_total") {
		t.Fatalf("violation: mock metrics returned when allow_mock=false: %s", res.Output)
	}
}

func TestPrometheusScraperPlugin_DirectContentParam(t *testing.T) {
	promPayload := `# HELP memory_bytes Memory
# TYPE memory_bytes gauge
memory_bytes 1048576
`
	p := &PrometheusScraperPlugin{}
	ctx := context.Background()

	// scrape_metrics with content
	res, err := p.Execute(ctx, "scrape_metrics", map[string]any{"content": promPayload}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Fatalf("expected success with direct content, got: err=%v, res=%+v", err, res)
	}
	dataMap, ok := res.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected res.Data to be map[string]any, got %T", res.Data)
	}
	if dataMap["total_samples"] != 1 {
		t.Fatalf("expected 1 sample, got %v", dataMap["total_samples"])
	}

	// find_metric with content
	res, err = p.Execute(ctx, "find_metric", map[string]any{"content": promPayload, "metric_name": "memory_bytes"}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Fatalf("expected success finding metric with content, got: err=%v, res=%+v", err, res)
	}
	dataMap, ok = res.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected res.Data to be map[string]any, got %T", res.Data)
	}
	if dataMap["match_count"] != 1 {
		t.Fatalf("expected 1 match, got %v", dataMap["match_count"])
	}

	// cardinality_check with content
	res, err = p.Execute(ctx, "cardinality_check", map[string]any{"content": promPayload}, 5*time.Second)
	if err != nil || res.Status != "ok" {
		t.Fatalf("expected success in cardinality_check with content, got: err=%v, res=%+v", err, res)
	}
	dataMap, ok = res.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected res.Data to be map[string]any, got %T", res.Data)
	}
	if dataMap["unique_metric_names"] != 1 {
		t.Fatalf("expected 1 unique metric name, got %v", dataMap["unique_metric_names"])
	}
}

func TestPrometheusScraperPlugin_UnknownAction(t *testing.T) {
	p := &PrometheusScraperPlugin{}
	ctx := context.Background()

	res, err := p.Execute(ctx, "non_existent_action", map[string]any{"content": "dummy 1"}, 5*time.Second)
	if err != ErrActionNotFound {
		t.Fatalf("expected ErrActionNotFound, got %v", err)
	}
	if res.Status != "error" {
		t.Fatalf("expected status 'error', got %q", res.Status)
	}
}
