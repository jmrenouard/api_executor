package api_test

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"

	"go-admin-tool/internal/api"
	"go-admin-tool/internal/core"
)

func TestTranslatePrometheusToOTLP_TypesAndConversions(t *testing.T) {
	counterName := "test_requests_total"
	counterHelp := "Total test requests count."
	counterVal := 42.0

	gaugeName := "test_memory_bytes"
	gaugeHelp := "Current memory in bytes."
	gaugeVal := 1048576.0

	histName := "test_latency_seconds"
	histHelp := "Latency in seconds."
	histCount := uint64(10)
	histSum := 1.25

	untypedName := "test_untyped_metric"
	untypedHelp := "Untyped test metric."
	untypedVal := 99.0

	labelName := "method"
	labelVal := "GET"
	leLabel := "le"
	leVal := "0.1"

	mfs := []*dto.MetricFamily{
		// 1. Counter
		{
			Name: proto.String(counterName),
			Help: proto.String(counterHelp),
			Type: dto.MetricType_COUNTER.Enum(),
			Metric: []*dto.Metric{
				{
					Label: []*dto.LabelPair{
						{Name: proto.String(labelName), Value: proto.String(labelVal)},
					},
					Counter: &dto.Counter{Value: proto.Float64(counterVal)},
				},
			},
		},
		// 2. Gauge
		{
			Name: proto.String(gaugeName),
			Help: proto.String(gaugeHelp),
			Type: dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{
				{
					Label: []*dto.LabelPair{
						{Name: proto.String(labelName), Value: proto.String(labelVal)},
					},
					Gauge: &dto.Gauge{Value: proto.Float64(gaugeVal)},
				},
			},
		},
		// 3. Histogram
		{
			Name: proto.String(histName),
			Help: proto.String(histHelp),
			Type: dto.MetricType_HISTOGRAM.Enum(),
			Metric: []*dto.Metric{
				{
					Label: []*dto.LabelPair{
						{Name: proto.String(labelName), Value: proto.String(labelVal)},
						{Name: proto.String(leLabel), Value: proto.String(leVal)}, // should be excluded
					},
					Histogram: &dto.Histogram{
						SampleCount: proto.Uint64(histCount),
						SampleSum:   proto.Float64(histSum),
						Bucket: []*dto.Bucket{
							{UpperBound: proto.Float64(0.05), CumulativeCount: proto.Uint64(3)},
							{UpperBound: proto.Float64(0.1), CumulativeCount: proto.Uint64(7)},
							{UpperBound: proto.Float64(0.5), CumulativeCount: proto.Uint64(9)},
							{UpperBound: proto.Float64(math.Inf(1)), CumulativeCount: proto.Uint64(10)}, // +Inf omitted in bounds
						},
					},
				},
			},
		},
		// 4. Untyped
		{
			Name: proto.String(untypedName),
			Help: proto.String(untypedHelp),
			Type: dto.MetricType_UNTYPED.Enum(),
			Metric: []*dto.Metric{
				{
					Label: []*dto.LabelPair{
						{Name: proto.String(labelName), Value: proto.String(labelVal)},
					},
					Untyped: &dto.Untyped{Value: proto.Float64(untypedVal)},
				},
			},
		},
	}

	startTime := time.Now().Add(-10 * time.Minute)
	extraAttrs := map[string]string{
		"deployment.environment": "staging",
	}

	otlpReq := api.TranslatePrometheusToOTLP(mfs, "my-service", "2.2.0", startTime, extraAttrs)
	if otlpReq == nil || len(otlpReq.ResourceMetrics) == 0 {
		t.Fatalf("expected non-empty ResourceMetrics")
	}

	rm := otlpReq.ResourceMetrics[0]
	// Verify Resource attributes
	attrMap := make(map[string]string)
	for _, attr := range rm.Resource.Attributes {
		if attr.Value.StringValue != nil {
			attrMap[attr.Key] = *attr.Value.StringValue
		}
	}
	if attrMap["service.name"] != "my-service" {
		t.Errorf("expected service.name 'my-service', got %q", attrMap["service.name"])
	}
	if attrMap["service.version"] != "2.2.0" {
		t.Errorf("expected service.version '2.2.0', got %q", attrMap["service.version"])
	}
	if attrMap["deployment.environment"] != "staging" {
		t.Errorf("expected deployment.environment 'staging', got %q", attrMap["deployment.environment"])
	}

	if len(rm.ScopeMetrics) == 0 {
		t.Fatalf("expected non-empty ScopeMetrics")
	}
	metrics := rm.ScopeMetrics[0].Metrics
	if len(metrics) != 4 {
		t.Fatalf("expected 4 converted metrics, got %d", len(metrics))
	}

	// 1. Check Counter -> Sum
	m0 := metrics[0]
	if m0.Name != counterName || m0.Unit != "1" || m0.Sum == nil {
		t.Fatalf("expected Sum metric for %s, got %+v", counterName, m0)
	}
	if !m0.Sum.IsMonotonic || m0.Sum.AggregationTemporality != 2 {
		t.Errorf("expected monotonic cumulative sum, got monotonic=%v temporality=%d", m0.Sum.IsMonotonic, m0.Sum.AggregationTemporality)
	}
	if len(m0.Sum.DataPoints) != 1 || *m0.Sum.DataPoints[0].AsDouble != counterVal {
		t.Errorf("expected counter value %f, got %+v", counterVal, m0.Sum.DataPoints)
	}

	// 2. Check Gauge
	m1 := metrics[1]
	if m1.Name != gaugeName || m1.Unit != "By" || m1.Gauge == nil {
		t.Fatalf("expected Gauge metric for %s, got %+v", gaugeName, m1)
	}
	if len(m1.Gauge.DataPoints) != 1 || *m1.Gauge.DataPoints[0].AsDouble != gaugeVal {
		t.Errorf("expected gauge value %f, got %+v", gaugeVal, m1.Gauge.DataPoints)
	}

	// 3. Check Histogram
	m2 := metrics[2]
	if m2.Name != histName || m2.Unit != "s" || m2.Histogram == nil {
		t.Fatalf("expected Histogram metric for %s, got %+v", histName, m2)
	}
	if m2.Histogram.AggregationTemporality != 2 {
		t.Errorf("expected cumulative temporality (2), got %d", m2.Histogram.AggregationTemporality)
	}
	if len(m2.Histogram.DataPoints) != 1 {
		t.Fatalf("expected 1 histogram data point, got %d", len(m2.Histogram.DataPoints))
	}
	dp := m2.Histogram.DataPoints[0]
	if dp.Count != "10" {
		t.Errorf("expected count '10', got %q", dp.Count)
	}
	if dp.Sum == nil || *dp.Sum != histSum {
		t.Errorf("expected sum %f, got %v", histSum, dp.Sum)
	}
	// ExplicitBounds: [0.05, 0.1, 0.5] (omits +Inf)
	if len(dp.ExplicitBounds) != 3 || dp.ExplicitBounds[0] != 0.05 || dp.ExplicitBounds[1] != 0.1 || dp.ExplicitBounds[2] != 0.5 {
		t.Errorf("unexpected explicitBounds: %+v", dp.ExplicitBounds)
	}
	// BucketCounts deltas: [3, 4, 2, 1]
	if len(dp.BucketCounts) != 4 || dp.BucketCounts[0] != "3" || dp.BucketCounts[1] != "4" || dp.BucketCounts[2] != "2" || dp.BucketCounts[3] != "1" {
		t.Errorf("unexpected bucketCounts: %+v", dp.BucketCounts)
	}
	// Verify "le" label is excluded from attributes
	for _, attr := range dp.Attributes {
		if attr.Key == "le" {
			t.Errorf("expected 'le' label to be stripped from histogram attributes, but found it")
		}
	}

	// 4. Check Untyped -> Gauge fallback
	m3 := metrics[3]
	if m3.Name != untypedName || m3.Gauge == nil {
		t.Fatalf("expected Gauge fallback for untyped metric, got %+v", m3)
	}
	if len(m3.Gauge.DataPoints) != 1 || *m3.Gauge.DataPoints[0].AsDouble != untypedVal {
		t.Errorf("expected untyped value %f, got %+v", untypedVal, m3.Gauge.DataPoints)
	}
}

func TestOTLPMetricsHandler_SuccessGET(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.OTLPExport = core.OTLPExportConfig{
		Enabled: true,
		ResourceAttributes: map[string]string{
			"service.name": "test-daemon",
		},
	}

	env := &api.APIEnv{
		Config:    cfg,
		StartTime: time.Now().Add(-1 * time.Hour),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/otlp", nil)
	rr := httptest.NewRecorder()

	env.OTLPMetricsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected application/json Content-Type, got %q", ct)
	}

	var otlpReq api.OTLPExportMetricsRequest
	if err := json.Unmarshal(rr.Body.Bytes(), &otlpReq); err != nil {
		t.Fatalf("failed to parse OTLP response JSON: %v", err)
	}

	if len(otlpReq.ResourceMetrics) == 0 {
		t.Fatalf("expected non-empty ResourceMetrics")
	}

	rm := otlpReq.ResourceMetrics[0]
	foundServiceName := false
	for _, attr := range rm.Resource.Attributes {
		if attr.Key == "service.name" && attr.Value.StringValue != nil && *attr.Value.StringValue == "test-daemon" {
			foundServiceName = true
			break
		}
	}
	if !foundServiceName {
		t.Errorf("expected service.name 'test-daemon' in resource attributes")
	}
}

func TestOTLPMetricsHandler_MethodNotAllowed(t *testing.T) {
	env := &api.APIEnv{
		Config: core.DefaultConfig(),
	}

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, m := range methods {
		req := httptest.NewRequest(m, "/api/v1/metrics/otlp", strings.NewReader(`{}`))
		rr := httptest.NewRecorder()

		env.OTLPMetricsHandler(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 Method Not Allowed for %s, got %d", m, rr.Code)
		}
		if allow := rr.Header().Get("Allow"); allow != "GET" {
			t.Errorf("expected Allow: GET header, got %q", allow)
		}
	}
}

func TestBuildOTLPMetrics_CustomGatherer(t *testing.T) {
	customReg := prometheus.NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "custom_counter_total",
		Help: "Custom counter help",
	})
	customReg.MustRegister(counter)
	counter.Inc()

	cfg := core.OTLPExportConfig{
		Enabled: true,
		ResourceAttributes: map[string]string{
			"service.name": "custom-reg-service",
		},
	}

	payload, err := api.BuildOTLPMetrics(cfg, customReg, time.Now())
	if err != nil {
		t.Fatalf("BuildOTLPMetrics failed: %v", err)
	}

	if len(payload.ResourceMetrics) == 0 {
		t.Fatalf("expected non-empty ResourceMetrics")
	}
	metrics := payload.ResourceMetrics[0].ScopeMetrics[0].Metrics
	if len(metrics) != 1 || metrics[0].Name != "custom_counter_total" {
		t.Errorf("expected custom_counter_total metric, got %+v", metrics)
	}
}

func TestNewOTLPPusher_NoOpAndValidation(t *testing.T) {
	// 1. Disabled or empty endpoint returns (nil, nil) as a no-op
	p, err := api.NewOTLPPusher(core.OTLPExportConfig{Enabled: false, Endpoint: "http://127.0.0.1:4318/v1/metrics"}, nil, time.Now(), nil)
	if err != nil || p != nil {
		t.Fatalf("expected (nil, nil) when disabled, got (%v, %v)", p, err)
	}

	p, err = api.NewOTLPPusher(core.OTLPExportConfig{Enabled: true, Endpoint: "   "}, nil, time.Now(), nil)
	if err != nil || p != nil {
		t.Fatalf("expected (nil, nil) when endpoint is empty, got (%v, %v)", p, err)
	}

	// 2. Disallowed URL schemes and missing hosts are rejected
	invalidEndpoints := []string{
		"file:///etc/passwd",
		"ftp://collector.internal:4318/v1/metrics",
		"gopher://127.0.0.1:4318",
		"http:///v1/metrics",
		"https://",
		"http://:4318/v1/metrics",
		"://bad-url",
	}
	for _, ep := range invalidEndpoints {
		p, err := api.NewOTLPPusher(core.OTLPExportConfig{Enabled: true, Endpoint: ep}, nil, time.Now(), nil)
		if err == nil || p != nil {
			t.Errorf("expected error for invalid endpoint %q, got (%v, %v)", ep, p, err)
		}
	}
}

func TestOTLPPusher_PushOnce_SuccessAndHeaders(t *testing.T) {
	customReg := prometheus.NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "otlp_push_test_total",
		Help: "Counter for OTLP push test.",
	})
	customReg.MustRegister(counter)
	counter.Add(7)

	var gotMethod string
	var gotContentType string
	var gotAPIKey string
	var gotAuth string
	var gotBody []byte

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAPIKey = r.Header.Get("DD-API-KEY")
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"partialSuccess":{}}`))
	}))
	defer collector.Close()

	cfg := core.OTLPExportConfig{
		Enabled:  true,
		Endpoint: collector.URL + "/v1/metrics",
		Timeout:  "5s",
		Headers: map[string]string{
			"DD-API-KEY":    "secret-key",
			"Authorization": "Bearer token-123",
		},
		ResourceAttributes: map[string]string{
			"service.name": "otlp-pusher-test",
		},
	}

	pusher, err := api.NewOTLPPusher(cfg, customReg, time.Now().Add(-time.Minute), nil)
	if err != nil {
		t.Fatalf("NewOTLPPusher failed: %v", err)
	}
	defer func() { _ = pusher.Close() }()

	if err := pusher.PushOnce(context.Background()); err != nil {
		t.Fatalf("PushOnce failed: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("expected POST method, got %q", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", gotContentType)
	}
	if gotAPIKey != "secret-key" || gotAuth != "Bearer token-123" {
		t.Errorf("custom headers not forwarded properly: DD-API-KEY=%q Authorization=%q", gotAPIKey, gotAuth)
	}

	var decoded api.OTLPExportMetricsRequest
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("collector received invalid OTLP JSON: %v", err)
	}
	if len(decoded.ResourceMetrics) == 0 || len(decoded.ResourceMetrics[0].ScopeMetrics) == 0 {
		t.Fatalf("expected non-empty ResourceMetrics and ScopeMetrics")
	}
	metrics := decoded.ResourceMetrics[0].ScopeMetrics[0].Metrics
	if len(metrics) != 1 || metrics[0].Name != "otlp_push_test_total" {
		t.Errorf("expected otlp_push_test_total in pushed payload, got %+v", metrics)
	}

	stats := pusher.Stats()
	if !stats.Enabled || stats.PushCount != 1 || stats.ErrorCount != 0 || stats.LastPushAt.IsZero() || stats.LastError != "" {
		t.Errorf("unexpected pusher stats after success: %+v", stats)
	}
}

func TestOTLPPusher_PushOnce_ErrorStatusRedirectAndTLS(t *testing.T) {
	// 1. Non-2xx response with > 4 KiB body
	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(strings.Repeat("X", 16*1024)))
	}))
	defer errServer.Close()

	customReg := prometheus.NewRegistry()
	pusher, err := api.NewOTLPPusher(core.OTLPExportConfig{
		Enabled:  true,
		Endpoint: errServer.URL,
		Timeout:  "2s",
	}, customReg, time.Now(), nil)
	if err != nil {
		t.Fatalf("NewOTLPPusher failed: %v", err)
	}
	defer func() { _ = pusher.Close() }()

	if err := pusher.PushOnce(context.Background()); err == nil {
		t.Fatalf("expected error on 503 response")
	}
	stats := pusher.Stats()
	if stats.PushCount != 0 || stats.ErrorCount != 1 || !strings.Contains(stats.LastError, "503") {
		t.Errorf("unexpected stats after 503 failure: %+v", stats)
	}

	// 2. Redirect to disallowed scheme (file://) must be refused
	redirServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer redirServer.Close()

	redirPusher, err := api.NewOTLPPusher(core.OTLPExportConfig{
		Enabled:  true,
		Endpoint: redirServer.URL,
		Timeout:  "2s",
	}, customReg, time.Now(), nil)
	if err != nil {
		t.Fatalf("NewOTLPPusher failed: %v", err)
	}
	defer func() { _ = redirPusher.Close() }()

	if err := redirPusher.PushOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "disallowed scheme") {
		t.Errorf("expected disallowed scheme redirect error, got %v", err)
	}

	// 3. HTTPS TLS verification vs InsecureSkipVerify
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer tlsServer.Close()

	strictTLS, err := api.NewOTLPPusher(core.OTLPExportConfig{
		Enabled:            true,
		Endpoint:           tlsServer.URL,
		InsecureSkipVerify: false,
	}, customReg, time.Now(), nil)
	if err != nil {
		t.Fatalf("NewOTLPPusher failed: %v", err)
	}
	defer func() { _ = strictTLS.Close() }()
	if err := strictTLS.PushOnce(context.Background()); err == nil {
		t.Errorf("expected TLS verification failure against self-signed httptest TLS server")
	}

	insecureTLS, err := api.NewOTLPPusher(core.OTLPExportConfig{
		Enabled:            true,
		Endpoint:           tlsServer.URL,
		InsecureSkipVerify: true,
	}, customReg, time.Now(), nil)
	if err != nil {
		t.Fatalf("NewOTLPPusher failed: %v", err)
	}
	defer func() { _ = insecureTLS.Close() }()
	if err := insecureTLS.PushOnce(context.Background()); err != nil {
		t.Errorf("expected TLS push with InsecureSkipVerify=true to succeed, got %v", err)
	}
}

func TestOTLPPusher_BackgroundTickerAndCleanClose(t *testing.T) {
	var hits atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	logger, err := core.NewLogger(core.LoggingConfig{Level: "warn"})
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer func() { _ = logger.Close() }()

	customReg := prometheus.NewRegistry()
	pusher, err := api.NewOTLPPusher(core.OTLPExportConfig{
		Enabled:      true,
		Endpoint:     collector.URL,
		PushInterval: "20ms",
		Timeout:      "1s",
	}, customReg, time.Now(), logger)
	if err != nil {
		t.Fatalf("NewOTLPPusher failed: %v", err)
	}

	pusher.Start()
	pusher.Start() // idempotent second Start

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st := pusher.Stats()
		if st.ErrorCount >= 1 && st.PushCount >= 1 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	if err := pusher.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := pusher.Close(); err != nil {
		t.Fatalf("idempotent second Close failed: %v", err)
	}

	countAfterClose := hits.Load()
	time.Sleep(80 * time.Millisecond)
	if hits.Load() != countAfterClose {
		t.Errorf("expected no pushes after Close(), had %d then %d", countAfterClose, hits.Load())
	}

	st := pusher.Stats()
	if st.ErrorCount < 1 || st.PushCount < 1 {
		t.Errorf("expected >=1 error and >=1 success from background ticker, got %+v", st)
	}
}
