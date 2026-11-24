package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go-admin-tool/internal/core"
	"go-admin-tool/internal/version"
)

// OTLPExportMetricsRequest represents standard OTLP/HTTP v1 ExportMetricsServiceRequest JSON payload.
type OTLPExportMetricsRequest struct {
	ResourceMetrics []OTLPResourceMetrics `json:"resourceMetrics"`
}

// OTLPResourceMetrics encapsulates metrics from a resource.
type OTLPResourceMetrics struct {
	Resource     OTLPResource       `json:"resource"`
	ScopeMetrics []OTLPScopeMetrics `json:"scopeMetrics"`
	SchemaURL    string             `json:"schemaUrl,omitempty"`
}

// OTLPResource describes the entity producing telemetry.
type OTLPResource struct {
	Attributes             []OTLPKeyValue `json:"attributes"`
	DroppedAttributesCount uint32         `json:"droppedAttributesCount,omitempty"`
}

// OTLPScopeMetrics groups metrics produced within an instrumentation scope.
type OTLPScopeMetrics struct {
	Scope     OTLPScope    `json:"scope"`
	Metrics   []OTLPMetric `json:"metrics"`
	SchemaURL string       `json:"schemaUrl,omitempty"`
}

// OTLPScope defines the name and version of the instrumentation scope.
type OTLPScope struct {
	Name                   string         `json:"name"`
	Version                string         `json:"version,omitempty"`
	Attributes             []OTLPKeyValue `json:"attributes,omitempty"`
	DroppedAttributesCount uint32         `json:"droppedAttributesCount,omitempty"`
}

// OTLPMetric represents an individual OpenTelemetry metric definition with data points.
type OTLPMetric struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Unit        string         `json:"unit,omitempty"`
	Gauge       *OTLPGauge     `json:"gauge,omitempty"`
	Sum         *OTLPSum       `json:"sum,omitempty"`
	Histogram   *OTLPHistogram `json:"histogram,omitempty"`
}

// OTLPGauge represents a gauge metric.
type OTLPGauge struct {
	DataPoints []OTLPNumberDataPoint `json:"dataPoints"`
}

// OTLPSum represents a cumulative or delta sum metric.
type OTLPSum struct {
	DataPoints             []OTLPNumberDataPoint `json:"dataPoints"`
	AggregationTemporality int                   `json:"aggregationTemporality"` // 2 = AGGREGATION_TEMPORALITY_CUMULATIVE
	IsMonotonic            bool                  `json:"isMonotonic"`
}

// OTLPHistogram represents a histogram metric.
type OTLPHistogram struct {
	DataPoints             []OTLPHistogramDataPoint `json:"dataPoints"`
	AggregationTemporality int                      `json:"aggregationTemporality"` // 2 = AGGREGATION_TEMPORALITY_CUMULATIVE
}

// OTLPNumberDataPoint holds a single numeric metric observation.
type OTLPNumberDataPoint struct {
	Attributes        []OTLPKeyValue `json:"attributes,omitempty"`
	StartTimeUnixNano string         `json:"startTimeUnixNano,omitempty"`
	TimeUnixNano      string         `json:"timeUnixNano"`
	AsDouble          *float64       `json:"asDouble,omitempty"`
}

// OTLPHistogramDataPoint holds a histogram observation with explicit bounds and bucket counts.
type OTLPHistogramDataPoint struct {
	Attributes        []OTLPKeyValue `json:"attributes,omitempty"`
	StartTimeUnixNano string         `json:"startTimeUnixNano,omitempty"`
	TimeUnixNano      string         `json:"timeUnixNano"`
	Count             string         `json:"count"`
	Sum               *float64       `json:"sum,omitempty"`
	BucketCounts      []string       `json:"bucketCounts"`
	ExplicitBounds    []float64      `json:"explicitBounds"`
	Min               *float64       `json:"min,omitempty"`
	Max               *float64       `json:"max,omitempty"`
}

// OTLPKeyValue represents an attribute key-value pair.
type OTLPKeyValue struct {
	Key   string       `json:"key"`
	Value OTLPAnyValue `json:"value"`
}

// OTLPAnyValue holds typed attribute values.
type OTLPAnyValue struct {
	StringValue *string  `json:"stringValue,omitempty"`
	IntValue    *int64   `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
}

func stringAttr(key, val string) OTLPKeyValue {
	return OTLPKeyValue{
		Key: key,
		Value: OTLPAnyValue{
			StringValue: &val,
		},
	}
}

func convertLabels(labels []*dto.LabelPair, excludeLE bool) []OTLPKeyValue {
	if len(labels) == 0 {
		return nil
	}
	attrs := make([]OTLPKeyValue, 0, len(labels))
	for _, lp := range labels {
		if lp == nil {
			continue
		}
		name := lp.GetName()
		if excludeLE && name == "le" {
			continue
		}
		val := lp.GetValue()
		attrs = append(attrs, OTLPKeyValue{
			Key: name,
			Value: OTLPAnyValue{
				StringValue: &val,
			},
		})
	}
	return attrs
}

func inferUnit(name string) string {
	switch {
	case strings.HasSuffix(name, "_seconds"):
		return "s"
	case strings.HasSuffix(name, "_bytes"):
		return "By"
	case strings.HasSuffix(name, "_total"):
		return "1"
	default:
		return "1"
	}
}

// TranslatePrometheusToOTLP converts Prometheus MetricFamily slices into standard OTLP JSON request.
func TranslatePrometheusToOTLP(mfs []*dto.MetricFamily, serviceName, appVersion string, startTime time.Time, extraResourceAttrs map[string]string) *OTLPExportMetricsRequest {
	now := time.Now()
	nowNanoStr := strconv.FormatInt(now.UnixNano(), 10)
	startNanoStr := strconv.FormatInt(startTime.UnixNano(), 10)
	if startTime.IsZero() {
		startNanoStr = nowNanoStr
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	if serviceName == "" {
		serviceName = "api-executor"
	}
	if appVersion == "" {
		appVersion = "2.2.0"
	}

	resourceAttrs := []OTLPKeyValue{
		stringAttr("service.name", serviceName),
		stringAttr("service.version", appVersion),
		stringAttr("host.name", hostname),
		stringAttr("telemetry.sdk.language", "go"),
		stringAttr("telemetry.sdk.name", "api-executor/otlp"),
		stringAttr("telemetry.sdk.version", appVersion),
	}

	if extraResourceAttrs != nil {
		for k, v := range extraResourceAttrs {
			if k == "service.name" || k == "service.version" || k == "host.name" ||
				k == "telemetry.sdk.language" || k == "telemetry.sdk.name" || k == "telemetry.sdk.version" {
				continue
			}
			resourceAttrs = append(resourceAttrs, stringAttr(k, v))
		}
	}

	otlpMetrics := make([]OTLPMetric, 0, len(mfs))

	for _, mf := range mfs {
		if mf == nil || len(mf.GetMetric()) == 0 {
			continue
		}
		mName := mf.GetName()
		mHelp := mf.GetHelp()
		unit := inferUnit(mName)

		switch mf.GetType() {
		case dto.MetricType_COUNTER:
			dataPoints := make([]OTLPNumberDataPoint, 0, len(mf.GetMetric()))
			for _, m := range mf.GetMetric() {
				if m == nil || m.Counter == nil {
					continue
				}
				val := m.Counter.GetValue()
				tStr := nowNanoStr
				if m.TimestampMs != nil && *m.TimestampMs > 0 {
					tStr = strconv.FormatInt(*m.TimestampMs*1000000, 10)
				}
				dataPoints = append(dataPoints, OTLPNumberDataPoint{
					Attributes:        convertLabels(m.GetLabel(), false),
					StartTimeUnixNano: startNanoStr,
					TimeUnixNano:      tStr,
					AsDouble:          &val,
				})
			}
			if len(dataPoints) > 0 {
				otlpMetrics = append(otlpMetrics, OTLPMetric{
					Name:        mName,
					Description: mHelp,
					Unit:        unit,
					Sum: &OTLPSum{
						DataPoints:             dataPoints,
						AggregationTemporality: 2, // CUMULATIVE
						IsMonotonic:            true,
					},
				})
			}

		case dto.MetricType_GAUGE:
			dataPoints := make([]OTLPNumberDataPoint, 0, len(mf.GetMetric()))
			for _, m := range mf.GetMetric() {
				if m == nil || m.Gauge == nil {
					continue
				}
				val := m.Gauge.GetValue()
				tStr := nowNanoStr
				if m.TimestampMs != nil && *m.TimestampMs > 0 {
					tStr = strconv.FormatInt(*m.TimestampMs*1000000, 10)
				}
				dataPoints = append(dataPoints, OTLPNumberDataPoint{
					Attributes:   convertLabels(m.GetLabel(), false),
					TimeUnixNano: tStr,
					AsDouble:     &val,
				})
			}
			if len(dataPoints) > 0 {
				otlpMetrics = append(otlpMetrics, OTLPMetric{
					Name:        mName,
					Description: mHelp,
					Unit:        unit,
					Gauge: &OTLPGauge{
						DataPoints: dataPoints,
					},
				})
			}

		case dto.MetricType_HISTOGRAM:
			dataPoints := make([]OTLPHistogramDataPoint, 0, len(mf.GetMetric()))
			for _, m := range mf.GetMetric() {
				if m == nil || m.Histogram == nil {
					continue
				}
				h := m.Histogram
				tStr := nowNanoStr
				if m.TimestampMs != nil && *m.TimestampMs > 0 {
					tStr = strconv.FormatInt(*m.TimestampMs*1000000, 10)
				}

				totalCount := h.GetSampleCount()
				sumVal := h.GetSampleSum()

				promBuckets := h.GetBucket()
				explicitBounds := make([]float64, 0, len(promBuckets))
				bucketCounts := make([]string, 0, len(promBuckets)+1)

				var prevCumulative uint64
				for _, b := range promBuckets {
					if b == nil {
						continue
					}
					bound := b.GetUpperBound()
					cumCount := b.GetCumulativeCount()

					if math.IsInf(bound, 1) {
						continue // OTLP explicitBounds omits +Inf
					}

					explicitBounds = append(explicitBounds, bound)
					var delta uint64
					if cumCount >= prevCumulative {
						delta = cumCount - prevCumulative
					}
					bucketCounts = append(bucketCounts, strconv.FormatUint(delta, 10))
					prevCumulative = cumCount
				}

				var lastDelta uint64
				if totalCount >= prevCumulative {
					lastDelta = totalCount - prevCumulative
				}
				bucketCounts = append(bucketCounts, strconv.FormatUint(lastDelta, 10))

				dataPoints = append(dataPoints, OTLPHistogramDataPoint{
					Attributes:        convertLabels(m.GetLabel(), true), // Exclude "le"
					StartTimeUnixNano: startNanoStr,
					TimeUnixNano:      tStr,
					Count:             strconv.FormatUint(totalCount, 10),
					Sum:               &sumVal,
					BucketCounts:      bucketCounts,
					ExplicitBounds:    explicitBounds,
				})
			}
			if len(dataPoints) > 0 {
				otlpMetrics = append(otlpMetrics, OTLPMetric{
					Name:        mName,
					Description: mHelp,
					Unit:        unit,
					Histogram: &OTLPHistogram{
						DataPoints:             dataPoints,
						AggregationTemporality: 2, // CUMULATIVE
					},
				})
			}

		case dto.MetricType_UNTYPED:
			dataPoints := make([]OTLPNumberDataPoint, 0, len(mf.GetMetric()))
			for _, m := range mf.GetMetric() {
				if m == nil || m.Untyped == nil {
					continue
				}
				val := m.Untyped.GetValue()
				tStr := nowNanoStr
				if m.TimestampMs != nil && *m.TimestampMs > 0 {
					tStr = strconv.FormatInt(*m.TimestampMs*1000000, 10)
				}
				dataPoints = append(dataPoints, OTLPNumberDataPoint{
					Attributes:   convertLabels(m.GetLabel(), false),
					TimeUnixNano: tStr,
					AsDouble:     &val,
				})
			}
			if len(dataPoints) > 0 {
				otlpMetrics = append(otlpMetrics, OTLPMetric{
					Name:        mName,
					Description: mHelp,
					Unit:        unit,
					Gauge: &OTLPGauge{
						DataPoints: dataPoints,
					},
				})
			}
		}
	}

	return &OTLPExportMetricsRequest{
		ResourceMetrics: []OTLPResourceMetrics{
			{
				Resource: OTLPResource{
					Attributes: resourceAttrs,
				},
				ScopeMetrics: []OTLPScopeMetrics{
					{
						Scope: OTLPScope{
							Name:    "api-executor/metrics",
							Version: appVersion,
						},
						Metrics: otlpMetrics,
					},
				},
			},
		},
	}
}

// BuildOTLPMetrics gathers metrics from gatherer and translates them into an OTLP request.
func BuildOTLPMetrics(cfg core.OTLPExportConfig, gatherer prometheus.Gatherer, startTime time.Time) (*OTLPExportMetricsRequest, error) {
	if gatherer == nil {
		gatherer = prometheus.DefaultGatherer
	}
	mfs, err := gatherer.Gather()
	if err != nil {
		return nil, fmt.Errorf("failed to gather Prometheus metrics: %w", err)
	}

	serviceName := "api-executor"
	if cfg.ResourceAttributes != nil && cfg.ResourceAttributes["service.name"] != "" {
		serviceName = cfg.ResourceAttributes["service.name"]
	}
	appVersion := version.Get().Version

	return TranslatePrometheusToOTLP(mfs, serviceName, appVersion, startTime, cfg.ResourceAttributes), nil
}

// OTLPMetricsHandler handles GET /api/v1/metrics/otlp.
func (env *APIEnv) OTLPMetricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var otlpCfg core.OTLPExportConfig
	if env != nil && env.Config != nil {
		otlpCfg = env.Config.OTLPExport
	} else {
		otlpCfg = core.OTLPExportConfig{
			Enabled: true,
			ResourceAttributes: map[string]string{
				"service.name": "api-executor",
			},
		}
	}

	var st time.Time
	if env != nil && !env.StartTime.IsZero() {
		st = env.StartTime
	}

	payload, err := BuildOTLPMetrics(otlpCfg, prometheus.DefaultGatherer, st)
	if err != nil {
		if env != nil && env.Logger != nil {
			env.Logger.Error(fmt.Sprintf("Failed to gather Prometheus metrics for OTLP: %v", err))
		}
		writeJSONError(w, "Failed to gather metrics", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}

const maxOTLPResponseDrainBytes = 4 * 1024

// OTLPPusherStats summarizes outbound OTLP background push telemetry.
type OTLPPusherStats struct {
	Enabled    bool      `json:"enabled"`
	Endpoint   string    `json:"endpoint,omitempty"`
	PushCount  int64     `json:"push_count"`
	ErrorCount int64     `json:"error_count"`
	LastPushAt time.Time `json:"last_push_at,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}

// OTLPPusher periodically exports Prometheus metrics to an OTLP/HTTP JSON collector endpoint.
type OTLPPusher struct {
	cfg       core.OTLPExportConfig
	endpoint  string
	headers   map[string]string
	gatherer  prometheus.Gatherer
	startTime time.Time
	logger    *core.Logger
	transport *http.Transport
	client    *http.Client

	mu         sync.Mutex
	started    bool
	closed     bool
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	pushCount  int64
	errorCount int64
	lastPushAt time.Time
	lastError  string
}

// NewOTLPPusher validates OTLP export configuration and builds an outbound OTLP/HTTP background pusher.
// When OTLP export is disabled or endpoint is empty, it returns (nil, nil) as a no-op.
func NewOTLPPusher(cfg core.OTLPExportConfig, gatherer prometheus.Gatherer, startTime time.Time, logger *core.Logger) (*OTLPPusher, error) {
	rawEndpoint := strings.TrimSpace(cfg.Endpoint)
	if !cfg.Enabled || rawEndpoint == "" {
		return nil, nil
	}

	parsed, err := url.Parse(rawEndpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || strings.TrimSpace(parsed.Host) == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid OTLP export endpoint %q: scheme must be http or https with a non-empty host", rawEndpoint)
	}

	if gatherer == nil {
		gatherer = prometheus.DefaultGatherer
	}
	if startTime.IsZero() {
		startTime = time.Now()
	}

	headersCopy := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headersCopy[k] = v
	}

	resAttrsCopy := make(map[string]string, len(cfg.ResourceAttributes))
	for k, v := range cfg.ResourceAttributes {
		resAttrsCopy[k] = v
	}
	cfgCopy := cfg
	cfgCopy.Endpoint = parsed.String()
	cfgCopy.Headers = headersCopy
	cfgCopy.ResourceAttributes = resAttrsCopy

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	client := &http.Client{
		Timeout:   cfg.EffectiveTimeout(),
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL == nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
				scheme := ""
				if req.URL != nil {
					scheme = req.URL.Scheme
				}
				return fmt.Errorf("refusing OTLP redirect to disallowed scheme %q", scheme)
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}

	return &OTLPPusher{
		cfg:       cfgCopy,
		endpoint:  parsed.String(),
		headers:   headersCopy,
		gatherer:  gatherer,
		startTime: startTime,
		logger:    logger,
		transport: transport,
		client:    client,
	}, nil
}

// Start launches a single background goroutine that pushes OTLP metrics on EffectivePushInterval.
func (p *OTLPPusher) Start() {
	if p == nil {
		return
	}

	p.mu.Lock()
	if p.closed || p.started {
		p.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.started = true
	p.wg.Add(1)
	p.mu.Unlock()

	interval := p.cfg.EffectivePushInterval()
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := p.PushOnce(ctx); err != nil && ctx.Err() == nil && p.logger != nil {
					p.logger.Warn(fmt.Sprintf("OTLP background metrics push failed: %v", err))
				}
			}
		}
	}()
}

// PushOnce gathers Prometheus metrics, encodes them as OTLP JSON, and POSTs them to the configured collector.
func (p *OTLPPusher) PushOnce(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	payload, err := BuildOTLPMetrics(p.cfg, p.gatherer, p.startTime)
	if err != nil {
		p.recordError(err)
		return err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		err = fmt.Errorf("failed to marshal OTLP metrics payload: %w", err)
		p.recordError(err)
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		err = fmt.Errorf("failed to build OTLP push request: %w", err)
		p.recordError(err)
		return err
	}

	for k, v := range p.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		err = fmt.Errorf("OTLP push request failed: %w", err)
		p.recordError(err)
		return err
	}
	defer resp.Body.Close()

	// Drain and cap response body to preserve keep-alive connections while bounding memory.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxOTLPResponseDrainBytes))

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		err = fmt.Errorf("OTLP collector returned HTTP %d", resp.StatusCode)
		p.recordError(err)
		return err
	}

	p.recordSuccess()
	return nil
}

// Close idempotently cancels the background push loop and waits for clean goroutine exit.
func (p *OTLPPusher) Close() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	alreadyClosed := p.closed
	p.closed = true
	cancel := p.cancel
	p.cancel = nil
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	p.wg.Wait()
	if !alreadyClosed && p.transport != nil {
		p.transport.CloseIdleConnections()
	}
	return nil
}

// Stats returns a thread-safe snapshot of OTLP pusher telemetry.
func (p *OTLPPusher) Stats() OTLPPusherStats {
	if p == nil {
		return OTLPPusherStats{}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	return OTLPPusherStats{
		Enabled:    p.cfg.Enabled,
		Endpoint:   p.endpoint,
		PushCount:  p.pushCount,
		ErrorCount: p.errorCount,
		LastPushAt: p.lastPushAt,
		LastError:  p.lastError,
	}
}

func (p *OTLPPusher) recordError(err error) {
	p.mu.Lock()
	p.errorCount++
	if err != nil {
		p.lastError = err.Error()
	}
	p.mu.Unlock()
}

func (p *OTLPPusher) recordSuccess() {
	p.mu.Lock()
	p.pushCount++
	p.lastPushAt = time.Now().UTC()
	p.lastError = ""
	p.mu.Unlock()
}
