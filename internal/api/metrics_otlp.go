package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
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
