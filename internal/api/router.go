package api

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	httpSwagger "github.com/swaggo/http-swagger"
)

const (
	// MaxDynamicActionLabels caps the number of distinct unconfigured action labels tracked in Prometheus
	// before falling back to the "unknown" label to prevent unbounded label cardinality DoS.
	MaxDynamicActionLabels = 64
	// MaxActionLabelLength caps the maximum character length of an action metric label.
	MaxActionLabelLength = 64
)

var (
	actionLabelsMu    sync.Mutex
	configuredActions = make(map[string]struct{})
	dynamicActions    = make(map[string]struct{})
)

// ActionMetricsSnapshot holds the current counter values for a specific action.
type ActionMetricsSnapshot struct {
	Action       string  `json:"action"`
	CallsTotal   float64 `json:"calls_total"`
	CallsOK      float64 `json:"calls_ok"`
	CallsError   float64 `json:"calls_error"`
	CallsFailure float64 `json:"calls_failure"`
	CallsTimeout float64 `json:"calls_timeout"`
}

func readCounterValue(c prometheus.Counter) float64 {
	var m dto.Metric
	if err := c.Write(&m); err != nil || m.Counter == nil {
		return 0
	}
	return m.Counter.GetValue()
}

// GetActionMetricsSnapshot returns the current Prometheus counter values for a given action.
func GetActionMetricsSnapshot(action string) ActionMetricsSnapshot {
	return ActionMetricsSnapshot{
		Action:       action,
		CallsTotal:   readCounterValue(actionCallsTotal.WithLabelValues(action)),
		CallsOK:      readCounterValue(actionCallsOKTotal.WithLabelValues(action)),
		CallsError:   readCounterValue(actionCallsErrorTotal.WithLabelValues(action)),
		CallsFailure: readCounterValue(actionCallsFailureTotal.WithLabelValues(action)),
		CallsTimeout: readCounterValue(actionCallsTimeoutTotal.WithLabelValues(action)),
	}
}

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests.",
		},
		[]string{"method", "path", "status"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Histogram of request latencies.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// Per-action Prometheus metrics
	actionCallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "action_calls_total",
			Help: "Total number of calls per action.",
		},
		[]string{"action"},
	)
	actionCallsOKTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "action_calls_ok_total",
			Help: "Total number of successful (OK) calls per action.",
		},
		[]string{"action"},
	)
	actionCallsErrorTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "action_calls_error_total",
			Help: "Total number of calls in error (invalid parameters, unknown action, or system/spawn error) per action.",
		},
		[]string{"action"},
	)
	actionCallsFailureTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "action_calls_failure_total",
			Help: "Total number of failed calls (non-zero exit code or execution timeout) per action.",
		},
		[]string{"action"},
	)
	actionCallsTimeoutTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "action_calls_timeout_total",
			Help: "Total number of timed-out calls per action.",
		},
		[]string{"action"},
	)
	actionCallsStatusTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "action_calls_status_total",
			Help: "Total number of calls per action partitioned by status (ok, error, failure).",
		},
		[]string{"action", "status"},
	)
	actionCallDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "action_call_duration_seconds",
			Help:    "Histogram of action execution latencies in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"action"},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(actionCallsTotal)
	prometheus.MustRegister(actionCallsOKTotal)
	prometheus.MustRegister(actionCallsErrorTotal)
	prometheus.MustRegister(actionCallsFailureTotal)
	prometheus.MustRegister(actionCallsTimeoutTotal)
	prometheus.MustRegister(actionCallsStatusTotal)
	prometheus.MustRegister(actionCallDuration)
}

// ResetActionMetrics resets all per-action Prometheus metric vectors (useful for isolated tests).
func ResetActionMetrics() {
	actionLabelsMu.Lock()
	configuredActions = make(map[string]struct{})
	dynamicActions = make(map[string]struct{})
	actionLabelsMu.Unlock()

	actionCallsTotal.Reset()
	actionCallsOKTotal.Reset()
	actionCallsErrorTotal.Reset()
	actionCallsFailureTotal.Reset()
	actionCallsTimeoutTotal.Reset()
	actionCallsStatusTotal.Reset()
	actionCallDuration.Reset()
}

// normalizeActionLabel sanitizes the action name and bounds dynamic label cardinality.
func normalizeActionLabel(action string) string {
	label := strings.TrimSpace(action)
	if label == "" || label == "unknown" || len(label) > MaxActionLabelLength {
		return "unknown"
	}
	for _, r := range label {
		if r < 0x20 || r == 0x7f {
			return "unknown"
		}
	}

	actionLabelsMu.Lock()
	defer actionLabelsMu.Unlock()

	if _, ok := configuredActions[label]; ok {
		return label
	}
	if _, ok := dynamicActions[label]; ok {
		return label
	}
	if len(dynamicActions) >= MaxDynamicActionLabels {
		return "unknown"
	}
	dynamicActions[label] = struct{}{}
	return label
}

// recordActionCall updates Prometheus counters and latency histograms for an action call.
// outcome must be one of "ok", "error", or "failure".
func recordActionCall(action, outcome string, timedOut bool, duration time.Duration) {
	label := normalizeActionLabel(action)

	actionCallsTotal.WithLabelValues(label).Inc()

	switch outcome {
	case "ok":
		actionCallsOKTotal.WithLabelValues(label).Inc()
		actionCallsStatusTotal.WithLabelValues(label, "ok").Inc()
	case "error":
		actionCallsErrorTotal.WithLabelValues(label).Inc()
		actionCallsStatusTotal.WithLabelValues(label, "error").Inc()
	case "failure":
		actionCallsFailureTotal.WithLabelValues(label).Inc()
		actionCallsStatusTotal.WithLabelValues(label, "failure").Inc()
	}

	if timedOut {
		actionCallsTimeoutTotal.WithLabelValues(label).Inc()
	}

	if duration > 0 {
		actionCallDuration.WithLabelValues(label).Observe(duration.Seconds())
	}
}

// initConfiguredActionMetrics pre-initializes Prometheus counters to 0 for all configured commands
// so they appear immediately on /metrics scrapes before any call is made.
func initConfiguredActionMetrics(env *APIEnv) {
	if env == nil || env.Config == nil {
		return
	}
	actionLabelsMu.Lock()
	for _, cmd := range env.Config.Executor.Commands {
		name := strings.TrimSpace(cmd.Name)
		if name != "" {
			configuredActions[name] = struct{}{}
		}
	}
	actionLabelsMu.Unlock()

	for _, cmd := range env.Config.Executor.Commands {
		name := strings.TrimSpace(cmd.Name)
		if name == "" {
			continue
		}
		actionCallsTotal.WithLabelValues(name).Add(0)
		actionCallsOKTotal.WithLabelValues(name).Add(0)
		actionCallsErrorTotal.WithLabelValues(name).Add(0)
		actionCallsFailureTotal.WithLabelValues(name).Add(0)
		actionCallsTimeoutTotal.WithLabelValues(name).Add(0)
		actionCallsStatusTotal.WithLabelValues(name, "ok").Add(0)
		actionCallsStatusTotal.WithLabelValues(name, "error").Add(0)
		actionCallsStatusTotal.WithLabelValues(name, "failure").Add(0)
		actionCallDuration.WithLabelValues(name)
	}
}

// responseWriter is a wrapper for http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// prometheusMiddleware wraps an http.Handler to collect metrics and apply HTTPS security headers.
func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		rw := &responseWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)

		statusCode := rw.statusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		duration := time.Since(start).Seconds()
		path := r.URL.Path

		httpRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

func NewRouter(env *APIEnv) http.Handler {
	initConfiguredActionMetrics(env)

	mux := http.NewServeMux()

	// API routes
	mux.Handle("/api/v1/commands", http.HandlerFunc(env.ListCommandsHandler))
	mux.Handle("/api/v1/execute", http.HandlerFunc(env.ExecuteCommandHandler))
	mux.Handle("/api/v1/presets", http.HandlerFunc(env.ListPresetsHandler))
	mux.Handle("/api/v1/presets/activate", http.HandlerFunc(env.ActivatePresetsHandler))
	mux.Handle("/api/v1/files", http.HandlerFunc(env.ListFilesHandler))
	mux.Handle("/api/v1/files/", http.HandlerFunc(env.DownloadFileHandler)) // Note the trailing slash

	// TLS management routes
	mux.Handle("/api/v1/tls/info", http.HandlerFunc(env.TLSInfoHandler))
	mux.Handle("/api/v1/tls/certificate", http.HandlerFunc(env.TLSCertificateHandler))
	mux.Handle("/api/v1/tls/renew", http.HandlerFunc(env.TLSRenewHandler))

	// Metrics
	mux.Handle("/metrics", promhttp.Handler())

	// Swagger Docs
	mux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// Frontend
	staticFileServer := http.FileServer(http.Dir("./web/static"))
	mux.Handle("/", staticFileServer)

	return prometheusMiddleware(mux)
}
