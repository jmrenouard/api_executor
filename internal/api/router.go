package api

import (
	"net/http"
	"os"
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

	// Mode-partitioned Prometheus metrics (v2.2.0+) distinguishing synchronous and asynchronous calls
	actionModeCallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "action_mode_calls_total",
			Help: "Total number of action calls partitioned by action, execution mode (sync, async), and status.",
		},
		[]string{"action", "mode", "status"},
	)
	actionModeCallDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "action_mode_call_duration_seconds",
			Help:    "Histogram of action execution latencies in seconds partitioned by action and execution mode.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300},
		},
		[]string{"action", "mode"},
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
	prometheus.MustRegister(actionModeCallsTotal)
	prometheus.MustRegister(actionModeCallDuration)
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

	actionModeCallsTotal.Reset()
	actionModeCallDuration.Reset()
}

// ResetHTTPMetrics resets HTTP request metric vectors (useful for isolated tests).
func ResetHTTPMetrics() {
	httpRequestsTotal.Reset()
	httpRequestDuration.Reset()
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

// RecordActionCall updates Prometheus counters and latency histograms for an action call.
func RecordActionCall(action, outcome string, timedOut bool, duration time.Duration) {
	recordActionCall(action, outcome, timedOut, duration)
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

	RecordActionCallWithMode(action, "sync", outcome, timedOut, duration)
}

// RecordActionCallWithMode updates Prometheus counters and latency histograms for an action call
// partitioned by execution mode ("sync" vs "async") and terminal status.
func RecordActionCallWithMode(action, mode, outcome string, timedOut bool, duration time.Duration) {
	normAction := normalizeActionLabel(action)
	normMode := strings.ToLower(strings.TrimSpace(mode))
	if normMode != "async" {
		normMode = "sync"
	}

	var status string
	if timedOut {
		status = "timeout"
	} else {
		normOutcome := strings.ToLower(strings.TrimSpace(outcome))
		switch normOutcome {
		case "ok", "completed":
			status = "ok"
		case "failure", "failed":
			status = "failure"
		case "error":
			status = "error"
		case "timeout", "timed_out":
			status = "timeout"
		case "cancelled", "canceled":
			status = "cancelled"
		default:
			status = "error"
		}
	}

	actionModeCallsTotal.WithLabelValues(normAction, normMode, status).Inc()
	if duration > 0 {
		actionModeCallDuration.WithLabelValues(normAction, normMode).Observe(duration.Seconds())
	}
}

// GetActionModeCallCount returns current counter value for action, mode, and status.
func GetActionModeCallCount(action, mode, status string) float64 {
	act := strings.TrimSpace(action)
	normMode := strings.ToLower(strings.TrimSpace(mode))
	if normMode != "async" {
		normMode = "sync"
	}
	normStatus := strings.ToLower(strings.TrimSpace(status))
	counter, err := actionModeCallsTotal.GetMetricWithLabelValues(act, normMode, normStatus)
	if err != nil {
		return 0
	}
	return readCounterValue(counter)
}

// initConfiguredActionMetrics pre-initializes Prometheus counters to 0 for all configured commands
// so they appear immediately on /metrics scrapes before any call is made.
func initConfiguredActionMetrics(env *APIEnv) {
	if env == nil || env.Config == nil {
		return
	}
	env.commandsMu.RLock()
	defer env.commandsMu.RUnlock()
	initConfiguredActionMetricsLocked(env)
}

// initConfiguredActionMetricsLocked pre-initializes Prometheus counters when env.commandsMu is already held.
func initConfiguredActionMetricsLocked(env *APIEnv) {
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

		actionModeCallsTotal.WithLabelValues(name, "sync", "ok").Add(0)
		actionModeCallsTotal.WithLabelValues(name, "async", "ok").Add(0)
		actionModeCallDuration.WithLabelValues(name, "sync")
		actionModeCallDuration.WithLabelValues(name, "async")
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

// knownStaticPaths contains recognized static endpoint paths whose cardinality is strictly bounded.
var knownStaticPaths = map[string]struct{}{
	"/":                                    {},
	"/index.html":                          {},
	"/health":                              {},
	"/metrics":                             {},
	"/api/v1/metrics/otlp":                 {},
	"/swagger":                             {},
	"/api/v1/version":                      {},
	"/api/v1/config":                       {},
	"/api/v1/configs":                      {},
	"/api/v1/commands":                     {},
	"/api/v1/execute":                      {},
	"/api/v1/presets":                      {},
	"/api/v1/presets/activate":             {},
	"/api/v1/files":                        {},
	"/api/v1/tls/info":                     {},
	"/api/v1/tls/certificate":              {},
	"/api/v1/tls/renew":                    {},
	"/api/v1/tls/certificate/renew":        {},
	"/api/v1/audit/logs":                   {},
	"/api/v1/audit/verify":                 {},
	"/api/v1/logs":                         {},
	"/api/v1/history":                      {},
	"/api/v1/auth/login":                   {},
	"/api/v1/auth/me":                      {},
	"/api/v1/auth/users":                   {},
	"/api/v1/auth/tokens":                  {},
	"/api/v1/auth/credentials":             {},
	"/api/v1/auth/service-accounts":        {},
	"/api/v1/auth/service-accounts/rotate": {},
	"/api/v1/plugins":                      {},
	"/api/v1/plugins/catalog":              {},
	"/api/v1/plugins/execute":              {},
	"/api/v1/plugins/declarative":          {},
	"/api/v1/db/tables":                    {},
	"/api/v1/db/query":                     {},
	"/api/v1/mcp":                          {},
	"/api/v1/mcp/tools":                    {},
	"/api/v1/mcp/resources":                {},
	"/api/v1/mcp/traces":                   {},
	"/api/v1/jobs":                         {},
	"/api/v1/jobs/queue":                   {},
}

// normalizeMetricPath normalizes HTTP request paths for Prometheus metrics to prevent
// unbounded label cardinality DoS. Dynamic parameterized routes are collapsed to their
// route pattern templates, recognized static routes are preserved, and unrecognized/random
// paths are collapsed to "other".
func normalizeMetricPath(path string) string {
	// Normalize dynamic parameterized routes
	if strings.HasPrefix(path, "/api/v1/config/") && path != "/api/v1/config" {
		return "/api/v1/config/:profile"
	}
	if strings.HasPrefix(path, "/api/v1/configs/") && path != "/api/v1/configs" {
		return "/api/v1/config/:profile"
	}
	if strings.HasPrefix(path, "/api/v1/files/") && path != "/api/v1/files" {
		return "/api/v1/files/:filename"
	}
	if strings.HasPrefix(path, "/api/v1/mcp/traces/") && path != "/api/v1/mcp/traces" {
		return "/api/v1/mcp/traces/:trace_id"
	}
	if strings.HasPrefix(path, "/api/v1/jobs/") {
		trimmed := strings.TrimSuffix(path, "/")
		if trimmed == "/api/v1/jobs" {
			return "/api/v1/jobs"
		}
		sub := strings.TrimPrefix(trimmed, "/api/v1/jobs/")
		parts := strings.Split(sub, "/")
		if len(parts) == 1 {
			if parts[0] == "queue" {
				return "/api/v1/jobs/queue"
			}
			return "/api/v1/jobs/:id"
		}
		if len(parts) == 2 {
			if parts[1] == "logs" {
				return "/api/v1/jobs/:id/logs"
			}
			if parts[1] == "cancel" {
				return "/api/v1/jobs/:id/cancel"
			}
			return "other"
		}
		return "other"
	}

	// Collapse swagger documentation paths
	if path == "/swagger" || strings.HasPrefix(path, "/swagger/") {
		return "/swagger"
	}

	// Check exact match for known static routes
	if _, ok := knownStaticPaths[path]; ok {
		return path
	}

	// Check if trailing slash was appended to a known static route
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		trimmed := strings.TrimSuffix(path, "/")
		if _, ok := knownStaticPaths[trimmed]; ok {
			return trimmed
		}
	}

	// Unrecognized or random 404 paths are bounded to "other"
	return "other"
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
		path := normalizeMetricPath(r.URL.Path)

		httpRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

func NewRouter(env *APIEnv) http.Handler {
	initConfiguredActionMetrics(env)

	mux := http.NewServeMux()

	// API routes
	mux.Handle("/api/v1/version", http.HandlerFunc(env.VersionHandler))
	mux.Handle("/api/v1/config", http.HandlerFunc(env.ConfigHandler))
	mux.Handle("/api/v1/config/", http.HandlerFunc(env.ConfigHandler))
	mux.Handle("/api/v1/configs", http.HandlerFunc(env.ConfigHandler))
	mux.Handle("/api/v1/configs/", http.HandlerFunc(env.ConfigHandler))
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

	// Audit, Structured Logs & Action History routes
	mux.Handle("/api/v1/audit/logs", http.HandlerFunc(env.AuditLogsHandler))
	mux.Handle("/api/v1/audit/verify", http.HandlerFunc(env.AuditVerifyHandler))
	mux.Handle("/api/v1/logs", http.HandlerFunc(env.SystemLogsHandler))
	mux.Handle("/api/v1/history", http.HandlerFunc(env.ActionHistoryHandler))

	// Authentication, RBAC Users, Personal Access Tokens & Third-Party Service Accounts routes
	mux.Handle("/api/v1/auth/login", http.HandlerFunc(env.AuthLoginHandler))
	mux.Handle("/api/v1/auth/me", http.HandlerFunc(env.AuthMeHandler))
	mux.Handle("/api/v1/auth/users", http.HandlerFunc(env.AuthUsersHandler))
	mux.Handle("/api/v1/auth/tokens", http.HandlerFunc(env.AuthTokensHandler))
	mux.Handle("/api/v1/auth/service-accounts", http.HandlerFunc(env.AuthServiceAccountsHandler))
	mux.Handle("/api/v1/auth/service-accounts/rotate", http.HandlerFunc(env.AuthServiceAccountRotateHandler))

	// Extensible Plugin System & Read-Only Database Exposure routes
	mux.Handle("/api/v1/plugins", http.HandlerFunc(env.PluginsListHandler))
	mux.Handle("/api/v1/plugins/execute", http.HandlerFunc(env.PluginExecuteHandler))
	mux.Handle("/api/v1/plugins/declarative", http.HandlerFunc(env.PluginDeclarativeRegisterHandler))
	mux.Handle("/api/v1/db/tables", http.HandlerFunc(env.DBTablesHandler))
	mux.Handle("/api/v1/db/query", http.HandlerFunc(env.DBQueryHandler))

	// Model Context Protocol (MCP) Server & Trace Retention routes
	mux.Handle("/api/v1/mcp", http.HandlerFunc(env.MCPHandler))
	mux.Handle("/api/v1/mcp/tools", http.HandlerFunc(env.MCPToolsHandler))
	mux.Handle("/api/v1/mcp/traces", http.HandlerFunc(env.MCPTracesHandler))
	mux.Handle("/api/v1/mcp/traces/", http.HandlerFunc(env.MCPTraceByIDHandler))

	// Asynchronous Action Execution, Job Queue, Logs & Telemetry routes
	mux.Handle("/api/v1/jobs", http.HandlerFunc(env.JobsHandler))
	mux.Handle("/api/v1/jobs/queue", http.HandlerFunc(env.JobQueueStatsHandler))
	mux.Handle("/api/v1/jobs/", http.HandlerFunc(env.JobSubroutesHandler))

	// Metrics
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/api/v1/metrics/otlp", http.HandlerFunc(env.OTLPMetricsHandler))
	mux.Handle("/api/v1/metrics/otlp/", http.HandlerFunc(env.OTLPMetricsHandler))

	// Swagger Docs
	mux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// Frontend
	staticFileServer := http.FileServer(http.Dir(resolveStaticDir()))
	mux.Handle("/", staticFileServer)

	return prometheusMiddleware(securityMiddleware(env, mux))
}

func resolveStaticDir() string {
	for _, candidate := range []string{"./web/static", "../../web/static"} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return "./web/static"
}
