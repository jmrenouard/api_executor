package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger"
)

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
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
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

// prometheusMiddleware wraps an http.Handler to collect metrics.
func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)

		statusCode := rw.statusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		duration := time.Since(start).Seconds()
		path := r.URL.Path

		// To avoid high cardinality, we can try to group paths.
		// For this simple case, we will use the raw path.
		// For a real-world application, you might want to use a router that provides path templates.
		httpRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

func NewRouter(env *APIEnv) http.Handler {
	mux := http.NewServeMux()

	// API routes
	mux.Handle("/api/v1/commands", http.HandlerFunc(env.ListCommandsHandler))
	mux.Handle("/api/v1/execute", http.HandlerFunc(env.ExecuteCommandHandler))
	mux.Handle("/api/v1/files", http.HandlerFunc(env.ListFilesHandler))
	mux.Handle("/api/v1/files/", http.HandlerFunc(env.DownloadFileHandler)) // Note the trailing slash

	// Metrics
	mux.Handle("/metrics", promhttp.Handler())

	// Swagger Docs
	mux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// Frontend
	staticFileServer := http.FileServer(http.Dir("./web/static"))
	mux.Handle("/", staticFileServer)

	return prometheusMiddleware(mux)
}
