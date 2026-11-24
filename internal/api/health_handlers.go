package api

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"time"

	"go-admin-tool/internal/version"
)

// HealthResponse defines the JSON payload returned by GET /health and GET /healthz.
type HealthResponse struct {
	Status        string  `json:"status"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Version       string  `json:"version"`
	TLSEnabled    bool    `json:"tls_enabled"`
}

// ReadinessResponse defines the JSON payload returned by GET /readyz.
type ReadinessResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

// HealthHandler godoc
// @Summary Liveness probe endpoint
// @Description Returns service liveness status, uptime in seconds, build version, and TLS state without exposing secrets or paths.
// @Tags system
// @Produce json
// @Success 200 {object} HealthResponse
// @Failure 405 {object} ErrorResponse
// @Router /health [get]
func (env *APIEnv) HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	st := defaultServerStartTime
	if env != nil && !env.StartTime.IsZero() {
		st = env.StartTime
	}
	dur := time.Since(st)
	if dur < 0 {
		dur = 0
	}
	uptime := math.Round(dur.Seconds()*100) / 100

	tlsEnabled := env != nil && env.Config != nil && env.Config.Server.TLS.Enabled

	resp := HealthResponse{
		Status:        "ok",
		UptimeSeconds: uptime,
		Version:       version.Get().Version,
		TLSEnabled:    tlsEnabled,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ReadinessHandler godoc
// @Summary Readiness probe endpoint
// @Description Verifies active subsystems (database connectivity, TLS certificate validity, and job queue capacity).
// @Tags system
// @Produce json
// @Success 200 {object} ReadinessResponse
// @Failure 405 {object} ErrorResponse
// @Failure 503 {object} ReadinessResponse
// @Router /readyz [get]
func (env *APIEnv) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	checks := make(map[string]string)
	ready := true

	if env != nil && env.DB != nil {
		if env.DB.IsInMemory() {
			checks["database"] = "in_memory"
		} else if env.DB.DB == nil {
			checks["database"] = "error"
			ready = false
		} else {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			err := env.DB.DB.PingContext(ctx)
			cancel()
			if err != nil {
				checks["database"] = "error"
				ready = false
			} else {
				checks["database"] = "ok"
			}
		}
	}

	if env != nil && env.Config != nil && env.Config.Server.TLS.Enabled && env.CertManager != nil {
		info := env.CertManager.Info()
		if info.Expired || (!info.NotAfter.IsZero() && time.Now().After(info.NotAfter)) {
			checks["tls"] = "expired"
			ready = false
		} else {
			checks["tls"] = "ok"
		}
	}

	if env != nil && env.JobEngine != nil {
		stats := env.JobEngine.QueueStats()
		if stats.QueuedJobs < stats.Capacity {
			checks["jobs"] = "ok"
		} else {
			checks["jobs"] = "queue_full"
			ready = false
		}
	}

	status := "ready"
	code := http.StatusOK
	if !ready {
		status = "not_ready"
		code = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(ReadinessResponse{
		Status: status,
		Checks: checks,
	})
}
