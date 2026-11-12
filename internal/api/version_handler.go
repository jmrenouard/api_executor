package api

import (
	"encoding/json"
	"net/http"
	"time"

	"go-admin-tool/internal/version"
)

var defaultServerStartTime = time.Now()

// VersionHandler godoc
// @Summary Certified native version & build metadata endpoint
// @Description Returns official source version, Git commit SHA, build date, integrity status, uptime, and Go runtime version directly from source truth without intermediaries.
// @Tags system
// @Produce json
// @Success 200 {object} version.VersionResponse
// @Failure 405 {object} ErrorResponse
// @Router /api/v1/version [get]
func (env *APIEnv) VersionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	st := defaultServerStartTime
	if env != nil && !env.StartTime.IsZero() {
		st = env.StartTime
	}

	resp := version.Get().Response(st)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
