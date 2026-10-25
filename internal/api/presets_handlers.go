package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"go-admin-tool/internal/core"
)

// ListPresetsHandler returns the catalog of predefined OS tasks for Ubuntu and RedHat, plus detected host OS family.
func (env *APIEnv) ListPresetsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		DetectedOSFamily string                 `json:"detected_os_family"`
		Catalogs         []core.OSPresetCatalog `json:"catalogs"`
	}{
		DetectedOSFamily: core.DetectHostOSFamily(),
		Catalogs:         core.AllOSPresetCatalogs(),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ActivatePresetsHandler merges the requested OS preset families ("ubuntu", "redhat", "all") into the active command list.
func (env *APIEnv) ActivatePresetsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Families []string `json:"families"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if len(req.Families) == 0 {
		family := strings.TrimSpace(r.URL.Query().Get("family"))
		if family != "" {
			req.Families = []string{family}
		} else {
			req.Families = []string{"ubuntu", "redhat", "common"}
		}
	}

	before := len(env.Config.Executor.Commands)
	env.Config.Executor.Commands = core.MergeOSPresets(env.Config.Executor.Commands, req.Families...)
	env.Config.Executor.EnableOSPresets = true
	initConfiguredActionMetrics(env)
	after := len(env.Config.Executor.Commands)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		ActivatedFamilies []string `json:"activated_families"`
		AddedCount        int      `json:"added_count"`
		TotalCommands     int      `json:"total_commands"`
	}{
		ActivatedFamilies: req.Families,
		AddedCount:        after - before,
		TotalCommands:     after,
	})
}
