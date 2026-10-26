package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
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
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if p.Type != "anonymous" && p.Role != auth.RoleAdmin {
		if authErr := auth.Authorize(p, "commands:execute", ""); authErr != nil {
			if env.AuditLogger != nil {
				_, _ = env.AuditLogger.Record(audit.AuditEvent{
					Category:  "admin",
					Action:    "presets.activate",
					ActorType: p.Type,
					ActorID:   p.Name,
					SourceIP:  r.RemoteAddr,
					Status:    "denied",
					Summary:   fmt.Sprintf("Denied OS preset activation for %s: %v", p.Name, authErr),
				})
			}
			writeJSONError(w, authErr.Error(), http.StatusForbidden)
			return
		}
	}

	var req struct {
		Families   []string `json:"families"`
		OSFamilies []string `json:"os_families"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if len(req.Families) == 0 && len(req.OSFamilies) > 0 {
		req.Families = req.OSFamilies
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

	if env.AuditLogger != nil {
		_, _ = env.AuditLogger.Record(audit.AuditEvent{
			Category:  "admin",
			Action:    "presets.activate",
			ActorType: p.Type,
			ActorID:   p.Name,
			SourceIP:  r.RemoteAddr,
			Status:    "ok",
			Summary:   fmt.Sprintf("Activated OS presets %v (%d added, %d total)", req.Families, after-before, after),
		})
	}

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
