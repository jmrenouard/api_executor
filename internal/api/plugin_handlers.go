package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/plugins"
)

// PluginsListHandler returns metadata and actions for all registered declarative and native plugins.
func (env *APIEnv) PluginsListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.Authorize(p, "plugins:read", ""); err != nil {
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	var list []plugins.PluginInfo
	if env.PluginRegistry != nil {
		list = env.PluginRegistry.List()
	} else {
		list = []plugins.PluginInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Plugins []plugins.PluginInfo `json:"plugins"`
	}{
		Plugins: list,
	})
}

// PluginExecuteHandler executes an action on a declarative or advanced native plugin.
func (env *APIEnv) PluginExecuteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if env.PluginRegistry == nil {
		writeJSONError(w, "Plugin registry is not initialized", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		PluginID string         `json:"plugin_id"`
		Action   string         `json:"action"`
		Params   map[string]any `json:"params,omitempty"`
		Timeout  string         `json:"timeout,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.PluginID = strings.TrimSpace(req.PluginID)
	req.Action = strings.TrimSpace(req.Action)
	if req.PluginID == "" || req.Action == "" {
		writeJSONError(w, "Both plugin_id and action are required", http.StatusBadRequest)
		return
	}

	actionKey := fmt.Sprintf("plugin:%s:%s", req.PluginID, req.Action)
	p, authErr := env.resolvePrincipal(r)
	if authErr != nil {
		recordActionCall(actionKey, "error", false, 0)
		writeJSONError(w, authErr.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.Authorize(p, "plugins:execute", actionKey); err != nil {
		// Also allow if service account allowed_actions matches plugin_id or action directly
		if auth.Authorize(p, "plugins:execute", req.PluginID) != nil && auth.Authorize(p, "plugins:execute", req.Action) != nil {
			recordActionCall(actionKey, "error", false, 0)
			if env.AuditLogger != nil {
				_, _ = env.AuditLogger.Record(audit.AuditEvent{
					Category:  "plugin",
					Action:    actionKey,
					ActorType: p.Type,
					ActorID:   p.Name,
					SourceIP:  r.RemoteAddr,
					Status:    "denied",
					Summary:   fmt.Sprintf("Denied plugin action %q for %s: %v", actionKey, p.Name, err),
				})
			}
			writeJSONError(w, err.Error(), http.StatusForbidden)
			return
		}
	}

	timeout := 30 * time.Second
	if env.Config != nil {
		timeout = env.Config.Executor.EffectiveDefaultTimeout()
	}
	if strings.TrimSpace(req.Timeout) != "" {
		parsed, err := core.ParseTimeoutDuration(req.Timeout)
		if err != nil {
			recordActionCall(actionKey, "error", false, 0)
			writeJSONError(w, fmt.Sprintf("Invalid plugin timeout: %v", err), http.StatusBadRequest)
			return
		}
		timeout = parsed
	}

	start := time.Now()
	res, execErr := env.PluginRegistry.Execute(r.Context(), req.PluginID, req.Action, req.Params, timeout)
	duration := time.Since(start)

	metricOutcome := "ok"
	if execErr != nil {
		if res.Status == "failure" {
			metricOutcome = "failure"
		} else {
			metricOutcome = "error"
		}
	}
	recordActionCall(actionKey, metricOutcome, res.TimedOut, duration)

	if env.AuditLogger != nil {
		_, _ = env.AuditLogger.Record(audit.AuditEvent{
			Category:   "plugin",
			Action:     actionKey,
			ActorType:  p.Type,
			ActorID:    p.Name,
			SourceIP:   r.RemoteAddr,
			Status:     res.Status,
			DurationMs: res.DurationMs,
			Summary:    fmt.Sprintf("Executed plugin %q action %q (status=%s)", req.PluginID, req.Action, res.Status),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if execErr != nil {
		if errors.Is(execErr, plugins.ErrPluginNotFound) || errors.Is(execErr, plugins.ErrActionNotFound) {
			w.WriteHeader(http.StatusNotFound)
		} else if errors.Is(execErr, plugins.ErrForbiddenSQL) {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}
	_ = json.NewEncoder(w).Encode(res)
}

// PluginDeclarativeRegisterHandler dynamically registers a new declarative command module from JSON or YAML.
func (env *APIEnv) PluginDeclarativeRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if env.PluginRegistry == nil {
		writeJSONError(w, "Plugin registry is not initialized", http.StatusServiceUnavailable)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if p.Type != "anonymous" && p.Role != auth.RoleAdmin {
		writeJSONError(w, "Admin role required to register declarative plugins", http.StatusForbidden)
		return
	}

	var spec plugins.DeclarativeModuleSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeJSONError(w, "Invalid declarative module specification", http.StatusBadRequest)
		return
	}
	declPlugin, err := env.PluginRegistry.RegisterDeclarativeModule(spec)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	info := plugins.PluginInfo{
		ID:          declPlugin.ID(),
		Name:        declPlugin.Name(),
		Version:     declPlugin.Version(),
		Kind:        declPlugin.Kind(),
		Description: declPlugin.Description(),
		Actions:     declPlugin.Actions(),
	}

	if env.AuditLogger != nil {
		_, _ = env.AuditLogger.Record(audit.AuditEvent{
			Category:  "plugin",
			Action:    "plugin.register_declarative",
			ActorType: p.Type,
			ActorID:   p.Name,
			SourceIP:  r.RemoteAddr,
			Status:    "ok",
			Summary:   fmt.Sprintf("Registered declarative plugin %q (%d actions)", info.ID, len(info.Actions)),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(info)
}

// DBTablesHandler exposes database tables and aggregate telemetry via the db-exposure plugin.
func (env *APIEnv) DBTablesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.Authorize(p, "plugins:read", "db-exposure"); err != nil {
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	dbPlugin := env.resolveDBExposurePlugin()
	if dbPlugin == nil {
		writeJSONError(w, "Database exposure plugin is not enabled", http.StatusServiceUnavailable)
		return
	}

	tablesRes, err := dbPlugin.Execute(r.Context(), "list_tables", nil, 10*time.Second)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	statsRes, _ := dbPlugin.Execute(r.Context(), "db_stats", nil, 10*time.Second)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tables": tablesRes.Data,
		"stats":  statsRes.Data,
	})
}

// DBQueryHandler executes a guarded read-only SQL SELECT query or table sample via the db-exposure plugin.
func (env *APIEnv) DBQueryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.Authorize(p, "plugins:execute", "db-exposure"); err != nil {
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	dbPlugin := env.resolveDBExposurePlugin()
	if dbPlugin == nil {
		writeJSONError(w, "Database exposure plugin is not enabled", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Action  string `json:"action,omitempty"`
		SQL     string `json:"sql,omitempty"`
		Table   string `json:"table,omitempty"`
		MaxRows int    `json:"max_rows,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	action := strings.TrimSpace(req.Action)
	if action == "" {
		if strings.TrimSpace(req.SQL) != "" {
			action = "query_readonly"
		} else {
			action = "table_sample"
		}
	}

	params := map[string]any{
		"sql":      req.SQL,
		"table":    req.Table,
		"max_rows": req.MaxRows,
		"limit":    req.MaxRows,
	}

	res, execErr := dbPlugin.Execute(r.Context(), action, params, 15*time.Second)
	if env.AuditLogger != nil {
		status := res.Status
		if execErr != nil && status == "" {
			status = "error"
		}
		_, _ = env.AuditLogger.Record(audit.AuditEvent{
			Category:   "database",
			Action:     "db." + action,
			ActorType:  p.Type,
			ActorID:    p.Name,
			SourceIP:   r.RemoteAddr,
			Status:     status,
			DurationMs: res.DurationMs,
			Summary:    fmt.Sprintf("Database exposure action %q (status=%s)", action, status),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if execErr != nil {
		if errors.Is(execErr, plugins.ErrForbiddenSQL) {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}
	_ = json.NewEncoder(w).Encode(res)
}

func (env *APIEnv) resolveDBExposurePlugin() plugins.Plugin {
	if env.PluginRegistry != nil {
		if p, ok := env.PluginRegistry.Get("db-exposure"); ok {
			return p
		}
	}
	if env.DB != nil {
		maxRows := 200
		if env.Config != nil && env.Config.Plugins.MaxQueryRows > 0 {
			maxRows = env.Config.Plugins.MaxQueryRows
		}
		return plugins.NewDatabaseExposurePlugin(env.DB, maxRows)
	}
	return nil
}
