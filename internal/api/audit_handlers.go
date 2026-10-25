package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

// AuditLogsHandler returns filtered tamper-evident audit events.
func (env *APIEnv) AuditLogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if env.AuditLogger == nil {
		_ = json.NewEncoder(w).Encode(struct {
			Events []audit.AuditEvent `json:"events"`
			Total  int                `json:"total"`
		}{Events: []audit.AuditEvent{}, Total: 0})
		return
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	filter := audit.AuditFilter{
		Category: q.Get("category"),
		Action:   q.Get("action"),
		ActorID:  q.Get("actor_id"),
		Status:   q.Get("status"),
		TraceID:  q.Get("trace_id"),
		Limit:    limit,
	}
	events := env.AuditLogger.Query(filter)
	if events == nil {
		events = []audit.AuditEvent{}
	}
	_ = json.NewEncoder(w).Encode(struct {
		Events []audit.AuditEvent `json:"events"`
		Total  int                `json:"total"`
	}{
		Events: events,
		Total:  env.AuditLogger.Count(),
	})
}

// AuditVerifyHandler verifies the SHA-256 hash chain integrity of all retained audit events.
func (env *APIEnv) AuditVerifyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if env.AuditLogger == nil {
		_ = json.NewEncoder(w).Encode(audit.ChainVerificationResult{
			Valid:       true,
			TotalEvents: 0,
			LastHash:    audit.GenesisHash,
		})
		return
	}
	_ = json.NewEncoder(w).Encode(env.AuditLogger.VerifyChain())
}

// SystemLogsHandler returns recent structured application log entries from the in-memory ring buffer.
func (env *APIEnv) SystemLogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if env.Logger == nil {
		_ = json.NewEncoder(w).Encode(struct {
			Logs []core.LogRecord `json:"logs"`
		}{Logs: []core.LogRecord{}})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	level := q.Get("level")
	entries := env.Logger.RecentEntries(limit, level)
	if entries == nil {
		entries = []core.LogRecord{}
	}
	_ = json.NewEncoder(w).Encode(struct {
		Logs []core.LogRecord `json:"logs"`
	}{Logs: entries})
}

// ActionHistoryHandler returns the most recent command execution history entries from SQLite / in-memory DB.
func (env *APIEnv) ActionHistoryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if env.DB == nil {
		_ = json.NewEncoder(w).Encode(struct {
			History []database.ActionHistory `json:"history"`
		}{History: []database.ActionHistory{}})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	records, err := env.DB.ListActions(limit)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if records == nil {
		records = []database.ActionHistory{}
	}
	_ = json.NewEncoder(w).Encode(struct {
		History []database.ActionHistory `json:"history"`
	}{History: records})
}
