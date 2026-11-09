package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/jobs"
)

// SubmitJobRequest defines the JSON payload for POST /api/v1/jobs.
type SubmitJobRequest struct {
	Type            jobs.JobType   `json:"type"`
	Action          string         `json:"action"`
	PluginID        string         `json:"plugin_id,omitempty"`
	Params          map[string]any `json:"params,omitempty"`
	Priority        jobs.Priority  `json:"priority,omitempty"`
	Timeout         string         `json:"timeout,omitempty"`
	TimeoutOverride string         `json:"timeout_override,omitempty"`
}

// SubmitJobResponse defines the response returned upon successful job enqueueing (HTTP 202).
type SubmitJobResponse struct {
	JobID     string         `json:"job_id"`
	Status    jobs.JobStatus `json:"status"`
	Priority  jobs.Priority  `json:"priority"`
	Action    string         `json:"action"`
	Type      jobs.JobType   `json:"type"`
	CreatedAt time.Time      `json:"created_at"`
	PollURL   string         `json:"poll_url"`
	LogsURL   string         `json:"logs_url"`
}

// JobListResponse defines the response structure for GET /api/v1/jobs.
type JobListResponse struct {
	Jobs   []*jobs.Job `json:"jobs"`
	Total  int         `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

// JobLogsResponse defines the chunked response for GET /api/v1/jobs/{id}/logs.
type JobLogsResponse struct {
	JobID      string         `json:"job_id"`
	Status     jobs.JobStatus `json:"status"`
	Logs       string         `json:"logs"`
	Offset     int            `json:"offset"`
	NextOffset int            `json:"next_offset"`
	Truncated  bool           `json:"truncated"`
	EOF        bool           `json:"eof"`
}

// CancelJobResponse defines the response for POST /api/v1/jobs/{id}/cancel.
type CancelJobResponse struct {
	JobID   string         `json:"job_id"`
	Status  jobs.JobStatus `json:"status"`
	Message string         `json:"message"`
}

// QueueStatsResponse defines the response for GET /api/v1/jobs/queue.
type QueueStatsResponse struct {
	QueuedJobs    int `json:"queued_jobs"`
	WorkersTotal  int `json:"workers_total"`
	WorkersActive int `json:"workers_active"`
	Capacity      int `json:"capacity"`
}

func (env *APIEnv) checkJobAuth(r *http.Request, requiredScope string) (*auth.Principal, error) {
	principal, err := env.resolvePrincipal(r)
	if err != nil {
		return nil, err
	}
	if env.Config != nil && env.Config.Auth.RequireAuth && (principal == nil || principal.Type == "anonymous") {
		return nil, auth.ErrInvalidToken
	}
	if err := auth.Authorize(principal, requiredScope, ""); err != nil {
		return principal, err
	}
	return principal, nil
}

func (env *APIEnv) recordJobAuditDenial(action string, p *auth.Principal, sourceIP, target string, err error) {
	if env.AuditLogger == nil || p == nil {
		return
	}
	actorID := p.Username
	if actorID == "" {
		actorID = p.Name
	}
	_, _ = env.AuditLogger.Record(audit.AuditEvent{
		Category:  "job",
		Action:    action,
		ActorType: p.Type,
		ActorID:   actorID,
		SourceIP:  sourceIP,
		Status:    "denied",
		Summary:   fmt.Sprintf("Denied %s on %q for %s (%s): %v", action, target, actorID, p.Type, err),
	})
}

// JobsHandler multiplexes POST (submit job) and GET (list jobs) on /api/v1/jobs.
func (env *APIEnv) JobsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		env.SubmitJobHandler(w, r)
	case http.MethodGet:
		env.ListJobsHandler(w, r)
	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// SubmitJobHandler enqueues a new background job (HTTP 202 Accepted).
func (env *APIEnv) SubmitJobHandler(w http.ResponseWriter, r *http.Request) {
	if env.JobEngine == nil {
		writeJSONError(w, "Job engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	principal, authErr := env.checkJobAuth(r, auth.ScopeJobsSubmit)
	if authErr != nil {
		if errors.Is(authErr, auth.ErrInvalidToken) || errors.Is(authErr, auth.ErrAccountDisabled) {
			writeJSONError(w, authErr.Error(), http.StatusUnauthorized)
			return
		}
		env.recordJobAuditDenial("job.submit", principal, r.RemoteAddr, "jobs:submit", authErr)
		writeJSONError(w, authErr.Error(), http.StatusForbidden)
		return
	}

	var req SubmitJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	jobType := jobs.JobType(strings.ToLower(strings.TrimSpace(string(req.Type))))
	if jobType == "" {
		jobType = jobs.TypeCommand
	}
	if jobType != jobs.TypeCommand && jobType != jobs.TypePlugin {
		writeJSONError(w, fmt.Sprintf("Unsupported job type %q", req.Type), http.StatusBadRequest)
		return
	}

	actionName := strings.TrimSpace(req.Action)
	if actionName == "" {
		writeJSONError(w, "Action is required", http.StatusBadRequest)
		return
	}

	pluginID := strings.TrimSpace(req.PluginID)
	if jobType == jobs.TypePlugin && pluginID == "" {
		writeJSONError(w, "Plugin ID is required for plugin job", http.StatusBadRequest)
		return
	}

	// Two-tier authorization: verify underlying command or plugin action
	if jobType == jobs.TypeCommand {
		if env.Config != nil && !env.Config.Executor.Enabled {
			writeJSONError(w, "Command executor is disabled", http.StatusNotFound)
			return
		}

		if err := auth.Authorize(principal, "commands:execute", actionName); err != nil {
			env.recordJobAuditDenial("job.submit", principal, r.RemoteAddr, actionName, err)
			writeJSONError(w, err.Error(), http.StatusForbidden)
			return
		}

		if _, found := env.FindCommand(actionName); !found {
			writeJSONError(w, fmt.Sprintf("Command %q not found", actionName), http.StatusNotFound)
			return
		}
	} else if jobType == jobs.TypePlugin {
		actionKey := fmt.Sprintf("plugin:%s:%s", pluginID, actionName)
		if err := auth.Authorize(principal, "plugins:execute", actionKey); err != nil {
			if auth.Authorize(principal, "plugins:execute", pluginID) != nil && auth.Authorize(principal, "plugins:execute", actionName) != nil {
				env.recordJobAuditDenial("job.submit", principal, r.RemoteAddr, actionKey, err)
				writeJSONError(w, err.Error(), http.StatusForbidden)
				return
			}
		}

		if env.PluginRegistry == nil {
			writeJSONError(w, "Plugin registry is not initialized", http.StatusNotFound)
			return
		}
		if _, found := env.PluginRegistry.Get(pluginID); !found {
			writeJSONError(w, fmt.Sprintf("Plugin %q not found", pluginID), http.StatusNotFound)
			return
		}
	}

	rawTimeout := strings.TrimSpace(req.Timeout)
	if rawTimeout == "" {
		rawTimeout = strings.TrimSpace(req.TimeoutOverride)
	}
	var timeoutOverride time.Duration
	if rawTimeout != "" {
		parsed, err := core.ParseTimeoutDuration(rawTimeout)
		if err != nil {
			writeJSONError(w, fmt.Sprintf("Invalid timeout parameter: %v", err), http.StatusBadRequest)
			return
		}
		timeoutOverride = parsed
	}

	if env.Config != nil && env.Config.Executor.MaxTimeoutSeconds > 0 && timeoutOverride > 0 {
		maxAllowed := time.Duration(env.Config.Executor.MaxTimeoutSeconds) * time.Second
		if timeoutOverride > maxAllowed {
			writeJSONError(w, fmt.Sprintf("Requested timeout %s exceeds maximum allowed timeout %s", timeoutOverride, maxAllowed), http.StatusBadRequest)
			return
		}
	}

	actorID := principal.Username
	if actorID == "" {
		actorID = principal.Name
	}

	jobReq := jobs.JobRequest{
		Type:            jobType,
		Action:          actionName,
		PluginID:        pluginID,
		Params:          req.Params,
		Priority:        jobs.ParsePriority(string(req.Priority)),
		TimeoutOverride: timeoutOverride,
		ActorType:       principal.Type,
		ActorID:         actorID,
		SourceIP:        r.RemoteAddr,
	}

	job, err := env.JobEngine.Enqueue(jobReq)
	if err != nil {
		if errors.Is(err, jobs.ErrQueueFull) {
			writeJSONError(w, "Queue capacity exceeded", http.StatusTooManyRequests)
			return
		}
		writeJSONError(w, fmt.Sprintf("Failed to enqueue job: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", fmt.Sprintf("/api/v1/jobs/%s", job.ID))
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(SubmitJobResponse{
		JobID:     job.ID,
		Status:    job.Status,
		Priority:  job.Priority,
		Action:    job.Action,
		Type:      job.Type,
		CreatedAt: job.CreatedAt,
		PollURL:   fmt.Sprintf("/api/v1/jobs/%s", job.ID),
		LogsURL:   fmt.Sprintf("/api/v1/jobs/%s/logs", job.ID),
	})
}

// ListJobsHandler lists existing and historical background jobs with filtering and pagination.
func (env *APIEnv) ListJobsHandler(w http.ResponseWriter, r *http.Request) {
	if env.JobEngine == nil {
		writeJSONError(w, "Job engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	principal, authErr := env.checkJobAuth(r, auth.ScopeJobsRead)
	if authErr != nil {
		if errors.Is(authErr, auth.ErrInvalidToken) || errors.Is(authErr, auth.ErrAccountDisabled) {
			writeJSONError(w, authErr.Error(), http.StatusUnauthorized)
			return
		}
		env.recordJobAuditDenial("job.list", principal, r.RemoteAddr, "jobs:read", authErr)
		writeJSONError(w, authErr.Error(), http.StatusForbidden)
		return
	}

	q := r.URL.Query()
	limit := 50
	if l := q.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
			if limit > 200 {
				limit = 200
			}
		}
	}

	offset := 0
	if o := q.Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	filter := jobs.JobFilter{
		Status:  jobs.JobStatus(strings.ToLower(strings.TrimSpace(q.Get("status")))),
		Type:    jobs.JobType(strings.ToLower(strings.TrimSpace(q.Get("type")))),
		Action:  strings.TrimSpace(q.Get("action")),
		ActorID: strings.TrimSpace(q.Get("actor_id")),
		Limit:   limit,
		Offset:  offset,
	}

	jobList, total := env.JobEngine.ListJobs(filter)
	if jobList == nil {
		jobList = []*jobs.Job{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(JobListResponse{
		Jobs:   jobList,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// JobQueueStatsHandler returns real-time worker pool and queue depth telemetry.
func (env *APIEnv) JobQueueStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if env.JobEngine == nil {
		writeJSONError(w, "Job engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	principal, authErr := env.checkJobAuth(r, auth.ScopeJobsRead)
	if authErr != nil {
		if errors.Is(authErr, auth.ErrInvalidToken) || errors.Is(authErr, auth.ErrAccountDisabled) {
			writeJSONError(w, authErr.Error(), http.StatusUnauthorized)
			return
		}
		env.recordJobAuditDenial("job.queue_stats", principal, r.RemoteAddr, "jobs:read", authErr)
		writeJSONError(w, authErr.Error(), http.StatusForbidden)
		return
	}

	stats := env.JobEngine.QueueStats()
	UpdateJobQueueMetrics(stats.QueuedJobs, stats.WorkersActive)
	UpdateJobWorkersTotal(stats.WorkersTotal)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(QueueStatsResponse{
		QueuedJobs:    stats.QueuedJobs,
		WorkersTotal:  stats.WorkersTotal,
		WorkersActive: stats.WorkersActive,
		Capacity:      stats.Capacity,
	})
}

// JobSubroutesHandler handles dynamic parameterized routes under /api/v1/jobs/{id}[/logs|/cancel].
func (env *APIEnv) JobSubroutesHandler(w http.ResponseWriter, r *http.Request) {
	subpath := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	subpath = strings.TrimSuffix(subpath, "/")

	if subpath == "queue" {
		env.JobQueueStatsHandler(w, r)
		return
	}

	parts := strings.Split(subpath, "/")
	if len(parts) == 0 || parts[0] == "" {
		env.JobsHandler(w, r)
		return
	}

	jobID := parts[0]
	if len(parts) == 1 {
		// GET /api/v1/jobs/{id}
		if r.Method != http.MethodGet {
			writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		env.GetJobByIDHandler(w, r, jobID)
		return
	}

	if len(parts) == 2 {
		switch parts[1] {
		case "logs":
			// GET /api/v1/jobs/{id}/logs
			if r.Method != http.MethodGet {
				writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			env.GetJobLogsHandler(w, r, jobID)
			return
		case "cancel":
			// POST /api/v1/jobs/{id}/cancel
			if r.Method != http.MethodPost {
				writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			env.CancelJobHandler(w, r, jobID)
			return
		}
	}

	writeJSONError(w, "Route not found", http.StatusNotFound)
}

// GetJobByIDHandler returns complete metadata and execution status for a job by ID.
func (env *APIEnv) GetJobByIDHandler(w http.ResponseWriter, r *http.Request, jobID string) {
	if env.JobEngine == nil {
		writeJSONError(w, "Job engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	principal, authErr := env.checkJobAuth(r, auth.ScopeJobsRead)
	if authErr != nil {
		if errors.Is(authErr, auth.ErrInvalidToken) || errors.Is(authErr, auth.ErrAccountDisabled) {
			writeJSONError(w, authErr.Error(), http.StatusUnauthorized)
			return
		}
		env.recordJobAuditDenial("job.get", principal, r.RemoteAddr, "jobs:read", authErr)
		writeJSONError(w, authErr.Error(), http.StatusForbidden)
		return
	}

	job, found := env.JobEngine.GetJob(jobID)
	if !found || job == nil {
		writeJSONError(w, "Job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(job)
}

// GetJobLogsHandler streams live chunked execution logs from the job buffer.
func (env *APIEnv) GetJobLogsHandler(w http.ResponseWriter, r *http.Request, jobID string) {
	if env.JobEngine == nil {
		writeJSONError(w, "Job engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	principal, authErr := env.checkJobAuth(r, auth.ScopeJobsRead)
	if authErr != nil {
		if errors.Is(authErr, auth.ErrInvalidToken) || errors.Is(authErr, auth.ErrAccountDisabled) {
			writeJSONError(w, authErr.Error(), http.StatusUnauthorized)
			return
		}
		env.recordJobAuditDenial("job.logs", principal, r.RemoteAddr, "jobs:read", authErr)
		writeJSONError(w, authErr.Error(), http.StatusForbidden)
		return
	}

	offset := 0
	if rawOffset := r.URL.Query().Get("offset"); rawOffset != "" {
		if parsed, err := strconv.Atoi(rawOffset); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	logs, nextOffset, truncated, eof, err := env.JobEngine.GetJobLogs(jobID, offset)
	if err != nil {
		if errors.Is(err, jobs.ErrJobNotFound) {
			writeJSONError(w, "Job not found", http.StatusNotFound)
			return
		}
		writeJSONError(w, fmt.Sprintf("Failed to retrieve job logs: %v", err), http.StatusInternalServerError)
		return
	}

	status := jobs.StatusQueued
	if job, found := env.JobEngine.GetJob(jobID); found && job != nil {
		status = job.Status
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(JobLogsResponse{
		JobID:      jobID,
		Status:     status,
		Logs:       logs,
		Offset:     offset,
		NextOffset: nextOffset,
		Truncated:  truncated,
		EOF:        eof,
	})
}

// CancelJobHandler aborts an active queued or running job by ID.
func (env *APIEnv) CancelJobHandler(w http.ResponseWriter, r *http.Request, jobID string) {
	if env.JobEngine == nil {
		writeJSONError(w, "Job engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	principal, authErr := env.resolvePrincipal(r)
	if authErr != nil {
		writeJSONError(w, authErr.Error(), http.StatusUnauthorized)
		return
	}
	if env.Config != nil && env.Config.Auth.RequireAuth && (principal == nil || principal.Type == "anonymous") {
		writeJSONError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	job, found := env.JobEngine.GetJob(jobID)
	if !found || job == nil {
		writeJSONError(w, "Job not found", http.StatusNotFound)
		return
	}

	if job.Status.IsTerminal() {
		writeJSONError(w, "job is already finished", http.StatusConflict)
		return
	}

	if err := auth.Authorize(principal, auth.ScopeJobsCancel, job.Action); err != nil {
		env.recordJobAuditDenial("job.cancel", principal, r.RemoteAddr, job.Action, err)
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	if err := env.JobEngine.CancelJob(jobID); err != nil {
		if errors.Is(err, jobs.ErrJobNotFound) {
			writeJSONError(w, "Job not found", http.StatusNotFound)
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "already finished") {
			writeJSONError(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSONError(w, fmt.Sprintf("Failed to cancel job: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(CancelJobResponse{
		JobID:   jobID,
		Status:  jobs.StatusCancelled,
		Message: "Job cancellation requested successfully",
	})
}
