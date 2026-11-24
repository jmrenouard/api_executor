package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/jobs"
)

const ssePollInterval = 100 * time.Millisecond

var sseKeepaliveInterval = 15 * time.Second

type sseLogEvent struct {
	JobID      string `json:"job_id"`
	Logs       string `json:"logs"`
	Offset     int    `json:"offset"`
	NextOffset int    `json:"next_offset"`
	Truncated  bool   `json:"truncated"`
}

type sseStatusEvent struct {
	JobID  string         `json:"job_id"`
	Status jobs.JobStatus `json:"status"`
}

type sseDoneEvent struct {
	JobID      string         `json:"job_id"`
	Status     jobs.JobStatus `json:"status"`
	NextOffset int            `json:"next_offset"`
	Truncated  bool           `json:"truncated"`
	EOF        bool           `json:"eof"`
}

// resolveFlusher unwraps middleware ResponseWriters to locate an http.Flusher.
func resolveFlusher(w http.ResponseWriter) (http.Flusher, bool) {
	for w != nil {
		if f, ok := w.(http.Flusher); ok {
			return f, true
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil, false
		}
		w = u.Unwrap()
	}
	return nil, false
}

// parseStreamStartOffset resolves the starting byte offset from ?offset= and Last-Event-ID.
// Last-Event-ID takes precedence so EventSource reconnects resume from the last delivered byte.
func parseStreamStartOffset(r *http.Request) int {
	offset := 0
	if rawOffset := strings.TrimSpace(r.URL.Query().Get("offset")); rawOffset != "" {
		if parsed, err := strconv.Atoi(rawOffset); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	if lastEventID := strings.TrimSpace(r.Header.Get("Last-Event-ID")); lastEventID != "" {
		if parsed, err := strconv.Atoi(lastEventID); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	return offset
}

func writeSSEEvent(w http.ResponseWriter, id string, event string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if id != "" {
		if _, err := fmt.Fprintf(w, "id: %s\n", id); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	return err
}

// StreamJobLogsHandler godoc
// @Summary Stream live job logs and status via Server-Sent Events (SSE)
// @Description Pushes real-time status transitions, log chunks, keepalive heartbeats, and terminal completion events over text/event-stream with Last-Event-ID and offset resume support.
// @Tags jobs
// @Produce text/event-stream
// @Param id path string true "Unique Job Identifier"
// @Param offset query integer false "Starting byte offset (default 0)"
// @Success 200 {string} string "SSE event stream"
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Failure 403 {object} ErrorResponse "Forbidden"
// @Failure 404 {object} ErrorResponse "Not Found"
// @Failure 405 {object} ErrorResponse "Method Not Allowed"
// @Failure 500 {object} ErrorResponse "Internal Server Error"
// @Failure 503 {object} ErrorResponse "Service Unavailable"
// @Router /api/v1/jobs/{id}/stream [get]
func (env *APIEnv) StreamJobLogsHandler(w http.ResponseWriter, r *http.Request, jobID string) {
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
		env.recordJobAuditDenial("job.stream", principal, r.RemoteAddr, "jobs:read", authErr)
		writeJSONError(w, authErr.Error(), http.StatusForbidden)
		return
	}

	job, found := env.JobEngine.GetJob(jobID)
	if !found || job == nil {
		writeJSONError(w, "Job not found", http.StatusNotFound)
		return
	}

	offset := parseStreamStartOffset(r)

	flusher, ok := resolveFlusher(w)
	if !ok {
		writeJSONError(w, "Streaming unsupported by response writer", http.StatusInternalServerError)
		return
	}

	// Clear the server-level WriteTimeout deadline so long-lived SSE streams are not aborted.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var lastStatus jobs.JobStatus

	emitUpdate := func() bool {
		logs, nextOffset, truncated, eof, err := env.JobEngine.GetJobLogs(jobID, offset)
		if err != nil {
			return true
		}

		curJob, jobFound := env.JobEngine.GetJob(jobID)
		if !jobFound || curJob == nil {
			return true
		}
		status := curJob.GetStatus()

		flushedNeeded := false
		if status != lastStatus {
			if err := writeSSEEvent(w, "", "status", sseStatusEvent{
				JobID:  jobID,
				Status: status,
			}); err != nil {
				return true
			}
			lastStatus = status
			flushedNeeded = true
		}

		if len(logs) > 0 {
			if err := writeSSEEvent(w, strconv.Itoa(nextOffset), "log", sseLogEvent{
				JobID:      jobID,
				Logs:       logs,
				Offset:     offset,
				NextOffset: nextOffset,
				Truncated:  truncated,
			}); err != nil {
				return true
			}
			offset = nextOffset
			flushedNeeded = true
		}

		if eof && status.IsTerminal() {
			_ = writeSSEEvent(w, strconv.Itoa(nextOffset), "done", sseDoneEvent{
				JobID:      jobID,
				Status:     status,
				NextOffset: nextOffset,
				Truncated:  truncated,
				EOF:        true,
			})
			flusher.Flush()
			return true
		}

		if flushedNeeded {
			flusher.Flush()
		}
		return false
	}

	if emitUpdate() {
		return
	}

	pollTicker := time.NewTicker(ssePollInterval)
	defer pollTicker.Stop()

	keepaliveTicker := time.NewTicker(sseKeepaliveInterval)
	defer keepaliveTicker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pollTicker.C:
			if emitUpdate() {
				return
			}
		case <-keepaliveTicker.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
