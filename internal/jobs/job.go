package jobs

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// JobStatus represents the lifecycle state of an asynchronous job.
type JobStatus string

const (
	StatusQueued    JobStatus = "queued"
	StatusRunning   JobStatus = "running"
	StatusCompleted JobStatus = "completed"
	StatusFailed    JobStatus = "failed"
	StatusCancelled JobStatus = "cancelled"
	StatusTimedOut  JobStatus = "timed_out"
)

// IsTerminal reports whether the job status is in an immutable, completed state.
func (s JobStatus) IsTerminal() bool {
	switch s {
	case StatusCompleted, StatusFailed, StatusCancelled, StatusTimedOut:
		return true
	default:
		return false
	}
}

// IsActive reports whether the job is queued or actively running.
func (s JobStatus) IsActive() bool {
	return s == StatusQueued || s == StatusRunning
}

// JobType represents the underlying execution mechanism.
type JobType string

const (
	TypeCommand JobType = "command"
	TypePlugin  JobType = "plugin"
)

// Priority represents the execution priority tier in the job queue.
type Priority string

const (
	PriorityHigh   Priority = "high"
	PriorityNormal Priority = "normal"
	PriorityLow    Priority = "low"
)

// Level maps Priority to an integer for heap comparisons. Higher values take precedence.
func (p Priority) Level() int {
	switch strings.ToLower(string(p)) {
	case "high", "urgent":
		return 3
	case "low":
		return 1
	case "normal", "":
		return 2
	default:
		return 2
	}
}

// Weight is an alias to Level for heap priority comparison.
func (p Priority) Weight() int {
	return p.Level()
}

// ParsePriority parses a string into a valid Priority, defaulting to PriorityNormal.
func ParsePriority(s string) Priority {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "urgent":
		return PriorityHigh
	case "low":
		return PriorityLow
	case "normal", "":
		return PriorityNormal
	default:
		return PriorityNormal
	}
}

// JobRequest defines the payload for submitting an asynchronous job.
type JobRequest struct {
	Type            JobType        `json:"type"`                       // "command" | "plugin"
	Action          string         `json:"action"`                     // Command name or plugin action
	PluginID        string         `json:"plugin_id,omitempty"`        // Plugin ID if Type == "plugin"
	Params          map[string]any `json:"params,omitempty"`           // Parameters for command or plugin
	Priority        Priority       `json:"priority,omitempty"`         // "high" | "normal" | "low"
	TimeoutOverride time.Duration  `json:"timeout_override,omitempty"` // Optional per-job timeout override
	ActorType       string         `json:"actor_type,omitempty"`       // user, token, service_account, anonymous
	ActorID         string         `json:"actor_id,omitempty"`         // Username or token name
	SourceIP        string         `json:"source_ip,omitempty"`        // Client remote address
}

// Job represents an asynchronous execution task, its metadata, lifecycle state, and logs.
type Job struct {
	mu sync.RWMutex

	ID          string         `json:"id"`
	Type        JobType        `json:"type"`
	Action      string         `json:"action"`
	PluginID    string         `json:"plugin_id,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
	Priority    Priority       `json:"priority"`
	Status      JobStatus      `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	DurationMs  int64          `json:"duration_ms,omitempty"`
	Timeout     time.Duration  `json:"timeout"`
	ActorType   string         `json:"actor_type"`
	ActorID     string         `json:"actor_id"`
	SourceIP    string         `json:"source_ip,omitempty"`
	Error       string         `json:"error,omitempty"`
	ResultData  any            `json:"result_data,omitempty"`

	// Runtime execution controls (unexported, protected by mu)
	cancelFn  context.CancelFunc
	logBuf    *JobLogBuffer
	queueSeq  int64 // Monotonic sequence counter for FIFO tie-breaking within same priority
	heapIndex int   // Index inside the priority queue heap array
}

// MarshalJSON implements json.Marshaler with read-lock synchronization
// to guarantee race-free serialization during concurrent worker mutations.
func (j *Job) MarshalJSON() ([]byte, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	type Alias Job
	return json.Marshal((*Alias)(j))
}

// Snapshot returns a thread-safe shallow copy of the job's public fields.
func (j *Job) Snapshot() *Job {
	j.mu.RLock()
	defer j.mu.RUnlock()

	snap := &Job{
		ID:         j.ID,
		Type:       j.Type,
		Action:     j.Action,
		PluginID:   j.PluginID,
		Priority:   j.Priority,
		Status:     j.Status,
		CreatedAt:  j.CreatedAt,
		DurationMs: j.DurationMs,
		Timeout:    j.Timeout,
		ActorType:  j.ActorType,
		ActorID:    j.ActorID,
		SourceIP:   j.SourceIP,
		Error:      j.Error,
		ResultData: j.ResultData,
	}

	if j.Params != nil {
		snap.Params = make(map[string]any, len(j.Params))
		for k, v := range j.Params {
			snap.Params[k] = v
		}
	}
	if j.StartedAt != nil {
		t := *j.StartedAt
		snap.StartedAt = &t
	}
	if j.CompletedAt != nil {
		t := *j.CompletedAt
		snap.CompletedAt = &t
	}
	return snap
}

// LogBuffer returns the JobLogBuffer attached to this job, or nil if none.
func (j *Job) LogBuffer() *JobLogBuffer {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.logBuf
}

// SetLogBuffer assigns the JobLogBuffer for this job.
func (j *Job) SetLogBuffer(buf *JobLogBuffer) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.logBuf = buf
}

// SetResultData updates the job's result data under mutex protection.
func (j *Job) SetResultData(res any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.ResultData = res
}

// GetResultData retrieves the job's result data under read-lock protection.
func (j *Job) GetResultData() any {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.ResultData
}

// GetStatus returns the current JobStatus in a thread-safe manner.
func (j *Job) GetStatus() JobStatus {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Status
}

// SetRunning transitions the job from queued to running, attaching its cancellation function.
// Returns false if the job was already cancelled or in a terminal state.
func (j *Job) SetRunning(startedAt time.Time, cancelFn context.CancelFunc) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Status != StatusQueued {
		return false
	}
	j.Status = StatusRunning
	t := startedAt.UTC()
	j.StartedAt = &t
	j.cancelFn = cancelFn
	return true
}

// SetCompleted marks the job as completed successfully.
func (j *Job) SetCompleted(completedAt time.Time, result any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	t := completedAt.UTC()
	j.CompletedAt = &t
	if j.StartedAt != nil {
		j.DurationMs = t.Sub(*j.StartedAt).Milliseconds()
	}
	j.Status = StatusCompleted
	j.ResultData = result
	if j.logBuf != nil {
		j.logBuf.SetEOF()
	}
}

// SetFailed marks the job as failed with an error message.
func (j *Job) SetFailed(completedAt time.Time, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	t := completedAt.UTC()
	j.CompletedAt = &t
	if j.StartedAt != nil {
		j.DurationMs = t.Sub(*j.StartedAt).Milliseconds()
	}
	j.Status = StatusFailed
	j.Error = errMsg
	if j.logBuf != nil {
		j.logBuf.SetEOF()
	}
}

// SetTimedOut marks the job as timed out.
func (j *Job) SetTimedOut(completedAt time.Time, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	t := completedAt.UTC()
	j.CompletedAt = &t
	if j.StartedAt != nil {
		j.DurationMs = t.Sub(*j.StartedAt).Milliseconds()
	}
	j.Status = StatusTimedOut
	j.Error = errMsg
	if j.logBuf != nil {
		j.logBuf.SetEOF()
	}
}

// Cancel attempts to cancel the job.
// If the job is queued, it transitions directly to cancelled.
// If the job is running, it invokes cancelFn() which signals the subprocess to terminate.
// Returns true if the job was cancelled or cancelFn invoked, false if already terminal.
func (j *Job) Cancel() bool {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.Status.IsTerminal() {
		return false
	}
	if j.Status == StatusQueued {
		j.Status = StatusCancelled
		now := time.Now().UTC()
		j.CompletedAt = &now
		j.Error = "job cancelled before execution"
		if j.logBuf != nil {
			j.logBuf.SetEOF()
		}
		return true
	}
	if j.Status == StatusRunning {
		if j.cancelFn != nil {
			j.cancelFn()
		}
		return true
	}
	return false
}

// SetCancelledFinal marks the job as cancelled after subprocess termination.
func (j *Job) SetCancelledFinal(completedAt time.Time, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	t := completedAt.UTC()
	j.CompletedAt = &t
	if j.StartedAt != nil {
		j.DurationMs = t.Sub(*j.StartedAt).Milliseconds()
	}
	j.Status = StatusCancelled
	j.Error = errMsg
	if j.logBuf != nil {
		j.logBuf.SetEOF()
	}
}

// PriorityQueue internal helpers for queue.go
func (j *Job) GetQueueSeq() int64 {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.queueSeq
}

func (j *Job) SetQueueSeq(seq int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.queueSeq = seq
}

func (j *Job) GetHeapIndex() int {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.heapIndex
}

func (j *Job) SetHeapIndex(idx int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.heapIndex = idx
}

// JobFilter defines query parameters for listing and filtering jobs.
type JobFilter struct {
	Status    JobStatus  `json:"status,omitempty"`
	Type      JobType    `json:"type,omitempty"`
	Action    string     `json:"action,omitempty"`
	ActorID   string     `json:"actor_id,omitempty"`
	ActorType string     `json:"actor_type,omitempty"`
	Since     *time.Time `json:"since,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// Matches reports whether a job satisfies the filter criteria (used for in-memory filtering).
func (f JobFilter) Matches(j *Job) bool {
	if f.Status != "" && j.Status != f.Status {
		return false
	}
	if f.Type != "" && j.Type != f.Type {
		return false
	}
	if f.Action != "" && j.Action != f.Action {
		return false
	}
	if f.ActorID != "" && j.ActorID != f.ActorID {
		return false
	}
	if f.ActorType != "" && j.ActorType != f.ActorType {
		return false
	}
	if f.Since != nil && j.CreatedAt.Before(*f.Since) {
		return false
	}
	return true
}
