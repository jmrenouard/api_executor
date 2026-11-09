package jobs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
)

// JobExecutorFn is the callback invoked by workers to execute a job's underlying action.
type JobExecutorFn func(ctx context.Context, job *Job, logWriter io.Writer) (result any, err error)

// EngineConfig holds configuration parameters for the asynchronous job engine.
type EngineConfig struct {
	WorkersCount    int           // default: 4
	QueueCapacity   int           // default: 1000
	MaxLogBytes     int           // default: 2 MiB (DefaultMaxLogBytes)
	PruneInterval   time.Duration // default: 10m
	MaxJobAge       time.Duration // default: 7 * 24h
	MaxRetainedJobs int           // default: 10000
}

// DefaultEngineConfig returns default configuration settings.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		WorkersCount:    4,
		QueueCapacity:   1000,
		MaxLogBytes:     DefaultMaxLogBytes,
		PruneInterval:   10 * time.Minute,
		MaxJobAge:       7 * 24 * time.Hour,
		MaxRetainedJobs: 10000,
	}
}

// QueueStats contains telemetry metrics regarding queue and worker pool state.
type QueueStats struct {
	QueuedJobs    int `json:"queued_jobs"`
	WorkersTotal  int `json:"workers_total"`
	WorkersActive int `json:"workers_active"`
	Capacity      int `json:"capacity"`
}

// Engine coordinates the job queue, worker pool, persistent store, and live log buffers.
type Engine struct {
	mu          sync.RWMutex
	cfg         EngineConfig
	queue       *JobQueue
	workerPool  *WorkerPool
	store       JobStore
	logBuffers  map[string]*JobLogBuffer
	auditLogger *audit.AuditLogger
	executor    JobExecutorFn
	pruneTicker *time.Ticker
	stopPrune   chan struct{}
	started     bool
}

// NewEngine creates an Engine instance.
func NewEngine(cfg EngineConfig, store JobStore, auditLogger *audit.AuditLogger, executor JobExecutorFn) (*Engine, error) {
	if cfg.WorkersCount <= 0 {
		cfg.WorkersCount = 4
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = 1000
	}
	if cfg.MaxLogBytes <= 0 {
		cfg.MaxLogBytes = DefaultMaxLogBytes
	}
	if cfg.PruneInterval <= 0 {
		cfg.PruneInterval = 10 * time.Minute
	}
	if cfg.MaxJobAge <= 0 {
		cfg.MaxJobAge = 7 * 24 * time.Hour
	}
	if cfg.MaxRetainedJobs <= 0 {
		cfg.MaxRetainedJobs = 10000
	}

	if store == nil {
		store = NewMemoryJobStore()
	}

	queue := NewJobQueue(cfg.QueueCapacity)

	e := &Engine{
		cfg:         cfg,
		queue:       queue,
		store:       store,
		logBuffers:  make(map[string]*JobLogBuffer),
		auditLogger: auditLogger,
		executor:    executor,
		stopPrune:   make(chan struct{}),
	}

	e.workerPool = NewWorkerPool(cfg.WorkersCount, queue, e.handleJobExecution)
	return e, nil
}

// Start boots the worker pool and background maintenance tasks.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.started {
		return errors.New("engine already started")
	}
	e.started = true

	if err := e.workerPool.Start(); err != nil {
		return err
	}

	e.pruneTicker = time.NewTicker(e.cfg.PruneInterval)
	go e.pruneLoop()
	return nil
}

func (e *Engine) pruneLoop() {
	for {
		select {
		case <-e.stopPrune:
			return
		case <-e.pruneTicker.C:
			_ = e.store.Prune(e.cfg.MaxJobAge, e.cfg.MaxRetainedJobs)
		}
	}
}

// SetExecutor updates the JobExecutorFn used to run jobs.
func (e *Engine) SetExecutor(fn JobExecutorFn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.executor = fn
}

func generateJobID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("job_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("job_%x", b)
}

// Enqueue validates and submits a new job for asynchronous execution.
func (e *Engine) Enqueue(req JobRequest) (*Job, error) {
	if req.Action == "" {
		return nil, errors.New("job action must not be empty")
	}
	if req.Type == "" {
		req.Type = TypeCommand
	}
	if req.Priority == "" {
		req.Priority = PriorityNormal
	}
	if req.ActorType == "" {
		req.ActorType = "system"
	}
	if req.ActorID == "" {
		req.ActorID = "operator"
	}

	timeout := req.TimeoutOverride
	if timeout <= 0 {
		timeout = DefaultJobTimeout
	}

	jobID := generateJobID()
	now := time.Now().UTC()

	job := &Job{
		ID:        jobID,
		Type:      req.Type,
		Action:    req.Action,
		PluginID:  req.PluginID,
		Params:    req.Params,
		Priority:  req.Priority,
		Status:    StatusQueued,
		CreatedAt: now,
		Timeout:   timeout,
		ActorType: req.ActorType,
		ActorID:   req.ActorID,
		SourceIP:  req.SourceIP,
	}

	logBuf := NewJobLogBuffer(e.cfg.MaxLogBytes)
	job.SetLogBuffer(logBuf)

	e.mu.Lock()
	e.logBuffers[jobID] = logBuf
	e.mu.Unlock()

	if err := e.store.SaveJob(job); err != nil {
		return nil, fmt.Errorf("failed to save job to store: %w", err)
	}

	e.recordAudit(job, "job.enqueued", "ok", fmt.Sprintf("enqueued %s action %s", job.Type, job.Action))

	if err := e.queue.Enqueue(job); err != nil {
		if errors.Is(err, ErrQueueFull) {
			job.SetFailed(time.Now().UTC(), "queue capacity exceeded")
			_ = e.store.SaveJob(job)
			e.recordAudit(job, "job.failed", "error", "queue capacity exceeded")
		}
		return nil, err
	}

	return job, nil
}

// GetJob retrieves a job by ID from the store.
func (e *Engine) GetJob(id string) (*Job, bool) {
	return e.store.GetJob(id)
}

// ListJobs queries jobs according to the filter.
func (e *Engine) ListJobs(filter JobFilter) ([]*Job, int) {
	return e.store.ListJobs(filter)
}

// GetJobLogs reads chunked logs from the job's log buffer or returns EOF if completed.
func (e *Engine) GetJobLogs(id string, offset int) (logs string, nextOffset int, truncated bool, eof bool, err error) {
	e.mu.RLock()
	buf, exists := e.logBuffers[id]
	e.mu.RUnlock()

	if exists && buf != nil {
		logs, nextOffset, truncated, eof = buf.ReadChunk(offset)
		return logs, nextOffset, truncated, eof, nil
	}

	// Buffer not in memory, check persistent store
	job, found := e.store.GetJob(id)
	if !found {
		return "", 0, false, false, ErrJobNotFound
	}
	if job.Status.IsTerminal() {
		return "", 0, false, true, nil
	}
	return "", 0, false, false, nil
}

// CancelJob cancels a queued or running job by ID.
func (e *Engine) CancelJob(id string) error {
	job, found := e.store.GetJob(id)
	if !found {
		return ErrJobNotFound
	}
	if job.Status.IsTerminal() {
		return errors.New("job is already finished")
	}

	if job.Status == StatusQueued {
		if removed, ok := e.queue.Remove(id); ok && removed != nil {
			removed.Cancel()
			_ = e.store.SaveJob(removed)
			e.recordAudit(removed, "job.cancelled", "cancelled", "job cancelled while queued")
			return nil
		}
	}

	cancelled := e.workerPool.CancelJob(id)
	if !cancelled {
		job.Cancel()
		_ = e.store.SaveJob(job)
		e.recordAudit(job, "job.cancelled", "cancelled", "job cancelled")
	}
	return nil
}

// QueueStats returns current queue and worker pool statistics.
func (e *Engine) QueueStats() QueueStats {
	return QueueStats{
		QueuedJobs:    e.queue.Len(),
		WorkersTotal:  e.workerPool.TotalWorkers(),
		WorkersActive: e.workerPool.ActiveWorkers(),
		Capacity:      e.queue.Capacity(),
	}
}

// Shutdown gracefully terminates the engine, draining workers and stopping maintenance.
func (e *Engine) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	if e.pruneTicker != nil {
		e.pruneTicker.Stop()
		close(e.stopPrune)
		e.pruneTicker = nil
	}
	e.mu.Unlock()

	wpErr := e.workerPool.Shutdown(ctx)
	stErr := e.store.Close()

	if wpErr != nil {
		return wpErr
	}
	return stErr
}

func (e *Engine) handleJobExecution(ctx context.Context, job *Job) error {
	_ = e.store.SaveJob(job)
	e.recordAudit(job, "job.started", "ok", fmt.Sprintf("started %s action %s", job.Type, job.Action))

	buf := job.LogBuffer()
	var res any
	var execErr error

	if e.executor != nil {
		res, execErr = e.executor(ctx, job, buf)
	}
	job.ResultData = res

	compTime := time.Now().UTC()
	if execErr != nil {
		if errors.Is(ctx.Err(), context.Canceled) || core.IsCommandCancelled(execErr) {
			job.SetCancelledFinal(compTime, "job execution cancelled")
			_ = e.store.SaveJob(job)
			e.recordAudit(job, "job.cancelled", "cancelled", "job execution cancelled")
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) || core.IsCommandTimeout(execErr) {
			job.SetTimedOut(compTime, fmt.Sprintf("job execution timed out after %s", job.Timeout))
			_ = e.store.SaveJob(job)
			e.recordAudit(job, "job.timed_out", "failure", "job execution timed out")
		} else {
			job.SetFailed(compTime, execErr.Error())
			_ = e.store.SaveJob(job)
			e.recordAudit(job, "job.failed", "error", execErr.Error())
		}
	} else {
		if !job.GetStatus().IsTerminal() {
			job.SetCompleted(compTime, res)
			_ = e.store.SaveJob(job)
			e.recordAudit(job, "job.completed", "ok", "job completed successfully")
		}
	}
	return execErr
}

func (e *Engine) recordAudit(job *Job, action, status, summary string) {
	if e.auditLogger == nil || job == nil {
		return
	}

	metadata := map[string]any{
		"job_id":      job.ID,
		"type":        string(job.Type),
		"action":      job.Action,
		"priority":    string(job.Priority),
		"status":      string(job.Status),
		"duration_ms": job.DurationMs,
	}
	if job.PluginID != "" {
		metadata["plugin_id"] = job.PluginID
	}
	if job.Error != "" {
		metadata["error"] = job.Error
	}

	actorType := job.ActorType
	if actorType == "" {
		actorType = "system"
	}
	actorID := job.ActorID
	if actorID == "" {
		actorID = "operator"
	}

	_, _ = e.auditLogger.Record(audit.AuditEvent{
		Category:   "job",
		Action:     action,
		ActorType:  actorType,
		ActorID:    actorID,
		SourceIP:   job.SourceIP,
		Status:     status,
		DurationMs: job.DurationMs,
		Summary:    summary,
		Metadata:   metadata,
	})
}
