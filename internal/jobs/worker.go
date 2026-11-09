package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go-admin-tool/internal/core"
)

// DefaultJobTimeout is the fallback execution timeout if neither job nor command defines one.
const DefaultJobTimeout = 30 * time.Second

// JobHandler executes the action associated with a job.
type JobHandler func(ctx context.Context, job *Job) error

// WorkerPool manages a fixed pool of worker goroutines consuming jobs from a JobQueue.
type WorkerPool struct {
	numWorkers int
	queue      *JobQueue
	handler    JobHandler

	mu         sync.Mutex
	running    bool
	closing    bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	activeJobs map[string]context.CancelFunc
}

// NewWorkerPool creates a new WorkerPool.
func NewWorkerPool(numWorkers int, queue *JobQueue, handler JobHandler) *WorkerPool {
	if numWorkers <= 0 {
		numWorkers = 4
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		numWorkers: numWorkers,
		queue:      queue,
		handler:    handler,
		ctx:        ctx,
		cancel:     cancel,
		activeJobs: make(map[string]context.CancelFunc),
	}
}

// Start launches the worker goroutines.
func (wp *WorkerPool) Start() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.running {
		return errors.New("worker pool already running")
	}
	wp.running = true
	wp.closing = false

	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.workerLoop(i + 1)
	}
	return nil
}

func (wp *WorkerPool) workerLoop(workerID int) {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		default:
		}

		job, err := wp.queue.Dequeue()
		if err != nil {
			// Queue closed and drained
			return
		}

		wp.runJob(workerID, job)
	}
}

func (wp *WorkerPool) runJob(workerID int, job *Job) {
	if job == nil || job.GetStatus().IsTerminal() {
		return
	}

	timeout := job.Timeout
	if timeout <= 0 {
		timeout = DefaultJobTimeout
	}

	jobCtx, jobCancel := context.WithTimeout(wp.ctx, timeout)

	now := time.Now().UTC()
	if !job.SetRunning(now, jobCancel) {
		jobCancel()
		return
	}

	wp.mu.Lock()
	wp.activeJobs[job.ID] = jobCancel
	wp.mu.Unlock()

	defer func() {
		jobCancel()
		wp.mu.Lock()
		delete(wp.activeJobs, job.ID)
		wp.mu.Unlock()

		if r := recover(); r != nil {
			compTime := time.Now().UTC()
			job.SetFailed(compTime, fmt.Sprintf("panic: %v", r))
		}
	}()

	err := wp.handler(jobCtx, job)
	compTime := time.Now().UTC()

	if err != nil {
		if errors.Is(jobCtx.Err(), context.Canceled) || core.IsCommandCancelled(err) {
			job.SetCancelledFinal(compTime, "job execution cancelled")
		} else if errors.Is(jobCtx.Err(), context.DeadlineExceeded) || core.IsCommandTimeout(err) {
			job.SetTimedOut(compTime, fmt.Sprintf("job execution timed out after %s", timeout))
		} else {
			job.SetFailed(compTime, err.Error())
		}
	} else {
		// Only transition to completed if not already cancelled or failed by handler
		if !job.GetStatus().IsTerminal() {
			job.SetCompleted(compTime, job.ResultData)
		}
	}
}

// CancelJob attempts to cancel a running job by ID.
func (wp *WorkerPool) CancelJob(jobID string) bool {
	wp.mu.Lock()
	cancelFn, exists := wp.activeJobs[jobID]
	wp.mu.Unlock()

	if exists && cancelFn != nil {
		cancelFn()
		return true
	}
	return false
}

// Shutdown gracefully stops the worker pool, allowing workers to drain pending jobs until ctx expires.
func (wp *WorkerPool) Shutdown(ctx context.Context) error {
	wp.mu.Lock()
	if !wp.running || wp.closing {
		wp.mu.Unlock()
		return nil
	}
	wp.closing = true
	wp.mu.Unlock()

	// Close queue to wake idle workers and disallow new enqueueing
	wp.queue.Close()

	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		wp.cancel()
		wp.mu.Lock()
		wp.running = false
		wp.mu.Unlock()
		return nil
	case <-ctx.Done():
		// Hard cancellation of remaining active jobs
		wp.mu.Lock()
		for _, cancel := range wp.activeJobs {
			cancel()
		}
		wp.mu.Unlock()
		wp.cancel()
		<-done
		wp.mu.Lock()
		wp.running = false
		wp.mu.Unlock()
		return ctx.Err()
	}
}

// ActiveWorkers returns the count of workers currently executing a job.
func (wp *WorkerPool) ActiveWorkers() int {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	return len(wp.activeJobs)
}

// TotalWorkers returns the configured number of workers.
func (wp *WorkerPool) TotalWorkers() int {
	return wp.numWorkers
}
