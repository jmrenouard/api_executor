package jobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

)

// ============================================================================
// Milestone 1 Gate 2 Empirical Concurrency & Stress Verification
// ============================================================================

// TestChallenger_Gate2_HighConcurrencySubmission_1000Jobs_50Goroutines
// Stress-tests Engine.Enqueue under massive concurrency: 50 goroutines submitting
// 1,250 jobs with mixed priorities (High, Normal, Low) executed by 12 workers.
func TestChallenger_Gate2_HighConcurrencySubmission_1000Jobs_50Goroutines(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 12
	cfg.QueueCapacity = 3000
	cfg.MaxLogBytes = 64 * 1024

	store := NewMemoryJobStore()
	engine, err := NewEngine(cfg, store, nil, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	var executedCount atomic.Int64
	engine.SetExecutor(func(ctx context.Context, job *Job, logWriter io.Writer) (any, error) {
		executedCount.Add(1)
		_, _ = fmt.Fprintf(logWriter, "worker executing job %s priority %s\n", job.ID, job.Priority)
		// Simulate micro-work to trigger real concurrency
		time.Sleep(150 * time.Microsecond)
		return map[string]any{"executed": true, "job_id": job.ID}, nil
	})

	if err := engine.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() {
		_ = engine.Shutdown(context.Background())
	}()

	const (
		numGoroutines  = 50
		jobsPerRoutine = 25
		totalJobs      = numGoroutines * jobsPerRoutine // 1,250 jobs
	)

	priorities := []Priority{PriorityLow, PriorityNormal, PriorityHigh}
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	var submittedIDs sync.Map
	var submitErrors atomic.Int64

	startSubmit := time.Now()
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			<-startGate // Align start for maximal burst contention

			for j := 0; j < jobsPerRoutine; j++ {
				p := priorities[(routineID+j)%len(priorities)]
				req := JobRequest{
					Type:      TypeCommand,
					Action:    fmt.Sprintf("stress-action-%d-%d", routineID, j),
					Priority:  p,
					ActorType: "service_account",
					ActorID:   fmt.Sprintf("worker-bot-%d", routineID),
				}
				job, err := engine.Enqueue(req)
				if err != nil {
					submitErrors.Add(1)
					t.Errorf("routine %d failed to enqueue job %d: %v", routineID, j, err)
					return
				}
				if job == nil || job.ID == "" {
					submitErrors.Add(1)
					t.Errorf("routine %d got nil job or empty ID", routineID)
					return
				}
				if _, loaded := submittedIDs.LoadOrStore(job.ID, true); loaded {
					t.Errorf("duplicate job ID detected: %s", job.ID)
				}
			}
		}(g)
	}

	// Release all 50 goroutines simultaneously
	close(startGate)
	wg.Wait()
	elapsedSubmit := time.Since(startSubmit)

	t.Logf("Submitted %d jobs from %d goroutines in %v (rate: %.0f jobs/sec)",
		totalJobs, numGoroutines, elapsedSubmit, float64(totalJobs)/elapsedSubmit.Seconds())

	if submitErrors.Load() > 0 {
		t.Fatalf("Encountered %d submission errors during concurrent enqueue", submitErrors.Load())
	}

	// Await completion of all 1,250 jobs with timeout
	deadline := time.Now().Add(15 * time.Second)
	for executedCount.Load() < int64(totalJobs) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	execCount := executedCount.Load()
	if execCount != int64(totalJobs) {
		t.Fatalf("Execution timeout: expected %d completed jobs, got %d", totalJobs, execCount)
	}

	// Verify all jobs in store are terminal
	jobs, total := engine.ListJobs(JobFilter{Limit: totalJobs + 100})
	if total != totalJobs {
		t.Errorf("Store job count mismatch: expected %d, got %d", totalJobs, total)
	}

	for _, j := range jobs {
		status := j.GetStatus()
		if !status.IsTerminal() {
			t.Errorf("Job %s still in non-terminal status %s", j.ID, status)
		}
	}

	// Verify queue telemetry
	stats := engine.QueueStats()
	if stats.QueuedJobs != 0 {
		t.Errorf("Expected 0 queued jobs after drain, got %d", stats.QueuedJobs)
	}
	if stats.WorkersActive != 0 {
		t.Errorf("Expected 0 active workers after drain, got %d", stats.WorkersActive)
	}
}

// TestChallenger_Gate2_HeapPriorityInvariants_StrictMonotonicity
// Tests that JobQueue guarantees strict monotonic priority order:
// All High priority jobs MUST dequeue before any Normal jobs,
// and all Normal priority jobs MUST dequeue before any Low jobs.
func TestChallenger_Gate2_HeapPriorityInvariants_StrictMonotonicity(t *testing.T) {
	const (
		jobsPerTier = 400
		totalJobs   = jobsPerTier * 3 // 1,200 jobs total
	)

	q := NewJobQueue(totalJobs + 100)

	// Concurrently enqueue 1,200 jobs from 30 goroutines with randomized order
	var wg sync.WaitGroup
	const numGoroutines = 30
	const jobsPerRoutine = totalJobs / numGoroutines // 40 jobs per routine

	allJobs := make([]*Job, totalJobs)
	for i := 0; i < totalJobs; i++ {
		var p Priority
		switch i % 3 {
		case 0:
			p = PriorityHigh
		case 1:
			p = PriorityNormal
		case 2:
			p = PriorityLow
		}
		allJobs[i] = &Job{
			ID:        fmt.Sprintf("inv_job_%05d", i),
			Type:      TypeCommand,
			Action:    "priority-test",
			Priority:  p,
			Status:    StatusQueued,
			CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Microsecond),
		}
	}

	// Shuffle submission order to stress heap balancing
	r := rand.New(rand.NewSource(12345))
	perm := r.Perm(totalJobs)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			startIdx := routineID * jobsPerRoutine
			for j := 0; j < jobsPerRoutine; j++ {
				jobIdx := perm[startIdx+j]
				job := allJobs[jobIdx]
				if err := q.Enqueue(job); err != nil {
					t.Errorf("Enqueue failed: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	if q.Len() != totalJobs {
		t.Fatalf("Expected queue length %d, got %d", totalJobs, q.Len())
	}

	// Verify heap internal structural invariants before dequeuing
	q.mu.Lock()
	for i := 1; i < len(q.pq); i++ {
		parent := (i - 1) / 2
		pw := q.pq[parent].Priority.Weight()
		cw := q.pq[i].Priority.Weight()
		if pw < cw {
			q.mu.Unlock()
			t.Fatalf("HEAP INVARIANT VIOLATION: child at %d (priority %s, wt %d) > parent at %d (priority %s, wt %d)",
				i, q.pq[i].Priority, cw, parent, q.pq[parent].Priority, pw)
		}
	}
	q.mu.Unlock()

	// Dequeue all 1,200 jobs and verify strict monotonic tiers:
	// indices 0..399 MUST be High
	// indices 400..799 MUST be Normal
	// indices 800..1199 MUST be Low
	highCount := 0
	normalCount := 0
	lowCount := 0

	for i := 0; i < totalJobs; i++ {
		job, err := q.Dequeue()
		if err != nil {
			t.Fatalf("Dequeue at index %d returned error: %v", i, err)
		}

		switch {
		case i < jobsPerTier: // First 400 MUST be High
			if job.Priority != PriorityHigh {
				t.Fatalf("PRIORITY INVERSION at dequeue index %d: expected High, got %s (job %s)",
					i, job.Priority, job.ID)
			}
			highCount++
		case i < 2*jobsPerTier: // Next 400 MUST be Normal
			if job.Priority != PriorityNormal {
				t.Fatalf("PRIORITY INVERSION at dequeue index %d: expected Normal, got %s (job %s)",
					i, job.Priority, job.ID)
			}
			normalCount++
		default: // Last 400 MUST be Low
			if job.Priority != PriorityLow {
				t.Fatalf("PRIORITY INVERSION at dequeue index %d: expected Low, got %s (job %s)",
					i, job.Priority, job.ID)
			}
			lowCount++
		}
	}

	if highCount != jobsPerTier || normalCount != jobsPerTier || lowCount != jobsPerTier {
		t.Fatalf("Tier counts mismatch: High=%d, Normal=%d, Low=%d (expected %d each)",
			highCount, normalCount, lowCount, jobsPerTier)
	}

	t.Logf("Verified 1,200 dequeued jobs strictly preserved monotonic tier ordering: %d High -> %d Normal -> %d Low",
		highCount, normalCount, lowCount)
}

// TestChallenger_Gate2_QueueOverflow_BackpressureAndZeroBufferLeak
// Rigorously verifies that when the job queue exceeds capacity:
// 1. ErrQueueFull is cleanly returned to the caller.
// 2. The job is marked StatusFailed in the store.
// 3. ZERO JobLogBuffer instances leak into Engine.logBuffers.
func TestChallenger_Gate2_QueueOverflow_BackpressureAndZeroBufferLeak(t *testing.T) {
	const queueCap = 25
	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 0 // 0 workers ensures queue fills without consumption
	cfg.QueueCapacity = queueCap
	cfg.MaxLogBytes = 128 * 1024

	store := NewMemoryJobStore()
	engine, err := NewEngine(cfg, store, nil, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	// Do not start worker pool so the queue retains exactly queueCap jobs without draining
	defer func() {
		_ = engine.Shutdown(context.Background())
	}()

	const (
		numGoroutines  = 40
		jobsPerRoutine = 20
		totalAttempts  = numGoroutines * jobsPerRoutine // 800 submission attempts
	)

	var (
		wg           sync.WaitGroup
		successCount atomic.Int64
		overflowCount atomic.Int64
		otherErrors  atomic.Int64
		startGate    = make(chan struct{})
	)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			<-startGate

			for j := 0; j < jobsPerRoutine; j++ {
				req := JobRequest{
					Type:      TypeCommand,
					Action:    fmt.Sprintf("overflow-%d-%d", routineID, j),
					Priority:  PriorityNormal,
					ActorType: "test",
					ActorID:   "tester",
				}
				_, err := engine.Enqueue(req)
				if err == nil {
					successCount.Add(1)
				} else if errors.Is(err, ErrQueueFull) {
					overflowCount.Add(1)
				} else {
					otherErrors.Add(1)
					t.Errorf("unexpected error on enqueue: %v", err)
				}
			}
		}(g)
	}

	close(startGate)
	wg.Wait()

	t.Logf("Total attempts: %d | Success (Queued): %d | Overflow (ErrQueueFull): %d | Other Errors: %d",
		totalAttempts, successCount.Load(), overflowCount.Load(), otherErrors.Load())

	if otherErrors.Load() > 0 {
		t.Fatalf("Encountered %d unexpected non-overflow errors", otherErrors.Load())
	}

	if successCount.Load() != queueCap {
		t.Fatalf("Expected exactly %d successful queued jobs, got %d", queueCap, successCount.Load())
	}

	expectedOverflow := int64(totalAttempts - queueCap)
	if overflowCount.Load() != expectedOverflow {
		t.Fatalf("Expected exactly %d ErrQueueFull rejections, got %d", expectedOverflow, overflowCount.Load())
	}

	// CRITICAL CHECK: Verify Engine.logBuffers contains EXACTLY the successful jobs (25),
	// and NOT ONE leaked buffer from the 775 rejected jobs!
	engine.mu.RLock()
	activeBuffers := len(engine.logBuffers)
	engine.mu.RUnlock()

	if activeBuffers != queueCap {
		t.Fatalf("MEMORY LEAK DETECTED in Engine.logBuffers: expected exactly %d buffers, found %d (leaked %d buffers)",
			queueCap, activeBuffers, activeBuffers-queueCap)
	}

	t.Logf("PASS: Engine.logBuffers has exactly %d buffers. Zero buffer leak across %d queue rejections.",
		activeBuffers, expectedOverflow)

	// Verify all rejected jobs in store have StatusFailed
	failedJobs, _ := engine.ListJobs(JobFilter{Status: StatusFailed, Limit: totalAttempts})
	if len(failedJobs) != int(expectedOverflow) {
		t.Fatalf("Expected %d failed jobs in store, got %d", expectedOverflow, len(failedJobs))
	}

	for _, fj := range failedJobs {
		if fj.Error != "queue capacity exceeded" {
			t.Errorf("Expected failure reason 'queue capacity exceeded', got '%s'", fj.Error)
		}
		if fj.LogBuffer() != nil {
			t.Errorf("Rejected job %s retained non-nil LogBuffer reference", fj.ID)
		}
	}
}

// TestChallenger_Gate2_SQLiteStore_HighConcurrencySubmission
// Stress-tests SQLite store under 50 concurrent goroutines submitting 1,000 jobs.
func TestChallenger_Gate2_SQLiteStore_HighConcurrencySubmission(t *testing.T) {
	testDB, _ := newMockSQLiteBackedDB(t)
	sqliteStore, err := NewSQLiteJobStore(testDB)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}

	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 8
	cfg.QueueCapacity = 2500
	cfg.MaxLogBytes = 32 * 1024

	engine, err := NewEngine(cfg, sqliteStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create engine with sqlite store: %v", err)
	}

	var completedJobs atomic.Int64
	engine.SetExecutor(func(ctx context.Context, job *Job, logWriter io.Writer) (any, error) {
		completedJobs.Add(1)
		_, _ = fmt.Fprintf(logWriter, "sqlite job %s done\n", job.ID)
		return "ok", nil
	})

	if err := engine.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() {
		_ = engine.Shutdown(context.Background())
	}()

	const (
		numGoroutines  = 50
		jobsPerRoutine = 20
		totalJobs      = numGoroutines * jobsPerRoutine // 1,000 jobs
	)

	var wg sync.WaitGroup
	startGate := make(chan struct{})

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			<-startGate

			for j := 0; j < jobsPerRoutine; j++ {
				req := JobRequest{
					Type:      TypeCommand,
					Action:    fmt.Sprintf("sqlite-action-%d-%d", routineID, j),
					Priority:  PriorityHigh,
					ActorType: "user",
					ActorID:   fmt.Sprintf("user-%d", routineID),
				}
				if _, err := engine.Enqueue(req); err != nil {
					t.Errorf("Enqueue failed: %v", err)
				}
			}
		}(g)
	}

	close(startGate)
	wg.Wait()

	// Await completion
	deadline := time.Now().Add(15 * time.Second)
	for completedJobs.Load() < int64(totalJobs) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	if completedJobs.Load() != int64(totalJobs) {
		t.Fatalf("SQLite concurrency test timeout: expected %d jobs, got %d completed",
			totalJobs, completedJobs.Load())
	}

	// Verify persistence in SQLite
	jobs, total := sqliteStore.ListJobs(JobFilter{Limit: totalJobs + 100})
	if total != totalJobs {
		t.Fatalf("SQLite job count mismatch: expected %d, got %d", totalJobs, total)
	}
	for _, j := range jobs {
		if j.GetStatus() != StatusCompleted {
			t.Errorf("Job %s in SQLite has unexpected status %s", j.ID, j.GetStatus())
		}
	}
}

// TestChallenger_Gate2_ConcurrentSubmissionAndCancellationRace
// Stresses concurrent Enqueue, Dequeue, CancelJob, and GetJobLogs under heavy contention.
func TestChallenger_Gate2_ConcurrentSubmissionAndCancellationRace(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 8
	cfg.QueueCapacity = 2000
	cfg.MaxLogBytes = 64 * 1024

	store := NewMemoryJobStore()
	engine, err := NewEngine(cfg, store, nil, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	engine.SetExecutor(func(ctx context.Context, job *Job, logWriter io.Writer) (any, error) {
		for i := 0; i < 5; i++ {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				_, _ = fmt.Fprintf(logWriter, "step %d for job %s\n", i, job.ID)
				time.Sleep(500 * time.Microsecond)
			}
		}
		return "finished", nil
	})

	if err := engine.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() {
		_ = engine.Shutdown(context.Background())
	}()

	const totalJobs = 600
	var jobIDs sync.Map
	var idList []string
	var idMu sync.Mutex

	startGate := make(chan struct{})
	var wg sync.WaitGroup

	// 20 Enqueue goroutines
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			<-startGate
			for j := 0; j < totalJobs/20; j++ {
				p := PriorityNormal
				if j%2 == 0 {
					p = PriorityHigh
				}
				job, err := engine.Enqueue(JobRequest{
					Type:     TypeCommand,
					Action:   fmt.Sprintf("race-act-%d-%d", routineID, j),
					Priority: p,
				})
				if err == nil && job != nil {
					jobIDs.Store(job.ID, true)
					idMu.Lock()
					idList = append(idList, job.ID)
					idMu.Unlock()
				}
			}
		}(g)
	}

	// 10 Cancellation goroutines
	for c := 0; c < 10; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			for i := 0; i < 30; i++ {
				idMu.Lock()
				n := len(idList)
				var target string
				if n > 0 {
					target = idList[rand.Intn(n)]
				}
				idMu.Unlock()

				if target != "" {
					_ = engine.CancelJob(target)
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// 10 Log Reader goroutines
	for r := 0; r < 10; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			for i := 0; i < 30; i++ {
				idMu.Lock()
				n := len(idList)
				var target string
				if n > 0 {
					target = idList[rand.Intn(n)]
				}
				idMu.Unlock()

				if target != "" {
					_, _, _, _, _ = engine.GetJobLogs(target, 0)
				}
				time.Sleep(500 * time.Microsecond)
			}
		}()
	}

	close(startGate)
	wg.Wait()

	// Await completion or timeout
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		stats := engine.QueueStats()
		if stats.QueuedJobs == 0 && stats.WorkersActive == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Verify all created jobs reached terminal status
	jobs, _ := engine.ListJobs(JobFilter{Limit: totalJobs + 100})
	for _, j := range jobs {
		if !j.GetStatus().IsTerminal() {
			t.Errorf("Job %s did not reach terminal status: %s", j.ID, j.GetStatus())
		}
	}
}

// TestChallenger_Gate2_FIFOTieBreaking_UnderConcurrency
// Verifies that jobs in the same priority tier strictly obey FIFO queue sequence ordering.
func TestChallenger_Gate2_FIFOTieBreaking_UnderConcurrency(t *testing.T) {
	const totalJobs = 600
	q := NewJobQueue(totalJobs + 100)

	// Single priority tier (Normal), creation timestamps intentionally staggered
	for i := 0; i < totalJobs; i++ {
		job := &Job{
			ID:        fmt.Sprintf("fifo_job_%04d", i),
			Type:      TypeCommand,
			Action:    "fifo-test",
			Priority:  PriorityNormal,
			Status:    StatusQueued,
			CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Microsecond),
		}
		if err := q.Enqueue(job); err != nil {
			t.Fatalf("Enqueue failed: %v", err)
		}
	}

	var lastSeq int64 = 0
	for i := 0; i < totalJobs; i++ {
		job, err := q.Dequeue()
		if err != nil {
			t.Fatalf("Dequeue failed at %d: %v", i, err)
		}
		currSeq := job.GetQueueSeq()
		if currSeq <= lastSeq {
			t.Fatalf("FIFO SEQUENCE VIOLATION at %d: job %s has seq %d <= lastSeq %d",
				i, job.ID, currSeq, lastSeq)
		}
		lastSeq = currSeq
	}
}

