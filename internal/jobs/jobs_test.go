package jobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
)

func TestJobModelValidationAndDefaults(t *testing.T) {
	// Priority parsing
	if ParsePriority("high") != PriorityHigh {
		t.Errorf("expected PriorityHigh, got %v", ParsePriority("high"))
	}
	if ParsePriority("urgent") != PriorityHigh {
		t.Errorf("expected PriorityHigh for 'urgent', got %v", ParsePriority("urgent"))
	}
	if ParsePriority("low") != PriorityLow {
		t.Errorf("expected PriorityLow, got %v", ParsePriority("low"))
	}
	if ParsePriority("normal") != PriorityNormal {
		t.Errorf("expected PriorityNormal, got %v", ParsePriority("normal"))
	}
	if ParsePriority("unknown") != PriorityNormal {
		t.Errorf("expected fallback PriorityNormal for unknown, got %v", ParsePriority("unknown"))
	}

	// Priority weight
	if PriorityHigh.Weight() <= PriorityNormal.Weight() || PriorityNormal.Weight() <= PriorityLow.Weight() {
		t.Errorf("expected High > Normal > Low weights, got %d, %d, %d",
			PriorityHigh.Weight(), PriorityNormal.Weight(), PriorityLow.Weight())
	}

	// Status terminal & active
	if !StatusCompleted.IsTerminal() || !StatusFailed.IsTerminal() || !StatusCancelled.IsTerminal() || !StatusTimedOut.IsTerminal() {
		t.Errorf("expected completed, failed, cancelled, timed_out to be terminal")
	}
	if StatusQueued.IsTerminal() || StatusRunning.IsTerminal() {
		t.Errorf("expected queued and running not to be terminal")
	}
	if !StatusQueued.IsActive() || !StatusRunning.IsActive() {
		t.Errorf("expected queued and running to be active")
	}
	if StatusCompleted.IsActive() || StatusFailed.IsActive() {
		t.Errorf("expected completed and failed not to be active")
	}

	// Snapshot immutability
	now := time.Now().UTC()
	j := &Job{
		ID:        "job_test_1",
		Type:      TypeCommand,
		Action:    "test-action",
		Priority:  PriorityHigh,
		Status:    StatusQueued,
		CreatedAt: now,
		Params:    map[string]any{"key1": "val1"},
	}

	snap := j.Snapshot()
	if snap.ID != j.ID || snap.Action != j.Action {
		t.Errorf("snapshot mismatch: %+v vs %+v", snap, j)
	}

	// Modifying snap params should not alter original
	snap.Params["key1"] = "mutated"
	if j.Params["key1"] == "mutated" {
		t.Errorf("modifying snapshot mutated original params")
	}

	// MarshalJSON race safety
	data, err := j.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	if !strings.Contains(string(data), "job_test_1") {
		t.Errorf("marshaled json missing job ID: %s", string(data))
	}
}

func TestJobLogBufferConcurrentReadWrite(t *testing.T) {
	buf := NewJobLogBuffer(64 * 1024)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				msg := fmt.Sprintf("w%d-msg%d\n", workerID, j)
				_, _ = buf.Write([]byte(msg))
			}
		}(i)
	}
	wg.Wait()

	if buf.Len() == 0 {
		t.Errorf("expected buffer len > 0")
	}

	// Read chunk from offset 0
	chunk, nextOffset, truncated, eof := buf.ReadChunk(0)
	if len(chunk) == 0 {
		t.Errorf("expected non-empty chunk from offset 0")
	}
	if nextOffset != buf.Len() {
		t.Errorf("expected nextOffset == buf.Len() (%d), got %d", buf.Len(), nextOffset)
	}
	if truncated {
		t.Errorf("expected truncated == false")
	}
	if eof {
		t.Errorf("expected eof == false before SetEOF")
	}

	// Reading from nextOffset should return empty string
	emptyChunk, afterOffset, _, _ := buf.ReadChunk(nextOffset)
	if emptyChunk != "" || afterOffset != nextOffset {
		t.Errorf("expected empty chunk past offset, got %q, next=%d", emptyChunk, afterOffset)
	}

	// Negative offset normalization
	chunkNeg, _, _, _ := buf.ReadChunk(-10)
	if len(chunkNeg) != len(chunk) {
		t.Errorf("expected negative offset to be normalized to 0")
	}

	// SetEOF
	buf.SetEOF()
	if !buf.IsEOF() {
		t.Errorf("expected IsEOF() == true")
	}
	// Bytes and String check
	rawBytes := buf.Bytes()
	if len(rawBytes) != buf.Len() {
		t.Errorf("expected len(buf.Bytes()) == buf.Len(), got %d vs %d", len(rawBytes), buf.Len())
	}
	if len(buf.String()) != buf.Len() {
		t.Errorf("expected len(buf.String()) == buf.Len()")
	}
}

func TestJobLogBufferBoundaryTruncation(t *testing.T) {
	buf := NewJobLogBuffer(1024) // 1 KiB limit

	chunk := strings.Repeat("X", 600)
	n1, err1 := buf.Write([]byte(chunk))
	if err1 != nil || n1 != 600 {
		t.Fatalf("first write failed: n=%d, err=%v", n1, err1)
	}
	if buf.Truncated() {
		t.Errorf("expected not truncated after 600 bytes")
	}

	// Second write exceeds 1024 bytes
	n2, err2 := buf.Write([]byte(chunk))
	if err2 != nil || n2 != 600 {
		t.Fatalf("second write failed: n=%d, err=%v", n2, err2)
	}
	if !buf.Truncated() {
		t.Errorf("expected Truncated() == true after 1200 bytes")
	}
	if buf.Len() != 1024 {
		t.Errorf("expected clamped len == 1024, got %d", buf.Len())
	}

	str := buf.String()
	if !strings.Contains(str, "[output truncated: exceeded 1024 bytes limit]") {
		t.Errorf("expected truncation suffix in String(), got %q", str)
	}

	// Reset
	buf.Reset()
	if buf.Len() != 0 || buf.Truncated() || buf.IsEOF() {
		t.Errorf("expected clean state after Reset")
	}
}

func TestPriorityQueueHeapOrdering(t *testing.T) {
	pq := NewJobQueue(100)

	baseTime := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	jLow1 := &Job{ID: "low1", Priority: PriorityLow, CreatedAt: baseTime}
	jNorm1 := &Job{ID: "norm1", Priority: PriorityNormal, CreatedAt: baseTime.Add(1 * time.Second)}
	jHigh1 := &Job{ID: "high1", Priority: PriorityHigh, CreatedAt: baseTime.Add(2 * time.Second)}
	jHigh2 := &Job{ID: "high2", Priority: PriorityHigh, CreatedAt: baseTime.Add(3 * time.Second)}
	jLow2 := &Job{ID: "low2", Priority: PriorityLow, CreatedAt: baseTime.Add(4 * time.Second)}
	jNorm2 := &Job{ID: "norm2", Priority: PriorityNormal, CreatedAt: baseTime.Add(5 * time.Second)}

	_ = pq.Enqueue(jLow1)
	_ = pq.Enqueue(jNorm1)
	_ = pq.Enqueue(jHigh1)
	_ = pq.Enqueue(jHigh2)
	_ = pq.Enqueue(jLow2)
	_ = pq.Enqueue(jNorm2)

	expectedOrder := []string{"high1", "high2", "norm1", "norm2", "low1", "low2"}
	for _, expectedID := range expectedOrder {
		j, err := pq.Dequeue()
		if err != nil {
			t.Fatalf("unexpected dequeue error: %v", err)
		}
		if j.ID != expectedID {
			t.Errorf("expected %s, got %s", expectedID, j.ID)
		}
	}
}

func TestPriorityQueueFIFOTieBreaking(t *testing.T) {
	pq := NewJobQueue(100)
	fixedTime := time.Now().UTC()

	var jobs []*Job
	for i := 1; i <= 10; i++ {
		j := &Job{
			ID:        fmt.Sprintf("job_%02d", i),
			Priority:  PriorityNormal,
			CreatedAt: fixedTime, // identical timestamp triggers sequence tie-breaker
		}
		jobs = append(jobs, j)
		if err := pq.Enqueue(j); err != nil {
			t.Fatalf("failed to enqueue: %v", err)
		}
	}

	for i := 1; i <= 10; i++ {
		j, err := pq.Dequeue()
		if err != nil {
			t.Fatalf("failed to dequeue: %v", err)
		}
		expectedID := fmt.Sprintf("job_%02d", i)
		if j.ID != expectedID {
			t.Errorf("expected FIFO dequeue %s, got %s", expectedID, j.ID)
		}
	}
}

func TestJobQueueBackpressure(t *testing.T) {
	pq := NewJobQueue(2)

	j1 := &Job{ID: "j1", Priority: PriorityNormal, CreatedAt: time.Now().UTC()}
	j2 := &Job{ID: "j2", Priority: PriorityNormal, CreatedAt: time.Now().UTC()}
	j3 := &Job{ID: "j3", Priority: PriorityNormal, CreatedAt: time.Now().UTC()}

	if err := pq.Enqueue(j1); err != nil {
		t.Fatalf("enqueue j1 failed: %v", err)
	}
	if err := pq.Enqueue(j2); err != nil {
		t.Fatalf("enqueue j2 failed: %v", err)
	}

	// 3rd enqueue should return ErrQueueFull
	if err := pq.Enqueue(j3); !errors.Is(err, ErrQueueFull) {
		t.Errorf("expected ErrQueueFull, got %v", err)
	}

	// Dequeue one
	popped, err := pq.Dequeue()
	if err != nil || popped.ID != "j1" {
		t.Fatalf("unexpected popped: %v, err=%v", popped, err)
	}

	// Now enqueueing j3 succeeds
	if err := pq.Enqueue(j3); err != nil {
		t.Fatalf("enqueue j3 after dequeue failed: %v", err)
	}
}

func TestJobQueueCloseAndDrain(t *testing.T) {
	pq := NewJobQueue(10)

	j1 := &Job{ID: "d1", Priority: PriorityNormal, CreatedAt: time.Now().UTC()}
	j2 := &Job{ID: "d2", Priority: PriorityNormal, CreatedAt: time.Now().UTC()}

	_ = pq.Enqueue(j1)
	_ = pq.Enqueue(j2)

	pq.Close()
	if !pq.IsClosed() {
		t.Errorf("expected IsClosed() == true")
	}

	// Enqueueing to closed queue fails
	j3 := &Job{ID: "d3", Priority: PriorityNormal, CreatedAt: time.Now().UTC()}
	if err := pq.Enqueue(j3); !errors.Is(err, ErrQueueClosed) {
		t.Errorf("expected ErrQueueClosed on enqueue after Close, got %v", err)
	}

	// Existing items drain successfully
	d1, err1 := pq.Dequeue()
	if err1 != nil || d1.ID != "d1" {
		t.Errorf("expected drain d1, got %v, err=%v", d1, err1)
	}
	d2, err2 := pq.Dequeue()
	if err2 != nil || d2.ID != "d2" {
		t.Errorf("expected drain d2, got %v, err=%v", d2, err2)
	}

	// Once drained, Dequeue returns ErrQueueClosed
	_, err3 := pq.Dequeue()
	if !errors.Is(err3, ErrQueueClosed) {
		t.Errorf("expected ErrQueueClosed once drained, got %v", err3)
	}
}

func TestJobQueueRemove(t *testing.T) {
	pq := NewJobQueue(10)

	j1 := &Job{ID: "r1", Priority: PriorityNormal, CreatedAt: time.Now().UTC()}
	j2 := &Job{ID: "r2", Priority: PriorityHigh, CreatedAt: time.Now().UTC()}
	j3 := &Job{ID: "r3", Priority: PriorityLow, CreatedAt: time.Now().UTC()}

	_ = pq.Enqueue(j1)
	_ = pq.Enqueue(j2)
	_ = pq.Enqueue(j3)

	// Remove j2 while in queue
	removed, ok := pq.Remove("r2")
	if !ok || removed == nil || removed.ID != "r2" {
		t.Errorf("expected Remove(r2) to succeed, got %v, ok=%v", removed, ok)
	}

	// Attempting to remove non-existent
	if _, ok := pq.Remove("nonexistent"); ok {
		t.Errorf("expected Remove(nonexistent) to return false")
	}

	// Dequeue remaining items: j1 (normal), then j3 (low)
	first, _ := pq.Dequeue()
	second, _ := pq.Dequeue()
	if first.ID != "r1" || second.ID != "r3" {
		t.Errorf("expected r1 then r3, got %s then %s", first.ID, second.ID)
	}
}

func TestWorkerPoolExecution(t *testing.T) {
	queue := NewJobQueue(20)

	var executedJobs []string
	var mu sync.Mutex

	handler := func(ctx context.Context, job *Job) error {
		mu.Lock()
		executedJobs = append(executedJobs, job.ID)
		mu.Unlock()
		return nil
	}

	pool := NewWorkerPool(3, queue, handler)
	if err := pool.Start(); err != nil {
		t.Fatalf("failed to start worker pool: %v", err)
	}

	for i := 1; i <= 6; i++ {
		j := &Job{
			ID:        fmt.Sprintf("exec_%d", i),
			Action:    "test-cmd",
			Priority:  PriorityNormal,
			Status:    StatusQueued,
			CreatedAt: time.Now().UTC(),
		}
		_ = queue.Enqueue(j)
	}

	// Wait for queue to drain
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		count := len(executedJobs)
		mu.Unlock()
		if count == 6 {
			break
		}
	}

	mu.Lock()
	count := len(executedJobs)
	mu.Unlock()
	if count != 6 {
		t.Fatalf("expected 6 executed jobs, got %d", count)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pool.Shutdown(ctx); err != nil {
		t.Errorf("pool shutdown failed: %v", err)
	}
}

func TestWorkerPoolJobCancellation(t *testing.T) {
	queue := NewJobQueue(10)
	startedCh := make(chan struct{})

	handler := func(ctx context.Context, job *Job) error {
		close(startedCh)
		<-ctx.Done()
		return ctx.Err()
	}

	pool := NewWorkerPool(2, queue, handler)
	_ = pool.Start()

	job := &Job{
		ID:        "cancel_job",
		Action:    "sleep-cmd",
		Priority:  PriorityNormal,
		Status:    StatusQueued,
		CreatedAt: time.Now().UTC(),
		Timeout:   10 * time.Second,
	}

	_ = queue.Enqueue(job)

	// Wait for job to start
	<-startedCh

	if !pool.CancelJob("cancel_job") {
		t.Fatalf("expected CancelJob to return true")
	}

	// Wait for status transition
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		if job.GetStatus() == StatusCancelled {
			break
		}
	}

	if job.GetStatus() != StatusCancelled {
		t.Errorf("expected job status StatusCancelled, got %s", job.GetStatus())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = pool.Shutdown(ctx)
}

func TestWorkerPoolJobTimeout(t *testing.T) {
	queue := NewJobQueue(10)

	handler := func(ctx context.Context, job *Job) error {
		<-ctx.Done()
		return ctx.Err()
	}

	pool := NewWorkerPool(2, queue, handler)
	_ = pool.Start()

	job := &Job{
		ID:        "timeout_job",
		Action:    "sleep-timeout",
		Priority:  PriorityNormal,
		Status:    StatusQueued,
		CreatedAt: time.Now().UTC(),
		Timeout:   50 * time.Millisecond,
	}

	_ = queue.Enqueue(job)

	// Wait for timeout to fire
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		if job.GetStatus() == StatusTimedOut {
			break
		}
	}

	if job.GetStatus() != StatusTimedOut {
		t.Errorf("expected status StatusTimedOut, got %s", job.GetStatus())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = pool.Shutdown(ctx)
}

func TestWorkerPoolPanicRecovery(t *testing.T) {
	queue := NewJobQueue(10)

	handler := func(ctx context.Context, job *Job) error {
		panic("deliberate panic for testing")
	}

	pool := NewWorkerPool(2, queue, handler)
	_ = pool.Start()

	job := &Job{
		ID:        "panic_job",
		Action:    "panic-cmd",
		Priority:  PriorityNormal,
		Status:    StatusQueued,
		CreatedAt: time.Now().UTC(),
	}

	_ = queue.Enqueue(job)

	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		if job.GetStatus() == StatusFailed {
			break
		}
	}

	if job.GetStatus() != StatusFailed {
		t.Errorf("expected status StatusFailed after panic, got %s", job.GetStatus())
	}
	if !strings.Contains(job.Error, "panic:") {
		t.Errorf("expected error to mention panic, got %q", job.Error)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = pool.Shutdown(ctx)
}

func TestEngineEnqueueAndExecution(t *testing.T) {
	store := NewMemoryJobStore()
	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 2

	executor := func(ctx context.Context, job *Job, logWriter io.Writer) (any, error) {
		if logWriter != nil {
			_, _ = logWriter.Write([]byte("log line 1\nlog line 2\n"))
		}
		return map[string]any{"result": "success"}, nil
	}

	eng, err := NewEngine(cfg, store, nil, executor)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = eng.Shutdown(ctx)
	}()

	req := JobRequest{
		Type:     TypeCommand,
		Action:   "test-echo",
		Priority: PriorityNormal,
	}

	job, err := eng.Enqueue(req)
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Wait for job completion
	var completedJob *Job
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		j, found := eng.GetJob(job.ID)
		if found && j.Status == StatusCompleted {
			completedJob = j
			break
		}
	}

	if completedJob == nil {
		t.Fatalf("job did not complete in time")
	}

	// Read logs
	logs, nextOffset, truncated, eof, err := eng.GetJobLogs(job.ID, 0)
	if err != nil {
		t.Fatalf("GetJobLogs failed: %v", err)
	}
	if !strings.Contains(logs, "log line 1") {
		t.Errorf("expected logs to contain 'log line 1', got %q", logs)
	}
	if !eof {
		t.Errorf("expected eof == true for completed job")
	}
	if truncated {
		t.Errorf("expected truncated == false")
	}
	if nextOffset == 0 {
		t.Errorf("expected nextOffset > 0")
	}

	// Telemetry
	stats := eng.QueueStats()
	if stats.WorkersTotal != 2 {
		t.Errorf("expected 2 total workers, got %d", stats.WorkersTotal)
	}

	// ListJobs & SetExecutor
	listed, total := eng.ListJobs(JobFilter{Action: "test-echo"})
	if total != 1 || len(listed) != 1 {
		t.Errorf("expected 1 listed job, got total=%d len=%d", total, len(listed))
	}
	eng.SetExecutor(executor)
}

func TestEngineCancelQueuedJob(t *testing.T) {
	store := NewMemoryJobStore()
	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 1

	blockCh := make(chan struct{})
	executor := func(ctx context.Context, job *Job, logWriter io.Writer) (any, error) {
		<-blockCh
		return nil, nil
	}

	eng, _ := NewEngine(cfg, store, nil, executor)
	_ = eng.Start()
	defer func() {
		close(blockCh)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = eng.Shutdown(ctx)
	}()

	// Job 1 occupies the single worker
	_, _ = eng.Enqueue(JobRequest{Action: "blocker"})

	// Job 2 is queued behind job 1
	j2, err := eng.Enqueue(JobRequest{Action: "queued-to-cancel"})
	if err != nil {
		t.Fatalf("Enqueue j2 failed: %v", err)
	}

	if err := eng.CancelJob(j2.ID); err != nil {
		t.Fatalf("CancelJob failed: %v", err)
	}

	stored, found := eng.GetJob(j2.ID)
	if !found || stored.Status != StatusCancelled {
		t.Errorf("expected j2 to be StatusCancelled, got %+v (found=%v)", stored, found)
	}
}

func TestEngineAuditTrailIntegration(t *testing.T) {
	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{
		Enabled: true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}

	store := NewMemoryJobStore()
	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 2

	executor := func(ctx context.Context, job *Job, logWriter io.Writer) (any, error) {
		return "done", nil
	}

	eng, err := NewEngine(cfg, store, auditLogger, executor)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	_ = eng.Start()

	j, err := eng.Enqueue(JobRequest{
		Type:      TypeCommand,
		Action:    "audit-test-cmd",
		ActorType: "user",
		ActorID:   "admin",
	})
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		job, found := eng.GetJob(j.ID)
		if found && job.Status == StatusCompleted {
			break
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = eng.Shutdown(ctx)

	// Verify cryptographic hash chain integrity
	verRes := auditLogger.VerifyChain()
	if !verRes.Valid {
		t.Errorf("expected audit chain to be valid, reason: %s", verRes.Reason)
	}
	if verRes.TotalEvents < 3 {
		t.Errorf("expected at least 3 audit events (enqueued, started, completed), got %d", verRes.TotalEvents)
	}

	// Filter audit logs for category "job"
	events := auditLogger.Query(audit.AuditFilter{Category: "job"})
	if len(events) < 3 {
		t.Errorf("expected >= 3 job audit events, got %d", len(events))
	}
}
