package jobs

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

// ============================================================================
// Suite 1: Cancellation Responsiveness & Process Group Termination
// ============================================================================

func TestChallenger_Cancellation_QueuedJobOlogN(t *testing.T) {
	q := NewJobQueue(2000)
	const totalJobs = 1000
	jobs := make([]*Job, totalJobs)

	// Enqueue 1,000 jobs with mixed priorities
	priorities := []Priority{PriorityLow, PriorityNormal, PriorityHigh}
	for i := 0; i < totalJobs; i++ {
		p := priorities[i%3]
		job := &Job{
			ID:        fmt.Sprintf("job_q_%04d", i),
			Type:      TypeCommand,
			Action:    "test-echo",
			Priority:  p,
			Status:    StatusQueued,
			CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Millisecond),
		}
		jobs[i] = job
		if err := q.Enqueue(job); err != nil {
			t.Fatalf("failed to enqueue job %d: %v", i, err)
		}
	}

	if q.Len() != totalJobs {
		t.Fatalf("expected queue length %d, got %d", totalJobs, q.Len())
	}

	// Select 100 random jobs to cancel
	r := rand.New(rand.NewSource(42))
	cancelIndices := r.Perm(totalJobs)[:100]
	cancelledMap := make(map[string]bool)

	startRemove := time.Now()
	for _, idx := range cancelIndices {
		targetID := jobs[idx].ID
		cancelledMap[targetID] = true

		removed, ok := q.Remove(targetID)
		if !ok || removed == nil {
			t.Fatalf("expected successful removal of queued job %s", targetID)
		}
		if removed.ID != targetID {
			t.Fatalf("removed job ID mismatch: expected %s, got %s", targetID, removed.ID)
		}
		if removed.GetHeapIndex() != -1 {
			t.Errorf("expected heap index to be -1 after removal, got %d", removed.GetHeapIndex())
		}
		removed.Cancel()
		if removed.GetStatus() != StatusCancelled {
			t.Errorf("expected status StatusCancelled, got %v", removed.GetStatus())
		}
	}
	elapsedRemove := time.Since(startRemove)
	avgPerRemoval := elapsedRemove / 100
	t.Logf("Removed 100 queued jobs in %v (avg %v per removal)", elapsedRemove, avgPerRemoval)
	if avgPerRemoval > 500*time.Microsecond {
		t.Errorf("O(log N) removal too slow: avg %v exceeded 500µs threshold", avgPerRemoval)
	}

	if q.Len() != totalJobs-100 {
		t.Fatalf("expected queue length %d after cancellations, got %d", totalJobs-100, q.Len())
	}

	// Dequeue all remaining 900 jobs and verify strict priority heap order
	var dequeued []*Job
	for q.Len() > 0 {
		item, err := q.Dequeue()
		if err != nil {
			t.Fatalf("dequeue failed: %v", err)
		}
		if cancelledMap[item.ID] {
			t.Errorf("cancelled job %s was dequeued", item.ID)
		}
		dequeued = append(dequeued, item)
	}

	if len(dequeued) != totalJobs-100 {
		t.Fatalf("expected 900 dequeued jobs, got %d", len(dequeued))
	}

	// Verify priority ordering: High > Normal > Low
	for i := 1; i < len(dequeued); i++ {
		prev := dequeued[i-1]
		curr := dequeued[i]
		if prev.Priority.Weight() < curr.Priority.Weight() {
			t.Fatalf("priority inversion at index %d: prev %v (weight %d) < curr %v (weight %d)",
				i, prev.Priority, prev.Priority.Weight(), curr.Priority, curr.Priority.Weight())
		}
		if prev.Priority.Weight() == curr.Priority.Weight() {
			if curr.CreatedAt.Before(prev.CreatedAt) {
				t.Fatalf("FIFO violation at index %d: curr %s created before prev %s",
					i, curr.CreatedAt, prev.CreatedAt)
			}
		}
	}
}

func TestChallenger_Cancellation_EngineQueuedJobCancel(t *testing.T) {
	store := NewMemoryJobStore()
	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 1

	// Block the single worker with a 2-second job
	blockerDone := make(chan struct{})
	var closeBlocker sync.Once
	safeCloseBlocker := func() {
		closeBlocker.Do(func() {
			close(blockerDone)
		})
	}
	executor := func(ctx context.Context, job *Job, logWriter io.Writer) (any, error) {
		if job.Action == "blocker" {
			select {
			case <-blockerDone:
			case <-ctx.Done():
			}
			return "unblocked", nil
		}
		return "executed", nil
	}

	engine, err := NewEngine(cfg, store, nil, executor)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() {
		safeCloseBlocker()
		_ = engine.Shutdown(context.Background())
	}()

	// Enqueue blocker job
	_, err = engine.Enqueue(JobRequest{
		Action:   "blocker",
		Priority: PriorityHigh,
	})
	if err != nil {
		t.Fatalf("failed to enqueue blocker: %v", err)
	}

	// Wait briefly for worker to pick up blocker
	time.Sleep(50 * time.Millisecond)

	// Enqueue a job that will remain queued behind blocker
	victim, err := engine.Enqueue(JobRequest{
		Action:   "victim-action",
		Priority: PriorityNormal,
	})
	if err != nil {
		t.Fatalf("failed to enqueue victim: %v", err)
	}

	// Verify victim is queued
	vJob, found := engine.GetJob(victim.ID)
	if !found || vJob.GetStatus() != StatusQueued {
		t.Fatalf("expected victim to be queued, found=%v status=%v", found, vJob.GetStatus())
	}

	// Cancel the queued victim job
	if err := engine.CancelJob(victim.ID); err != nil {
		t.Fatalf("failed to cancel queued job: %v", err)
	}

	// Verify victim is now StatusCancelled in store
	vJobAfter, found := engine.GetJob(victim.ID)
	if !found {
		t.Fatalf("victim not found in store after cancel")
	}
	if vJobAfter.GetStatus() != StatusCancelled {
		t.Errorf("expected victim status StatusCancelled, got %v", vJobAfter.GetStatus())
	}
	if vJobAfter.CompletedAt == nil {
		t.Errorf("expected victim CompletedAt to be non-nil")
	}

	// Unblock worker and let it finish
	safeCloseBlocker()
	time.Sleep(100 * time.Millisecond)

	// Verify victim was NEVER executed
	vJobFinal, _ := engine.GetJob(victim.ID)
	if vJobFinal.GetStatus() != StatusCancelled {
		t.Errorf("victim status altered after worker drained: %v", vJobFinal.GetStatus())
	}
}

func TestChallenger_Cancellation_RunningSubprocessTree_LatencyAndOrphans(t *testing.T) {
	// Build a command that creates a child process hierarchy
	var cmdDef core.CommandDefinition
	if runtime.GOOS == "windows" {
		// cmd.exe spawns ping.exe as a child process which pings 127.0.0.1 30 times
		cmdDef = core.CommandDefinition{
			Name:    "deep-child-tree",
			Command: "cmd",
			Args:    []string{"/C", "ping", "-n", "30", "127.0.0.1"},
		}
	} else {
		// sh spawns sleep 30
		cmdDef = core.CommandDefinition{
			Name:    "deep-child-tree",
			Command: "sh",
			Args:    []string{"-c", "sleep 30"},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	var execDuration time.Duration
	var execErr error
	done := make(chan struct{})

	go func() {
		defer close(done)
		start := time.Now()
		_, execErr = core.ExecuteCommandWithContext(ctx, cmdDef, 40*time.Second, nil)
		execDuration = time.Since(start)
	}()

	// Wait 200ms to ensure the parent process and its child (powershell/sleep) are fully running
	time.Sleep(200 * time.Millisecond)

	// Measure cancellation latency strictly from cancel() call to ExecuteCommandWithContext return
	cancelStart := time.Now()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("cancellation hung: ExecuteCommandWithContext did not return within 2 seconds")
	}

	cancelLatency := time.Since(cancelStart)
	t.Logf("Cancellation completed in %v (total exec duration %v)", cancelLatency, execDuration)

	threshold := 500 * time.Millisecond
	if runtime.GOOS == "windows" {
		threshold = 800 * time.Millisecond
	}
	if cancelLatency >= threshold {
		t.Errorf("cancellation responsiveness VIOLATION: latency %v exceeded %v threshold", cancelLatency, threshold)
	}

	if execErr == nil {
		t.Fatalf("expected cancellation error, got nil")
	}
	if !core.IsCommandCancelled(execErr) {
		t.Errorf("expected IsCommandCancelled(execErr) == true, got %v", execErr)
	}

	// Verify no orphaned child processes remain
	if runtime.GOOS == "windows" {
		// Brief pause for OS process table update
		time.Sleep(150 * time.Millisecond)

		// Check if PING.EXE child process is still alive
		out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq PING.EXE").CombinedOutput()
		if err == nil {
			outputStr := string(out)
			if strings.Contains(strings.ToUpper(outputStr), "PING.EXE") {
				t.Errorf("ORPHAN PROCESS DETECTED on Windows: child process PING.EXE still running:\n%s", outputStr)
				// Clean up orphan so host machine stays clean
				_ = exec.Command("taskkill", "/F", "/IM", "PING.EXE").Run()
			}
		}
	}
}

func TestChallenger_Cancellation_RunningJobViaEngine(t *testing.T) {
	store := NewMemoryJobStore()
	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 2

	var runningCmdStarted sync.WaitGroup
	runningCmdStarted.Add(1)

	executor := func(ctx context.Context, job *Job, logWriter io.Writer) (any, error) {
		if job.Action == "cancellable-sleep" {
			runningCmdStarted.Done()
			var cmdDef core.CommandDefinition
			if runtime.GOOS == "windows" {
				cmdDef = core.CommandDefinition{
					Name:    "sleep-cmd",
					Command: "powershell",
					Args:    []string{"-NoProfile", "-Command", "Start-Sleep -Seconds 20"},
				}
			} else {
				cmdDef = core.CommandDefinition{
					Name:    "sleep-cmd",
					Command: "sh",
					Args:    []string{"-c", "sleep 20"},
				}
			}
			return core.ExecuteCommandWithContext(ctx, cmdDef, 25*time.Second, logWriter)
		}
		return "ok", nil
	}

	engine, err := NewEngine(cfg, store, nil, executor)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() {
		_ = engine.Shutdown(context.Background())
	}()

	job, err := engine.Enqueue(JobRequest{
		Action:   "cancellable-sleep",
		Priority: PriorityHigh,
	})
	if err != nil {
		t.Fatalf("failed to enqueue: %v", err)
	}

	// Wait until subprocess is actually running
	runningCmdStarted.Wait()
	time.Sleep(100 * time.Millisecond)

	// Cancel the running job via Engine
	cancelStart := time.Now()
	if err := engine.CancelJob(job.ID); err != nil {
		t.Fatalf("engine.CancelJob failed: %v", err)
	}

	// Poll until status transitions to terminal
	var finalJob *Job
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		j, ok := engine.GetJob(job.ID)
		if ok && j.GetStatus().IsTerminal() {
			finalJob = j
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancelLatency := time.Since(cancelStart)
	t.Logf("Engine cancelled running job in %v", cancelLatency)

	if finalJob == nil {
		t.Fatalf("job did not transition to terminal state within 3s")
	}
	if finalJob.GetStatus() != StatusCancelled {
		t.Errorf("expected StatusCancelled, got %v", finalJob.GetStatus())
	}
	if finalJob.CompletedAt == nil {
		t.Errorf("expected CompletedAt to be set")
	}
	if finalJob.Error == "" {
		t.Errorf("expected Error message to indicate cancellation, got empty")
	}
	maxLatency := 500 * time.Millisecond
	if runtime.GOOS == "windows" {
		// Spawning taskkill.exe /T /F under parallel test load on Windows can take ~400-600ms
		maxLatency = 800 * time.Millisecond
	}
	if cancelLatency >= maxLatency {
		t.Errorf("cancellation responsiveness VIOLATION: latency %v exceeded %v threshold", cancelLatency, maxLatency)
	}
}

// ============================================================================
// Suite 2: Timeout Accuracy & State Transition
// ============================================================================

func TestChallenger_Timeout_AccuracyAndStateTransition(t *testing.T) {
	store := NewMemoryJobStore()
	cfg := DefaultEngineConfig()
	cfg.WorkersCount = 2

	executor := func(ctx context.Context, job *Job, logWriter io.Writer) (any, error) {
		var cmdDef core.CommandDefinition
		if runtime.GOOS == "windows" {
			cmdDef = core.CommandDefinition{
				Name:    "timeout-sleep",
				Command: "powershell",
				Args:    []string{"-NoProfile", "-Command", "Start-Sleep -Seconds 10"},
			}
		} else {
			cmdDef = core.CommandDefinition{
				Name:    "timeout-sleep",
				Command: "sh",
				Args:    []string{"-c", "sleep 10"},
			}
		}
		return core.ExecuteCommandWithContext(ctx, cmdDef, job.Timeout, logWriter)
	}

	engine, err := NewEngine(cfg, store, nil, executor)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() {
		_ = engine.Shutdown(context.Background())
	}()

	const targetTimeout = 300 * time.Millisecond
	start := time.Now()

	job, err := engine.Enqueue(JobRequest{
		Action:          "long-sleep",
		TimeoutOverride: targetTimeout,
	})
	if err != nil {
		t.Fatalf("failed to enqueue: %v", err)
	}

	// Poll until terminal
	var finalJob *Job
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, ok := engine.GetJob(job.ID)
		if ok && j.GetStatus().IsTerminal() {
			finalJob = j
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	elapsed := time.Since(start)

	if finalJob == nil {
		t.Fatalf("job did not timeout within 5s")
	}

	t.Logf("Job with 300ms timeout completed in %v, status=%s, durationMs=%d",
		elapsed, finalJob.GetStatus(), finalJob.DurationMs)

	// Assert StatusTimedOut
	if finalJob.GetStatus() != StatusTimedOut {
		t.Errorf("expected status %s, got %s", StatusTimedOut, finalJob.GetStatus())
	}
	if !strings.Contains(strings.ToLower(finalJob.Error), "timed out") {
		t.Errorf("expected error to mention 'timed out', got: %s", finalJob.Error)
	}
	if finalJob.CompletedAt == nil {
		t.Errorf("expected CompletedAt to be set")
	}
	if finalJob.DurationMs <= 0 {
		t.Errorf("expected positive DurationMs, got %d", finalJob.DurationMs)
	}

	// Timeout accuracy: elapsed should be close to 300ms (accounting for process launch on Windows, max 1.5s)
	if elapsed < targetTimeout {
		t.Errorf("timed out prematurely: elapsed %v < timeout %v", elapsed, targetTimeout)
	}
	if elapsed > 2*time.Second {
		t.Errorf("timeout too slow: elapsed %v took far longer than 300ms", elapsed)
	}

	// Verify log buffer EOF
	logs, nextOffset, truncated, eof, err := engine.GetJobLogs(job.ID, 0)
	if err != nil {
		t.Fatalf("GetJobLogs failed: %v", err)
	}
	if !eof {
		t.Errorf("expected eof == true for timed out job, got false (logs=%q, nextOffset=%d, truncated=%v)", logs, nextOffset, truncated)
	}
}

// ============================================================================
// Suite 3: Log Buffer Boundaries (> 10 MiB Clamping & Arbitrary Chunk Reading)
// ============================================================================

func TestChallenger_LogBuffer_BoundaryClampingAndChunkedReading(t *testing.T) {
	buf := NewJobLogBuffer(DefaultMaxLogBytes) // 2 MiB capacity

	// Generate 12 MiB of test data (192 chunks of 64 KiB)
	const totalBytes = 12 * 1024 * 1024
	const chunkSize = 64 * 1024
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte('A' + (i % 26))
	}

	writeStart := time.Now()
	var totalWritten int
	for written := 0; written < totalBytes; written += chunkSize {
		n, err := buf.Write(chunk)
		if err != nil {
			t.Fatalf("unexpected Write error: %v", err)
		}
		if n != chunkSize {
			t.Fatalf("expected Write to return %d bytes, got %d", chunkSize, n)
		}
		totalWritten += n
	}
	writeDuration := time.Since(writeStart)
	t.Logf("Wrote %d bytes (12 MiB) to JobLogBuffer in %v", totalWritten, writeDuration)

	// Verify write does not block subprocess writers
	if writeDuration > 500*time.Millisecond {
		t.Errorf("writing 12 MiB took %v (exceeded 500ms non-blocking expectation)", writeDuration)
	}

	// Boundary check: Buffer MUST clamp at exactly DefaultMaxLogBytes (2,097,152 bytes)
	if buf.Len() != DefaultMaxLogBytes {
		t.Errorf("buffer clamping VIOLATION: expected Len() == %d, got %d", DefaultMaxLogBytes, buf.Len())
	}
	if !buf.Truncated() {
		t.Errorf("expected Truncated() == true after writing 12 MiB, got false")
	}

	// Verify String() output includes truncation footer
	strOutput := buf.String()
	expectedFooter := fmt.Sprintf("[output truncated: exceeded %d bytes limit]", DefaultMaxLogBytes)
	if !strings.HasSuffix(strings.TrimSpace(strOutput), expectedFooter) {
		t.Errorf("expected String() to end with truncation footer %q", expectedFooter)
	}

	// Test chunked reading at arbitrary offsets
	tests := []struct {
		name         string
		offset       int
		expectEmpty  bool
		expectedNext int
	}{
		{"offset zero returns initial chunk", 0, false, DefaultMaxLogBytes},
		{"offset mid-buffer", 1024 * 1024, false, DefaultMaxLogBytes},
		{"offset near end", DefaultMaxLogBytes - 100, false, DefaultMaxLogBytes},
		{"offset exact capacity", DefaultMaxLogBytes, true, DefaultMaxLogBytes},
		{"offset past capacity", DefaultMaxLogBytes + 5000, true, DefaultMaxLogBytes},
		{"negative offset normalizes to zero", -500, false, DefaultMaxLogBytes},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs, nextOffset, truncated, _ := buf.ReadChunk(tc.offset)
			if tc.expectEmpty && logs != "" {
				t.Errorf("expected empty logs at offset %d, got %d bytes", tc.offset, len(logs))
			}
			if !tc.expectEmpty && len(logs) == 0 {
				t.Errorf("expected non-empty logs at offset %d, got 0", tc.offset)
			}
			if nextOffset != tc.expectedNext {
				t.Errorf("expected nextOffset %d, got %d", tc.expectedNext, nextOffset)
			}
			if !truncated {
				t.Errorf("expected truncated == true, got false")
			}
		})
	}
}

func TestChallenger_LogBuffer_ConcurrentWritersAndReadersStress(t *testing.T) {
	buf := NewJobLogBuffer(DefaultMaxLogBytes)
	const numWriters = 10
	const numReaders = 10
	const chunksPerWriter = 40 // 40 * 64 KiB = 2.5 MiB per writer -> 25 MiB total

	var wg sync.WaitGroup
	var stopReaders atomic.Bool

	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = 'X'
	}

	// Start readers querying arbitrary offsets
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(int64(readerID * 100)))
			for !stopReaders.Load() {
				randOffset := rnd.Intn(3 * 1024 * 1024) - 1000 // test negative, mid, and past capacity offsets
				logs, nextOffset, _, _ := buf.ReadChunk(randOffset)
				if randOffset >= DefaultMaxLogBytes && logs != "" {
					t.Errorf("reader %d got logs beyond capacity: len=%d", readerID, len(logs))
				}
				if nextOffset > DefaultMaxLogBytes {
					t.Errorf("reader %d nextOffset %d exceeded capacity %d", readerID, nextOffset, DefaultMaxLogBytes)
				}
				time.Sleep(500 * time.Microsecond)
			}
		}(r)
	}

	// Start writers concurrently saturating buffer
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for c := 0; c < chunksPerWriter; c++ {
				_, err := buf.Write(chunk)
				if err != nil {
					t.Errorf("writer %d chunk %d failed: %v", writerID, c, err)
				}
			}
		}(w)
	}

	// Wait for writers to complete
	time.Sleep(200 * time.Millisecond)
	stopReaders.Store(true)
	wg.Wait()

	if buf.Len() != DefaultMaxLogBytes {
		t.Errorf("concurrent stress clamping failed: expected Len() == %d, got %d", DefaultMaxLogBytes, buf.Len())
	}
	if !buf.Truncated() {
		t.Errorf("expected Truncated() == true, got false")
	}
}

// ============================================================================
// Suite 4: In-Memory Store Deep-Cloning & SQLite Upsert Idempotency
// ============================================================================

func TestChallenger_MemoryJobStore_DeepCloningImmutability(t *testing.T) {
	store := NewMemoryJobStore()

	origJob := &Job{
		ID:        "job_deep_clone_1",
		Type:      TypeCommand,
		Action:    "backup-db",
		Priority:  PriorityHigh,
		Status:    StatusQueued,
		CreatedAt: time.Now().UTC(),
		Params: map[string]any{
			"target": "prod-db",
			"retries": 3,
			"flags":   []string{"--fast", "--compact"},
		},
	}

	if err := store.SaveJob(origJob); err != nil {
		t.Fatalf("SaveJob failed: %v", err)
	}

	// Retrieve job copy
	retrieved, ok := store.GetJob(origJob.ID)
	if !ok || retrieved == nil {
		t.Fatalf("GetJob failed")
	}

	// Adversarial Mutation 1: Mutate retrieved top-level fields
	retrieved.Status = StatusFailed
	retrieved.Action = "MALICIOUS_OVERWRITE"

	// Adversarial Mutation 2: Mutate retrieved Params map
	retrieved.Params["target"] = "CORRUPTED_TARGET"
	retrieved.Params["evil_key"] = "evil_value"

	// Adversarial Mutation 3: Mutate original struct after SaveJob
	origJob.Status = StatusRunning
	origJob.Params["target"] = "ORIGINAL_MUTATED"

	// Re-fetch from store and verify total immutability
	fresh, ok := store.GetJob(origJob.ID)
	if !ok || fresh == nil {
		t.Fatalf("second GetJob failed")
	}

	if fresh.Status != StatusQueued {
		t.Errorf("IMMUTABILITY VIOLATION: stored status modified to %v (expected StatusQueued)", fresh.Status)
	}
	if fresh.Action != "backup-db" {
		t.Errorf("IMMUTABILITY VIOLATION: stored action modified to %v", fresh.Action)
	}
	if fresh.Params["target"] != "prod-db" {
		t.Errorf("IMMUTABILITY VIOLATION: stored params target modified to %v", fresh.Params["target"])
	}
	if _, exists := fresh.Params["evil_key"]; exists {
		t.Errorf("IMMUTABILITY VIOLATION: evil_key injected into stored job params")
	}

	// Test ListJobs immutability
	list, total := store.ListJobs(JobFilter{})
	if total != 1 || len(list) != 1 {
		t.Fatalf("expected 1 listed job, got total=%d len=%d", total, len(list))
	}

	// Mutate element in returned list
	list[0].Status = StatusTimedOut
	list[0].Params["target"] = "LIST_MUTATION"

	// Verify fresh read is still untainted
	fresh2, _ := store.GetJob(origJob.ID)
	if fresh2.Status != StatusQueued || fresh2.Params["target"] != "prod-db" {
		t.Errorf("IMMUTABILITY VIOLATION via ListJobs: status=%v target=%v",
			fresh2.Status, fresh2.Params["target"])
	}
}

func TestChallenger_MemoryJobStore_ConcurrentMutationsRace(t *testing.T) {
	store := NewMemoryJobStore()
	const numGoroutines = 50
	const iterations = 50

	var wg sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			jobID := fmt.Sprintf("job_concurrent_%d", gid%10)

			for i := 0; i < iterations; i++ {
				// Upsert
				j := &Job{
					ID:        jobID,
					Type:      TypeCommand,
					Action:    fmt.Sprintf("action_%d", i),
					Priority:  PriorityNormal,
					Status:    StatusRunning,
					CreatedAt: time.Now().UTC(),
					Params: map[string]any{
						"iter": i,
						"gid":  gid,
					},
				}
				_ = store.SaveJob(j)

				// Read and attempt dirty mutation
				if got, ok := store.GetJob(jobID); ok && got != nil {
					got.Status = StatusFailed
					got.Params["dirty"] = true
				}

				// List and attempt dirty mutation
				list, _ := store.ListJobs(JobFilter{Limit: 5})
				for _, item := range list {
					item.Status = StatusCancelled
					if item.Params != nil {
						item.Params["corrupted"] = true
					}
				}
			}
		}(g)
	}

	wg.Wait()
	t.Logf("Completed %d concurrent reader/writer goroutines with dirty mutation attempts", numGoroutines)
}

func TestChallenger_SQLiteJobStore_UpsertIdempotencyAndConcurrency(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_challenger_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "challenger_test.db")
	var db *database.DB
	realDB, err := database.NewDB(dbPath)
	if err == nil && !realDB.IsInMemory() {
		db = realDB
		defer db.Close()
	} else {
		if realDB != nil {
			_ = realDB.Close()
		}
		db, _ = newMockSQLiteBackedDB(t)
		defer db.Close()
	}

	store, err := NewSQLiteJobStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteJobStore failed: %v", err)
	}

	// 1. Initial Insert (StatusQueued)
	createdAt := time.Now().UTC().Truncate(time.Millisecond)
	job := &Job{
		ID:        "job_sqlite_upsert_1",
		Type:      TypeCommand,
		Action:    "db-vacuum",
		PluginID:  "",
		Priority:  PriorityHigh,
		Status:    StatusQueued,
		CreatedAt: createdAt,
		Timeout:   10 * time.Second,
		ActorType: "user",
		ActorID:   "admin",
		SourceIP:  "127.0.0.1",
		Params: map[string]any{
			"mode": "full",
		},
	}

	// Call SaveJob 10 times consecutively with identical job (idempotency check)
	for i := 0; i < 10; i++ {
		if err := store.SaveJob(job); err != nil {
			t.Fatalf("SaveJob iteration %d failed: %v", i, err)
		}
	}

	// Verify exactly 1 row exists
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM job_history WHERE id = ?", job.ID).Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("IDEMPOTENCY VIOLATION: expected 1 row for job, got %d", count)
	}

	// 2. State Transition 1: Queued -> Running
	startedAt := createdAt.Add(100 * time.Millisecond)
	job.Status = StatusRunning
	job.StartedAt = &startedAt
	if err := store.SaveJob(job); err != nil {
		t.Fatalf("SaveJob (running) failed: %v", err)
	}

	savedRunning, ok := store.GetJob(job.ID)
	if !ok || savedRunning == nil {
		t.Fatalf("failed to retrieve running job")
	}
	if savedRunning.Status != StatusRunning {
		t.Errorf("expected StatusRunning, got %v", savedRunning.Status)
	}
	if savedRunning.StartedAt == nil || !savedRunning.StartedAt.Equal(startedAt) {
		t.Errorf("StartedAt mismatch: got %v, expected %v", savedRunning.StartedAt, startedAt)
	}
	// Verify static submission fields were preserved across upsert
	if savedRunning.Action != "db-vacuum" || savedRunning.ActorID != "admin" || savedRunning.Priority != PriorityHigh {
		t.Errorf("static submission fields corrupted across upsert: %+v", savedRunning)
	}

	// 3. State Transition 2: Running -> Completed
	completedAt := startedAt.Add(500 * time.Millisecond)
	job.Status = StatusCompleted
	job.CompletedAt = &completedAt
	job.DurationMs = 500
	job.ResultData = map[string]any{"pages_freed": float64(1420)}
	if err := store.SaveJob(job); err != nil {
		t.Fatalf("SaveJob (completed) failed: %v", err)
	}

	savedCompleted, ok := store.GetJob(job.ID)
	if !ok || savedCompleted == nil {
		t.Fatalf("failed to retrieve completed job")
	}
	if savedCompleted.Status != StatusCompleted {
		t.Errorf("expected StatusCompleted, got %v", savedCompleted.Status)
	}
	if savedCompleted.DurationMs != 500 {
		t.Errorf("expected DurationMs 500, got %d", savedCompleted.DurationMs)
	}
	if savedCompleted.CompletedAt == nil || !savedCompleted.CompletedAt.Equal(completedAt) {
		t.Errorf("CompletedAt mismatch: got %v, expected %v", savedCompleted.CompletedAt, completedAt)
	}

	// 4. Concurrency Stress: 20 goroutines concurrently upserting the exact same job ID
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			snap := job.Snapshot()
			snap.DurationMs = int64(500 + workerID)
			_ = store.SaveJob(snap)
		}(g)
	}
	wg.Wait()

	// Verify row count is STILL exactly 1
	if err := db.QueryRow("SELECT COUNT(*) FROM job_history WHERE id = ?", job.ID).Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 1 {
		t.Errorf("concurrent upsert produced duplicate rows: expected 1, got %d", count)
	}

	// 5. Test Prune on SQLiteJobStore executes without error
	if err := store.Prune(1*time.Hour, 100); err != nil {
		t.Fatalf("SQLiteJobStore.Prune failed: %v", err)
	}

	// 6. Test Prune on MemoryJobStore explicitly verifies active job retention
	memStore := NewMemoryJobStore()
	activeJob := &Job{
		ID:        "job_active_unpruned",
		Type:      TypeCommand,
		Action:    "long-running",
		Priority:  PriorityNormal,
		Status:    StatusRunning,
		CreatedAt: time.Now().UTC().Add(-48 * time.Hour), // 2 days old but STILL RUNNING
	}
	terminalOldJob := &Job{
		ID:          "job_terminal_old",
		Type:        TypeCommand,
		Action:      "old-done",
		Priority:    PriorityNormal,
		Status:      StatusCompleted,
		CreatedAt:   time.Now().UTC().Add(-48 * time.Hour),
		CompletedAt: &activeJob.CreatedAt,
	}
	_ = memStore.SaveJob(activeJob)
	_ = memStore.SaveJob(terminalOldJob)

	if err := memStore.Prune(1*time.Hour, 0); err != nil {
		t.Fatalf("MemoryJobStore.Prune failed: %v", err)
	}

	// Terminal old job MUST be pruned
	if _, found := memStore.GetJob(terminalOldJob.ID); found {
		t.Errorf("PRUNE VIOLATION: terminal old job was not deleted by Prune")
	}
	// Active running job MUST still exist
	if _, found := memStore.GetJob(activeJob.ID); !found {
		t.Errorf("PRUNE SAFETY VIOLATION: active running job was erroneously deleted by Prune")
	}
}

// ============================================================================
// Bug Reproduction: Engine.pruneLoop Nil-Pointer Dereference on Shutdown
// ============================================================================

func TestChallenger_Engine_ShutdownPruneLoopNilPointerRace(t *testing.T) {
	// Triggers nil pointer dereference in Engine.pruneLoop when Shutdown()
	// sets e.pruneTicker = nil while pruneLoop evaluates e.pruneTicker.C
	for i := 0; i < 50; i++ {
		cfg := DefaultEngineConfig()
		cfg.PruneInterval = 5 * time.Millisecond
		store := NewMemoryJobStore()
		engine, err := NewEngine(cfg, store, nil, nil)
		if err != nil {
			t.Fatalf("failed to create engine: %v", err)
		}
		if err := engine.Start(); err != nil {
			t.Fatalf("failed to start engine: %v", err)
		}
		// Race window: Shutdown sets e.pruneTicker = nil while pruneLoop loops
		time.Sleep(3 * time.Millisecond)
		_ = engine.Shutdown(context.Background())
	}
}

