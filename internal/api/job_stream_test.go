package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/jobs"
)

type parsedSSEFrame struct {
	ID      string
	Event   string
	Data    string
	Comment string
}

func readSSEFrames(t *testing.T, r io.Reader, stopOnDone bool) []parsedSSEFrame {
	t.Helper()
	scanner := bufio.NewScanner(r)
	var frames []parsedSSEFrame
	var cur parsedSSEFrame
	hasFields := false

	flushCur := func() {
		if !hasFields {
			return
		}
		frames = append(frames, cur)
		cur = parsedSSEFrame{}
		hasFields = false
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flushCur()
			if stopOnDone && len(frames) > 0 && frames[len(frames)-1].Event == "done" {
				return frames
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			frames = append(frames, parsedSSEFrame{Comment: strings.TrimSpace(strings.TrimPrefix(line, ":"))})
			continue
		}
		if strings.HasPrefix(line, "id:") {
			cur.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			hasFields = true
		} else if strings.HasPrefix(line, "event:") {
			cur.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			hasFields = true
		} else if strings.HasPrefix(line, "data:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if cur.Data != "" {
				cur.Data += "\n" + val
			} else {
				cur.Data = val
			}
			hasFields = true
		}
	}
	flushCur()
	return frames
}

func waitForTerminalJobInStore(t *testing.T, engine *jobs.Engine, jobID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		j, found := engine.GetJob(jobID)
		if found && j != nil && j.GetStatus().IsTerminal() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach terminal state in store within timeout", jobID)
}

// nonFlusherResponseWriter intentionally omits http.Flusher and Unwrap to test 500 handling.
type nonFlusherResponseWriter struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func newNonFlusherResponseWriter() *nonFlusherResponseWriter {
	return &nonFlusherResponseWriter{header: make(http.Header)}
}

func (n *nonFlusherResponseWriter) Header() http.Header         { return n.header }
func (n *nonFlusherResponseWriter) Write(p []byte) (int, error) { return n.body.Write(p) }
func (n *nonFlusherResponseWriter) WriteHeader(code int)        { n.code = code }

func TestStreamJobLogsHandler_LiveEventsAndSubmitStreamURL(t *testing.T) {
	_, router, _ := setupTestJobAPIEnv(t)

	srv := httptest.NewServer(router)
	defer srv.Close()

	payload, _ := json.Marshal(map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	})
	submitResp, err := srv.Client().Post(srv.URL+"/api/v1/jobs", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("failed to submit job: %v", err)
	}
	defer func() { _ = submitResp.Body.Close() }()

	if submitResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d", submitResp.StatusCode)
	}

	var submitted SubmitJobResponse
	if err := json.NewDecoder(submitResp.Body).Decode(&submitted); err != nil {
		t.Fatalf("failed to decode submit response: %v", err)
	}
	expectedStreamURL := fmt.Sprintf("/api/v1/jobs/%s/stream", submitted.JobID)
	if submitted.StreamURL != expectedStreamURL {
		t.Fatalf("expected StreamURL %q, got %q", expectedStreamURL, submitted.StreamURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+submitted.StreamURL, nil)
	if err != nil {
		t.Fatalf("failed to build stream request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("stream request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("expected Cache-Control no-cache, got %q", cc)
	}
	if conn := resp.Header.Get("Connection"); conn != "keep-alive" {
		t.Errorf("expected Connection keep-alive, got %q", conn)
	}
	if xab := resp.Header.Get("X-Accel-Buffering"); xab != "no" {
		t.Errorf("expected X-Accel-Buffering no, got %q", xab)
	}

	frames := readSSEFrames(t, resp.Body, false)

	var gotStatus, gotLog, gotDone bool
	var combinedLogs strings.Builder
	for _, f := range frames {
		switch f.Event {
		case "status":
			var ev sseStatusEvent
			if err := json.Unmarshal([]byte(f.Data), &ev); err != nil {
				t.Fatalf("invalid status JSON %q: %v", f.Data, err)
			}
			if ev.JobID != submitted.JobID {
				t.Errorf("status job_id mismatch: got %q, want %q", ev.JobID, submitted.JobID)
			}
			gotStatus = true
		case "log":
			var ev sseLogEvent
			if err := json.Unmarshal([]byte(f.Data), &ev); err != nil {
				t.Fatalf("invalid log JSON %q: %v", f.Data, err)
			}
			if f.ID == "" {
				t.Errorf("expected non-empty id on log event")
			}
			combinedLogs.WriteString(ev.Logs)
			gotLog = true
		case "done":
			var ev sseDoneEvent
			if err := json.Unmarshal([]byte(f.Data), &ev); err != nil {
				t.Fatalf("invalid done JSON %q: %v", f.Data, err)
			}
			if !ev.EOF {
				t.Errorf("expected eof=true on done event")
			}
			if ev.Status != jobs.StatusCompleted {
				t.Errorf("expected terminal status completed on done event, got %q", ev.Status)
			}
			gotDone = true
		}
	}

	if !gotStatus {
		t.Errorf("expected at least one status event, frames=%+v", frames)
	}
	if !gotLog {
		t.Errorf("expected at least one log event, frames=%+v", frames)
	}
	if !strings.Contains(combinedLogs.String(), "hello-async") {
		t.Errorf("expected combined streamed logs to contain 'hello-async', got %q", combinedLogs.String())
	}
	if !gotDone {
		t.Errorf("expected done event, frames=%+v", frames)
	}
}

func TestStreamJobLogsHandler_IncrementalRunningJob(t *testing.T) {
	_, router, engine := setupTestJobAPIEnv(t)

	chunk1Written := make(chan struct{})
	allowFinish := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-allowFinish:
		default:
			close(allowFinish)
		}
	})

	engine.SetExecutor(func(ctx context.Context, job *jobs.Job, logWriter io.Writer) (any, error) {
		_, _ = logWriter.Write([]byte("line-one\n"))
		close(chunk1Written)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-allowFinish:
		}
		_, _ = logWriter.Write([]byte("line-two\n"))
		return map[string]any{"ok": true}, nil
	})

	job, err := engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "echo-cmd"})
	if err != nil {
		t.Fatalf("failed to enqueue job: %v", err)
	}

	<-chunk1Written

	srv := httptest.NewServer(router)
	defer srv.Close()

	go func() {
		time.Sleep(150 * time.Millisecond)
		close(allowFinish)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/jobs/%s/stream", srv.URL, job.ID), nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("stream request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	frames := readSSEFrames(t, resp.Body, false)

	var statuses []jobs.JobStatus
	var logs strings.Builder
	var doneStatus jobs.JobStatus
	for _, f := range frames {
		switch f.Event {
		case "status":
			var ev sseStatusEvent
			_ = json.Unmarshal([]byte(f.Data), &ev)
			statuses = append(statuses, ev.Status)
		case "log":
			var ev sseLogEvent
			_ = json.Unmarshal([]byte(f.Data), &ev)
			logs.WriteString(ev.Logs)
		case "done":
			var ev sseDoneEvent
			_ = json.Unmarshal([]byte(f.Data), &ev)
			doneStatus = ev.Status
		}
	}

	if logs.String() != "line-one\nline-two\n" {
		t.Errorf("expected full streamed logs %q, got %q", "line-one\\nline-two\\n", logs.String())
	}
	if len(statuses) < 2 {
		t.Errorf("expected multiple status transition events (running -> completed), got %v", statuses)
	}
	if doneStatus != jobs.StatusCompleted {
		t.Errorf("expected done status completed, got %q", doneStatus)
	}
}

func TestStreamJobLogsHandler_OffsetAndLastEventIDResume(t *testing.T) {
	_, router, engine := setupTestJobAPIEnv(t)

	engine.SetExecutor(func(ctx context.Context, job *jobs.Job, logWriter io.Writer) (any, error) {
		_, _ = logWriter.Write([]byte("part1\n"))
		_, _ = logWriter.Write([]byte("part2\n"))
		return map[string]any{"ok": true}, nil
	})

	job, err := engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "echo-cmd"})
	if err != nil {
		t.Fatalf("failed to enqueue job: %v", err)
	}
	waitForTerminalJobInStore(t, engine, job.ID)

	// 1. Resume via ?offset=6
	req1 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/stream?offset=6", job.ID), nil)
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec1.Code)
	}
	frames1 := readSSEFrames(t, rec1.Body, false)
	var log1 string
	for _, f := range frames1 {
		if f.Event == "log" {
			var ev sseLogEvent
			_ = json.Unmarshal([]byte(f.Data), &ev)
			if ev.Offset != 6 || ev.NextOffset != 12 {
				t.Errorf("expected offset=6 next_offset=12, got offset=%d next_offset=%d", ev.Offset, ev.NextOffset)
			}
			log1 += ev.Logs
		}
	}
	if log1 != "part2\n" {
		t.Errorf("expected ?offset=6 to stream only 'part2\\n', got %q", log1)
	}

	// 2. Resume via Last-Event-ID: 6 overriding ?offset=0
	req2 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/stream?offset=0", job.ID), nil)
	req2.Header.Set("Last-Event-ID", "6")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)

	frames2 := readSSEFrames(t, rec2.Body, false)
	var log2 string
	for _, f := range frames2 {
		if f.Event == "log" {
			var ev sseLogEvent
			_ = json.Unmarshal([]byte(f.Data), &ev)
			log2 += ev.Logs
		}
	}
	if log2 != "part2\n" {
		t.Errorf("expected Last-Event-ID=6 to stream only 'part2\\n', got %q", log2)
	}

	// 3. Invalid/negative ?offset=-5 defaults safely to 0
	req3 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/stream?offset=-5", job.ID), nil)
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)

	frames3 := readSSEFrames(t, rec3.Body, false)
	var log3 string
	for _, f := range frames3 {
		if f.Event == "log" {
			var ev sseLogEvent
			_ = json.Unmarshal([]byte(f.Data), &ev)
			log3 += ev.Logs
		}
	}
	if log3 != "part1\npart2\n" {
		t.Errorf("expected negative offset fallback to 0 ('part1\\npart2\\n'), got %q", log3)
	}
}

func TestStreamJobLogsHandler_AuthAndErrors(t *testing.T) {
	env, router, engine := setupTestJobAPIEnv(t)

	job, err := engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "echo-cmd"})
	if err != nil {
		t.Fatalf("failed to enqueue job: %v", err)
	}

	// 1. Unknown job -> 404
	req404 := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/unknown-job-id/stream", nil)
	rec404 := httptest.NewRecorder()
	router.ServeHTTP(rec404, req404)
	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown job, got %d", rec404.Code)
	}

	// 2. Non-GET method -> 405 with Allow: GET
	req405 := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/jobs/%s/stream", job.ID), nil)
	rec405 := httptest.NewRecorder()
	router.ServeHTTP(rec405, req405)
	if rec405.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST /stream, got %d", rec405.Code)
	}
	if allow := rec405.Header().Get("Allow"); allow != http.MethodGet {
		t.Errorf("expected Allow: GET header on 405, got %q", allow)
	}

	// 3. Non-Flusher ResponseWriter -> 500
	nonFlusher := newNonFlusherResponseWriter()
	req500 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/stream", job.ID), nil)
	router.ServeHTTP(nonFlusher, req500)
	if nonFlusher.code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-flusher ResponseWriter, got %d: %s", nonFlusher.code, nonFlusher.body.String())
	}

	// 4. Auth enforcement (401 unauthenticated, 403 insufficient scope + audit denial)
	env.Config.Auth.RequireAuth = true
	req401 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/stream", job.ID), nil)
	rec401 := httptest.NewRecorder()
	router.ServeHTTP(rec401, req401)
	if rec401.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when unauthenticated and RequireAuth=true, got %d", rec401.Code)
	}

	user, err := env.AuthManager.CreateUser("stream-limited", "Limited User", "limited@example.com", auth.RoleViewer, "password-12345")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	_, rawNoScopeToken, err := env.AuthManager.CreateToken(user.ID, "No Jobs Read PAT", []string{"commands:read"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	req403 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/stream", job.ID), nil)
	req403.Header.Set("Authorization", "Bearer "+rawNoScopeToken)
	rec403 := httptest.NewRecorder()
	router.ServeHTTP(rec403, req403)
	if rec403.Code != http.StatusForbidden {
		t.Errorf("expected 403 for token lacking jobs:read, got %d: %s", rec403.Code, rec403.Body.String())
	}

	deniedEvents := env.AuditLogger.Query(audit.AuditFilter{
		Category: "job",
		Action:   "job.stream",
		Status:   "denied",
	})
	if len(deniedEvents) == 0 {
		t.Errorf("expected job.stream denied audit event to be recorded")
	}

	// 5. JobEngine nil -> 503
	savedEngine := env.JobEngine
	env.JobEngine = nil
	req503 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/stream", job.ID), nil)
	rec503 := httptest.NewRecorder()
	router.ServeHTTP(rec503, req503)
	if rec503.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when JobEngine is nil, got %d", rec503.Code)
	}
	env.JobEngine = savedEngine
}

func TestStreamJobLogsHandler_ClientCancelNoGoroutineLeak(t *testing.T) {
	_, router, engine := setupTestJobAPIEnv(t)

	releaseJob := make(chan struct{})
	t.Cleanup(func() { close(releaseJob) })
	engine.SetExecutor(func(ctx context.Context, job *jobs.Job, logWriter io.Writer) (any, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-releaseJob:
			return nil, nil
		}
	})

	job, err := engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "block-cmd"})
	if err != nil {
		t.Fatalf("failed to enqueue job: %v", err)
	}

	srv := httptest.NewServer(router)
	defer srv.Close()

	// Allow HTTP server listener/worker goroutines to settle before baseline.
	runtime.Gosched()
	time.Sleep(30 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/jobs/%s/stream", srv.URL, job.ID), nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		cancel()
		t.Fatalf("failed to connect to stream: %v", err)
	}

	// Read first event (initial status) to ensure the streaming loop is active.
	reader := bufio.NewReader(resp.Body)
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			_ = resp.Body.Close()
			cancel()
			t.Fatalf("failed reading initial SSE event: %v", readErr)
		}
		if line == "\n" {
			break
		}
	}

	cancel()
	_ = resp.Body.Close()

	// Wait briefly for server handler goroutine to observe ctx.Done() and exit.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseGoroutines+1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > baseGoroutines+2 {
		t.Errorf("potential goroutine leak after SSE client cancel: baseline=%d, after=%d", baseGoroutines, after)
	}
}

func TestStreamJobLogsHandler_KeepaliveAndWriteTimeoutCleared(t *testing.T) {
	origKeepalive := sseKeepaliveInterval
	sseKeepaliveInterval = 25 * time.Millisecond
	t.Cleanup(func() { sseKeepaliveInterval = origKeepalive })

	_, router, engine := setupTestJobAPIEnv(t)

	releaseJob := make(chan struct{})
	t.Cleanup(func() { close(releaseJob) })
	engine.SetExecutor(func(ctx context.Context, job *jobs.Job, logWriter io.Writer) (any, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-releaseJob:
			return nil, nil
		}
	})

	job, err := engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "block-cmd"})
	if err != nil {
		t.Fatalf("failed to enqueue job: %v", err)
	}

	srv := httptest.NewUnstartedServer(router)
	srv.Config.WriteTimeout = 75 * time.Millisecond
	srv.Start()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/jobs/%s/stream", srv.URL, job.ID), nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("stream request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	scanner := bufio.NewScanner(resp.Body)
	keepaliveCount := 0
	start := time.Now()
	for scanner.Scan() {
		line := scanner.Text()
		if line == ": keepalive" {
			keepaliveCount++
			if keepaliveCount >= 4 && time.Since(start) > 90*time.Millisecond {
				// Exceeded the 75ms server WriteTimeout while receiving keepalive heartbeats.
				cancel()
				break
			}
		}
	}
	if keepaliveCount < 4 {
		t.Fatalf("expected at least 4 keepalive heartbeats surviving past 75ms WriteTimeout, got %d (scan err=%v)", keepaliveCount, scanner.Err())
	}
}
