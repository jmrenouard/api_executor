package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go-admin-tool/docs"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

func setupTestEnvForMetricsAndTimeout(t *testing.T) *APIEnv {
	t.Helper()
	tmpDir := t.TempDir()

	var okCmd, failCmd, slowCmd, fastOverrideCmd core.CommandDefinition
	if runtime.GOOS == "windows" {
		okCmd = core.CommandDefinition{
			Name:    "action-ok",
			Command: "cmd",
			Args:    []string{"/C", "echo ok-output"},
		}
		failCmd = core.CommandDefinition{
			Name:    "action-fail",
			Command: "cmd",
			Args:    []string{"/C", "exit /B 2"},
		}
		slowCmd = core.CommandDefinition{
			Name:    "action-slow",
			Command: "powershell",
			Args:    []string{"-NoProfile", "-Command", "Start-Sleep -Seconds 5"},
		}
		fastOverrideCmd = core.CommandDefinition{
			Name:    "action-short-default",
			Command: "powershell",
			Args:    []string{"-NoProfile", "-Command", "Start-Sleep -Milliseconds 250; Write-Output done"},
			Timeout: "50ms", // too short by default, unless overridden at call time
		}
	} else {
		okCmd = core.CommandDefinition{
			Name:    "action-ok",
			Command: "sh",
			Args:    []string{"-c", "echo ok-output"},
		}
		failCmd = core.CommandDefinition{
			Name:    "action-fail",
			Command: "sh",
			Args:    []string{"-c", "exit 2"},
		}
		slowCmd = core.CommandDefinition{
			Name:    "action-slow",
			Command: "sh",
			Args:    []string{"-c", "sleep 5"},
		}
		fastOverrideCmd = core.CommandDefinition{
			Name:    "action-short-default",
			Command: "sh",
			Args:    []string{"-c", "sleep 0.25 && echo done"},
			Timeout: "50ms",
		}
	}

	brokenBinCmd := core.CommandDefinition{
		Name:    "action-bad-binary",
		Command: "nonexistent_binary_for_error_metric_test_12345",
	}

	cfg := core.DefaultConfig()
	cfg.Executor = core.ExecutorConfig{
		Enabled:               true,
		DefaultTimeoutSeconds: 30,
		DefaultTimeout:        "30s",
		MaxTimeoutSeconds:     120,
		Commands: []core.CommandDefinition{
			okCmd,
			failCmd,
			slowCmd,
			fastOverrideCmd,
			brokenBinCmd,
		},
	}

	logger, err := core.NewLogger(core.LoggingConfig{Level: "error"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	db, err := database.NewDB(filepath.Join(tmpDir, "test_history.db"))
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Init(); err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}

	return &APIEnv{
		Config: cfg,
		Logger: logger,
		DB:     db,
	}
}

func assertMetricsInvariant(t *testing.T, action string) {
	t.Helper()
	snap := GetActionMetricsSnapshot(action)
	sum := snap.CallsOK + snap.CallsError + snap.CallsFailure
	if snap.CallsTotal != sum {
		t.Errorf("invariant violated for action %q: CallsTotal(%v) != CallsOK(%v) + CallsError(%v) + CallsFailure(%v)",
			action, snap.CallsTotal, snap.CallsOK, snap.CallsError, snap.CallsFailure)
	}
}

func TestPrometheusActionMetricsEnrichment(t *testing.T) {
	ResetActionMetrics()
	env := setupTestEnvForMetricsAndTimeout(t)
	router := NewRouter(env)

	// 0. Configured actions are pre-initialized to 0 in Prometheus before any call,
	// and all 7 per-action metric families are immediately exposed on GET /metrics at startup.
	initialSnap := GetActionMetricsSnapshot("action-ok")
	if initialSnap.CallsTotal != 0 || initialSnap.CallsOK != 0 || initialSnap.CallsError != 0 || initialSnap.CallsFailure != 0 {
		t.Fatalf("expected 0 initial metrics for action-ok, got %+v", initialSnap)
	}
	{
		initMetricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		initMetricsRec := httptest.NewRecorder()
		router.ServeHTTP(initMetricsRec, initMetricsReq)
		if initMetricsRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on initial /metrics scrape, got %d", initMetricsRec.Code)
		}
		initBody := initMetricsRec.Body.String()
		for _, metricName := range []string{
			"action_calls_total",
			"action_calls_ok_total",
			"action_calls_error_total",
			"action_calls_failure_total",
			"action_calls_timeout_total",
			"action_calls_status_total",
			"action_call_duration_seconds",
		} {
			if !strings.Contains(initBody, metricName) {
				t.Errorf("expected initial /metrics output (before any call) to contain %q", metricName)
			}
		}
	}

	// 1. Execute "action-ok" twice -> 2 calls, 2 OK, 0 error, 0 failure
	for i := 0; i < 2; i++ {
		body := bytes.NewBufferString(`{"name":"action-ok"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for action-ok, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	snapOK := GetActionMetricsSnapshot("action-ok")
	if snapOK.CallsTotal != 2 || snapOK.CallsOK != 2 || snapOK.CallsError != 0 || snapOK.CallsFailure != 0 {
		t.Errorf("unexpected metrics for action-ok: %+v", snapOK)
	}
	assertMetricsInvariant(t, "action-ok")

	// 2. Execute "action-fail" (non-zero exit code) -> 1 call, 0 OK, 0 error, 1 failure
	{
		body := bytes.NewBufferString(`{"name":"action-fail"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 for action-fail, got %d", rec.Code)
		}
	}
	snapFail := GetActionMetricsSnapshot("action-fail")
	if snapFail.CallsTotal != 1 || snapFail.CallsOK != 0 || snapFail.CallsError != 0 || snapFail.CallsFailure != 1 {
		t.Errorf("unexpected metrics for action-fail: %+v", snapFail)
	}
	assertMetricsInvariant(t, "action-fail")

	// 3. Execute "action-bad-binary" (executable not found) -> 1 call, 0 OK, 1 error, 0 failure
	{
		body := bytes.NewBufferString(`{"name":"action-bad-binary"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 for action-bad-binary, got %d", rec.Code)
		}
	}
	snapBadBin := GetActionMetricsSnapshot("action-bad-binary")
	if snapBadBin.CallsTotal != 1 || snapBadBin.CallsOK != 0 || snapBadBin.CallsError != 1 || snapBadBin.CallsFailure != 0 {
		t.Errorf("unexpected metrics for action-bad-binary: %+v", snapBadBin)
	}
	assertMetricsInvariant(t, "action-bad-binary")

	// 4. Call with invalid timeout parameter on "action-ok" -> increments total and error for "action-ok"
	{
		body := bytes.NewBufferString(`{"name":"action-ok","timeout":"-5s"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for negative timeout, got %d", rec.Code)
		}
	}
	snapOK = GetActionMetricsSnapshot("action-ok")
	if snapOK.CallsTotal != 3 || snapOK.CallsOK != 2 || snapOK.CallsError != 1 || snapOK.CallsFailure != 0 {
		t.Errorf("unexpected metrics for action-ok after invalid timeout: %+v", snapOK)
	}
	assertMetricsInvariant(t, "action-ok")

	// 5. Call unknown command "nonexistent-action" -> 404 and increments total and error for "nonexistent-action"
	{
		body := bytes.NewBufferString(`{"name":"nonexistent-action"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 Not Found for unknown command, got %d", rec.Code)
		}
	}
	snapUnknown := GetActionMetricsSnapshot("nonexistent-action")
	if snapUnknown.CallsTotal != 1 || snapUnknown.CallsError != 1 {
		t.Errorf("unexpected metrics for nonexistent-action: %+v", snapUnknown)
	}
	assertMetricsInvariant(t, "nonexistent-action")

	// 6. Malformed JSON and empty command name -> increments total and error for "unknown"
	{
		reqBadJSON := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{malformed`))
		recBadJSON := httptest.NewRecorder()
		router.ServeHTTP(recBadJSON, reqBadJSON)
		if recBadJSON.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for malformed JSON, got %d", recBadJSON.Code)
		}

		reqEmptyName := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"   "}`))
		recEmptyName := httptest.NewRecorder()
		router.ServeHTTP(recEmptyName, reqEmptyName)
		if recEmptyName.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for empty command name, got %d", recEmptyName.Code)
		}
	}
	snapMalformed := GetActionMetricsSnapshot("unknown")
	if snapMalformed.CallsTotal != 2 || snapMalformed.CallsError != 2 {
		t.Errorf("expected 2 error calls for action='unknown', got %+v", snapMalformed)
	}
	assertMetricsInvariant(t, "unknown")

	// 7. Scrape GET /metrics and verify all metric names are present in Prometheus exposition output
	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	router.ServeHTTP(metricsRec, metricsReq)
	if metricsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /metrics, got %d", metricsRec.Code)
	}
	metricsBody := metricsRec.Body.String()
	for _, metricName := range []string{
		"action_calls_total",
		"action_calls_ok_total",
		"action_calls_error_total",
		"action_calls_failure_total",
		"action_calls_timeout_total",
		"action_calls_status_total",
		"action_call_duration_seconds",
	} {
		if !strings.Contains(metricsBody, metricName) {
			t.Errorf("expected /metrics output to contain %q", metricName)
		}
	}
}

func TestCallTimeoutDefaultAndPerCallOverride(t *testing.T) {
	ResetActionMetrics()
	env := setupTestEnvForMetricsAndTimeout(t)
	router := NewRouter(env)

	// 1. Override timeout via JSON string field: {"name":"action-slow","timeout":"120ms"} -> times out
	{
		body := bytes.NewBufferString(`{"name":"action-slow","timeout":"120ms"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatalf("expected non-200 when command times out, got 200")
		}
		var resp ExecuteCommandResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if !resp.TimedOut {
			t.Errorf("expected resp.TimedOut=true on timeout")
		}
		if !strings.Contains(strings.ToLower(resp.Error), "timed out") && !strings.Contains(strings.ToLower(resp.Error), "timeout") {
			t.Errorf("expected error message to mention timeout, got %q", resp.Error)
		}
	}

	// Verify timeout incremented total, failure, and timeout metrics for "action-slow"
	snapSlow := GetActionMetricsSnapshot("action-slow")
	if snapSlow.CallsTotal != 1 || snapSlow.CallsFailure != 1 || snapSlow.CallsTimeout != 1 {
		t.Errorf("unexpected metrics for action-slow after first timeout: %+v", snapSlow)
	}
	assertMetricsInvariant(t, "action-slow")

	// 2. Override timeout via query parameter: POST /api/v1/execute?timeout=120ms
	{
		body := bytes.NewBufferString(`{"name":"action-slow"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute?timeout=120ms", body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatalf("expected non-200 when command times out via query param, got 200")
		}
	}
	snapSlow = GetActionMetricsSnapshot("action-slow")
	if snapSlow.CallsTotal != 2 || snapSlow.CallsFailure != 2 || snapSlow.CallsTimeout != 2 {
		t.Errorf("unexpected metrics for action-slow after second timeout: %+v", snapSlow)
	}
	assertMetricsInvariant(t, "action-slow")

	// 3. Override numeric timeout in JSON body (e.g. {"name":"action-short-default","timeout":2})
	// "action-short-default" has a 50ms command timeout and sleeps 250ms, so without override it times out,
	// but with a 2s per-call override it succeeds!
	{
		body := bytes.NewBufferString(`{"name":"action-short-default","timeout":2}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK when overriding short default timeout with 2s, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp ExecuteCommandResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if !strings.Contains(resp.Output, "done") {
			t.Errorf("expected output to contain 'done', got %q", resp.Output)
		}
		if resp.Timeout != "2s" {
			t.Errorf("expected resp.Timeout='2s', got %q", resp.Timeout)
		}
	}

	// 4. Test invalid timeout edge cases: zero timeout, garbage timeout, exceeding MaxTimeoutSeconds (120s),
	// invalid timeout_seconds / timeout_ms types, and mixed valid+invalid timeout fields.
	invalidRequests := []struct {
		url     string
		payload string
	}{
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout":0}`},
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout":"0s"}`},
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout":"garbage"}`},
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout_seconds":-10}`},
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout_seconds":"not-a-number"}`},
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout_ms":0}`},
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout_ms":"not-an-int"}`},
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout":"5s","timeout_seconds":-10}`},
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout":"5s","timeout_ms":-5}`},
		{url: "/api/v1/execute", payload: `{"name":"action-ok","timeout":"999s"}`}, // exceeds MaxTimeoutSeconds=120
		{url: "/api/v1/execute?timeout=invalid", payload: `{"name":"action-ok"}`},
		{url: "/api/v1/execute?timeout_ms=-5", payload: `{"name":"action-ok"}`},
		{url: "/api/v1/execute?timeout=5s&timeout_ms=-5", payload: `{"name":"action-ok"}`},
		{url: "/api/v1/execute?timeout=", payload: `{"name":"action-ok"}`},
	}
	for _, tc := range invalidRequests {
		req := httptest.NewRequest(http.MethodPost, tc.url, bytes.NewBufferString(tc.payload))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for %s with %s, got %d (%s)", tc.url, tc.payload, rec.Code, rec.Body.String())
		}
	}
	snapOKAfterInvalid := GetActionMetricsSnapshot("action-ok")
	if int(snapOKAfterInvalid.CallsError) != len(invalidRequests) {
		t.Errorf("expected all %d invalid timeout requests for action-ok to be attributed to action='action-ok', got CallsError=%v",
			len(invalidRequests), snapOKAfterInvalid.CallsError)
	}
	assertMetricsInvariant(t, "action-ok")

	// 5. Verify GET /api/v1/commands exposes default_timeout and per-command effective timeouts
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/commands", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK on /api/v1/commands, got %d", rec.Code)
		}
		var listResp struct {
			DefaultTimeout string `json:"default_timeout"`
			Commands       []struct {
				Name    string `json:"name"`
				Timeout string `json:"timeout"`
			} `json:"commands"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
			t.Fatalf("failed to decode /api/v1/commands response: %v", err)
		}
		if listResp.DefaultTimeout != "30s" {
			t.Errorf("expected default_timeout='30s', got %q", listResp.DefaultTimeout)
		}
	}
}

func TestPrometheusActionLabelCardinalityBounding(t *testing.T) {
	ResetActionMetrics()
	env := setupTestEnvForMetricsAndTimeout(t)
	router := NewRouter(env)

	// Send MaxDynamicActionLabels + 20 distinct unknown action names
	extraCount := 20
	for i := 0; i < MaxDynamicActionLabels+extraCount; i++ {
		actionName := fmt.Sprintf("unknown-action-%d", i)
		body := bytes.NewBufferString(fmt.Sprintf(`{"name":%q}`, actionName))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for %s, got %d", actionName, rec.Code)
		}
	}

	// Also send an oversized action name (> MaxActionLabelLength) and a control-char action name
	longName := strings.Repeat("x", MaxActionLabelLength+10)
	for _, badPayload := range []string{
		fmt.Sprintf(`{"name":%q}`, longName),
		`{"name":"bad\ncontrol"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(badPayload))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}

	// First MaxDynamicActionLabels unknown actions should have their own counter = 1
	firstSnap := GetActionMetricsSnapshot("unknown-action-0")
	if firstSnap.CallsTotal != 1 || firstSnap.CallsError != 1 {
		t.Errorf("expected unknown-action-0 to have 1 error call, got %+v", firstSnap)
	}

	// Actions beyond MaxDynamicActionLabels plus the 2 invalid-label requests should be bucketed under "unknown"
	overflowSnap := GetActionMetricsSnapshot(fmt.Sprintf("unknown-action-%d", MaxDynamicActionLabels+5))
	if overflowSnap.CallsTotal != 0 {
		t.Errorf("expected overflow dynamic action label to not allocate new series, got %+v", overflowSnap)
	}

	unknownSnap := GetActionMetricsSnapshot("unknown")
	expectedUnknown := float64(extraCount + 2)
	if unknownSnap.CallsTotal != expectedUnknown || unknownSnap.CallsError != expectedUnknown {
		t.Errorf("expected %v overflow/invalid calls bucketed under 'unknown', got %+v", expectedUnknown, unknownSnap)
	}
	assertMetricsInvariant(t, "unknown")
}

func TestSwaggerDocIncludesTimeoutParameters(t *testing.T) {
	docJSON := docs.SwaggerInfo.ReadDoc()
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(docJSON), &parsed); err != nil {
		t.Fatalf("SwaggerInfo.ReadDoc() produced invalid JSON: %v", err)
	}
	for _, field := range []string{"timeout", "timeout_seconds", "timeout_ms", "timed_out", "default_timeout"} {
		if !strings.Contains(docJSON, field) {
			t.Errorf("expected Swagger doc to document %q", field)
		}
	}
}

