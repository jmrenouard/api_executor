package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

func TestAuditLogsVerifyAndSystemLogsEndpoints(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cmd := core.CommandDefinition{Name: "audit-echo", Command: "sh", Args: []string{"-c", "echo audited"}}
	if runtime.GOOS == "windows" {
		cmd = core.CommandDefinition{Name: "audit-echo", Command: "cmd", Args: []string{"/C", "echo audited"}}
	}
	cfg.Executor.Commands = []core.CommandDefinition{cmd}

	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	db, err := database.NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()
	_ = db.Init()

	auditLogger, err := audit.NewAuditLogger(cfg.Audit, db, logger)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	env := &APIEnv{
		Config:      cfg,
		Logger:      logger,
		DB:          db,
		AuditLogger: auditLogger,
	}
	router := NewRouter(env)

	// 1. Execute command to generate audit event, history record, and structured log
	body, _ := json.Marshal(map[string]any{"name": "audit-echo"})
	reqExec := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewReader(body))
	recExec := httptest.NewRecorder()
	router.ServeHTTP(recExec, reqExec)
	if recExec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/execute, got %d: %s", recExec.Code, recExec.Body.String())
	}

	// 2. GET /api/v1/audit/logs
	reqLogs := httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs?category=command", nil)
	recLogs := httptest.NewRecorder()
	router.ServeHTTP(recLogs, reqLogs)
	if recLogs.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/audit/logs, got %d", recLogs.Code)
	}
	var auditResp struct {
		Events []audit.AuditEvent `json:"events"`
		Total  int                `json:"total"`
	}
	if err := json.Unmarshal(recLogs.Body.Bytes(), &auditResp); err != nil {
		t.Fatalf("failed to decode audit logs: %v", err)
	}
	if len(auditResp.Events) == 0 {
		t.Fatalf("expected at least 1 audit event after command execution")
	}

	// 3. GET /api/v1/audit/verify
	reqVerify := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	recVerify := httptest.NewRecorder()
	router.ServeHTTP(recVerify, reqVerify)
	if recVerify.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/audit/verify, got %d", recVerify.Code)
	}
	var verifyResp audit.ChainVerificationResult
	if err := json.Unmarshal(recVerify.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("failed to decode chain verification: %v", err)
	}
	if !verifyResp.Valid || verifyResp.TotalEvents < 1 {
		t.Fatalf("expected valid hash chain with >=1 event, got %+v", verifyResp)
	}

	// 4. GET /api/v1/logs
	reqSysLogs := httptest.NewRequest(http.MethodGet, "/api/v1/logs?limit=20", nil)
	recSysLogs := httptest.NewRecorder()
	router.ServeHTTP(recSysLogs, reqSysLogs)
	if recSysLogs.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/logs, got %d", recSysLogs.Code)
	}

	// 5. GET /api/v1/history
	reqHist := httptest.NewRequest(http.MethodGet, "/api/v1/history?limit=10", nil)
	recHist := httptest.NewRecorder()
	router.ServeHTTP(recHist, reqHist)
	if recHist.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/history, got %d", recHist.Code)
	}
}
