package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go-admin-tool/internal/api"
	"go-admin-tool/internal/approval"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/gatekeeper"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"
)

// TestTier4_ZeroTrustMCPBastion_TLS13_FullLifecycle certifies the complete Zero-Trust MCP Bastion
// architecture over real HTTPS TLS 1.3 with RequireAuth=true and non-root sandbox UID/GID 10001:
//   - TLS 1.3 enforcement (TLS 1.2 client rejected, TLS 1.3 client verified)
//   - MicroLLM (microllm.guard.v1) System-1 allow / block / escalate (x_abstain)
//   - HITL approval challenge -> self-approval blocked (403) -> distinct admin approval (200) ->
//     TOCTOU payload tamper blocked (403) -> single-use execution (200) -> double-consume blocked (409)
//   - Cryptographic SHA-256 audit chain + MCP trace hash chain cross-verification
//   - Deterministic MCP trace replay (dry_run, operator live blocked 403, admin live lineage match)
//   - Read-only CISBenchmarks (cis.mcp.contract.v1) MCP resource, prompt, forbidden-flag rejection & scoped RBAC
//   - Prometheus /metrics cardinality audit (zero raw approval_id or trace_id leaks)
func TestTier4_ZeroTrustMCPBastion_TLS13_FullLifecycle(t *testing.T) {
	api.ResetHTTPMetrics()
	api.ResetActionMetrics()

	tmpDir := t.TempDir()

	// 1. Mock local MicroLLM (microllm.guard.v1) HTTP gatekeeper server with thread-safe decision switching.
	var gkMu sync.Mutex
	gkResponse := `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.97,"abstain":false,"reason":"safe operation","risk_score":0.04}`
	setGatekeeperResp := func(raw string) {
		gkMu.Lock()
		gkResponse = raw
		gkMu.Unlock()
	}

	mockMicroLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/guard/evaluate" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var wire map[string]any
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		// Enforce microllm.guard.v1 strict request contract (extra="forbid").
		allowedReqKeys := map[string]bool{
			"tool_name": true, "command": true, "arguments": true,
			"context": true, "environment": true, "threshold": true,
			"abstain_policy": true, "policy_boundaries": true, "custom_rubrics": true,
		}
		for k := range wire {
			if !allowedReqKeys[k] {
				http.Error(w, "unexpected extra request field: "+k, http.StatusUnprocessableEntity)
				return
			}
		}
		if _, ok := wire["tool_name"]; !ok {
			http.Error(w, "missing tool_name", http.StatusUnprocessableEntity)
			return
		}
		gkMu.Lock()
		body := gkResponse
		gkMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer mockMicroLLM.Close()

	// 2. Configure Zero-Trust Bastion server: TLS 1.3, RequireAuth=true, UID 10001 sandbox, HITL + System-1.
	cmdEchoName, baseEchoArgs := crossPlatformEcho()
	echoArgs := append(append([]string{}, baseEchoArgs...), "bastion-e2e-ok")

	cfg := core.DefaultConfig()
	cfg.Server.TLS = core.TLSConfig{
		Enabled:      true,
		AutoGenerate: true,
		CertFile:     filepath.Join(tmpDir, "bastion.crt"),
		KeyFile:      filepath.Join(tmpDir, "bastion.key"),
		Organization: "API Executor Zero-Trust Bastion E2E",
		ValidityDays: 7,
		MinVersion:   "1.3",
		Hosts:        []string{"localhost", "127.0.0.1"},
	}
	cfg.Sandbox = core.DefaultSandboxConfig()
	if err := cfg.Sandbox.Validate(); err != nil {
		t.Fatalf("Sandbox.Validate failed: %v", err)
	}
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true
	cfg.Auth.StorePath = filepath.Join(tmpDir, "auth.json")
	cfg.Auth.BootstrapUsername = "bastion_admin"
	cfg.Auth.BootstrapPassword = "BastionAdmin!2026"
	cfg.Audit.Enabled = true
	cfg.Audit.MaxMemoryLog = 500
	cfg.MCP.Enabled = true
	cfg.MCP.RetainTraces = true
	cfg.MCP.MaxTraces = 200
	cfg.Executor.Enabled = true
	cfg.Executor.MaxTimeoutSeconds = 30
	cfg.Executor.Commands = []core.CommandDefinition{
		{Name: "bastion-echo", Command: cmdEchoName, Args: echoArgs, Timeout: "5s"},
	}
	cfg.Approval = core.ApprovalConfig{
		Enabled:                 true,
		DefaultTTL:              "10m",
		MaxPending:              100,
		RequireDistinctApprover: true,
	}
	cfg.Gatekeeper = core.GatekeeperConfig{
		Enabled:       true,
		Mode:          "http",
		Endpoint:      mockMicroLLM.URL + "/v1/guard/evaluate",
		Timeout:       "250ms",
		MinConfidence: 0.70,
		FailMode:      "escalate_hitl",
		Environment:   "production",
	}

	db, err := database.NewDB(filepath.Join(tmpDir, "bastion.db"))
	if err != nil {
		t.Fatalf("database.NewDB: %v", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}

	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("core.NewLogger: %v", err)
	}
	defer logger.Close()

	certMgr, err := core.NewCertManager(cfg.Server.TLS, "127.0.0.1")
	if err != nil {
		t.Fatalf("core.NewCertManager: %v", err)
	}
	serverTLS, err := certMgr.TLSConfig()
	if err != nil {
		t.Fatalf("certMgr.TLSConfig: %v", err)
	}
	// Populate serverTLS.Certificates explicitly so httptest.StartTLS does not inject its own fallback cert.
	leafPair, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		t.Fatalf("tls.LoadX509KeyPair: %v", err)
	}
	serverTLS.Certificates = []tls.Certificate{leafPair}
	certPEM, err := certMgr.CertPEM()
	if err != nil {
		t.Fatalf("certMgr.CertPEM: %v", err)
	}

	auditLogger, err := audit.NewAuditLogger(cfg.Audit, db, logger)
	if err != nil {
		t.Fatalf("audit.NewAuditLogger: %v", err)
	}
	defer auditLogger.Close()

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("auth.NewManager: %v", err)
	}

	// Provision distinct principals across all RBAC roles + scoped CIS service account.
	_, _, admin1Tok, err := authMgr.AuthenticateUser("bastion_admin", "BastionAdmin!2026")
	if err != nil {
		t.Fatalf("login admin1: %v", err)
	}
	admin2User, err := authMgr.CreateUser("bastion_admin2", "BastionAdmin2!2026", "Second Admin", "admin2@bastion.local", auth.RoleAdmin)
	if err != nil {
		t.Fatalf("create admin2: %v", err)
	}
	_, admin2Tok, err := authMgr.CreateToken(admin2User.ID, "admin2-pat", []string{"*"}, time.Hour)
	if err != nil {
		t.Fatalf("create admin2 token: %v", err)
	}
	opUser, err := authMgr.CreateUser("bastion_op", "BastionOp!2026", "Operator", "op@bastion.local", auth.RoleOperator)
	if err != nil {
		t.Fatalf("create operator: %v", err)
	}
	_, opTok, err := authMgr.CreateToken(opUser.ID, "op-pat", nil, time.Hour)
	if err != nil {
		t.Fatalf("create operator token: %v", err)
	}
	viewerUser, err := authMgr.CreateUser("bastion_viewer", "BastionView!2026", "Viewer", "viewer@bastion.local", auth.RoleViewer)
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	_, viewerTok, err := authMgr.CreateToken(viewerUser.ID, "viewer-pat", nil, time.Hour)
	if err != nil {
		t.Fatalf("create viewer token: %v", err)
	}
	_, cisSvcKey, err := authMgr.CreateServiceAccount(
		"cis-auditor-svc",
		"CIS Compliance Scanner",
		"Read-only CIS Benchmarks audit service account",
		[]string{"plugins:read", "plugins:execute", "mcp:access"},
		[]string{"plugin:cis-benchmarks-audit:*"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("create CIS service account: %v", err)
	}

	approvalStore, err := approval.NewStore(cfg.Approval, db, auditLogger)
	if err != nil {
		t.Fatalf("approval.NewStore: %v", err)
	}

	gkClient, err := gatekeeper.NewFromConfig(cfg.Gatekeeper, cfg.Sandbox)
	if err != nil {
		t.Fatalf("gatekeeper.NewFromConfig: %v", err)
	}

	reg := plugins.NewRegistry()
	_ = reg.Register(plugins.NewSystemDiagnosticsPlugin())
	_ = reg.Register(plugins.NewDatabaseExposurePlugin(db, 100))
	pluginsDir := "plugins"
	if _, statErr := os.Stat(pluginsDir); statErr != nil {
		pluginsDir = "../../plugins"
	}
	if _, err := reg.LoadDeclarativeDirectory(pluginsDir); err != nil {
		t.Fatalf("LoadDeclarativeDirectory(%s): %v", pluginsDir, err)
	}

	mcpSrv, err := mcp.NewServer(cfg.MCP, cfg, db, certMgr, reg, auditLogger, logger, api.RecordActionCall)
	if err != nil {
		t.Fatalf("mcp.NewServer: %v", err)
	}
	defer mcpSrv.Close()

	env := &api.APIEnv{
		Config:         cfg,
		Logger:         logger,
		DB:             db,
		CertManager:    certMgr,
		AuditLogger:    auditLogger,
		AuthManager:    authMgr,
		ApprovalStore:  approvalStore,
		Gatekeeper:     gkClient,
		PluginRegistry: reg,
		MCPServer:      mcpSrv,
	}
	mcpSrv.SetApprovalGate(env.NewMCPApprovalGate())

	ts := httptest.NewUnstartedServer(api.NewRouter(env))
	ts.TLS = serverTLS
	ts.StartTLS()
	defer ts.Close()

	// Build strict TLS 1.3 client verifying the auto-generated ECDSA server cert via RootCAs.
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		t.Fatalf("failed to parse generated server cert PEM")
	}
	tls13Client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	doReq := func(method, path, token string, body any, extraHeaders map[string]string) (*http.Response, []byte) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			rdr = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(context.Background(), method, ts.URL+path, rdr)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		resp, err := tls13Client.Do(req)
		if err != nil {
			t.Fatalf("HTTPS request %s %s failed: %v", method, path, err)
		}
		defer resp.Body.Close()
		if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("expected negotiated TLS 1.3 (0x0304) on %s %s, got %+v", method, path, resp.TLS)
		}
		rawBody, _ := io.ReadAll(resp.Body)
		return resp, rawBody
	}

	// =========================================================================
	// PHASE 1: TLS 1.3 Downgrade Rejection & Zero-Trust Fail-Closed Auth (401/403)
	// =========================================================================
	tls12OnlyClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			},
		},
	}
	if _, err := tls12OnlyClient.Get(ts.URL + "/healthz"); err == nil {
		t.Fatalf("expected TLS 1.2 client to be rejected by TLS 1.3 Bastion server")
	}

	resp, _ := doReq(http.MethodGet, "/api/v1/approvals", "", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated GET /api/v1/approvals, got %d", resp.StatusCode)
	}
	for _, viewerBlocked := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/approvals", nil},
		{http.MethodGet, "/api/v1/mcp/traces/verify", nil},
		{http.MethodPost, "/api/v1/mcp/traces/mcp_tr_missing/replay", map[string]any{"mode": "dry_run"}},
	} {
		r, b := doReq(viewerBlocked.method, viewerBlocked.path, viewerTok, viewerBlocked.body, nil)
		if r.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for viewer on %s %s, got %d: %s", viewerBlocked.method, viewerBlocked.path, r.StatusCode, string(b))
		}
	}

	// =========================================================================
	// PHASE 2: MicroLLM System-1 Allow & Block (Deny)
	// =========================================================================
	setGatekeeperResp(`{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.98,"abstain":false,"reason":"clean","risk_score":0.02}`)
	resp, raw := doReq(http.MethodPost, "/api/v1/execute", opTok, map[string]any{"name": "bastion-echo"}, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "bastion-e2e-ok") {
		t.Fatalf("expected 200 OK when MicroLLM allows bastion-echo, got %d: %s", resp.StatusCode, string(raw))
	}

	setGatekeeperResp(`{"schema_version":"microllm.guard.v1","decision":"block","confidence":0.99,"abstain":false,"reason":"prompt injection detected","risk_score":0.97,"hijack_suspected":true}`)
	resp, raw = doReq(http.MethodPost, "/api/v1/execute", opTok, map[string]any{"name": "bastion-echo"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when MicroLLM blocks command, got %d: %s", resp.StatusCode, string(raw))
	}

	// =========================================================================
	// PHASE 3: MicroLLM x_abstain -> HITL Pending -> Self-Approve Blocked ->
	//          Distinct Admin Approve -> TOCTOU Tamper Blocked -> Single-Use -> Replay Blocked
	// =========================================================================
	setGatekeeperResp(`{"schema_version":"microllm.guard.v1","decision":"escalate","confidence":0.41,"abstain":true,"reason":"ambiguous risk","risk_score":0.74}`)
	resp, raw = doReq(http.MethodPost, "/api/v1/execute", admin1Tok, map[string]any{"name": "bastion-echo", "timeout": "4s"}, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted HITL challenge on x_abstain, got %d: %s", resp.StatusCode, string(raw))
	}
	var restChallenge struct {
		Status        string `json:"status"`
		ApprovalID    string `json:"approval_id"`
		PayloadSHA256 string `json:"payload_sha256"`
	}
	if err := json.Unmarshal(raw, &restChallenge); err != nil || restChallenge.ApprovalID == "" {
		t.Fatalf("failed to parse HITL challenge: err=%v body=%s", err, string(raw))
	}
	if restChallenge.Status != "pending_approval" || len(restChallenge.PayloadSHA256) != 64 {
		t.Fatalf("unexpected HITL challenge payload: %+v", restChallenge)
	}

	// Operator cannot approve (403).
	resp, _ = doReq(http.MethodPost, "/api/v1/approvals/"+restChallenge.ApprovalID+"/approve", opTok, map[string]any{"comment": "op attempt"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for operator approval attempt, got %d", resp.StatusCode)
	}
	// Self-approval by admin1 is blocked (403).
	resp, _ = doReq(http.MethodPost, "/api/v1/approvals/"+restChallenge.ApprovalID+"/approve", admin1Tok, map[string]any{"comment": "self approve"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for distinct-approver violation, got %d", resp.StatusCode)
	}
	// Distinct admin2 approves (200).
	resp, raw = doReq(http.MethodPost, "/api/v1/approvals/"+restChallenge.ApprovalID+"/approve", admin2Tok, map[string]any{"comment": "verified safe"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on distinct admin approval, got %d: %s", resp.StatusCode, string(raw))
	}

	// TOCTOU tamper (changing timeout from 4s to 5s) must be rejected (403).
	resp, _ = doReq(http.MethodPost, "/api/v1/execute", admin1Tok, map[string]any{"name": "bastion-echo", "timeout": "5s"}, map[string]string{
		"X-Approval-ID": restChallenge.ApprovalID,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on TOCTOU payload tamper, got %d", resp.StatusCode)
	}

	// Exact approved payload executes once (200).
	resp, raw = doReq(http.MethodPost, "/api/v1/execute", admin1Tok, map[string]any{"name": "bastion-echo", "timeout": "4s"}, map[string]string{
		"X-Approval-ID": restChallenge.ApprovalID,
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "bastion-e2e-ok") {
		t.Fatalf("expected 200 OK executing approved payload, got %d: %s", resp.StatusCode, string(raw))
	}

	// Reusing consumed approval_id is rejected (409).
	resp, _ = doReq(http.MethodPost, "/api/v1/execute", admin1Tok, map[string]any{"name": "bastion-echo", "timeout": "4s"}, map[string]string{
		"X-Approval-ID": restChallenge.ApprovalID,
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on approval replay, got %d", resp.StatusCode)
	}

	// =========================================================================
	// PHASE 4: MCP x_abstain -> HITL Approve -> Execute -> Dual SHA-256 Chain Verification
	// =========================================================================
	resp, raw = doReq(http.MethodPost, "/api/v1/mcp", opTok, map[string]any{
		"jsonrpc": "2.0",
		"id":      101,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "execute_command",
			"arguments": map[string]any{"name": "bastion-echo"},
		},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 MCP envelope on x_abstain, got %d: %s", resp.StatusCode, string(raw))
	}
	var mcpPend struct {
		Result struct {
			IsError           bool           `json:"isError"`
			StructuredContent map[string]any `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &mcpPend); err != nil {
		t.Fatalf("unmarshal MCP pending response: %v", err)
	}
	mcpApprovalID, _ := mcpPend.Result.StructuredContent["approval_id"].(string)
	if mcpPend.Result.IsError || mcpApprovalID == "" {
		t.Fatalf("expected MCP pending_approval with approval_id, got %s", string(raw))
	}

	// Distinct admin2 approves MCP approval request.
	resp, raw = doReq(http.MethodPost, "/api/v1/approvals/"+mcpApprovalID+"/approve", admin2Tok, map[string]any{"comment": "approved mcp tool"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 approving MCP approval %s, got %d: %s", mcpApprovalID, resp.StatusCode, string(raw))
	}

	// Operator executes approved MCP tool call via _approval_id.
	resp, raw = doReq(http.MethodPost, "/api/v1/mcp", opTok, map[string]any{
		"jsonrpc": "2.0",
		"id":      102,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "execute_command",
			"arguments": map[string]any{"name": "bastion-echo", "_approval_id": mcpApprovalID},
		},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on approved MCP execution, got %d: %s", resp.StatusCode, string(raw))
	}
	var mcpExec struct {
		TraceID string `json:"trace_id"`
		Result  struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &mcpExec); err != nil || mcpExec.TraceID == "" {
		t.Fatalf("failed to parse approved MCP execution: err=%v body=%s", err, string(raw))
	}
	if mcpExec.Result.IsError || len(mcpExec.Result.Content) == 0 || !strings.Contains(mcpExec.Result.Content[0].Text, "bastion-e2e-ok") {
		t.Fatalf("unexpected approved MCP execution result: %s", string(raw))
	}

	// Verify SHA-256 Audit Chain.
	resp, raw = doReq(http.MethodGet, "/api/v1/audit/verify", admin2Tok, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/audit/verify failed: %d %s", resp.StatusCode, string(raw))
	}
	var auditVerify struct {
		Valid       bool `json:"valid"`
		TotalEvents int  `json:"total_events"`
	}
	if err := json.Unmarshal(raw, &auditVerify); err != nil || !auditVerify.Valid || auditVerify.TotalEvents < 5 {
		t.Fatalf("expected valid audit chain with >=5 events, got %+v (%s)", auditVerify, string(raw))
	}

	// Verify Full MCP Trace SHA-256 Chain and Single Trace Cross-Link Integrity.
	resp, raw = doReq(http.MethodGet, "/api/v1/mcp/traces/verify", admin2Tok, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/mcp/traces/verify failed: %d %s", resp.StatusCode, string(raw))
	}
	var chainVerify mcp.TraceChainVerificationResult
	if err := json.Unmarshal(raw, &chainVerify); err != nil || !chainVerify.Valid || !chainVerify.AuditChainValid || chainVerify.TotalTraces < 2 {
		t.Fatalf("expected valid MCP trace chain with >=2 traces, got %+v", chainVerify)
	}

	resp, raw = doReq(http.MethodGet, "/api/v1/mcp/traces/"+mcpExec.TraceID+"/verify", admin2Tok, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/mcp/traces/%s/verify failed: %d %s", mcpExec.TraceID, resp.StatusCode, string(raw))
	}
	var singleVerify mcp.TraceIntegrityResult
	if err := json.Unmarshal(raw, &singleVerify); err != nil || !singleVerify.Valid || !singleVerify.AuditLinkValid || !singleVerify.AuditChainValid {
		t.Fatalf("expected single trace integrity + audit cross-link match, got %+v", singleVerify)
	}

	// =========================================================================
	// PHASE 5: Deterministic MCP Trace Replay (dry_run, Operator live 403, Admin live lineage)
	// =========================================================================
	setGatekeeperResp(`{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.99,"abstain":false,"reason":"replay allowed","risk_score":0.01}`)
	// Record a clean deterministic MCP trace (execute_command bastion-echo) without _approval_id for live replay.
	resp, raw = doReq(http.MethodPost, "/api/v1/mcp", opTok, map[string]any{
		"jsonrpc": "2.0",
		"id":      103,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "execute_command",
			"arguments": map[string]any{"name": "bastion-echo"},
		},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 recording replay baseline trace, got %d", resp.StatusCode)
	}
	var baselineMCP struct {
		TraceID string `json:"trace_id"`
	}
	if err := json.Unmarshal(raw, &baselineMCP); err != nil || baselineMCP.TraceID == "" {
		t.Fatalf("failed to extract baseline traceId: %s", string(raw))
	}

	// Operator dry_run succeeds (200).
	resp, raw = doReq(http.MethodPost, "/api/v1/mcp/traces/"+baselineMCP.TraceID+"/replay", opTok, map[string]any{"mode": "dry_run"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on operator dry_run replay, got %d: %s", resp.StatusCode, string(raw))
	}
	var dryReport mcp.ReplayReport
	if err := json.Unmarshal(raw, &dryReport); err != nil || !dryReport.PolicyEligible || !dryReport.IntegrityValid || !dryReport.AuditChainValid {
		t.Fatalf("unexpected dry_run replay report: %+v", dryReport)
	}

	// Operator live replay is strictly blocked (403).
	resp, _ = doReq(http.MethodPost, "/api/v1/mcp/traces/"+baselineMCP.TraceID+"/replay", opTok, map[string]any{"mode": "live"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for operator live replay, got %d", resp.StatusCode)
	}

	// Admin live replay succeeds with deterministic output match and parent_trace_id lineage.
	resp, raw = doReq(http.MethodPost, "/api/v1/mcp/traces/"+baselineMCP.TraceID+"/replay", admin2Tok, map[string]any{"mode": "live"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on admin live replay, got %d: %s", resp.StatusCode, string(raw))
	}
	var liveReport mcp.ReplayReport
	if err := json.Unmarshal(raw, &liveReport); err != nil {
		t.Fatalf("unmarshal live replay report: %v", err)
	}
	if !liveReport.IntegrityValid || !liveReport.StatusMatch || !liveReport.DeterministicMatch || liveReport.OriginalTraceID != baselineMCP.TraceID || liveReport.ReplayTraceID == "" {
		t.Fatalf("expected deterministic live replay with parent lineage, got %+v", liveReport)
	}

	// Verify the recorded replay trace carries parent_trace_id == baselineMCP.TraceID.
	resp, raw = doReq(http.MethodGet, "/api/v1/mcp/traces/"+liveReport.ReplayTraceID, admin2Tok, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/mcp/traces/%s failed: %d %s", liveReport.ReplayTraceID, resp.StatusCode, string(raw))
	}
	var replayedTrace mcp.MCPTrace
	if err := json.Unmarshal(raw, &replayedTrace); err != nil || replayedTrace.ParentTraceID != baselineMCP.TraceID {
		t.Fatalf("expected replay trace ParentTraceID=%q, got %+v (raw=%s)", baselineMCP.TraceID, replayedTrace, string(raw))
	}

	// =========================================================================
	// PHASE 6: Read-Only CISBenchmarks (cis.mcp.contract.v1) Preset & Scoped Service Account
	// =========================================================================
	resp, raw = doReq(http.MethodPost, "/api/v1/mcp", cisSvcKey, map[string]any{
		"jsonrpc": "2.0",
		"id":      201,
		"method":  "resources/read",
		"params":  map[string]any{"uri": mcp.CISResourceURI},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 reading CIS preset resource, got %d: %s", resp.StatusCode, string(raw))
	}
	var cisResEnv struct {
		Result struct {
			Contents []struct {
				URI  string `json:"uri"`
				Text string `json:"text"`
			} `json:"contents"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &cisResEnv); err != nil || len(cisResEnv.Result.Contents) != 1 {
		t.Fatalf("failed to decode MCP resource envelope: err=%v raw=%s", err, string(raw))
	}
	var cisPreset mcp.CISBenchmarksPresetResource
	if err := json.Unmarshal([]byte(cisResEnv.Result.Contents[0].Text), &cisPreset); err != nil {
		t.Fatalf("failed to decode CISBenchmarksPresetResource JSON: %v", err)
	}
	if cisPreset.SchemaVersion != mcp.CISContractSchemaVersion || !cisPreset.ReadOnly || cisPreset.Mutating || !cisPreset.PluginLoaded || len(cisPreset.CanonicalTargets) != 18 {
		t.Fatalf("unexpected CIS preset resource payload: %+v", cisPreset)
	}

	resp, raw = doReq(http.MethodPost, "/api/v1/mcp", cisSvcKey, map[string]any{
		"jsonrpc": "2.0",
		"id":      202,
		"method":  "prompts/get",
		"params":  map[string]any{"name": mcp.CISPromptName, "arguments": map[string]string{"target": "rhel9", "format": "sarif"}},
	}, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "cis_audit_sarif") {
		t.Fatalf("expected cis-benchmark-audit prompt with cis_audit_sarif, got %d: %s", resp.StatusCode, string(raw))
	}

	// Forbidden remediation flag smuggling rejected fail-closed before subprocess spawn.
	resp, raw = doReq(http.MethodPost, "/api/v1/mcp", cisSvcKey, map[string]any{
		"jsonrpc": "2.0",
		"id":      203,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "execute_plugin",
			"arguments": map[string]any{
				"plugin_id": mcp.CISPluginID,
				"action":    "cis_audit_json",
				"params":    map[string]any{"target": "--apply"},
			},
		},
	}, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"isError":true`) {
		t.Fatalf("expected MCP tool error rejecting --apply flag, got %d: %s", resp.StatusCode, string(raw))
	}

	// Scoped CIS service account is blocked (403) on unrelated plugins.
	resp, _ = doReq(http.MethodPost, "/api/v1/plugins/execute", cisSvcKey, map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for scoped CIS service account on sys-diagnostics, got %d", resp.StatusCode)
	}

	// Final cryptographic chain verification after full Bastion workload.
	resp, raw = doReq(http.MethodGet, "/api/v1/audit/verify", admin2Tok, nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"valid":true`) {
		t.Fatalf("final audit verify failed: %d %s", resp.StatusCode, string(raw))
	}
	resp, raw = doReq(http.MethodGet, "/api/v1/mcp/traces/verify", admin2Tok, nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"valid":true`) {
		t.Fatalf("final MCP trace verify failed: %d %s", resp.StatusCode, string(raw))
	}

	// =========================================================================
	// PHASE 7: Prometheus /metrics Zero Dynamic-ID Cardinality Audit
	// =========================================================================
	resp, raw = doReq(http.MethodGet, "/metrics", "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics failed: %d", resp.StatusCode)
	}
	metricsText := string(raw)
	for _, forbiddenLeak := range []string{restChallenge.ApprovalID, mcpApprovalID, mcpExec.TraceID, baselineMCP.TraceID, liveReport.ReplayTraceID} {
		if forbiddenLeak != "" && strings.Contains(metricsText, forbiddenLeak) {
			t.Errorf("Prometheus /metrics leaked dynamic ID %q!", forbiddenLeak)
		}
	}
	for _, expectedMetric := range []string{
		`/api/v1/approvals/:id/approve`,
		`/api/v1/mcp/traces/:trace_id/verify`,
		`/api/v1/mcp/traces/:trace_id/replay`,
		`gatekeeper_decisions_total`,
		`gatekeeper_latency_seconds`,
	} {
		if !strings.Contains(metricsText, expectedMetric) {
			t.Errorf("expected normalized metric marker %q in /metrics output", expectedMetric)
		}
	}
}
