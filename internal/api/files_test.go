package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go-admin-tool/internal/core"
)

func TestSecureFileServerListAndDownloadHandlers(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.FileServer.Enabled = false
	cfg.FileServer.SecureDir = tmpDir

	env := &APIEnv{Config: cfg}
	router := NewRouter(env)

	// 1. When FileServer.Enabled is false -> 404 Not Found
	reqDisabledList := httptest.NewRequest(http.MethodGet, "/api/v1/files", nil)
	recDisabledList := httptest.NewRecorder()
	router.ServeHTTP(recDisabledList, reqDisabledList)
	if recDisabledList.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when file server disabled, got %d", recDisabledList.Code)
	}

	reqDisabledDl := httptest.NewRequest(http.MethodGet, "/api/v1/files/report.txt", nil)
	recDisabledDl := httptest.NewRecorder()
	router.ServeHTTP(recDisabledDl, reqDisabledDl)
	if recDisabledDl.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on download when file server disabled, got %d", recDisabledDl.Code)
	}

	// 2. Enable FileServer with non-existent directory -> 500 on list
	cfg.FileServer.Enabled = true
	cfg.FileServer.SecureDir = filepath.Join(tmpDir, "missing-dir")
	reqMissingDir := httptest.NewRequest(http.MethodGet, "/api/v1/files", nil)
	recMissingDir := httptest.NewRecorder()
	router.ServeHTTP(recMissingDir, reqMissingDir)
	if recMissingDir.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when SecureDir does not exist, got %d", recMissingDir.Code)
	}

	// 3. Populate valid SecureDir with a file and a subdirectory
	cfg.FileServer.SecureDir = tmpDir
	if err := os.WriteFile(filepath.Join(tmpDir, "audit-report.txt"), []byte("confidential-audit-payload"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "nested-dir"), 0755); err != nil {
		t.Fatalf("failed to create nested dir: %v", err)
	}

	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/files", nil)
	recList := httptest.NewRecorder()
	router.ServeHTTP(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/files, got %d", recList.Code)
	}
	var listResp FileListResponse
	if err := json.Unmarshal(recList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode FileListResponse: %v", err)
	}
	if len(listResp.Files) != 1 || listResp.Files[0] != "audit-report.txt" {
		t.Fatalf("expected ['audit-report.txt'] (excluding directories), got %+v", listResp.Files)
	}

	// 4. Download existing file -> 200 OK with exact content
	reqDl := httptest.NewRequest(http.MethodGet, "/api/v1/files/audit-report.txt", nil)
	recDl := httptest.NewRecorder()
	router.ServeHTTP(recDl, reqDl)
	if recDl.Code != http.StatusOK || recDl.Body.String() != "confidential-audit-payload" {
		t.Fatalf("expected 200 with file content, got %d: %q", recDl.Code, recDl.Body.String())
	}

	// 5. Path traversal and invalid filename characters rejected with 400 Bad Request
	for _, badPath := range []string{
		"/api/v1/files/..%2Fsecret.txt",
		"/api/v1/files/sub/file.txt",
		"/api/v1/files/..\\secret.txt",
	} {
		reqTrav := httptest.NewRequest(http.MethodGet, badPath, nil)
		recTrav := httptest.NewRecorder()
		env.DownloadFileHandler(recTrav, reqTrav)
		if recTrav.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for %q, got %d", badPath, recTrav.Code)
		}
	}

	// 6. Non-existent file or directory download -> 404 Not Found
	for _, missing := range []string{"/api/v1/files/missing.txt", "/api/v1/files/nested-dir"} {
		reqNotFound := httptest.NewRequest(http.MethodGet, missing, nil)
		recNotFound := httptest.NewRecorder()
		router.ServeHTTP(recNotFound, reqNotFound)
		if recNotFound.Code != http.StatusNotFound {
			t.Errorf("expected 404 for %q, got %d", missing, recNotFound.Code)
		}
	}
}

func TestExecutorDisabledAndQueryParamCommandFallback(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Executor.Enabled = false

	env := &APIEnv{Config: cfg}
	router := NewRouter(env)

	// ListCommands when disabled -> 404
	reqCmds := httptest.NewRequest(http.MethodGet, "/api/v1/commands", nil)
	recCmds := httptest.NewRecorder()
	router.ServeHTTP(recCmds, reqCmds)
	if recCmds.Code != http.StatusNotFound {
		t.Errorf("expected 404 from /api/v1/commands when executor disabled, got %d", recCmds.Code)
	}

	// ExecuteCommand when disabled -> 404
	reqExecDis := httptest.NewRequest(http.MethodPost, "/api/v1/execute?name=test-cmd", nil)
	recExecDis := httptest.NewRecorder()
	router.ServeHTTP(recExecDis, reqExecDis)
	if recExecDis.Code != http.StatusNotFound {
		t.Errorf("expected 404 from /api/v1/execute when executor disabled, got %d", recExecDis.Code)
	}

	// Enable executor and execute via query parameter ?name=... with empty body
	cfg.Executor.Enabled = true
	cmd := core.CommandDefinition{Name: "query-echo", Command: "sh", Args: []string{"-c", "echo query-ok"}}
	if runtime.GOOS == "windows" {
		cmd = core.CommandDefinition{Name: "query-echo", Command: "cmd", Args: []string{"/C", "echo query-ok"}}
	}
	cfg.Executor.Commands = []core.CommandDefinition{cmd}

	reqQueryExec := httptest.NewRequest(http.MethodPost, "/api/v1/execute?name=query-echo&timeout_ms=5000", nil)
	recQueryExec := httptest.NewRecorder()
	router.ServeHTTP(recQueryExec, reqQueryExec)
	if recQueryExec.Code != http.StatusOK || !strings.Contains(recQueryExec.Body.String(), "query-ok") {
		t.Errorf("expected 200 and query-ok when executing via ?name=query-echo, got %d: %s", recQueryExec.Code, recQueryExec.Body.String())
	}

	// Malformed JSON body -> 400
	reqBadJSON := httptest.NewRequest(http.MethodPost, "/api/v1/execute?name=query-echo", strings.NewReader("{bad"))
	recBadJSON := httptest.NewRecorder()
	router.ServeHTTP(recBadJSON, reqBadJSON)
	if recBadJSON.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed JSON body, got %d", recBadJSON.Code)
	}

	// Missing command name -> 400
	reqNoName := httptest.NewRequest(http.MethodPost, "/api/v1/execute", strings.NewReader(`{}`))
	recNoName := httptest.NewRecorder()
	router.ServeHTTP(recNoName, reqNoName)
	if recNoName.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing command name, got %d", recNoName.Code)
	}
}
