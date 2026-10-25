package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

// APIEnv holds dependencies for API handlers.
type APIEnv struct {
	Config      *core.Config
	Logger      *core.Logger
	DB          *database.DB
	CertManager *core.CertManager
	AuditLogger *audit.AuditLogger
}

// ExecuteCommandRequest defines the structure for the command execution request body.
// Timeout may be passed as a duration string (e.g., "10s", "500ms") or numeric seconds (e.g., 10),
// or via timeout_seconds / timeout_ms fields, or via URL query parameters (?timeout=10s).
type ExecuteCommandRequest struct {
	Name              string  `json:"name"`
	Timeout           string  `json:"timeout,omitempty"`
	TimeoutSeconds    float64 `json:"timeout_seconds,omitempty"`
	TimeoutMs         int64   `json:"timeout_ms,omitempty"`
	rawTimeout        string
	hasRawTimeout     bool
	rawTimeoutSeconds string
	hasRawTimeoutSecs bool
	rawTimeoutMs      string
	hasRawTimeoutMs   bool
}

func decodeRawTimeoutToken(raw json.RawMessage) (val string, present bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if strings.TrimSpace(s) == "" {
			return "", false
		}
		return s, true
	}
	return strings.TrimSpace(string(raw)), true
}

// UnmarshalJSON supports both string ("5s", "500ms", "5") and numeric (5, 0.5) values for "timeout",
// as well as "timeout_seconds" and "timeout_ms", while preserving Name even when timeout fields are malformed.
func (r *ExecuteCommandRequest) UnmarshalJSON(data []byte) error {
	var raw struct {
		Name           json.RawMessage `json:"name"`
		Timeout        json.RawMessage `json:"timeout"`
		TimeoutSeconds json.RawMessage `json:"timeout_seconds"`
		TimeoutMs      json.RawMessage `json:"timeout_ms"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if len(raw.Name) > 0 && string(raw.Name) != "null" {
		if err := json.Unmarshal(raw.Name, &r.Name); err != nil {
			return err
		}
	}

	if val, ok := decodeRawTimeoutToken(raw.Timeout); ok {
		r.hasRawTimeout = true
		r.rawTimeout = val
		r.Timeout = val
	}

	if val, ok := decodeRawTimeoutToken(raw.TimeoutSeconds); ok {
		r.hasRawTimeoutSecs = true
		r.rawTimeoutSeconds = val
		if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil {
			r.TimeoutSeconds = f
		}
	}

	if val, ok := decodeRawTimeoutToken(raw.TimeoutMs); ok {
		r.hasRawTimeoutMs = true
		r.rawTimeoutMs = val
		if ms, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64); err == nil {
			r.TimeoutMs = ms
		}
	}

	return nil
}

// ExecuteCommandResponse defines the structure for the command execution response.
type ExecuteCommandResponse struct {
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
	TimedOut bool   `json:"timed_out,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
}

// FileListResponse defines the structure for the file list response.
type FileListResponse struct {
	Files []string `json:"files"`
}

// ErrorResponse defines a generic error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// extractTimeoutOverride resolves and validates all per-call timeout overrides from the request body and URL query parameters.
func extractTimeoutOverride(r *http.Request, req ExecuteCommandRequest) (time.Duration, error) {
	var bodyDuration time.Duration
	hasBody := false

	// 1. Validate ALL provided request body timeout fields (timeout_ms, timeout_seconds, timeout)
	if req.hasRawTimeoutMs || req.TimeoutMs != 0 {
		if req.hasRawTimeoutMs {
			ms, err := strconv.ParseInt(strings.TrimSpace(req.rawTimeoutMs), 10, 64)
			if err != nil || ms <= 0 {
				return 0, fmt.Errorf("invalid timeout_ms %q (must be a strictly positive integer)", req.rawTimeoutMs)
			}
			bodyDuration = time.Duration(ms) * time.Millisecond
			hasBody = true
		} else {
			if req.TimeoutMs <= 0 {
				return 0, fmt.Errorf("timeout_ms must be strictly positive, got %d", req.TimeoutMs)
			}
			bodyDuration = time.Duration(req.TimeoutMs) * time.Millisecond
			hasBody = true
		}
	}

	if req.hasRawTimeoutSecs || req.TimeoutSeconds != 0 {
		rawSecs := req.rawTimeoutSeconds
		if !req.hasRawTimeoutSecs {
			rawSecs = strconv.FormatFloat(req.TimeoutSeconds, 'f', -1, 64)
		}
		d, err := core.ParseTimeoutDuration(rawSecs)
		if err != nil || d <= 0 {
			if err != nil {
				return 0, fmt.Errorf("invalid timeout_seconds: %w", err)
			}
			return 0, fmt.Errorf("timeout_seconds must be strictly positive, got %q", rawSecs)
		}
		bodyDuration = d
		hasBody = true
	}

	if req.hasRawTimeout || strings.TrimSpace(req.Timeout) != "" {
		rawVal := req.rawTimeout
		if rawVal == "" {
			rawVal = req.Timeout
		}
		d, err := core.ParseTimeoutDuration(rawVal)
		if err != nil || d <= 0 {
			if err != nil {
				return 0, err
			}
			return 0, fmt.Errorf("timeout must be strictly positive, got %q", rawVal)
		}
		bodyDuration = d
		hasBody = true
	}

	// 2. Validate ALL provided URL query parameters (?timeout_ms=..., ?timeout_seconds=..., ?timeout=...)
	var queryDuration time.Duration
	hasQuery := false
	if r != nil && r.URL != nil {
		q := r.URL.Query()
		if rawMs, exists := q["timeout_ms"]; exists && len(rawMs) > 0 {
			trimmed := strings.TrimSpace(rawMs[0])
			if trimmed == "" {
				return 0, fmt.Errorf("timeout_ms query parameter cannot be empty")
			}
			ms, err := strconv.ParseInt(trimmed, 10, 64)
			if err != nil || ms <= 0 {
				return 0, fmt.Errorf("invalid timeout_ms query parameter %q (must be a positive integer)", rawMs[0])
			}
			queryDuration = time.Duration(ms) * time.Millisecond
			hasQuery = true
		}
		if rawSecs, exists := q["timeout_seconds"]; exists && len(rawSecs) > 0 {
			if strings.TrimSpace(rawSecs[0]) == "" {
				return 0, fmt.Errorf("timeout_seconds query parameter cannot be empty")
			}
			d, err := core.ParseTimeoutDuration(rawSecs[0])
			if err != nil {
				return 0, err
			}
			queryDuration = d
			hasQuery = true
		}
		if rawTimeout, exists := q["timeout"]; exists && len(rawTimeout) > 0 {
			if strings.TrimSpace(rawTimeout[0]) == "" {
				return 0, fmt.Errorf("timeout query parameter cannot be empty")
			}
			d, err := core.ParseTimeoutDuration(rawTimeout[0])
			if err != nil {
				return 0, err
			}
			queryDuration = d
			hasQuery = true
		}
	}

	if hasBody && bodyDuration > 0 {
		return bodyDuration, nil
	}
	if hasQuery && queryDuration > 0 {
		return queryDuration, nil
	}
	return 0, nil
}

// ExecuteCommandHandler godoc
// @Summary Execute a predefined command
// @Description Executes a command predefined in the server's configuration, with optional per-call timeout override.
// @Tags commands
// @Accept  json
// @Produce  json
// @Param   command          body   ExecuteCommandRequest  true   "Command to execute (with optional timeout override)"
// @Param   timeout          query  string                 false  "Optional timeout override (e.g., 10s, 500ms, or seconds)"
// @Param   timeout_seconds  query  number                 false  "Optional timeout override in seconds"
// @Param   timeout_ms       query  integer                false  "Optional timeout override in milliseconds"
// @Success 200 {object} ExecuteCommandResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/execute [post]
func (env *APIEnv) ExecuteCommandHandler(w http.ResponseWriter, r *http.Request) {
	var req ExecuteCommandRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			queryName := ""
			if r.URL != nil {
				queryName = strings.TrimSpace(r.URL.Query().Get("name"))
			}
			if errors.Is(err, io.EOF) && queryName != "" {
				req.Name = queryName
			} else {
				targetAction := "unknown"
				if queryName != "" {
					targetAction = queryName
				}
				recordActionCall(targetAction, "error", false, 0)
				writeJSONError(w, "Invalid request body", http.StatusBadRequest)
				return
			}
		}
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" && r.URL != nil {
		req.Name = strings.TrimSpace(r.URL.Query().Get("name"))
	}
	if req.Name == "" {
		recordActionCall("unknown", "error", false, 0)
		writeJSONError(w, "Command name is required", http.StatusBadRequest)
		return
	}

	if !env.Config.Executor.Enabled {
		recordActionCall(req.Name, "error", false, 0)
		writeJSONError(w, "Command executor is disabled", http.StatusNotFound)
		return
	}

	timeoutOverride, err := extractTimeoutOverride(r, req)
	if err != nil {
		recordActionCall(req.Name, "error", false, 0)
		writeJSONError(w, fmt.Sprintf("Invalid timeout parameter: %v", err), http.StatusBadRequest)
		return
	}

	if env.Config.Executor.MaxTimeoutSeconds > 0 && timeoutOverride > 0 {
		maxAllowed := time.Duration(env.Config.Executor.MaxTimeoutSeconds) * time.Second
		if timeoutOverride > maxAllowed {
			recordActionCall(req.Name, "error", false, 0)
			writeJSONError(w, fmt.Sprintf("Requested timeout %s exceeds maximum allowed timeout %s", timeoutOverride, maxAllowed), http.StatusBadRequest)
			return
		}
	}

	var cmdDef *core.CommandDefinition
	for _, cmd := range env.Config.Executor.Commands {
		if cmd.Name == req.Name {
			cmdCopy := cmd
			cmdDef = &cmdCopy
			break
		}
	}

	if cmdDef == nil {
		recordActionCall(req.Name, "error", false, 0)
		writeJSONError(w, "Command not found", http.StatusNotFound)
		return
	}

	effectiveTimeout := env.Config.Executor.ResolveTimeout(*cmdDef, timeoutOverride)

	execStart := time.Now()
	output, err := core.ExecuteCommandWithTimeout(*cmdDef, effectiveTimeout)
	execDuration := time.Since(execStart)

	status := "success"
	errMsg := ""
	timedOut := false

	if err != nil {
		errMsg = err.Error()
		timedOut = core.IsCommandTimeout(err)
		if core.IsCommandSystemError(err) {
			status = "error"
			recordActionCall(req.Name, "error", false, execDuration)
		} else {
			status = "failure"
			recordActionCall(req.Name, "failure", timedOut, execDuration)
		}
	} else {
		recordActionCall(req.Name, "ok", false, execDuration)
	}

	if env.DB != nil {
		if _, dbErr := env.DB.RecordAction(req.Name, status, output); dbErr != nil && env.Logger != nil {
			env.Logger.Error(fmt.Sprintf("Failed to record action to database: %v", dbErr))
		}
	}

	if env.AuditLogger != nil {
		auditStatus := "ok"
		if err != nil {
			auditStatus = status
		}
		_, _ = env.AuditLogger.Record(audit.AuditEvent{
			Category:   "command",
			Action:     req.Name,
			ActorType:  "user",
			ActorID:    "api-caller",
			SourceIP:   r.RemoteAddr,
			Status:     auditStatus,
			DurationMs: execDuration.Milliseconds(),
			Summary:    fmt.Sprintf("Executed command %q (status=%s, timeout=%s)", req.Name, auditStatus, effectiveTimeout),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	_ = json.NewEncoder(w).Encode(ExecuteCommandResponse{
		Output:   output,
		Error:    errMsg,
		TimedOut: timedOut,
		Timeout:  effectiveTimeout.String(),
	})
}

func writeJSONError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: msg})
}

// ListFilesHandler godoc
// @Summary List files in the secure directory
// @Description Retrieves a list of files available for download from the configured secure directory.
// @Tags files
// @Produce  json
// @Success 200 {object} FileListResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/files [get]
func (env *APIEnv) ListFilesHandler(w http.ResponseWriter, r *http.Request) {
	if !env.Config.FileServer.Enabled {
		http.Error(w, "File server is disabled", http.StatusNotFound)
		return
	}

	files, err := os.ReadDir(env.Config.FileServer.SecureDir)
	if err != nil {
		http.Error(w, "Could not list files", http.StatusInternalServerError)
		return
	}

	var fileNames []string
	for _, file := range files {
		if !file.IsDir() {
			fileNames = append(fileNames, file.Name())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(FileListResponse{Files: fileNames})
}

// DownloadFileHandler godoc
// @Summary Download a file from the secure directory
// @Description Downloads a specific file from the configured secure directory.
// @Tags files
// @Param   filename  path  string  true  "Filename to download"
// @Success 200 {file} binary
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/files/{filename} [get]
func (env *APIEnv) DownloadFileHandler(w http.ResponseWriter, r *http.Request) {
	if !env.Config.FileServer.Enabled {
		http.Error(w, "File server is disabled", http.StatusNotFound)
		return
	}

	// Extract filename from URL path, e.g., /api/v1/files/myfile.log -> myfile.log
	fileName := strings.TrimPrefix(r.URL.Path, "/api/v1/files/")

	// Security: Prevent directory traversal attacks.
	if strings.Contains(fileName, "..") || strings.Contains(fileName, "/") || strings.Contains(fileName, "\\") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(env.Config.FileServer.SecureDir, fileName)

	// Security: Double-check that the resolved path is still within the secure directory.
	absSecureDir, err := filepath.Abs(env.Config.FileServer.SecureDir)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !strings.HasPrefix(absFilePath, absSecureDir) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Check if file exists
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	http.ServeFile(w, r, filePath)
}

// ListCommandsHandler godoc
// @Summary List available commands
// @Description Retrieves a list of commands that are available to be executed, along with their effective timeouts.
// @Tags commands
// @Produce  json
// @Success 200 {object} core.ExecutorConfig
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/commands [get]
func (env *APIEnv) ListCommandsHandler(w http.ResponseWriter, r *http.Request) {
	if !env.Config.Executor.Enabled {
		http.Error(w, "Command executor is disabled", http.StatusNotFound)
		return
	}

	defaultTimeout := env.Config.Executor.EffectiveDefaultTimeout()

	// To avoid exposing the raw binary/arguments, we only return the metadata and effective timeouts.
	type commandInfo struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		OSFamily    string `json:"os_family,omitempty"`
		Category    string `json:"category,omitempty"`
		Timeout     string `json:"timeout"`
		Preset      bool   `json:"preset,omitempty"`
	}
	var commands []commandInfo
	for _, c := range env.Config.Executor.Commands {
		commands = append(commands, commandInfo{
			Name:        c.Name,
			Description: c.Description,
			OSFamily:    c.OSFamily,
			Category:    c.Category,
			Timeout:     c.EffectiveTimeout(defaultTimeout).String(),
			Preset:      c.Preset,
		})
	}

	response := struct {
		Commands       []commandInfo `json:"commands"`
		DefaultTimeout string        `json:"default_timeout"`
	}{
		Commands:       commands,
		DefaultTimeout: defaultTimeout.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// TLSInfoHandler returns metadata about the server's TLS certificate configuration.
func (env *APIEnv) TLSInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if env.CertManager == nil || !env.Config.Server.TLS.Enabled {
		_ = json.NewEncoder(w).Encode(core.CertificateInfo{Enabled: false})
		return
	}
	_ = json.NewEncoder(w).Encode(env.CertManager.Info())
}

// TLSCertificateHandler downloads the active PEM-encoded public TLS certificate.
func (env *APIEnv) TLSCertificateHandler(w http.ResponseWriter, r *http.Request) {
	if env.CertManager == nil || !env.Config.Server.TLS.Enabled {
		writeJSONError(w, "TLS is disabled", http.StatusNotFound)
		return
	}
	certPEM, err := env.CertManager.CertPEM()
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"server.crt\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(certPEM)
}

// TLSRenewHandler rotates/renews the server's self-signed TLS certificate live.
func (env *APIEnv) TLSRenewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if env.CertManager == nil || !env.Config.Server.TLS.Enabled {
		writeJSONError(w, "TLS is disabled", http.StatusBadRequest)
		return
	}
	info, err := env.CertManager.Rotate()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("Failed to renew TLS certificate: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(info)
}
