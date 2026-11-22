package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/mcp"
)

// MCPHandler handles JSON-RPC 2.0 Model Context Protocol requests on POST /api/v1/mcp
// and returns MCP server metadata on GET /api/v1/mcp.
func (env *APIEnv) MCPHandler(w http.ResponseWriter, r *http.Request) {
	if env.MCPServer == nil {
		writeJSONError(w, "MCP server is not initialized", http.StatusServiceUnavailable)
		return
	}

	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.Authorize(p, "mcp:access", ""); err != nil {
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"protocol_version": mcp.MCPProtocolVersion,
			"tools":            env.MCPServer.Tools(),
			"resources":        env.MCPServer.Resources(),
			"prompts":          env.MCPServer.Prompts(),
		})
		return
	}

	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rpcReq mcp.JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&rpcReq); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &mcp.JSONRPCError{
				Code:    -32700,
				Message: "Parse error: invalid JSON-RPC payload",
			},
		})
		return
	}

	sessionID := strings.TrimSpace(r.Header.Get("X-MCP-Session-ID"))
	if sessionID == "" {
		sessionID = strings.TrimSpace(r.URL.Query().Get("session_id"))
	}
	actor := p.Type + ":" + p.Name
	mcpCtx := withMCPApprovalContext(r.Context(), p, r.RemoteAddr, r.Header.Get("X-Approval-ID"))

	rpcResp := env.MCPServer.HandleJSONRPCWithAuthorizer(mcpCtx, rpcReq, sessionID, actor, func(requiredScope, targetAction string) error {
		return auth.Authorize(p, requiredScope, targetAction)
	})
	if rpcResp.TraceID != "" {
		w.Header().Set("X-MCP-Trace-ID", rpcResp.TraceID)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rpcResp)
}

// MCPToolsHandler returns the catalog of MCP tools, resources, and prompts.
func (env *APIEnv) MCPToolsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if env.MCPServer == nil {
		writeJSONError(w, "MCP server is not initialized", http.StatusServiceUnavailable)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.Authorize(p, "mcp:access", ""); err != nil {
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tools":     env.MCPServer.Tools(),
		"resources": env.MCPServer.Resources(),
		"prompts":   env.MCPServer.Prompts(),
	})
}

// MCPTracesHandler lists or clears retained MCP interaction traces.
func (env *APIEnv) MCPTracesHandler(w http.ResponseWriter, r *http.Request) {
	if env.MCPServer == nil {
		writeJSONError(w, "MCP server is not initialized", http.StatusServiceUnavailable)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if err := auth.Authorize(p, "mcp:access", ""); err != nil {
			writeJSONError(w, err.Error(), http.StatusForbidden)
			return
		}
		limit := 100
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				limit = n
			}
		}
		traces := env.MCPServer.ListTraces(mcp.TraceFilter{
			Method:    r.URL.Query().Get("method"),
			ToolName:  r.URL.Query().Get("tool_name"),
			SessionID: r.URL.Query().Get("session_id"),
			Status:    r.URL.Query().Get("status"),
			Limit:     limit,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Count  int            `json:"count"`
			Traces []mcp.MCPTrace `json:"traces"`
		}{
			Count:  len(traces),
			Traces: traces,
		})

	case http.MethodDelete:
		if p == nil || p.Type == "anonymous" || p.Role != auth.RoleAdmin {
			writeJSONError(w, "Admin role required to clear traces", http.StatusForbidden)
			return
		}
		cleared := env.MCPServer.ClearTraces()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"cleared": cleared})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// MCPTracesVerifyHandler verifies the cryptographic SHA-256 hash chain across all retained MCP traces.
func (env *APIEnv) MCPTracesVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if env.MCPServer == nil {
		writeJSONError(w, "MCP server is not initialized", http.StatusServiceUnavailable)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.Authorize(p, "mcp:access", ""); err != nil {
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	ver := env.MCPServer.VerifyTraceChain()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ver)
}

// MCPTraceByIDHandler dispatches GET /api/v1/mcp/traces/verify, GET /api/v1/mcp/traces/{trace_id}/verify,
// POST /api/v1/mcp/traces/{trace_id}/replay, and GET /api/v1/mcp/traces/{trace_id}.
func (env *APIEnv) MCPTraceByIDHandler(w http.ResponseWriter, r *http.Request) {
	if env.MCPServer == nil {
		writeJSONError(w, "MCP server is not initialized", http.StatusServiceUnavailable)
		return
	}

	trimmed := strings.TrimSuffix(r.URL.Path, "/")
	if trimmed == "/api/v1/mcp/traces" {
		env.MCPTracesHandler(w, r)
		return
	}
	if trimmed == "/api/v1/mcp/traces/verify" {
		env.MCPTracesVerifyHandler(w, r)
		return
	}

	sub := strings.TrimPrefix(trimmed, "/api/v1/mcp/traces/")
	parts := strings.Split(sub, "/")
	traceID := strings.TrimSpace(parts[0])
	if traceID == "" {
		env.MCPTracesHandler(w, r)
		return
	}

	if len(parts) == 2 && parts[1] == "replay" {
		env.handleMCPTraceReplay(w, r, traceID)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.Authorize(p, "mcp:access", ""); err != nil {
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	if len(parts) == 2 && parts[1] == "verify" {
		res, verifyErr := env.MCPServer.VerifyTraceIntegrity(traceID)
		if verifyErr != nil {
			if errors.Is(verifyErr, mcp.ErrTraceNotFound) {
				writeJSONError(w, verifyErr.Error(), http.StatusNotFound)
				return
			}
			writeJSONError(w, verifyErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
		return
	}

	if len(parts) != 1 {
		writeJSONError(w, "Unknown MCP trace subroute", http.StatusNotFound)
		return
	}

	tr, err := env.MCPServer.GetTrace(traceID)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tr)
}

func (env *APIEnv) handleMCPTraceReplay(w http.ResponseWriter, r *http.Request, traceID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.Authorize(p, "mcp:access", ""); err != nil {
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return
	}

	var body struct {
		Mode       string `json:"mode,omitempty"`
		ApprovalID string `json:"approval_id,omitempty"`
		SessionID  string `json:"session_id,omitempty"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
	}

	mode, err := mcp.ParseReplayMode(body.Mode)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if mode == mcp.ReplayModeLive {
		if p == nil || p.Type == "anonymous" || p.Role != auth.RoleAdmin {
			if env.AuditLogger != nil {
				_, _ = env.AuditLogger.Record(audit.AuditEvent{
					TraceID:   traceID,
					Category:  "mcp",
					Action:    "mcp.trace_replay",
					ActorType: p.Type,
					ActorID:   principalActorID(p),
					SourceIP:  r.RemoteAddr,
					Status:    "denied",
					Summary:   fmt.Sprintf("Denied live MCP trace replay of %s for %s: admin role required", traceID, principalActorID(p)),
				})
			}
			writeJSONError(w, "Authenticated admin role required for live MCP trace replay", http.StatusForbidden)
			return
		}
	}

	approvalID := extractApprovalID(r, body.ApprovalID)
	replayCtx := withMCPApprovalContext(r.Context(), p, r.RemoteAddr, approvalID)
	actor := p.Type + ":" + principalActorID(p)

	report, replayErr := env.MCPServer.ReplayTrace(replayCtx, traceID, mcp.ReplayOptions{
		Mode:       mode,
		Actor:      actor,
		SessionID:  body.SessionID,
		ApprovalID: approvalID,
	}, func(requiredScope, targetAction string) error {
		return auth.Authorize(p, requiredScope, targetAction)
	})
	if replayErr != nil {
		if errors.Is(replayErr, mcp.ErrTraceNotFound) {
			writeJSONError(w, replayErr.Error(), http.StatusNotFound)
			return
		}
		if errors.Is(replayErr, mcp.ErrIntegrityFailed) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(report)
			return
		}
		if errors.Is(replayErr, mcp.ErrInvalidReplayMode) {
			writeJSONError(w, replayErr.Error(), http.StatusBadRequest)
			return
		}
		writeJSONError(w, replayErr.Error(), http.StatusInternalServerError)
		return
	}

	if report.ReplayTraceID != "" {
		w.Header().Set("X-MCP-Trace-ID", report.ReplayTraceID)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}
