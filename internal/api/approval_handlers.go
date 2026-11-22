package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go-admin-tool/internal/approval"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/gatekeeper"
	"go-admin-tool/internal/mcp"
)

// ApprovalChallengeResponse is returned (HTTP 202 Accepted) when a critical operation
// pauses for Human-in-the-Loop approval before execution.
type ApprovalChallengeResponse struct {
	Status             string    `json:"status"`
	ApprovalID         string    `json:"approval_id"`
	ExpiresAt          time.Time `json:"expires_at"`
	PayloadSHA256      string    `json:"payload_sha256"`
	Message            string    `json:"message"`
	ApproveURL         string    `json:"approve_url"`
	RejectURL          string    `json:"reject_url"`
	GatekeeperDecision string    `json:"gatekeeper_decision,omitempty"`
	RiskScore          float64   `json:"risk_score,omitempty"`
}

type mcpApprovalCtxKey struct{}

type mcpApprovalCtxData struct {
	Principal  *auth.Principal
	SourceIP   string
	ApprovalID string
}

func withMCPApprovalContext(ctx context.Context, p *auth.Principal, sourceIP, approvalID string) context.Context {
	return context.WithValue(ctx, mcpApprovalCtxKey{}, mcpApprovalCtxData{
		Principal:  p,
		SourceIP:   sourceIP,
		ApprovalID: strings.TrimSpace(approvalID),
	})
}

func extractApprovalID(r *http.Request, bodyApprovalID string) string {
	if id := strings.TrimSpace(bodyApprovalID); id != "" {
		return id
	}
	if r != nil {
		if id := strings.TrimSpace(r.Header.Get("X-Approval-ID")); id != "" {
			return id
		}
	}
	return ""
}

func cloneApprovalParamsWithTimeout(params map[string]any, timeoutOverride time.Duration) map[string]any {
	if len(params) == 0 && timeoutOverride <= 0 {
		return nil
	}
	out := make(map[string]any, len(params)+1)
	for k, v := range params {
		out[k] = v
	}
	if timeoutOverride > 0 {
		out["_timeout"] = timeoutOverride.String()
	}
	return out
}

func (env *APIEnv) hasActiveGatekeeper() bool {
	return env != nil && env.Gatekeeper != nil && env.Gatekeeper.Mode() != "noop"
}

func (env *APIEnv) recordGatekeeperAudit(channel, targetAction, actorType, actorID, sourceIP string, resp gatekeeper.EvalResponse) {
	if env == nil || env.AuditLogger == nil {
		return
	}
	auditStatus := "ok"
	if resp.Decision == gatekeeper.DecisionDeny {
		auditStatus = "denied"
	}
	_, _ = env.AuditLogger.Record(audit.AuditEvent{
		Category:   "gatekeeper",
		Action:     "gatekeeper." + string(resp.Decision),
		ActorType:  actorType,
		ActorID:    actorID,
		SourceIP:   sourceIP,
		Status:     auditStatus,
		DurationMs: int64(resp.LatencyMs),
		Summary:    fmt.Sprintf("System-1 gatekeeper %s on %s:%s (risk=%.3f, conf=%.3f) — %s", resp.Decision, channel, targetAction, resp.RiskScore, resp.Confidence, resp.Reason),
		Metadata: map[string]any{
			"gatekeeper_decision":   string(resp.Decision),
			"gatekeeper_risk_score": resp.RiskScore,
			"gatekeeper_confidence": resp.Confidence,
			"gatekeeper_latency_ms": resp.LatencyMs,
			"primary_threat":        resp.PrimaryThreat,
			"hijack_suspected":      resp.HijackSuspected,
			"fail_closed":           resp.FailClosed,
			"channel":               channel,
			"target_action":         targetAction,
		},
	})
}

func (env *APIEnv) writeApprovalChallenge(w http.ResponseWriter, req *approval.Request, message, gkDecision string, riskScore float64) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Approval-ID", req.ID)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ApprovalChallengeResponse{
		Status:             "pending_approval",
		ApprovalID:         req.ID,
		ExpiresAt:          req.ExpiresAt,
		PayloadSHA256:      req.PayloadSHA256,
		Message:            message,
		ApproveURL:         fmt.Sprintf("/api/v1/approvals/%s/approve", req.ID),
		RejectURL:          fmt.Sprintf("/api/v1/approvals/%s/reject", req.ID),
		GatekeeperDecision: gkDecision,
		RiskScore:          riskScore,
	})
}

// enforcePreExecutionGates enforces strict zero-trust pre-execution gating AFTER RBAC:
// 1. If a single-use approval_id is supplied, verify canonical payload_sha256 and consume atomically.
// 2. Static HITL policy check (System-1 allow NEVER overrides RequireApproval / critical_* rules).
// 3. System-1 MicroLLM gatekeeper hook (allow proceeds, deny returns 403, x_abstain escalates to HITL or fails closed 403 when HITL is disabled).
func (env *APIEnv) enforcePreExecutionGates(
	w http.ResponseWriter,
	r *http.Request,
	p *auth.Principal,
	target approval.Target,
	commandFlag bool,
	suppliedApprovalID string,
	evalReq gatekeeper.EvalRequest,
) bool {
	if env == nil {
		return true
	}

	actorID := principalActorID(p)
	actorType := "anonymous"
	if p != nil && strings.TrimSpace(p.Type) != "" {
		actorType = p.Type
	}
	sourceIP := ""
	if r != nil {
		sourceIP = r.RemoteAddr
	}

	approvalID := extractApprovalID(r, suppliedApprovalID)
	staticRequired := env.ApprovalStore != nil && env.ApprovalStore.Policy().RequiresApproval(target, commandFlag)
	gkActive := env.hasActiveGatekeeper()

	// Step 1: Consume a pre-approved single-use approval_id if supplied (used for both static HITL and x_abstain escalations).
	if approvalID != "" {
		if env.ApprovalStore == nil {
			writeJSONError(w, "Approval store is not initialized", http.StatusServiceUnavailable)
			return false
		}
		digest, err := approval.ComputePayloadSHA256(target)
		if err != nil {
			writeJSONError(w, fmt.Sprintf("Failed to compute approval payload digest: %v", err), http.StatusBadRequest)
			return false
		}
		if _, consumeErr := env.ApprovalStore.Consume(approvalID, digest, actorID, actorType, sourceIP); consumeErr != nil {
			switch {
			case errors.Is(consumeErr, approval.ErrNotFound):
				writeJSONError(w, consumeErr.Error(), http.StatusNotFound)
			case errors.Is(consumeErr, approval.ErrPayloadMismatch):
				writeJSONError(w, consumeErr.Error(), http.StatusForbidden)
			case errors.Is(consumeErr, approval.ErrAlreadyConsumed),
				errors.Is(consumeErr, approval.ErrExpired),
				errors.Is(consumeErr, approval.ErrInvalidTransition):
				writeJSONError(w, consumeErr.Error(), http.StatusConflict)
			default:
				writeJSONError(w, consumeErr.Error(), http.StatusInternalServerError)
			}
			return false
		}
		return true
	}

	// Step 2: Static HITL policy takes precedence over System-1 (System-1 allow must never bypass static RequireApproval).
	if staticRequired {
		req, createErr := env.ApprovalStore.Create(approval.CreateParams{
			Target:        target,
			RequesterID:   actorID,
			RequesterType: actorType,
			SourceIP:      sourceIP,
			Reason:        fmt.Sprintf("HITL policy requires approval for %s:%s", target.Channel, target.Action),
		})
		if createErr != nil {
			if errors.Is(createErr, approval.ErrMaxPendingReached) {
				writeJSONError(w, createErr.Error(), http.StatusTooManyRequests)
				return false
			}
			writeJSONError(w, fmt.Sprintf("Failed to create approval request: %v", createErr), http.StatusInternalServerError)
			return false
		}
		env.writeApprovalChallenge(w, req, "Human-in-the-Loop approval required before execution", "", 0)
		return false
	}

	// Step 3: System-1 MicroLLM Gatekeeper evaluation.
	if !gkActive {
		return true
	}

	evalStart := time.Now()
	evalResp := env.Gatekeeper.Evaluate(r.Context(), evalReq)
	evalDur := time.Since(evalStart)
	RecordGatekeeperEvaluation(env.Gatekeeper.Mode(), string(target.Channel), string(evalResp.Decision), evalDur)
	env.recordGatekeeperAudit(string(target.Channel), target.Action, actorType, actorID, sourceIP, evalResp)

	switch evalResp.Decision {
	case gatekeeper.DecisionAllow:
		return true
	case gatekeeper.DecisionDeny:
		writeJSONError(w, fmt.Sprintf("Execution denied by System-1 gatekeeper: %s", evalResp.Reason), http.StatusForbidden)
		return false
	default:
		// x_abstain (or any unknown value) escalates to HITL; fails closed 403 if HITL is disabled/unavailable.
		if env.ApprovalStore == nil || !env.ApprovalStore.Policy().Enabled() {
			if env.AuditLogger != nil {
				_, _ = env.AuditLogger.Record(audit.AuditEvent{
					Category:  "gatekeeper",
					Action:    "gatekeeper.abstain_fail_closed",
					ActorType: actorType,
					ActorID:   actorID,
					SourceIP:  sourceIP,
					Status:    "denied",
					Summary:   fmt.Sprintf("Failed closed on System-1 x_abstain for %s:%s because HITL approval is disabled", target.Channel, target.Action),
				})
			}
			writeJSONError(w, fmt.Sprintf("System-1 gatekeeper abstained (%s) and HITL approval escalation is disabled", evalResp.Reason), http.StatusForbidden)
			return false
		}

		req, createErr := env.ApprovalStore.Create(approval.CreateParams{
			Target:        target,
			RequesterID:   actorID,
			RequesterType: actorType,
			SourceIP:      sourceIP,
			Reason:        fmt.Sprintf("System-1 gatekeeper abstained: %s", evalResp.Reason),
			Metadata: map[string]any{
				"gatekeeper_decision":   string(gatekeeper.DecisionAbstain),
				"risk_score":            evalResp.RiskScore,
				"confidence":            evalResp.Confidence,
				"gatekeeper_latency_ms": evalResp.LatencyMs,
				"primary_threat":        evalResp.PrimaryThreat,
				"hijack_suspected":      evalResp.HijackSuspected,
			},
		})
		if createErr != nil {
			if errors.Is(createErr, approval.ErrMaxPendingReached) {
				writeJSONError(w, createErr.Error(), http.StatusTooManyRequests)
				return false
			}
			writeJSONError(w, fmt.Sprintf("Failed to create HITL escalation request: %v", createErr), http.StatusInternalServerError)
			return false
		}
		env.writeApprovalChallenge(w, req, fmt.Sprintf("System-1 gatekeeper abstained (%s); Human-in-the-Loop approval required", evalResp.Reason), string(gatekeeper.DecisionAbstain), evalResp.RiskScore)
		return false
	}
}

func shouldRunSystem1OnMCPTool(toolName string) bool {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "execute_command", "execute_plugin", "db_query":
		return true
	default:
		return false
	}
}

// NewMCPApprovalGate builds a decoupled mcp.ApprovalGate callback combining static HITL policy
// and System-1 MicroLLM evaluation with fail-closed x_abstain -> HITL escalation.
func (env *APIEnv) NewMCPApprovalGate() mcp.ApprovalGate {
	return func(ctx context.Context, req mcp.ApprovalGateRequest) (mcp.ApprovalGateDecision, error) {
		if env == nil {
			return mcp.ApprovalGateDecision{Allowed: true}, nil
		}
		target := approval.Target{
			Channel:    approval.ChannelMCP,
			Action:     req.Action,
			PluginID:   req.PluginID,
			ToolName:   req.ToolName,
			Parameters: req.Parameters,
		}

		actorID := strings.TrimSpace(req.Actor)
		actorType := "mcp_client"
		sourceIP := ""
		approvalID := strings.TrimSpace(req.ApprovalID)

		if ctxData, ok := ctx.Value(mcpApprovalCtxKey{}).(mcpApprovalCtxData); ok {
			if ctxData.Principal != nil {
				actorID = principalActorID(ctxData.Principal)
				if strings.TrimSpace(ctxData.Principal.Type) != "" {
					actorType = ctxData.Principal.Type
				}
			}
			sourceIP = ctxData.SourceIP
			if approvalID == "" {
				approvalID = ctxData.ApprovalID
			}
		}

		// Step 1: Consume pre-approved single-use approval_id if supplied.
		if approvalID != "" {
			if env.ApprovalStore == nil {
				return mcp.ApprovalGateDecision{Allowed: false}, errors.New("approval store is not initialized")
			}
			digest, err := approval.ComputePayloadSHA256(target)
			if err != nil {
				return mcp.ApprovalGateDecision{Allowed: false}, err
			}
			if _, consumeErr := env.ApprovalStore.Consume(approvalID, digest, actorID, actorType, sourceIP); consumeErr != nil {
				return mcp.ApprovalGateDecision{Allowed: false, Reason: consumeErr.Error()}, consumeErr
			}
			return mcp.ApprovalGateDecision{Allowed: true, ApprovalID: approvalID}, nil
		}

		// Step 2: Static HITL policy check (never bypassed by System-1 allow).
		if env.ApprovalStore != nil && env.ApprovalStore.Policy().RequiresApproval(target, req.CommandFlag) {
			created, createErr := env.ApprovalStore.Create(approval.CreateParams{
				Target:        target,
				RequesterID:   actorID,
				RequesterType: actorType,
				SourceIP:      sourceIP,
				Reason:        fmt.Sprintf("HITL policy requires approval for MCP tool %s", req.ToolName),
			})
			if createErr != nil {
				return mcp.ApprovalGateDecision{Allowed: false}, createErr
			}
			return mcp.ApprovalGateDecision{
				Allowed:       false,
				Pending:       true,
				ApprovalID:    created.ID,
				ExpiresAt:     created.ExpiresAt,
				PayloadSHA256: created.PayloadSHA256,
				Reason:        "Human-in-the-Loop approval required before MCP tool execution",
			}, nil
		}

		// Step 3: System-1 MicroLLM Gatekeeper evaluation on execution tools.
		if !env.hasActiveGatekeeper() || !shouldRunSystem1OnMCPTool(req.ToolName) {
			return mcp.ApprovalGateDecision{Allowed: true}, nil
		}

		evalStart := time.Now()
		evalResp := env.Gatekeeper.Evaluate(ctx, gatekeeper.EvalRequest{
			Channel:   string(approval.ChannelMCP),
			ToolName:  req.ToolName,
			Command:   req.CommandLine,
			Arguments: req.Parameters,
			Actor:     actorID,
		})
		evalDur := time.Since(evalStart)
		RecordGatekeeperEvaluation(env.Gatekeeper.Mode(), string(approval.ChannelMCP), string(evalResp.Decision), evalDur)
		env.recordGatekeeperAudit(string(approval.ChannelMCP), req.ToolName+":"+req.Action, actorType, actorID, sourceIP, evalResp)

		switch evalResp.Decision {
		case gatekeeper.DecisionAllow:
			return mcp.ApprovalGateDecision{
				Allowed:             true,
				GatekeeperDecision:  string(evalResp.Decision),
				GatekeeperRiskScore: evalResp.RiskScore,
				GatekeeperLatencyMs: evalResp.LatencyMs,
			}, nil

		case gatekeeper.DecisionDeny:
			return mcp.ApprovalGateDecision{
				Allowed:             false,
				Reason:              fmt.Sprintf("System-1 gatekeeper denied MCP tool %q: %s", req.ToolName, evalResp.Reason),
				GatekeeperDecision:  string(evalResp.Decision),
				GatekeeperRiskScore: evalResp.RiskScore,
				GatekeeperLatencyMs: evalResp.LatencyMs,
			}, nil

		default:
			if env.ApprovalStore == nil || !env.ApprovalStore.Policy().Enabled() {
				if env.AuditLogger != nil {
					_, _ = env.AuditLogger.Record(audit.AuditEvent{
						Category:  "gatekeeper",
						Action:    "gatekeeper.abstain_fail_closed",
						ActorType: actorType,
						ActorID:   actorID,
						SourceIP:  sourceIP,
						Status:    "denied",
						Summary:   fmt.Sprintf("Failed closed on System-1 x_abstain for MCP tool %s because HITL approval is disabled", req.ToolName),
					})
				}
				return mcp.ApprovalGateDecision{
					Allowed:             false,
					Reason:              fmt.Sprintf("System-1 gatekeeper abstained (%s) and HITL approval escalation is disabled", evalResp.Reason),
					GatekeeperDecision:  string(gatekeeper.DecisionAbstain),
					GatekeeperRiskScore: evalResp.RiskScore,
					GatekeeperLatencyMs: evalResp.LatencyMs,
				}, nil
			}

			created, createErr := env.ApprovalStore.Create(approval.CreateParams{
				Target:        target,
				RequesterID:   actorID,
				RequesterType: actorType,
				SourceIP:      sourceIP,
				Reason:        fmt.Sprintf("System-1 gatekeeper abstained on MCP tool %s: %s", req.ToolName, evalResp.Reason),
				Metadata: map[string]any{
					"gatekeeper_decision":   string(gatekeeper.DecisionAbstain),
					"risk_score":            evalResp.RiskScore,
					"confidence":            evalResp.Confidence,
					"gatekeeper_latency_ms": evalResp.LatencyMs,
					"primary_threat":        evalResp.PrimaryThreat,
					"hijack_suspected":      evalResp.HijackSuspected,
				},
			})
			if createErr != nil {
				return mcp.ApprovalGateDecision{
					Allowed:             false,
					GatekeeperDecision:  string(gatekeeper.DecisionAbstain),
					GatekeeperRiskScore: evalResp.RiskScore,
					GatekeeperLatencyMs: evalResp.LatencyMs,
				}, createErr
			}
			return mcp.ApprovalGateDecision{
				Allowed:             false,
				Pending:             true,
				ApprovalID:          created.ID,
				ExpiresAt:           created.ExpiresAt,
				PayloadSHA256:       created.PayloadSHA256,
				Reason:              fmt.Sprintf("System-1 gatekeeper abstained (%s); Human-in-the-Loop approval required", evalResp.Reason),
				GatekeeperDecision:  string(gatekeeper.DecisionAbstain),
				GatekeeperRiskScore: evalResp.RiskScore,
				GatekeeperLatencyMs: evalResp.LatencyMs,
			}, nil
		}
	}
}

// ApprovalListResponse defines the JSON response returned by GET /api/v1/approvals.
type ApprovalListResponse struct {
	Approvals []*approval.Request `json:"approvals"`
	Total     int                 `json:"total"`
	Limit     int                 `json:"limit"`
	Offset    int                 `json:"offset"`
}

func principalActorID(p *auth.Principal) string {
	if p == nil {
		return "anonymous"
	}
	if strings.TrimSpace(p.Username) != "" {
		return strings.TrimSpace(p.Username)
	}
	if strings.TrimSpace(p.Name) != "" {
		return strings.TrimSpace(p.Name)
	}
	return strings.TrimSpace(p.ID)
}

func (env *APIEnv) recordApprovalAuthDenial(action string, p *auth.Principal, sourceIP, target string, reason string) {
	if env.AuditLogger == nil {
		return
	}
	actorType := "anonymous"
	actorID := "anonymous"
	if p != nil {
		actorType = p.Type
		actorID = principalActorID(p)
	}
	_, _ = env.AuditLogger.Record(audit.AuditEvent{
		Category:  "approval",
		Action:    action,
		ActorType: actorType,
		ActorID:   actorID,
		SourceIP:  sourceIP,
		Status:    "denied",
		Summary:   fmt.Sprintf("Denied %s on %q for %s (%s): %s", action, target, actorID, actorType, reason),
	})
}

func (env *APIEnv) requireApprovalReadAuth(w http.ResponseWriter, r *http.Request, action string) (*auth.Principal, bool) {
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return nil, false
	}
	if err := auth.Authorize(p, auth.ScopeApprovalsRead, ""); err != nil {
		env.recordApprovalAuthDenial(action, p, r.RemoteAddr, auth.ScopeApprovalsRead, err.Error())
		writeJSONError(w, err.Error(), http.StatusForbidden)
		return nil, false
	}
	return p, true
}

func (env *APIEnv) requireApprovalDecideAuth(w http.ResponseWriter, r *http.Request, action, approvalID string) (*auth.Principal, bool) {
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return nil, false
	}
	if p == nil || p.Type == "anonymous" || p.Role != auth.RoleAdmin || auth.Authorize(p, auth.ScopeApprovalsDecide, "") != nil {
		env.recordApprovalAuthDenial(action, p, r.RemoteAddr, approvalID, "authenticated admin role required")
		writeJSONError(w, "Authenticated admin role required to decide approval requests", http.StatusForbidden)
		return nil, false
	}
	return p, true
}

// ApprovalsHandler handles GET /api/v1/approvals to list HITL approval requests.
func (env *APIEnv) ApprovalsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if env.ApprovalStore == nil {
		writeJSONError(w, "Approval store is not initialized", http.StatusServiceUnavailable)
		return
	}
	if _, ok := env.requireApprovalReadAuth(w, r, "approval.list"); !ok {
		return
	}

	q := r.URL.Query()
	limit := 50
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			if n > 200 {
				n = 200
			}
			limit = n
		}
	}
	offset := 0
	if raw := strings.TrimSpace(q.Get("offset")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			offset = n
		}
	}

	items, total := env.ApprovalStore.List(approval.Filter{
		Status:      approval.Status(strings.TrimSpace(q.Get("status"))),
		Channel:     approval.Channel(strings.TrimSpace(q.Get("channel"))),
		Action:      strings.TrimSpace(q.Get("action")),
		RequesterID: strings.TrimSpace(q.Get("requester_id")),
		Limit:       limit,
		Offset:      offset,
	})
	if items == nil {
		items = []*approval.Request{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ApprovalListResponse{
		Approvals: items,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
	})
}

// ApprovalSubroutesHandler dispatches GET /api/v1/approvals/{id}, POST /api/v1/approvals/{id}/approve,
// and POST /api/v1/approvals/{id}/reject.
func (env *APIEnv) ApprovalSubroutesHandler(w http.ResponseWriter, r *http.Request) {
	if env.ApprovalStore == nil {
		writeJSONError(w, "Approval store is not initialized", http.StatusServiceUnavailable)
		return
	}

	trimmed := strings.TrimSuffix(r.URL.Path, "/")
	if trimmed == "/api/v1/approvals" {
		env.ApprovalsHandler(w, r)
		return
	}

	sub := strings.TrimPrefix(trimmed, "/api/v1/approvals/")
	parts := strings.Split(sub, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		writeJSONError(w, "Approval ID is required", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(parts[0])

	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := env.requireApprovalReadAuth(w, r, "approval.get"); !ok {
			return
		}
		req, err := env.ApprovalStore.Get(id)
		if err != nil {
			if errors.Is(err, approval.ErrNotFound) {
				writeJSONError(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(req)
		return
	}

	if len(parts) == 2 && (parts[1] == "approve" || parts[1] == "reject") {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		decision := parts[1]
		p, ok := env.requireApprovalDecideAuth(w, r, "approval."+decision, id)
		if !ok {
			return
		}

		var body struct {
			Comment string `json:"comment"`
			Reason  string `json:"reason"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
				writeJSONError(w, "Invalid request body", http.StatusBadRequest)
				return
			}
		}
		comment := strings.TrimSpace(body.Comment)
		if comment == "" {
			comment = strings.TrimSpace(body.Reason)
		}

		var (
			updated *approval.Request
			err     error
		)
		if decision == "approve" {
			updated, err = env.ApprovalStore.Approve(id, principalActorID(p), p.Type, r.RemoteAddr, comment)
		} else {
			updated, err = env.ApprovalStore.Reject(id, principalActorID(p), p.Type, r.RemoteAddr, comment)
		}
		if err != nil {
			switch {
			case errors.Is(err, approval.ErrNotFound):
				writeJSONError(w, err.Error(), http.StatusNotFound)
			case errors.Is(err, approval.ErrSelfApprovalForbidden):
				writeJSONError(w, err.Error(), http.StatusForbidden)
			case errors.Is(err, approval.ErrExpired), errors.Is(err, approval.ErrInvalidTransition):
				writeJSONError(w, err.Error(), http.StatusConflict)
			case errors.Is(err, approval.ErrInvalidRequest):
				writeJSONError(w, err.Error(), http.StatusBadRequest)
			default:
				writeJSONError(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(updated)
		return
	}

	writeJSONError(w, "Unknown approval subroute", http.StatusNotFound)
}
