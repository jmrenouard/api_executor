package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go-admin-tool/internal/audit"
)

// ReplayMode controls whether trace replay runs read-only verification or live execution.
type ReplayMode string

const (
	ReplayModeDryRun ReplayMode = "dry_run"
	ReplayModeLive   ReplayMode = "live"
)

var (
	ErrInvalidReplayMode = errors.New("invalid replay mode (expected 'dry_run' or 'live')")
	ErrIntegrityFailed   = errors.New("trace cryptographic integrity verification failed")
)

// ReplayOptions configures a deterministic MCP trace replay operation.
type ReplayOptions struct {
	Mode       ReplayMode `json:"mode,omitempty"`
	Actor      string     `json:"actor,omitempty"`
	SessionID  string     `json:"session_id,omitempty"`
	ApprovalID string     `json:"approval_id,omitempty"`
}

// ReplayReport captures cryptographic integrity checks, live replay lineage, and deterministic output comparison.
type ReplayReport struct {
	OriginalTraceID        string     `json:"original_trace_id"`
	ReplayTraceID          string     `json:"replay_trace_id,omitempty"`
	Mode                   ReplayMode `json:"mode"`
	Method                 string     `json:"method"`
	ToolName               string     `json:"tool_name,omitempty"`
	IntegrityValid         bool       `json:"integrity_valid"`
	AuditChainValid        bool       `json:"audit_chain_valid"`
	PolicyEligible         bool       `json:"policy_eligible"`
	OriginalStatus         string     `json:"original_status"`
	ReplayedStatus         string     `json:"replayed_status,omitempty"`
	OriginalResponseSHA256 string     `json:"original_response_sha256,omitempty"`
	ReplayedResponseSHA256 string     `json:"replayed_response_sha256,omitempty"`
	StatusMatch            bool       `json:"status_match"`
	DeterministicMatch     bool       `json:"deterministic_match"`
	Divergences            []string   `json:"divergences,omitempty"`
}

// ParseReplayMode normalizes a replay mode string, defaulting empty input to dry_run.
func ParseReplayMode(raw string) (ReplayMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(ReplayModeDryRun):
		return ReplayModeDryRun, nil
	case string(ReplayModeLive):
		return ReplayModeLive, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidReplayMode, raw)
	}
}

func stripEphemeralTraceIDs(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, val := range typed {
			if k == "traceId" || k == "trace_id" {
				continue
			}
			out[k] = stripEphemeralTraceIDs(val)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = stripEphemeralTraceIDs(item)
		}
		return out
	default:
		return v
	}
}

// canonicalReplayResponseSHA256 computes a deterministic SHA-256 digest over a response payload
// after removing ephemeral traceId/trace_id fields so live replays can verify semantic determinism.
func canonicalReplayResponseSHA256(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return "", err
	}
	cleaned := stripEphemeralTraceIDs(normalized)
	return CanonicalJSONSHA256(cleaned)
}

func reconstructReplayParams(tr MCPTrace, approvalID string) (json.RawMessage, error) {
	if tr.RequestPayload == nil {
		return nil, nil
	}
	raw, err := json.Marshal(tr.RequestPayload)
	if err != nil {
		return nil, err
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil, err
	}
	if tr.Method == "tools/call" {
		if args, ok := cloned["arguments"].(map[string]any); ok {
			delete(args, "_approval_id")
			if strings.TrimSpace(approvalID) != "" {
				args["_approval_id"] = strings.TrimSpace(approvalID)
			}
		} else if strings.TrimSpace(approvalID) != "" {
			cloned["arguments"] = map[string]any{"_approval_id": strings.TrimSpace(approvalID)}
		}
	}
	return json.Marshal(cloned)
}

func checkDryRunEligibility(tr MCPTrace, authorizer ToolAuthorizer) error {
	if authorizer == nil || tr.Method != "tools/call" {
		return nil
	}
	var args map[string]any
	if tr.RequestPayload != nil {
		if m, ok := tr.RequestPayload["arguments"].(map[string]any); ok {
			args = m
		}
	}
	switch tr.ToolName {
	case "execute_command":
		cmdName := ""
		if args != nil {
			if v, ok := args["name"]; ok && v != nil {
				cmdName = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
		return authorizer("commands:execute", cmdName)
	case "execute_plugin":
		pluginID, action := "", ""
		if args != nil {
			if v, ok := args["plugin_id"]; ok && v != nil {
				pluginID = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
			if v, ok := args["action"]; ok && v != nil {
				action = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
		metricLabel := fmt.Sprintf("plugin:%s:%s", pluginID, action)
		if err := authorizer("plugins:execute", metricLabel); err != nil {
			if authorizer("plugins:execute", pluginID) != nil && authorizer("plugins:execute", action) != nil {
				return err
			}
		}
		return nil
	case "db_query":
		if err := authorizer("plugins:execute", "db-exposure"); err != nil && authorizer("plugins:execute", "plugin:db-exposure:query_readonly") != nil {
			return err
		}
		return nil
	case "db_list_tables":
		if err := authorizer("plugins:read", "db-exposure"); err != nil && authorizer("plugins:execute", "db-exposure") != nil {
			return err
		}
		return nil
	default:
		return nil
	}
}

// ReplayTrace verifies cryptographic integrity of a historical MCP trace and either performs
// a zero-side-effect dry_run check (default) or executes a live replay with append-only lineage.
func (s *Server) ReplayTrace(ctx context.Context, traceID string, opts ReplayOptions, authorizer ToolAuthorizer) (ReplayReport, error) {
	if s == nil {
		return ReplayReport{}, ErrTraceNotFound
	}
	mode, err := ParseReplayMode(string(opts.Mode))
	if err != nil {
		return ReplayReport{}, err
	}

	orig, err := s.GetTrace(traceID)
	if err != nil {
		return ReplayReport{}, err
	}

	ver, err := s.VerifyTraceIntegrity(orig.TraceID)
	if err != nil {
		return ReplayReport{}, err
	}

	report := ReplayReport{
		OriginalTraceID:        orig.TraceID,
		Mode:                   mode,
		Method:                 orig.Method,
		ToolName:               orig.ToolName,
		IntegrityValid:         ver.Valid,
		AuditChainValid:        ver.AuditChainValid,
		OriginalStatus:         orig.Status,
		OriginalResponseSHA256: orig.ResponseSHA256,
	}

	actor := strings.TrimSpace(opts.Actor)
	if actor == "" {
		actor = "replay_operator"
	}

	// Fail closed immediately if cryptographic integrity of the retained trace or audit chain is compromised.
	if !ver.Valid {
		report.Divergences = append(report.Divergences, "integrity_failed: "+ver.Reason)
		if s.auditLogger != nil {
			_, _ = s.auditLogger.Record(audit.AuditEvent{
				TraceID:   orig.TraceID,
				Category:  "mcp",
				Action:    "mcp.trace_replay",
				ActorType: "mcp_client",
				ActorID:   actor,
				Status:    "denied",
				Summary:   fmt.Sprintf("Aborted MCP trace replay (%s) for %s: integrity check failed (%s)", mode, orig.TraceID, ver.Reason),
				Metadata: map[string]any{
					"parent_trace_id": orig.TraceID,
					"mode":            string(mode),
					"reason":          ver.Reason,
				},
			})
		}
		return report, fmt.Errorf("%w: %s", ErrIntegrityFailed, ver.Reason)
	}

	paramsRaw, err := reconstructReplayParams(orig, opts.ApprovalID)
	if err != nil {
		report.Divergences = append(report.Divergences, fmt.Sprintf("request_reconstruction_failed: %v", err))
		return report, err
	}

	eligErr := checkDryRunEligibility(orig, authorizer)
	report.PolicyEligible = eligErr == nil
	if eligErr != nil {
		report.Divergences = append(report.Divergences, fmt.Sprintf("policy_ineligible: %v", eligErr))
	}

	if mode == ReplayModeDryRun {
		report.StatusMatch = true
		report.DeterministicMatch = report.IntegrityValid && report.AuditChainValid && report.PolicyEligible
		if s.auditLogger != nil {
			_, _ = s.auditLogger.Record(audit.AuditEvent{
				TraceID:   orig.TraceID,
				Category:  "mcp",
				Action:    "mcp.trace_replay",
				ActorType: "mcp_client",
				ActorID:   actor,
				Status:    "ok",
				Summary:   fmt.Sprintf("Dry-run verified MCP trace %s (integrity=%t, eligible=%t)", orig.TraceID, report.IntegrityValid, report.PolicyEligible),
				Metadata: map[string]any{
					"parent_trace_id": orig.TraceID,
					"mode":            string(mode),
					"policy_eligible": report.PolicyEligible,
				},
			})
		}
		return report, nil
	}

	// Live replay: preserve original trace verbatim and append a linked child trace.
	sessionID := strings.TrimSpace(opts.SessionID)
	if sessionID == "" {
		sessionID = "replay:" + orig.TraceID
	}
	rpcReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      "replay_" + orig.TraceID,
		Method:  orig.Method,
		Params:  paramsRaw,
	}

	replayResp := s.handleJSONRPCInternal(ctx, rpcReq, sessionID, actor, orig.TraceID, authorizer)
	report.ReplayTraceID = replayResp.TraceID

	var replayPayload any = replayResp.Result
	if replayResp.Error != nil {
		replayPayload = replayResp.Error
	}

	if replayTrace, getErr := s.GetTrace(replayResp.TraceID); getErr == nil {
		report.ReplayedStatus = replayTrace.Status
		report.ReplayedResponseSHA256 = replayTrace.ResponseSHA256
	} else {
		if replayResp.Error != nil {
			report.ReplayedStatus = "error"
		} else {
			report.ReplayedStatus = "ok"
		}
		if d, dErr := CanonicalJSONSHA256(replayPayload); dErr == nil {
			report.ReplayedResponseSHA256 = d
		}
	}

	report.StatusMatch = report.ReplayedStatus == orig.Status
	if !report.StatusMatch {
		report.Divergences = append(report.Divergences,
			fmt.Sprintf("status_mismatch: original=%q replayed=%q", orig.Status, report.ReplayedStatus))
	}

	origNormHash, errOrig := canonicalReplayResponseSHA256(orig.ResponsePayload)
	replayNormHash, errReplay := canonicalReplayResponseSHA256(replayPayload)
	payloadMatch := errOrig == nil && errReplay == nil && constantTimeHexEqual(origNormHash, replayNormHash)
	if !payloadMatch {
		report.Divergences = append(report.Divergences,
			fmt.Sprintf("response_digest_mismatch: original=%s replayed=%s", origNormHash, replayNormHash))
	}
	report.DeterministicMatch = report.StatusMatch && payloadMatch

	if s.auditLogger != nil {
		_, _ = s.auditLogger.Record(audit.AuditEvent{
			TraceID:   report.ReplayTraceID,
			Category:  "mcp",
			Action:    "mcp.trace_replay",
			ActorType: "mcp_client",
			ActorID:   actor,
			Status:    "ok",
			Summary:   fmt.Sprintf("Live replayed MCP trace %s -> %s (status_match=%t, deterministic_match=%t)", orig.TraceID, report.ReplayTraceID, report.StatusMatch, report.DeterministicMatch),
			Metadata: map[string]any{
				"parent_trace_id":     orig.TraceID,
				"replay_trace_id":     report.ReplayTraceID,
				"mode":                string(mode),
				"status_match":        report.StatusMatch,
				"deterministic_match": report.DeterministicMatch,
			},
		})
	}

	return report, nil
}
