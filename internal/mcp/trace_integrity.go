package mcp

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go-admin-tool/internal/audit"
)

// MCPTraceGenesisHash anchors the first MCPTrace in the SHA-256 hash chain.
const MCPTraceGenesisHash = "MCP_TRACE_GENESIS_0000000000000000000000000000000000000000000000"

// ErrTraceNotFound is returned when a requested MCP trace ID does not exist.
var ErrTraceNotFound = errors.New("MCP trace not found")

// TraceChainVerificationResult reports the integrity of the entire retained MCP trace chain.
type TraceChainVerificationResult struct {
	Valid           bool   `json:"valid"`
	TotalTraces     int    `json:"total_traces"`
	LastTraceHash   string `json:"last_trace_hash"`
	BrokenAtTraceID string `json:"broken_at_trace_id,omitempty"`
	Reason          string `json:"reason,omitempty"`
	AuditChainValid bool   `json:"audit_chain_valid"`
}

// TraceIntegrityResult reports cryptographic verification of a single MCP trace and its linked audit event.
type TraceIntegrityResult struct {
	TraceID             string `json:"trace_id"`
	Valid               bool   `json:"valid"`
	RequestDigestValid  bool   `json:"request_digest_valid"`
	ResponseDigestValid bool   `json:"response_digest_valid"`
	TraceHashValid      bool   `json:"trace_hash_valid"`
	ChainLinkValid      bool   `json:"chain_link_valid"`
	AuditLinkValid      bool   `json:"audit_link_valid"`
	AuditChainValid     bool   `json:"audit_chain_valid"`
	AuditEventID        string `json:"audit_event_id,omitempty"`
	AuditEntryHash      string `json:"audit_entry_hash,omitempty"`
	TraceHash           string `json:"trace_hash,omitempty"`
	Reason              string `json:"reason,omitempty"`
}

// CanonicalJSONSHA256 computes a deterministic lowercase SHA-256 hex digest over
// canonical sorted-key JSON encoding of v (independent of Go struct field declaration order).
func CanonicalJSONSHA256(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON payload: %w", err)
	}
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return "", fmt.Errorf("failed to canonicalize JSON payload: %w", err)
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("failed to re-marshal canonical JSON payload: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// ComputeTraceHash computes the chained SHA-256 digest for an MCPTrace record.
func ComputeTraceHash(tr MCPTrace) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%t|%d|%s|%s|%s|%s|%s",
		tr.TraceID,
		tr.SessionID,
		tr.Timestamp.UTC().Format(time.RFC3339Nano),
		tr.Method,
		tr.ToolName,
		tr.Actor,
		tr.Status,
		tr.IsError,
		tr.DurationMs,
		tr.RequestSHA256,
		tr.ResponseSHA256,
		tr.AuditEventID,
		tr.AuditEntryHash,
		tr.PrevTraceHash,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func constantTimeHexEqual(a, b string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// VerifyTraceChain validates request/response digests, per-trace hashes, and prev_trace_hash linkage
// across all retained MCP traces, alongside the underlying SHA-256 audit chain.
func (s *Server) VerifyTraceChain() TraceChainVerificationResult {
	auditValid := true
	if s != nil && s.auditLogger != nil {
		auditValid = s.auditLogger.VerifyChain().Valid
	}
	if s == nil {
		return TraceChainVerificationResult{
			Valid:           true,
			TotalTraces:     0,
			LastTraceHash:   MCPTraceGenesisHash,
			AuditChainValid: auditValid,
		}
	}

	s.mu.RLock()
	traces := make([]MCPTrace, len(s.traces))
	copy(traces, s.traces)
	firstIsGenesis := s.firstTraceIsGenesis
	lastHash := s.lastTraceHash
	s.mu.RUnlock()

	if len(traces) == 0 {
		return TraceChainVerificationResult{
			Valid:           auditValid,
			TotalTraces:     0,
			LastTraceHash:   lastHash,
			AuditChainValid: auditValid,
			Reason:          auditInvalidReason(auditValid),
		}
	}

	for i, tr := range traces {
		reqDigest, err := CanonicalJSONSHA256(tr.RequestPayload)
		if err != nil || !constantTimeHexEqual(reqDigest, tr.RequestSHA256) {
			return TraceChainVerificationResult{
				Valid:           false,
				TotalTraces:     len(traces),
				LastTraceHash:   lastHash,
				BrokenAtTraceID: tr.TraceID,
				Reason:          fmt.Sprintf("request_sha256 mismatch at trace %s", tr.TraceID),
				AuditChainValid: auditValid,
			}
		}
		respDigest, err := CanonicalJSONSHA256(tr.ResponsePayload)
		if err != nil || !constantTimeHexEqual(respDigest, tr.ResponseSHA256) {
			return TraceChainVerificationResult{
				Valid:           false,
				TotalTraces:     len(traces),
				LastTraceHash:   lastHash,
				BrokenAtTraceID: tr.TraceID,
				Reason:          fmt.Sprintf("response_sha256 mismatch at trace %s", tr.TraceID),
				AuditChainValid: auditValid,
			}
		}
		expectedHash := ComputeTraceHash(tr)
		if !constantTimeHexEqual(expectedHash, tr.TraceHash) {
			return TraceChainVerificationResult{
				Valid:           false,
				TotalTraces:     len(traces),
				LastTraceHash:   lastHash,
				BrokenAtTraceID: tr.TraceID,
				Reason:          fmt.Sprintf("trace_hash mismatch at trace %s", tr.TraceID),
				AuditChainValid: auditValid,
			}
		}
		if i == 0 && firstIsGenesis && tr.PrevTraceHash != MCPTraceGenesisHash {
			return TraceChainVerificationResult{
				Valid:           false,
				TotalTraces:     len(traces),
				LastTraceHash:   lastHash,
				BrokenAtTraceID: tr.TraceID,
				Reason:          fmt.Sprintf("genesis prev_trace_hash mismatch at trace %s", tr.TraceID),
				AuditChainValid: auditValid,
			}
		}
		if i > 0 && !constantTimeHexEqual(tr.PrevTraceHash, traces[i-1].TraceHash) {
			return TraceChainVerificationResult{
				Valid:           false,
				TotalTraces:     len(traces),
				LastTraceHash:   lastHash,
				BrokenAtTraceID: tr.TraceID,
				Reason:          fmt.Sprintf("broken chain link between %s and %s", traces[i-1].TraceID, tr.TraceID),
				AuditChainValid: auditValid,
			}
		}
	}

	if !auditValid {
		return TraceChainVerificationResult{
			Valid:           false,
			TotalTraces:     len(traces),
			LastTraceHash:   lastHash,
			AuditChainValid: false,
			Reason:          "underlying SHA-256 audit chain verification failed",
		}
	}

	return TraceChainVerificationResult{
		Valid:           true,
		TotalTraces:     len(traces),
		LastTraceHash:   lastHash,
		AuditChainValid: true,
	}
}

func auditInvalidReason(valid bool) string {
	if valid {
		return ""
	}
	return "underlying SHA-256 audit chain verification failed"
}

// VerifyTraceIntegrity cryptographically verifies a single retained MCP trace, its chain predecessor,
// and its cross-linked SHA-256 audit event.
func (s *Server) VerifyTraceIntegrity(traceID string) (TraceIntegrityResult, error) {
	if s == nil {
		return TraceIntegrityResult{}, ErrTraceNotFound
	}
	targetID := strings.TrimSpace(traceID)
	if targetID == "" {
		return TraceIntegrityResult{}, ErrTraceNotFound
	}

	s.mu.RLock()
	idx := -1
	for i := len(s.traces) - 1; i >= 0; i-- {
		if s.traces[i].TraceID == targetID {
			idx = i
			break
		}
	}
	if idx == -1 {
		s.mu.RUnlock()
		return TraceIntegrityResult{}, ErrTraceNotFound
	}
	tr := s.traces[idx]
	var prevHash string
	hasPrev := idx > 0
	if hasPrev {
		prevHash = s.traces[idx-1].TraceHash
	}
	firstIsGenesis := s.firstTraceIsGenesis
	s.mu.RUnlock()

	res := TraceIntegrityResult{
		TraceID:        tr.TraceID,
		AuditEventID:   tr.AuditEventID,
		AuditEntryHash: tr.AuditEntryHash,
		TraceHash:      tr.TraceHash,
	}

	var reasons []string

	reqDigest, err := CanonicalJSONSHA256(tr.RequestPayload)
	res.RequestDigestValid = err == nil && constantTimeHexEqual(reqDigest, tr.RequestSHA256)
	if !res.RequestDigestValid {
		reasons = append(reasons, "request_sha256 mismatch")
	}

	respDigest, err := CanonicalJSONSHA256(tr.ResponsePayload)
	res.ResponseDigestValid = err == nil && constantTimeHexEqual(respDigest, tr.ResponseSHA256)
	if !res.ResponseDigestValid {
		reasons = append(reasons, "response_sha256 mismatch")
	}

	expectedTraceHash := ComputeTraceHash(tr)
	res.TraceHashValid = constantTimeHexEqual(expectedTraceHash, tr.TraceHash)
	if !res.TraceHashValid {
		reasons = append(reasons, "trace_hash mismatch")
	}

	if hasPrev {
		res.ChainLinkValid = constantTimeHexEqual(tr.PrevTraceHash, prevHash)
	} else if firstIsGenesis {
		res.ChainLinkValid = tr.PrevTraceHash == MCPTraceGenesisHash
	} else {
		res.ChainLinkValid = len(tr.PrevTraceHash) == 64
	}
	if !res.ChainLinkValid {
		reasons = append(reasons, "prev_trace_hash chain link invalid")
	}

	if s.auditLogger == nil {
		res.AuditChainValid = true
		res.AuditLinkValid = tr.AuditEventID == "" && tr.AuditEntryHash == ""
		if !res.AuditLinkValid {
			reasons = append(reasons, "audit logger unavailable to verify audit cross-link")
		}
	} else {
		auditVer := s.auditLogger.VerifyChain()
		res.AuditChainValid = auditVer.Valid
		if !res.AuditChainValid {
			reasons = append(reasons, "audit chain invalid: "+auditVer.Reason)
		}
		if tr.AuditEventID != "" && tr.AuditEntryHash != "" {
			events := s.auditLogger.Query(audit.AuditFilter{TraceID: tr.TraceID, Limit: 20})
			for _, ev := range events {
				if ev.EventID == tr.AuditEventID && constantTimeHexEqual(ev.EntryHash, tr.AuditEntryHash) {
					res.AuditLinkValid = true
					break
				}
			}
		}
		if !res.AuditLinkValid {
			reasons = append(reasons, "matching audit event or audit_entry_hash not found")
		}
	}

	res.Valid = res.RequestDigestValid &&
		res.ResponseDigestValid &&
		res.TraceHashValid &&
		res.ChainLinkValid &&
		res.AuditLinkValid &&
		res.AuditChainValid
	if len(reasons) > 0 {
		res.Reason = strings.Join(reasons, "; ")
	}
	return res, nil
}
