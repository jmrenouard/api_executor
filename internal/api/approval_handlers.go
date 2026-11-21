package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"go-admin-tool/internal/approval"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
)

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
