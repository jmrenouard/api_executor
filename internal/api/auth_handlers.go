package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
)

// resolvePrincipal extracts and validates the caller's token or service account key if provided.
// If Auth.RequireAuth is true (or if a token is explicitly supplied), invalid credentials return an error.
func (env *APIEnv) resolvePrincipal(r *http.Request) (*auth.Principal, error) {
	rawToken, hasToken := auth.ExtractTokenFromRequest(r)
	if !hasToken {
		if env.Config != nil && env.Config.Auth.Enabled && env.Config.Auth.RequireAuth && env.AuthManager != nil {
			return nil, auth.ErrInvalidToken
		}
		return &auth.Principal{
			Type:   "anonymous",
			ID:     "anonymous",
			Name:   "anonymous",
			Role:   auth.RoleAdmin,
			Scopes: []string{"*"},
		}, nil
	}
	if env.AuthManager == nil {
		return &auth.Principal{
			Type:   "anonymous",
			ID:     "anonymous",
			Name:   "anonymous",
			Role:   auth.RoleAdmin,
			Scopes: []string{"*"},
		}, nil
	}
	return env.AuthManager.AuthenticateCredential(rawToken)
}

// AuthLoginHandler authenticates a user by username and password and issues a 24h session token.
func (env *APIEnv) AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if env.AuthManager == nil {
		writeJSONError(w, "Authentication manager is not initialized", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, tok, rawSecret, err := env.AuthManager.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		if env.AuditLogger != nil {
			_, _ = env.AuditLogger.Record(audit.AuditEvent{
				Category:  "auth",
				Action:    "login",
				ActorType: "user",
				ActorID:   req.Username,
				SourceIP:  r.RemoteAddr,
				Status:    "denied",
				Summary:   fmt.Sprintf("Failed login attempt for user %q: %v", req.Username, err),
			})
		}
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if env.AuditLogger != nil {
		_, _ = env.AuditLogger.Record(audit.AuditEvent{
			Category:  "auth",
			Action:    "login",
			ActorType: "user",
			ActorID:   user.Username,
			SourceIP:  r.RemoteAddr,
			Status:    "ok",
			Summary:   fmt.Sprintf("User %q logged in (role=%s)", user.Username, user.Role),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		User      auth.User     `json:"user"`
		Token     auth.APIToken `json:"token_info"`
		RawSecret string        `json:"token"`
	}{
		User:      user,
		Token:     tok,
		RawSecret: rawSecret,
	})
}

// AuthMeHandler returns the currently authenticated principal and auth policy status.
func (env *APIEnv) AuthMeHandler(w http.ResponseWriter, r *http.Request) {
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	requireAuth := false
	if env.Config != nil {
		requireAuth = env.Config.Auth.RequireAuth
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Principal   *auth.Principal `json:"principal"`
		RequireAuth bool            `json:"require_auth"`
	}{
		Principal:   p,
		RequireAuth: requireAuth,
	})
}

// AuthUsersHandler lists, creates, updates, or deletes user accounts.
func (env *APIEnv) AuthUsersHandler(w http.ResponseWriter, r *http.Request) {
	if env.AuthManager == nil {
		writeJSONError(w, "Authentication manager is not initialized", http.StatusServiceUnavailable)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Users []auth.User `json:"users"`
		}{Users: env.AuthManager.ListUsers()})

	case http.MethodPost:
		if p.Type != "anonymous" && p.Role != auth.RoleAdmin {
			writeJSONError(w, "Admin role required to create users", http.StatusForbidden)
			return
		}
		var req struct {
			Username    string `json:"username"`
			Password    string `json:"password"`
			DisplayName string `json:"display_name"`
			Email       string `json:"email"`
			Role        string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		u, err := env.AuthManager.CreateUser(req.Username, req.Password, req.DisplayName, req.Email, req.Role)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if env.AuditLogger != nil {
			_, _ = env.AuditLogger.Record(audit.AuditEvent{
				Category:  "auth",
				Action:    "user.create",
				ActorType: p.Type,
				ActorID:   p.Name,
				Status:    "ok",
				Summary:   fmt.Sprintf("Created user %q with role %q", u.Username, u.Role),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(u)

	case http.MethodPatch, http.MethodPut:
		if p.Type != "anonymous" && p.Role != auth.RoleAdmin {
			writeJSONError(w, "Admin role required to update users", http.StatusForbidden)
			return
		}
		var req struct {
			ID     string `json:"id"`
			Active *bool  `json:"active"`
			Role   string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		u, err := env.AuthManager.UpdateUser(req.ID, req.Active, req.Role)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(u)

	case http.MethodDelete:
		if p.Type != "anonymous" && p.Role != auth.RoleAdmin {
			writeJSONError(w, "Admin role required to delete users", http.StatusForbidden)
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if err := env.AuthManager.DeleteUser(id); err != nil {
			writeJSONError(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": id})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// AuthTokensHandler lists, creates, or revokes Personal Access Tokens (PAT) for remote API calls.
func (env *APIEnv) AuthTokensHandler(w http.ResponseWriter, r *http.Request) {
	if env.AuthManager == nil {
		writeJSONError(w, "Authentication manager is not initialized", http.StatusServiceUnavailable)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Tokens []auth.APIToken `json:"tokens"`
		}{Tokens: env.AuthManager.ListTokens()})

	case http.MethodPost:
		var req struct {
			UserID string   `json:"user_id"`
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
			TTL    string   `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.UserID) == "" {
			req.UserID = "admin"
		}
		var ttl time.Duration
		if strings.TrimSpace(req.TTL) != "" {
			d, err := core.ParseTimeoutDuration(req.TTL)
			if err != nil {
				writeJSONError(w, fmt.Sprintf("Invalid token TTL: %v", err), http.StatusBadRequest)
				return
			}
			ttl = d
		}
		tok, rawSecret, err := env.AuthManager.CreateToken(req.UserID, req.Name, req.Scopes, ttl)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if env.AuditLogger != nil {
			_, _ = env.AuditLogger.Record(audit.AuditEvent{
				Category:  "auth",
				Action:    "token.create",
				ActorType: p.Type,
				ActorID:   p.Name,
				Status:    "ok",
				Summary:   fmt.Sprintf("Created personal access token %q for user %q", tok.Name, tok.Username),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(struct {
			TokenInfo auth.APIToken `json:"token_info"`
			RawToken  string        `json:"token"`
		}{
			TokenInfo: tok,
			RawToken:  rawSecret,
		})

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if err := env.AuthManager.RevokeToken(id); err != nil {
			writeJSONError(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"revoked": id})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// AuthServiceAccountsHandler lists, creates, or deletes third-party service accounts.
func (env *APIEnv) AuthServiceAccountsHandler(w http.ResponseWriter, r *http.Request) {
	if env.AuthManager == nil {
		writeJSONError(w, "Authentication manager is not initialized", http.StatusServiceUnavailable)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			ServiceAccounts []auth.ServiceAccount `json:"service_accounts"`
		}{ServiceAccounts: env.AuthManager.ListServiceAccounts()})

	case http.MethodPost:
		if p.Type != "anonymous" && p.Role != auth.RoleAdmin {
			writeJSONError(w, "Admin role required to create service accounts", http.StatusForbidden)
			return
		}
		var req struct {
			Name           string   `json:"name"`
			ServiceName    string   `json:"service_name"`
			Description    string   `json:"description"`
			Scopes         []string `json:"scopes"`
			AllowedActions []string `json:"allowed_actions"`
			TTL            string   `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		var ttl time.Duration
		if strings.TrimSpace(req.TTL) != "" {
			d, err := core.ParseTimeoutDuration(req.TTL)
			if err != nil {
				writeJSONError(w, fmt.Sprintf("Invalid service account TTL: %v", err), http.StatusBadRequest)
				return
			}
			ttl = d
		}
		sa, rawKey, err := env.AuthManager.CreateServiceAccount(req.Name, req.ServiceName, req.Description, req.Scopes, req.AllowedActions, ttl)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if env.AuditLogger != nil {
			_, _ = env.AuditLogger.Record(audit.AuditEvent{
				Category:  "auth",
				Action:    "service_account.create",
				ActorType: p.Type,
				ActorID:   p.Name,
				Status:    "ok",
				Summary:   fmt.Sprintf("Created third-party service account %q (%s) with allowed_actions=%v", sa.Name, sa.ServiceName, sa.AllowedActions),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(struct {
			ServiceAccount auth.ServiceAccount `json:"service_account"`
			RawKey         string              `json:"api_key"`
		}{
			ServiceAccount: sa,
			RawKey:         rawKey,
		})

	case http.MethodDelete:
		if p.Type != "anonymous" && p.Role != auth.RoleAdmin {
			writeJSONError(w, "Admin role required to delete service accounts", http.StatusForbidden)
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if err := env.AuthManager.DeleteServiceAccount(id); err != nil {
			writeJSONError(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": id})

	default:
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// AuthServiceAccountRotateHandler rotates the API key for a third-party service account.
func (env *APIEnv) AuthServiceAccountRotateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if env.AuthManager == nil {
		writeJSONError(w, "Authentication manager is not initialized", http.StatusServiceUnavailable)
		return
	}
	p, err := env.resolvePrincipal(r)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if p.Type != "anonymous" && p.Role != auth.RoleAdmin {
		writeJSONError(w, "Admin role required to rotate service account keys", http.StatusForbidden)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.TrimSpace(req.ID) == "" {
		req.ID = strings.TrimSpace(r.URL.Query().Get("id"))
	}
	sa, newKey, err := env.AuthManager.RotateServiceAccountKey(req.ID)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		ServiceAccount auth.ServiceAccount `json:"service_account"`
		RawKey         string              `json:"api_key"`
	}{
		ServiceAccount: sa,
		RawKey:         newKey,
	})
}
