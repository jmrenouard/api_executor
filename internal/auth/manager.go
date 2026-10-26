package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go-admin-tool/internal/core"
)

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
	RoleService  = "service"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrInvalidToken       = errors.New("invalid, expired, or revoked authentication token")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrForbiddenScope     = errors.New("insufficient scope or role permissions")
	ErrForbiddenAction    = errors.New("action is not permitted for this service account")
	ErrUserAlreadyExists  = errors.New("username already exists")
	ErrNotFound           = errors.New("entity not found")
)

// User represents a human administrator, operator, or viewer account.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name"`
	Email        string     `json:"email,omitempty"`
	Role         string     `json:"role"` // admin, operator, viewer
	Active       bool       `json:"active"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	PasswordSalt string     `json:"password_salt,omitempty"`
	PasswordHash string     `json:"password_hash,omitempty"`
}

// PublicUser returns a copy of User with password material stripped for JSON responses.
func (u User) PublicUser() User {
	u.PasswordSalt = ""
	u.PasswordHash = ""
	return u
}

// APIToken represents a Personal Access Token (PAT) or session token belonging to a User for remote API calls.
type APIToken struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	UserID      string     `json:"user_id"`
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	Scopes      []string   `json:"scopes"`
	TokenPrefix string     `json:"token_prefix"`
	TokenHash   string     `json:"token_hash,omitempty"`
	Revoked     bool       `json:"revoked"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	UseCount    int64      `json:"use_count"`
}

// PublicToken returns a copy of APIToken with the secret hash stripped.
func (t APIToken) PublicToken() APIToken {
	t.TokenHash = ""
	return t
}

// ServiceAccount represents a machine-to-machine identity for third-party services.
type ServiceAccount struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	ServiceName    string     `json:"service_name"`
	Description    string     `json:"description,omitempty"`
	ClientID       string     `json:"client_id"`
	KeyPrefix      string     `json:"key_prefix"`
	KeyHash        string     `json:"key_hash,omitempty"`
	Role           string     `json:"role"`
	Scopes         []string   `json:"scopes"`
	AllowedActions []string   `json:"allowed_actions"`
	Active         bool       `json:"active"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	CallCount      int64      `json:"call_count"`
}

// PublicServiceAccount returns a copy of ServiceAccount with KeyHash removed.
func (s ServiceAccount) PublicServiceAccount() ServiceAccount {
	s.KeyHash = ""
	return s
}

// Principal represents the authenticated caller resolved from a token or service account key.
type Principal struct {
	Type           string   `json:"type"` // "user_token", "service_account", "anonymous"
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Username       string   `json:"username,omitempty"`
	ServiceName    string   `json:"service_name,omitempty"`
	Role           string   `json:"role"`
	Scopes         []string `json:"scopes"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
}

// Manager manages users, personal access tokens, and third-party service accounts.
type Manager struct {
	mu              sync.RWMutex
	cfg             core.AuthConfig
	users           map[string]User
	tokens          map[string]APIToken
	serviceAccounts map[string]ServiceAccount
}

type persistedState struct {
	Users           map[string]User           `json:"users"`
	Tokens          map[string]APIToken       `json:"tokens"`
	ServiceAccounts map[string]ServiceAccount `json:"service_accounts"`
}

// NewManager initializes the authentication manager and seeds bootstrap accounts if none exist.
func NewManager(cfg core.AuthConfig) (*Manager, error) {
	m := &Manager{
		cfg:             cfg,
		users:           make(map[string]User),
		tokens:          make(map[string]APIToken),
		serviceAccounts: make(map[string]ServiceAccount),
	}

	if cfg.StorePath != "" {
		_ = m.loadFromFile(cfg.StorePath)
	}

	// Ensure bootstrap admin user exists if no users are present
	if len(m.users) == 0 {
		adminUser := strings.TrimSpace(cfg.BootstrapUsername)
		if adminUser == "" {
			adminUser = "admin"
		}
		adminPass := cfg.BootstrapPassword
		if adminPass == "" {
			adminPass = "admin-change-me"
		}
		u, err := m.CreateUser(adminUser, adminPass, "System Administrator", "admin@localhost", RoleAdmin)
		if err != nil {
			return nil, fmt.Errorf("failed to create bootstrap admin user: %w", err)
		}

		// If a deterministic bootstrap token is configured, register it for immediate remote API use
		if strings.TrimSpace(cfg.BootstrapToken) != "" {
			rawTok := strings.TrimSpace(cfg.BootstrapToken)
			prefix := rawTok
			if len(prefix) > 12 {
				prefix = prefix[:12]
			}
			now := time.Now().UTC()
			tok := APIToken{
				ID:          "tok_bootstrap",
				Name:        "bootstrap-admin-token",
				UserID:      u.ID,
				Username:    u.Username,
				Role:        RoleAdmin,
				Scopes:      []string{"*"},
				TokenPrefix: prefix,
				TokenHash:   hashSecret(rawTok),
				CreatedAt:   now,
			}
			m.mu.Lock()
			m.tokens[tok.ID] = tok
			m.mu.Unlock()
		}
	}

	return m, nil
}

func randomHex(bytesLen int) string {
	b := make([]byte, bytesLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPassword(password, salt string) string {
	// Iterative salted SHA-256 derivation (10,000 rounds) for zero-CGO portability
	h := sha256.Sum256([]byte(salt + ":" + password))
	for i := 0; i < 10000; i++ {
		data := append(h[:], []byte(salt)...)
		h = sha256.Sum256(data)
	}
	return hex.EncodeToString(h[:])
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqualsHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleAdmin:
		return RoleAdmin
	case RoleOperator:
		return RoleOperator
	case RoleViewer:
		return RoleViewer
	case RoleService:
		return RoleService
	default:
		return RoleOperator
	}
}

func defaultScopesForRole(role string) []string {
	switch normalizeRole(role) {
	case RoleAdmin:
		return []string{"*"}
	case RoleOperator:
		return []string{"commands:read", "commands:execute", "plugins:read", "plugins:execute", "mcp:access", "files:read", "audit:read"}
	case RoleViewer:
		return []string{"commands:read", "plugins:read", "files:read", "tls:read"}
	case RoleService:
		return []string{"commands:read", "commands:execute", "plugins:execute", "mcp:access"}
	default:
		return []string{"commands:read"}
	}
}

func (m *Manager) saveIfNeededLocked() {
	if m.cfg.StorePath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(m.cfg.StorePath), 0755)
	state := persistedState{
		Users:           m.users,
		Tokens:          m.tokens,
		ServiceAccounts: m.serviceAccounts,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err == nil {
		_ = os.WriteFile(m.cfg.StorePath, data, 0600)
	}
}

func (m *Manager) loadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if state.Users != nil {
		m.users = state.Users
	}
	if state.Tokens != nil {
		m.tokens = state.Tokens
	}
	if state.ServiceAccounts != nil {
		m.serviceAccounts = state.ServiceAccounts
	}
	return nil
}

// CreateUser registers a new user account.
func (m *Manager) CreateUser(username, password, displayName, email, role string) (User, error) {
	uname := strings.TrimSpace(username)
	if uname == "" {
		return User{}, errors.New("username cannot be empty")
	}
	if len(password) < 6 {
		return User{}, errors.New("password must be at least 6 characters")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.users {
		if strings.EqualFold(existing.Username, uname) {
			return User{}, ErrUserAlreadyExists
		}
	}

	salt := randomHex(16)
	if strings.TrimSpace(displayName) == "" {
		displayName = uname
	}
	u := User{
		ID:           "usr_" + randomHex(8),
		Username:     uname,
		DisplayName:  strings.TrimSpace(displayName),
		Email:        strings.TrimSpace(email),
		Role:         normalizeRole(role),
		Active:       true,
		CreatedAt:    time.Now().UTC(),
		PasswordSalt: salt,
		PasswordHash: hashPassword(password, salt),
	}
	m.users[u.ID] = u
	m.saveIfNeededLocked()
	return u.PublicUser(), nil
}

// AuthenticateUser verifies username & password and issues a 24h session token for Web/API calls.
func (m *Manager) AuthenticateUser(username, password string) (User, APIToken, string, error) {
	uname := strings.TrimSpace(username)
	m.mu.Lock()
	var found *User
	for _, u := range m.users {
		if strings.EqualFold(u.Username, uname) {
			uCopy := u
			found = &uCopy
			break
		}
	}
	if found == nil {
		m.mu.Unlock()
		return User{}, APIToken{}, "", ErrInvalidCredentials
	}
	if !found.Active {
		m.mu.Unlock()
		return User{}, APIToken{}, "", ErrAccountDisabled
	}

	expectedHash := hashPassword(password, found.PasswordSalt)
	if !constantTimeEqualsHex(expectedHash, found.PasswordHash) {
		m.mu.Unlock()
		return User{}, APIToken{}, "", ErrInvalidCredentials
	}

	now := time.Now().UTC()
	found.LastLoginAt = &now
	m.users[found.ID] = *found
	m.saveIfNeededLocked()
	m.mu.Unlock()

	tok, rawSecret, err := m.CreateToken(found.ID, "web-session-"+now.Format("20060102-150405"), defaultScopesForRole(found.Role), 24*time.Hour)
	if err != nil {
		return User{}, APIToken{}, "", err
	}
	return found.PublicUser(), tok, rawSecret, nil
}

// ListUsers returns all registered users without password hashes.
func (m *Manager) ListUsers() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u.PublicUser())
	}
	return out
}

// UpdateUser updates a user's active status or role.
func (m *Manager) UpdateUser(id string, active *bool, role string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	if active != nil {
		u.Active = *active
	}
	if strings.TrimSpace(role) != "" {
		u.Role = normalizeRole(role)
	}
	m.users[id] = u
	m.saveIfNeededLocked()
	return u.PublicUser(), nil
}

// DeleteUser removes a user and revokes all their tokens.
func (m *Manager) DeleteUser(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[id]; !ok {
		return ErrNotFound
	}
	delete(m.users, id)
	for tid, tok := range m.tokens {
		if tok.UserID == id {
			delete(m.tokens, tid)
		}
	}
	m.saveIfNeededLocked()
	return nil
}

// CreateToken creates a Personal Access Token (PAT) for remote API calls.
func (m *Manager) CreateToken(userID, name string, scopes []string, ttl time.Duration) (APIToken, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	u, ok := m.users[userID]
	if !ok {
		// Allow specifying username in place of userID
		for _, candidate := range m.users {
			if strings.EqualFold(candidate.Username, userID) {
				u = candidate
				ok = true
				break
			}
		}
	}
	if !ok {
		return APIToken{}, "", ErrNotFound
	}
	if !u.Active {
		return APIToken{}, "", ErrAccountDisabled
	}

	if strings.TrimSpace(name) == "" {
		name = "remote-api-token"
	}
	if len(scopes) == 0 {
		scopes = defaultScopesForRole(u.Role)
	}

	rawToken := "gat_pat_" + randomHex(20)
	var exp *time.Time
	if ttl > 0 {
		t := time.Now().UTC().Add(ttl)
		exp = &t
	}

	tok := APIToken{
		ID:          "tok_" + randomHex(8),
		Name:        strings.TrimSpace(name),
		UserID:      u.ID,
		Username:    u.Username,
		Role:        u.Role,
		Scopes:      scopes,
		TokenPrefix: rawToken[:16],
		TokenHash:   hashSecret(rawToken),
		Revoked:     false,
		ExpiresAt:   exp,
		CreatedAt:   time.Now().UTC(),
	}
	m.tokens[tok.ID] = tok
	m.saveIfNeededLocked()
	return tok.PublicToken(), rawToken, nil
}

// ListTokens returns all personal access tokens (with secret hashes stripped).
func (m *Manager) ListTokens() []APIToken {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]APIToken, 0, len(m.tokens))
	for _, t := range m.tokens {
		out = append(out, t.PublicToken())
	}
	return out
}

// RevokeToken marks a token as revoked or deletes it.
func (m *Manager) RevokeToken(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.tokens[id]
	if !ok {
		return ErrNotFound
	}
	tok.Revoked = true
	m.tokens[id] = tok
	m.saveIfNeededLocked()
	return nil
}

// CreateServiceAccount creates a new third-party service account with an API key and action allowlist.
func (m *Manager) CreateServiceAccount(name, serviceName, description string, scopes, allowedActions []string, ttl time.Duration) (ServiceAccount, string, error) {
	trimmedName := strings.TrimSpace(name)
	trimmedService := strings.TrimSpace(serviceName)
	if trimmedName == "" {
		return ServiceAccount{}, "", errors.New("service account name is required")
	}
	if trimmedService == "" {
		trimmedService = trimmedName
	}
	if len(scopes) == 0 {
		scopes = defaultScopesForRole(RoleService)
	}
	if len(allowedActions) == 0 {
		allowedActions = []string{"*"}
	}

	rawKey := "gat_svc_" + randomHex(24)
	var exp *time.Time
	if ttl > 0 {
		t := time.Now().UTC().Add(ttl)
		exp = &t
	}

	sa := ServiceAccount{
		ID:             "svc_" + randomHex(8),
		Name:           trimmedName,
		ServiceName:    trimmedService,
		Description:    strings.TrimSpace(description),
		ClientID:       "svc_client_" + randomHex(8),
		KeyPrefix:      rawKey[:16],
		KeyHash:        hashSecret(rawKey),
		Role:           RoleService,
		Scopes:         scopes,
		AllowedActions: allowedActions,
		Active:         true,
		ExpiresAt:      exp,
		CreatedAt:      time.Now().UTC(),
	}

	m.mu.Lock()
	m.serviceAccounts[sa.ID] = sa
	m.saveIfNeededLocked()
	m.mu.Unlock()

	return sa.PublicServiceAccount(), rawKey, nil
}

// RotateServiceAccountKey generates a new secret API key for an existing third-party service account.
func (m *Manager) RotateServiceAccountKey(id string) (ServiceAccount, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sa, ok := m.serviceAccounts[id]
	if !ok {
		return ServiceAccount{}, "", ErrNotFound
	}
	rawKey := "gat_svc_" + randomHex(24)
	sa.KeyPrefix = rawKey[:16]
	sa.KeyHash = hashSecret(rawKey)
	m.serviceAccounts[id] = sa
	m.saveIfNeededLocked()
	return sa.PublicServiceAccount(), rawKey, nil
}

// ListServiceAccounts returns all registered third-party service accounts.
func (m *Manager) ListServiceAccounts() []ServiceAccount {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ServiceAccount, 0, len(m.serviceAccounts))
	for _, sa := range m.serviceAccounts {
		out = append(out, sa.PublicServiceAccount())
	}
	return out
}

// DeleteServiceAccount deletes a service account.
func (m *Manager) DeleteServiceAccount(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.serviceAccounts[id]; !ok {
		return ErrNotFound
	}
	delete(m.serviceAccounts, id)
	m.saveIfNeededLocked()
	return nil
}

// AuthenticateCredential validates a raw user token (`gat_pat_...`) or service account key (`gat_svc_...`).
func (m *Manager) AuthenticateCredential(rawCredential string) (*Principal, error) {
	cred := strings.TrimSpace(rawCredential)
	if cred == "" {
		return nil, ErrInvalidToken
	}
	candHash := hashSecret(cred)
	now := time.Now().UTC()

	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Check user tokens
	for id, tok := range m.tokens {
		if constantTimeEqualsHex(candHash, tok.TokenHash) {
			if tok.Revoked {
				return nil, ErrInvalidToken
			}
			if tok.ExpiresAt != nil && now.After(*tok.ExpiresAt) {
				return nil, ErrInvalidToken
			}
			if u, exists := m.users[tok.UserID]; exists && !u.Active {
				return nil, ErrAccountDisabled
			}
			tok.LastUsedAt = &now
			tok.UseCount++
			m.tokens[id] = tok
			return &Principal{
				Type:     "user_token",
				ID:       tok.ID,
				Name:     tok.Name,
				Username: tok.Username,
				Role:     tok.Role,
				Scopes:   tok.Scopes,
			}, nil
		}
	}

	// 2. Check third-party service accounts
	for id, sa := range m.serviceAccounts {
		if constantTimeEqualsHex(candHash, sa.KeyHash) {
			if !sa.Active {
				return nil, ErrAccountDisabled
			}
			if sa.ExpiresAt != nil && now.After(*sa.ExpiresAt) {
				return nil, ErrInvalidToken
			}
			sa.LastUsedAt = &now
			sa.CallCount++
			m.serviceAccounts[id] = sa
			return &Principal{
				Type:           "service_account",
				ID:             sa.ID,
				Name:           sa.Name,
				ServiceName:    sa.ServiceName,
				Role:           sa.Role,
				Scopes:         sa.Scopes,
				AllowedActions: sa.AllowedActions,
			}, nil
		}
	}

	return nil, ErrInvalidToken
}

// Authorize checks if the principal has the required scope and (for service accounts) whether the target action is allowed.
func Authorize(p *Principal, requiredScope string, targetAction string) error {
	if p == nil {
		return ErrInvalidToken
	}
	if p.Role == RoleAdmin {
		return nil
	}

	// Check scope
	if requiredScope != "" {
		hasScope := false
		for _, s := range p.Scopes {
			s = strings.TrimSpace(s)
			if s == "*" || s == "admin:*" || strings.EqualFold(s, requiredScope) {
				hasScope = true
				break
			}
			if strings.HasSuffix(s, ":*") {
				prefix := strings.TrimSuffix(s, "*")
				if strings.HasPrefix(requiredScope, prefix) {
					hasScope = true
					break
				}
			}
		}
		if !hasScope {
			return fmt.Errorf("%w: requires scope %q", ErrForbiddenScope, requiredScope)
		}
	}

	// Check AllowedActions for third-party service accounts
	if p.Type == "service_account" && targetAction != "" {
		allowed := false
		for _, pattern := range p.AllowedActions {
			pattern = strings.TrimSpace(pattern)
			if pattern == "*" || strings.EqualFold(pattern, targetAction) {
				allowed = true
				break
			}
			if strings.HasSuffix(pattern, "*") {
				prefix := strings.TrimSuffix(pattern, "*")
				if strings.HasPrefix(targetAction, prefix) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return fmt.Errorf("%w: action %q is not in service account allowlist %v", ErrForbiddenAction, targetAction, p.AllowedActions)
		}
	}

	return nil
}

// ExtractTokenFromRequest extracts a Bearer token or API key from HTTP headers or query string.
func ExtractTokenFromRequest(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			return strings.TrimSpace(authHeader[7:]), true
		}
		return authHeader, true
	}
	for _, hdr := range []string{"X-API-Token", "X-API-Key", "X-Service-Key"} {
		if val := strings.TrimSpace(r.Header.Get(hdr)); val != "" {
			return val, true
		}
	}
	return "", false
}
