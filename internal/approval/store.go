package approval

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

var (
	ErrNotFound              = errors.New("approval request not found")
	ErrMaxPendingReached     = errors.New("maximum pending approval requests reached")
	ErrInvalidTransition     = errors.New("invalid approval state transition")
	ErrSelfApprovalForbidden = errors.New("requester cannot self-approve their own request")
	ErrExpired               = errors.New("approval request has expired")
	ErrPayloadMismatch       = errors.New("request payload digest does not match approved payload")
	ErrAlreadyConsumed       = errors.New("approval request has already been consumed")
	ErrInvalidRequest        = errors.New("invalid approval request parameters")
)

// Request represents a single tamper-evident Human-in-the-Loop approval record.
type Request struct {
	ID              string         `json:"id"`
	Status          Status         `json:"status"`
	Channel         Channel        `json:"channel"`
	Action          string         `json:"action"`
	PluginID        string         `json:"plugin_id,omitempty"`
	ToolName        string         `json:"tool_name,omitempty"`
	Parameters      map[string]any `json:"parameters,omitempty"`
	PayloadSHA256   string         `json:"payload_sha256"`
	RequesterID     string         `json:"requester_id"`
	RequesterType   string         `json:"requester_type"`
	SourceIP        string         `json:"source_ip,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	ApproverID      string         `json:"approver_id,omitempty"`
	DecisionComment string         `json:"decision_comment,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	ExpiresAt       time.Time      `json:"expires_at"`
	DecidedAt       *time.Time     `json:"decided_at,omitempty"`
	ConsumedAt      *time.Time     `json:"consumed_at,omitempty"`
}

// CreateParams holds the inputs required to open a pending approval request.
type CreateParams struct {
	Target        Target
	RequesterID   string
	RequesterType string
	SourceIP      string
	Reason        string
	Metadata      map[string]any
	TTL           time.Duration
}

// Filter scopes queries against Store.List.
type Filter struct {
	Status      Status
	Channel     Channel
	Action      string
	RequesterID string
	Limit       int
	Offset      int
}

// Store manages the lifecycle, bounded persistence, and audit trail of HITL approval requests.
type Store struct {
	mu          sync.Mutex
	cfg         core.ApprovalConfig
	policy      *Policy
	db          *database.DB
	inMemory    bool
	auditLogger *audit.AuditLogger
	nowFn       func() time.Time
	maxPending  int
	maxRetained int
	requests    map[string]*Request
	order       []string
}

// NewStore initializes a concurrency-safe HITL approval store backed by SQLite when available
// or an identical pure-Go in-memory store when db is nil or operating in CGO_ENABLED=0 fallback.
func NewStore(cfg core.ApprovalConfig, db *database.DB, auditLogger *audit.AuditLogger) (*Store, error) {
	maxPending := cfg.EffectiveMaxPending()
	maxRetained := maxPending * 4
	if maxRetained < 2000 {
		maxRetained = 2000
	}

	s := &Store{
		cfg:         cfg,
		policy:      NewPolicy(cfg),
		db:          db,
		inMemory:    db == nil || db.IsInMemory() || db.DB == nil,
		auditLogger: auditLogger,
		nowFn:       func() time.Time { return time.Now().UTC() },
		maxPending:  maxPending,
		maxRetained: maxRetained,
		requests:    make(map[string]*Request),
		order:       make([]string, 0, 64),
	}

	if !s.inMemory {
		if err := s.initSchema(); err != nil {
			return nil, fmt.Errorf("failed to initialize approval_requests schema: %w", err)
		}
		if err := s.loadFromDB(); err != nil {
			return nil, fmt.Errorf("failed to load approval_requests from database: %w", err)
		}
	}

	return s, nil
}

// Policy returns the approval policy associated with this store.
func (s *Store) Policy() *Policy {
	if s == nil {
		return NewPolicy(core.DefaultApprovalConfig())
	}
	return s.policy
}

// SetNowFunc overrides the clock function (intended for deterministic expiration testing).
func (s *Store) SetNowFunc(fn func() time.Time) {
	if s == nil || fn == nil {
		return
	}
	s.mu.Lock()
	s.nowFn = fn
	s.mu.Unlock()
}

// IsInMemory reports whether the store runs strictly in memory (no SQLite backing).
func (s *Store) IsInMemory() bool {
	return s == nil || s.inMemory
}

func (s *Store) initSchema() error {
	const ddl = `
	CREATE TABLE IF NOT EXISTS approval_requests (
		id TEXT NOT NULL PRIMARY KEY,
		status TEXT NOT NULL,
		channel TEXT NOT NULL,
		action TEXT NOT NULL,
		plugin_id TEXT,
		tool_name TEXT,
		parameters_json TEXT,
		payload_sha256 TEXT NOT NULL,
		requester_id TEXT NOT NULL,
		requester_type TEXT NOT NULL,
		source_ip TEXT,
		reason TEXT,
		metadata_json TEXT,
		approver_id TEXT,
		decision_comment TEXT,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		decided_at DATETIME,
		consumed_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);
	CREATE INDEX IF NOT EXISTS idx_approval_requests_expires_at ON approval_requests(expires_at);
	CREATE INDEX IF NOT EXISTS idx_approval_requests_created_at ON approval_requests(created_at DESC);
	`
	_, err := s.db.Exec(ddl)
	return err
}

func (s *Store) loadFromDB() error {
	rows, err := s.db.Query(`
		SELECT id, status, channel, action, plugin_id, tool_name, parameters_json, payload_sha256,
		       requester_id, requester_type, source_ip, reason, metadata_json, approver_id,
		       decision_comment, created_at, expires_at, decided_at, consumed_at
		FROM approval_requests
		ORDER BY created_at ASC
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var req Request
		var statusStr, channelStr string
		var pluginID, toolName, paramsJSON, sourceIP, reason, metaJSON, approverID, comment sql.NullString
		var decidedAt, consumedAt sql.NullTime

		if err := rows.Scan(
			&req.ID, &statusStr, &channelStr, &req.Action, &pluginID, &toolName, &paramsJSON, &req.PayloadSHA256,
			&req.RequesterID, &req.RequesterType, &sourceIP, &reason, &metaJSON, &approverID,
			&comment, &req.CreatedAt, &req.ExpiresAt, &decidedAt, &consumedAt,
		); err != nil {
			return err
		}

		req.Status = Status(statusStr)
		req.Channel = Channel(channelStr)
		req.PluginID = pluginID.String
		req.ToolName = toolName.String
		req.SourceIP = sourceIP.String
		req.Reason = reason.String
		req.ApproverID = approverID.String
		req.DecisionComment = comment.String
		req.CreatedAt = req.CreatedAt.UTC()
		req.ExpiresAt = req.ExpiresAt.UTC()
		if decidedAt.Valid {
			t := decidedAt.Time.UTC()
			req.DecidedAt = &t
		}
		if consumedAt.Valid {
			t := consumedAt.Time.UTC()
			req.ConsumedAt = &t
		}
		if paramsJSON.Valid && paramsJSON.String != "" {
			_ = json.Unmarshal([]byte(paramsJSON.String), &req.Parameters)
		}
		if metaJSON.Valid && metaJSON.String != "" {
			_ = json.Unmarshal([]byte(metaJSON.String), &req.Metadata)
		}

		rCopy := cloneRequest(&req)
		s.requests[rCopy.ID] = rCopy
		s.order = append(s.order, rCopy.ID)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.pruneRetainedLocked()
	return nil
}

func generateApprovalID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate approval ID: %w", err)
	}
	return "apr_" + hex.EncodeToString(b), nil
}

func cloneValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return v
	}
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	cp := make(map[string]any, len(src))
	for k, v := range src {
		cp[k] = cloneValue(v)
	}
	return cp
}

func cloneRequest(r *Request) *Request {
	if r == nil {
		return nil
	}
	cp := *r
	cp.Parameters = cloneMap(r.Parameters)
	cp.Metadata = cloneMap(r.Metadata)
	if r.DecidedAt != nil {
		t := *r.DecidedAt
		cp.DecidedAt = &t
	}
	if r.ConsumedAt != nil {
		t := *r.ConsumedAt
		cp.ConsumedAt = &t
	}
	return &cp
}

// Create opens a new pending HITL approval request bound to the canonical SHA-256 payload digest.
func (s *Store) Create(params CreateParams) (*Request, error) {
	if s == nil {
		return nil, ErrInvalidRequest
	}
	channel := Channel(strings.ToLower(strings.TrimSpace(string(params.Target.Channel))))
	action := strings.TrimSpace(params.Target.Action)
	toolName := strings.TrimSpace(params.Target.ToolName)
	if channel == "" || (action == "" && toolName == "") {
		return nil, fmt.Errorf("%w: channel and action/tool_name are required", ErrInvalidRequest)
	}

	digest, err := ComputePayloadSHA256(params.Target)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	id, err := generateApprovalID()
	if err != nil {
		return nil, err
	}

	requesterID := strings.TrimSpace(params.RequesterID)
	if requesterID == "" {
		requesterID = "anonymous"
	}
	requesterType := strings.TrimSpace(params.RequesterType)
	if requesterType == "" {
		requesterType = "anonymous"
	}

	ttl := params.TTL
	if ttl <= 0 {
		ttl = s.cfg.EffectiveTTL()
	}

	s.mu.Lock()
	now := s.nowFn().UTC()
	expired := s.expireStaleLocked(now)

	pendingCount := 0
	for _, existing := range s.requests {
		if existing.Status == StatusPending {
			pendingCount++
		}
	}
	if pendingCount >= s.maxPending {
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, ErrMaxPendingReached
	}

	req := &Request{
		ID:            id,
		Status:        StatusPending,
		Channel:       channel,
		Action:        action,
		PluginID:      strings.TrimSpace(params.Target.PluginID),
		ToolName:      toolName,
		Parameters:    cloneMap(params.Target.Parameters),
		PayloadSHA256: digest,
		RequesterID:   requesterID,
		RequesterType: requesterType,
		SourceIP:      strings.TrimSpace(params.SourceIP),
		Reason:        strings.TrimSpace(params.Reason),
		Metadata:      cloneMap(params.Metadata),
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}

	if !s.inMemory {
		if err := s.insertDBLocked(req); err != nil {
			s.mu.Unlock()
			s.auditExpiredBatch(expired)
			return nil, fmt.Errorf("failed to persist approval request: %w", err)
		}
	}

	s.requests[req.ID] = req
	s.order = append(s.order, req.ID)
	s.pruneRetainedLocked()
	snap := cloneRequest(req)
	s.mu.Unlock()

	s.auditExpiredBatch(expired)
	s.recordAudit("approval.requested", snap.RequesterType, snap.RequesterID, snap.SourceIP, "ok",
		fmt.Sprintf("Approval %s requested for %s:%s (expires=%s)", snap.ID, snap.Channel, snap.Action, snap.ExpiresAt.Format(time.RFC3339)),
		map[string]any{
			"approval_id":    snap.ID,
			"channel":        string(snap.Channel),
			"action":         snap.Action,
			"plugin_id":      snap.PluginID,
			"tool_name":      snap.ToolName,
			"payload_sha256": snap.PayloadSHA256,
		})

	return snap, nil
}

// Get retrieves an approval request by ID after expiring any stale records.
func (s *Store) Get(id string) (*Request, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	expired := s.expireStaleLocked(s.nowFn().UTC())
	req, ok := s.requests[strings.TrimSpace(id)]
	if !ok {
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, ErrNotFound
	}
	snap := cloneRequest(req)
	s.mu.Unlock()

	s.auditExpiredBatch(expired)
	return snap, nil
}

// List returns matching approval requests ordered newest first alongside total matching count.
func (s *Store) List(filter Filter) ([]*Request, int) {
	if s == nil {
		return []*Request{}, 0
	}

	s.mu.Lock()
	expired := s.expireStaleLocked(s.nowFn().UTC())

	statusFilter := Status(strings.ToLower(strings.TrimSpace(string(filter.Status))))
	channelFilter := Channel(strings.ToLower(strings.TrimSpace(string(filter.Channel))))
	actionFilter := strings.ToLower(strings.TrimSpace(filter.Action))
	requesterFilter := strings.ToLower(strings.TrimSpace(filter.RequesterID))

	matched := make([]*Request, 0)
	for i := len(s.order) - 1; i >= 0; i-- {
		req, ok := s.requests[s.order[i]]
		if !ok {
			continue
		}
		if statusFilter != "" && req.Status != statusFilter {
			continue
		}
		if channelFilter != "" && req.Channel != channelFilter {
			continue
		}
		if actionFilter != "" && !strings.Contains(strings.ToLower(req.Action), actionFilter) {
			continue
		}
		if requesterFilter != "" && !strings.EqualFold(req.RequesterID, requesterFilter) {
			continue
		}
		matched = append(matched, cloneRequest(req))
	}
	s.mu.Unlock()

	s.auditExpiredBatch(expired)

	total := len(matched)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*Request{}, total
	}
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return matched[offset:end], total
}

// Approve transitions a pending approval request to approved, enforcing distinct approver separation of duties.
func (s *Store) Approve(id, approverID, approverType, sourceIP, comment string) (*Request, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	approverID = strings.TrimSpace(approverID)
	approverType = strings.TrimSpace(approverType)
	if approverID == "" || strings.EqualFold(approverType, "anonymous") {
		return nil, fmt.Errorf("%w: authenticated approver is required", ErrInvalidRequest)
	}

	s.mu.Lock()
	now := s.nowFn().UTC()
	expired := s.expireStaleLocked(now)

	req, ok := s.requests[strings.TrimSpace(id)]
	if !ok {
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, ErrNotFound
	}
	if req.Status == StatusExpired || !now.Before(req.ExpiresAt) {
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, ErrExpired
	}
	if req.Status != StatusPending {
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, fmt.Errorf("%w: cannot approve request in status %q", ErrInvalidTransition, req.Status)
	}
	if s.cfg.RequireDistinctApprover && req.RequesterID != "" && strings.EqualFold(req.RequesterID, approverID) {
		snap := cloneRequest(req)
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		s.recordAudit("approval.approved", approverType, approverID, sourceIP, "denied",
			fmt.Sprintf("Denied self-approval of %s by requester %q", snap.ID, approverID),
			map[string]any{"approval_id": snap.ID, "reason": "self_approval_forbidden"})
		return nil, ErrSelfApprovalForbidden
	}

	decidedAt := now
	trimmedComment := strings.TrimSpace(comment)
	if !s.inMemory {
		if err := s.updateDecisionDBLocked(req.ID, StatusApproved, approverID, trimmedComment, decidedAt); err != nil {
			s.mu.Unlock()
			s.auditExpiredBatch(expired)
			return nil, fmt.Errorf("failed to persist approval decision: %w", err)
		}
	}

	req.Status = StatusApproved
	req.ApproverID = approverID
	req.DecisionComment = trimmedComment
	req.DecidedAt = &decidedAt
	snap := cloneRequest(req)
	s.mu.Unlock()

	s.auditExpiredBatch(expired)
	s.recordAudit("approval.approved", approverType, approverID, sourceIP, "ok",
		fmt.Sprintf("Approved request %s for %s:%s", snap.ID, snap.Channel, snap.Action),
		map[string]any{
			"approval_id":    snap.ID,
			"requester_id":   snap.RequesterID,
			"payload_sha256": snap.PayloadSHA256,
		})

	return snap, nil
}

// Reject transitions a pending approval request to rejected.
func (s *Store) Reject(id, approverID, approverType, sourceIP, comment string) (*Request, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	approverID = strings.TrimSpace(approverID)
	approverType = strings.TrimSpace(approverType)
	if approverID == "" || strings.EqualFold(approverType, "anonymous") {
		return nil, fmt.Errorf("%w: authenticated approver is required", ErrInvalidRequest)
	}

	s.mu.Lock()
	now := s.nowFn().UTC()
	expired := s.expireStaleLocked(now)

	req, ok := s.requests[strings.TrimSpace(id)]
	if !ok {
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, ErrNotFound
	}
	if req.Status == StatusExpired || !now.Before(req.ExpiresAt) {
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, ErrExpired
	}
	if req.Status != StatusPending {
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, fmt.Errorf("%w: cannot reject request in status %q", ErrInvalidTransition, req.Status)
	}

	decidedAt := now
	trimmedComment := strings.TrimSpace(comment)
	if !s.inMemory {
		if err := s.updateDecisionDBLocked(req.ID, StatusRejected, approverID, trimmedComment, decidedAt); err != nil {
			s.mu.Unlock()
			s.auditExpiredBatch(expired)
			return nil, fmt.Errorf("failed to persist rejection decision: %w", err)
		}
	}

	req.Status = StatusRejected
	req.ApproverID = approverID
	req.DecisionComment = trimmedComment
	req.DecidedAt = &decidedAt
	snap := cloneRequest(req)
	s.mu.Unlock()

	s.auditExpiredBatch(expired)
	s.recordAudit("approval.rejected", approverType, approverID, sourceIP, "ok",
		fmt.Sprintf("Rejected request %s for %s:%s", snap.ID, snap.Channel, snap.Action),
		map[string]any{
			"approval_id":  snap.ID,
			"requester_id": snap.RequesterID,
		})

	return snap, nil
}

// Consume atomically verifies that an approval is in approved status, unexpired, and matches
// expectedPayloadSHA256 in constant time, then transitions it to single-use consumed status.
func (s *Store) Consume(id, expectedPayloadSHA256, consumerID, consumerType, sourceIP string) (*Request, error) {
	if s == nil {
		return nil, ErrNotFound
	}

	s.mu.Lock()
	now := s.nowFn().UTC()
	expired := s.expireStaleLocked(now)

	req, ok := s.requests[strings.TrimSpace(id)]
	if !ok {
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, ErrNotFound
	}
	switch req.Status {
	case StatusConsumed:
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, ErrAlreadyConsumed
	case StatusExpired:
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, ErrExpired
	case StatusApproved:
		if !now.Before(req.ExpiresAt) {
			s.mu.Unlock()
			s.auditExpiredBatch(expired)
			return nil, ErrExpired
		}
		// proceed to constant-time digest verification
	default:
		status := req.Status
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		return nil, fmt.Errorf("%w: approval is in status %q", ErrInvalidTransition, status)
	}

	if !ConstantTimeDigestEqual(req.PayloadSHA256, strings.TrimSpace(expectedPayloadSHA256)) {
		snap := cloneRequest(req)
		s.mu.Unlock()
		s.auditExpiredBatch(expired)
		s.recordAudit("approval.consumed", consumerType, consumerID, sourceIP, "denied",
			fmt.Sprintf("Rejected consumption of approval %s due to payload SHA-256 mismatch", snap.ID),
			map[string]any{"approval_id": snap.ID, "reason": "payload_sha256_mismatch"})
		return nil, ErrPayloadMismatch
	}

	consumedAt := now
	if !s.inMemory {
		res, err := s.db.Exec(
			`UPDATE approval_requests SET status = ?, consumed_at = ? WHERE id = ? AND status = ?`,
			string(StatusConsumed), consumedAt, req.ID, string(StatusApproved),
		)
		if err != nil {
			s.mu.Unlock()
			s.auditExpiredBatch(expired)
			return nil, fmt.Errorf("failed to consume approval in database: %w", err)
		}
		if affected, err := res.RowsAffected(); err != nil || affected != 1 {
			s.mu.Unlock()
			s.auditExpiredBatch(expired)
			return nil, ErrAlreadyConsumed
		}
	}

	req.Status = StatusConsumed
	req.ConsumedAt = &consumedAt
	snap := cloneRequest(req)
	s.mu.Unlock()

	s.auditExpiredBatch(expired)
	s.recordAudit("approval.consumed", consumerType, consumerID, sourceIP, "ok",
		fmt.Sprintf("Consumed single-use approval %s for %s:%s", snap.ID, snap.Channel, snap.Action),
		map[string]any{
			"approval_id":    snap.ID,
			"approver_id":    snap.ApproverID,
			"payload_sha256": snap.PayloadSHA256,
		})

	return snap, nil
}

// PendingCount returns the current number of active unexpired pending approval requests.
func (s *Store) PendingCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	expired := s.expireStaleLocked(s.nowFn().UTC())
	count := 0
	for _, r := range s.requests {
		if r.Status == StatusPending {
			count++
		}
	}
	s.mu.Unlock()
	s.auditExpiredBatch(expired)
	return count
}

func (s *Store) expireStaleLocked(now time.Time) []*Request {
	var expired []*Request
	for _, id := range s.order {
		req, ok := s.requests[id]
		if !ok {
			continue
		}
		if (req.Status == StatusPending || req.Status == StatusApproved) && !now.Before(req.ExpiresAt) {
			if !s.inMemory {
				if _, err := s.db.Exec(
					`UPDATE approval_requests SET status = ? WHERE id = ? AND status IN (?, ?)`,
					string(StatusExpired), req.ID, string(StatusPending), string(StatusApproved),
				); err != nil {
					continue
				}
			}
			req.Status = StatusExpired
			expired = append(expired, cloneRequest(req))
		}
	}
	return expired
}

func (s *Store) pruneRetainedLocked() {
	if len(s.order) <= s.maxRetained {
		return
	}
	excess := len(s.order) - s.maxRetained
	newOrder := make([]string, 0, len(s.order))
	for _, id := range s.order {
		req, ok := s.requests[id]
		if !ok {
			continue
		}
		if excess > 0 && req.Status.IsTerminal() {
			delete(s.requests, id)
			excess--
			continue
		}
		newOrder = append(newOrder, id)
	}
	s.order = newOrder
}

func (s *Store) insertDBLocked(req *Request) error {
	var paramsJSON, metaJSON sql.NullString
	if req.Parameters != nil {
		if b, err := json.Marshal(req.Parameters); err == nil {
			paramsJSON = sql.NullString{String: string(b), Valid: true}
		}
	}
	if req.Metadata != nil {
		if b, err := json.Marshal(req.Metadata); err == nil {
			metaJSON = sql.NullString{String: string(b), Valid: true}
		}
	}
	_, err := s.db.Exec(
		`INSERT INTO approval_requests(
			id, status, channel, action, plugin_id, tool_name, parameters_json, payload_sha256,
			requester_id, requester_type, source_ip, reason, metadata_json, approver_id,
			decision_comment, created_at, expires_at, decided_at, consumed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.ID, string(req.Status), string(req.Channel), req.Action, req.PluginID, req.ToolName,
		paramsJSON, req.PayloadSHA256, req.RequesterID, req.RequesterType, req.SourceIP,
		req.Reason, metaJSON, req.ApproverID, req.DecisionComment,
		req.CreatedAt, req.ExpiresAt, nil, nil,
	)
	return err
}

func (s *Store) updateDecisionDBLocked(id string, status Status, approverID, comment string, decidedAt time.Time) error {
	res, err := s.db.Exec(
		`UPDATE approval_requests SET status = ?, approver_id = ?, decision_comment = ?, decided_at = ? WHERE id = ? AND status = ?`,
		string(status), approverID, comment, decidedAt, id, string(StatusPending),
	)
	if err != nil {
		return err
	}
	if affected, err := res.RowsAffected(); err != nil || affected != 1 {
		return ErrInvalidTransition
	}
	return nil
}

func (s *Store) auditExpiredBatch(expired []*Request) {
	for _, req := range expired {
		s.recordAudit("approval.expired", "system", "approval_store", "", "ok",
			fmt.Sprintf("Approval %s expired for %s:%s", req.ID, req.Channel, req.Action),
			map[string]any{"approval_id": req.ID, "requester_id": req.RequesterID})
	}
}

func (s *Store) recordAudit(action, actorType, actorID, sourceIP, status, summary string, metadata map[string]any) {
	if s.auditLogger == nil {
		return
	}
	if actorType == "" {
		actorType = "system"
	}
	if actorID == "" {
		actorID = "system"
	}
	_, _ = s.auditLogger.Record(audit.AuditEvent{
		Category:  "approval",
		Action:    action,
		ActorType: actorType,
		ActorID:   actorID,
		SourceIP:  sourceIP,
		Status:    status,
		Summary:   summary,
		Metadata:  metadata,
	})
}
