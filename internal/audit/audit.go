package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

const GenesisHash = "GENESIS_00000000000000000000000000000000000000000000000000000000"

// AuditEvent represents an immutable, hash-chained security and operational audit record.
type AuditEvent struct {
	ID         int64          `json:"id"`
	EventID    string         `json:"event_id"`
	Timestamp  time.Time      `json:"timestamp"`
	TraceID    string         `json:"trace_id,omitempty"`
	Category   string         `json:"category"` // command, plugin, mcp, auth, admin, file, tls
	Action     string         `json:"action"`
	ActorType  string         `json:"actor_type"` // user, token, service_account, mcp_client, anonymous
	ActorID    string         `json:"actor_id"`
	SourceIP   string         `json:"source_ip,omitempty"`
	Status     string         `json:"status"` // ok, error, failure, denied
	DurationMs int64          `json:"duration_ms"`
	Summary    string         `json:"summary"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	PrevHash   string         `json:"prev_hash"`
	EntryHash  string         `json:"entry_hash"`
}

// AuditFilter defines query parameters for searching audit logs.
type AuditFilter struct {
	Category string
	Action   string
	ActorID  string
	Status   string
	TraceID  string
	Limit    int
}

// ChainVerificationResult reports the integrity status of the SHA-256 hash-chained audit trail.
type ChainVerificationResult struct {
	Valid       bool   `json:"valid"`
	TotalEvents int    `json:"total_events"`
	LastHash    string `json:"last_hash"`
	BrokenAtID  int64  `json:"broken_at_id,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// AuditLogger manages tamper-evident SHA-256 hash-chained audit logging.
type AuditLogger struct {
	mu       sync.RWMutex
	cfg      core.AuditConfig
	db       *database.DB
	logger   *core.Logger
	events   []AuditEvent
	lastHash string
	nextID   int64
}

// NewAuditLogger creates and initializes an AuditLogger.
func NewAuditLogger(cfg core.AuditConfig, db *database.DB, logger *core.Logger) (*AuditLogger, error) {
	if cfg.MaxMemoryLog <= 0 {
		cfg.MaxMemoryLog = 1000
	}
	al := &AuditLogger{
		cfg:      cfg,
		db:       db,
		logger:   logger,
		events:   make([]AuditEvent, 0, 128),
		lastHash: GenesisHash,
		nextID:   1,
	}

	if db != nil && !db.IsInMemory() && db.DB != nil {
		const createSQL = `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			event_id TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			trace_id TEXT,
			category TEXT NOT NULL,
			action TEXT NOT NULL,
			actor_type TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			source_ip TEXT,
			status TEXT NOT NULL,
			duration_ms INTEGER NOT NULL,
			summary TEXT,
			metadata_json TEXT,
			prev_hash TEXT NOT NULL,
			entry_hash TEXT NOT NULL
		);`
		if _, err := db.Exec(createSQL); err != nil {
			return nil, fmt.Errorf("failed to initialize audit_logs table: %w", err)
		}
	}

	if cfg.FilePath != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create audit log directory: %w", err)
		}
	}

	return al, nil
}

func generateEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "evt_" + hex.EncodeToString(b)
}

func computeEntryHash(ev AuditEvent) string {
	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|%s",
		ev.ID,
		ev.EventID,
		ev.Timestamp.UTC().Format(time.RFC3339Nano),
		ev.TraceID,
		ev.Category,
		ev.Action,
		ev.ActorType,
		ev.ActorID,
		ev.Status,
		ev.DurationMs,
		ev.Summary,
		ev.PrevHash,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// Record appends a new event to the tamper-evident audit trail and returns the finalized event with hashes.
func (al *AuditLogger) Record(ev AuditEvent) (AuditEvent, error) {
	if al == nil {
		return ev, nil
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	ev.ID = al.nextID
	al.nextID++
	if ev.EventID == "" {
		ev.EventID = generateEventID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	} else {
		ev.Timestamp = ev.Timestamp.UTC()
	}
	if ev.Category == "" {
		ev.Category = "system"
	}
	if ev.ActorType == "" {
		ev.ActorType = "anonymous"
	}
	if ev.ActorID == "" {
		ev.ActorID = "anonymous"
	}
	if ev.Status == "" {
		ev.Status = "ok"
	}

	ev.PrevHash = al.lastHash
	ev.EntryHash = computeEntryHash(ev)
	al.lastHash = ev.EntryHash

	if len(al.events) >= al.cfg.MaxMemoryLog {
		// Retain sliding window in memory while preserving chain continuity internally
		al.events = append(al.events[1:], ev)
	} else {
		al.events = append(al.events, ev)
	}

	if al.cfg.FilePath != "" {
		f, err := os.OpenFile(al.cfg.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			_ = json.NewEncoder(f).Encode(ev)
			_ = f.Close()
		}
	}

	if al.db != nil && !al.db.IsInMemory() && al.db.DB != nil {
		metaBytes, _ := json.Marshal(ev.Metadata)
		_, _ = al.db.Exec(
			`INSERT INTO audit_logs(event_id, timestamp, trace_id, category, action, actor_type, actor_id, source_ip, status, duration_ms, summary, metadata_json, prev_hash, entry_hash)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ev.EventID, ev.Timestamp, ev.TraceID, ev.Category, ev.Action, ev.ActorType, ev.ActorID,
			ev.SourceIP, ev.Status, ev.DurationMs, ev.Summary, string(metaBytes), ev.PrevHash, ev.EntryHash,
		)
	}

	if al.logger != nil {
		al.logger.LogStructured("INFO", "audit", ev.TraceID, fmt.Sprintf("[%s:%s] actor=%s:%s status=%s — %s",
			ev.Category, ev.Action, ev.ActorType, ev.ActorID, ev.Status, ev.Summary), map[string]any{
			"event_id":   ev.EventID,
			"entry_hash": ev.EntryHash,
		})
	}

	return ev, nil
}

// Query returns audit events matching the provided filter (newest first).
func (al *AuditLogger) Query(filter AuditFilter) []AuditEvent {
	if al == nil {
		return nil
	}
	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	al.mu.RLock()
	defer al.mu.RUnlock()

	catFilter := strings.ToLower(strings.TrimSpace(filter.Category))
	actFilter := strings.ToLower(strings.TrimSpace(filter.Action))
	actorFilter := strings.ToLower(strings.TrimSpace(filter.ActorID))
	statusFilter := strings.ToLower(strings.TrimSpace(filter.Status))
	traceFilter := strings.TrimSpace(filter.TraceID)

	result := make([]AuditEvent, 0, limit)
	for i := len(al.events) - 1; i >= 0 && len(result) < limit; i-- {
		ev := al.events[i]
		if catFilter != "" && strings.ToLower(ev.Category) != catFilter {
			continue
		}
		if actFilter != "" && !strings.Contains(strings.ToLower(ev.Action), actFilter) {
			continue
		}
		if actorFilter != "" && strings.ToLower(ev.ActorID) != actorFilter {
			continue
		}
		if statusFilter != "" && strings.ToLower(ev.Status) != statusFilter {
			continue
		}
		if traceFilter != "" && ev.TraceID != traceFilter {
			continue
		}
		result = append(result, ev)
	}
	return result
}

// VerifyChain validates the cryptographic SHA-256 hash chain across all retained audit events.
func (al *AuditLogger) VerifyChain() ChainVerificationResult {
	if al == nil {
		return ChainVerificationResult{Valid: true, TotalEvents: 0, LastHash: GenesisHash}
	}

	al.mu.RLock()
	defer al.mu.RUnlock()

	if len(al.events) == 0 {
		return ChainVerificationResult{
			Valid:       true,
			TotalEvents: 0,
			LastHash:    al.lastHash,
		}
	}

	for i, ev := range al.events {
		expectedEntryHash := computeEntryHash(ev)
		if ev.EntryHash != expectedEntryHash {
			return ChainVerificationResult{
				Valid:       false,
				TotalEvents: len(al.events),
				LastHash:    al.lastHash,
				BrokenAtID:  ev.ID,
				Reason:      fmt.Sprintf("entry_hash mismatch at event ID %d (expected %s, got %s)", ev.ID, expectedEntryHash, ev.EntryHash),
			}
		}
		if i == 0 && ev.ID == 1 && ev.PrevHash != GenesisHash {
			return ChainVerificationResult{
				Valid:       false,
				TotalEvents: len(al.events),
				LastHash:    al.lastHash,
				BrokenAtID:  ev.ID,
				Reason:      fmt.Sprintf("genesis prev_hash mismatch at event ID 1 (got %s)", ev.PrevHash),
			}
		}
		if i > 0 {
			prev := al.events[i-1]
			if ev.PrevHash != prev.EntryHash {
				return ChainVerificationResult{
					Valid:       false,
					TotalEvents: len(al.events),
					LastHash:    al.lastHash,
					BrokenAtID:  ev.ID,
					Reason:      fmt.Sprintf("chain link broken between ID %d and ID %d", prev.ID, ev.ID),
				}
			}
		}
	}

	return ChainVerificationResult{
		Valid:       true,
		TotalEvents: len(al.events),
		LastHash:    al.lastHash,
	}
}

// Count returns the number of audit events currently retained.
func (al *AuditLogger) Count() int {
	if al == nil {
		return 0
	}
	al.mu.RLock()
	defer al.mu.RUnlock()
	return len(al.events)
}
