package jobs

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go-admin-tool/internal/database"
)

// JobStore defines the persistence interface for asynchronous jobs.
type JobStore interface {
	// SaveJob inserts a new job or updates an existing job's status and execution metadata.
	SaveJob(job *Job) error

	// GetJob retrieves a job by ID. Returns (job, true) if found, or (nil, false) if not found.
	GetJob(id string) (*Job, bool)

	// ListJobs returns a filtered, paginated slice of jobs sorted newest first, along with the total count.
	ListJobs(filter JobFilter) ([]*Job, int)

	// Prune deletes terminal jobs (completed, failed, cancelled, timed_out) older than maxAge.
	// If maxCount > 0, it also caps the total retained terminal jobs to maxCount.
	// Non-terminal jobs (queued, running) are NEVER pruned.
	Prune(maxAge time.Duration, maxCount int) error

	// Close releases any database or background resources.
	Close() error
}

// NewJobStore creates a JobStore instance. If db is nil or in-memory, MemoryJobStore is returned.
func NewJobStore(db *database.DB) (JobStore, error) {
	if db == nil || db.IsInMemory() || db.DB == nil {
		return NewMemoryJobStore(), nil
	}
	return NewSQLiteJobStore(db)
}

// MemoryJobStore is a thread-safe in-memory implementation of JobStore.
type MemoryJobStore struct {
	mu    sync.RWMutex
	jobs  map[string]Job // stores snapshot values for thread-safety and immutability
	order []string       // job IDs in insertion order
}

// NewMemoryJobStore creates an initialized MemoryJobStore.
func NewMemoryJobStore() *MemoryJobStore {
	return &MemoryJobStore{
		jobs:  make(map[string]Job),
		order: make([]string, 0),
	}
}

func (m *MemoryJobStore) SaveJob(job *Job) error {
	if job == nil {
		return errors.New("cannot save nil job")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	snap := job.Snapshot()
	if _, exists := m.jobs[snap.ID]; !exists {
		m.order = append(m.order, snap.ID)
	}
	m.jobs[snap.ID] = snap
	return nil
}

func (m *MemoryJobStore) GetJob(id string) (*Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snap, exists := m.jobs[id]
	if !exists {
		return nil, false
	}
	j := snap.Snapshot()
	return &j, true
}

func (m *MemoryJobStore) ListJobs(filter JobFilter) ([]*Job, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []*Job
	// Walk in reverse order (newest first)
	for i := len(m.order) - 1; i >= 0; i-- {
		id := m.order[i]
		snap, exists := m.jobs[id]
		if !exists {
			continue
		}
		if filter.Matches(&snap) {
			copySnap := snap.Snapshot()
			matched = append(matched, &copySnap)
		}
	}

	total := len(matched)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		return []*Job{}, total
	}

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return matched[offset:end], total
}

func (m *MemoryJobStore) Prune(maxAge time.Duration, maxCount int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	cutoff := now.Add(-maxAge)

	var retainedOrder []string
	var terminalIDs []string

	for _, id := range m.order {
		snap, exists := m.jobs[id]
		if !exists {
			continue
		}
		// Non-terminal jobs are NEVER pruned
		if !snap.Status.IsTerminal() {
			retainedOrder = append(retainedOrder, id)
			continue
		}

		// Terminal job: check age
		t := snap.CreatedAt
		if snap.CompletedAt != nil {
			t = *snap.CompletedAt
		}
		if maxAge > 0 && t.Before(cutoff) {
			delete(m.jobs, id)
			continue
		}

		terminalIDs = append(terminalIDs, id)
		retainedOrder = append(retainedOrder, id)
	}

	// Cap terminal jobs to maxCount if maxCount > 0
	if maxCount > 0 && len(terminalIDs) > maxCount {
		excess := len(terminalIDs) - maxCount
		for i := 0; i < excess; i++ {
			delete(m.jobs, terminalIDs[i])
		}
		var newOrder []string
		for _, id := range retainedOrder {
			if _, exists := m.jobs[id]; exists {
				newOrder = append(newOrder, id)
			}
		}
		retainedOrder = newOrder
	}

	m.order = retainedOrder
	return nil
}

func (m *MemoryJobStore) Close() error {
	return nil
}

// SQLiteJobStore is a persistent SQLite-backed implementation of JobStore.
type SQLiteJobStore struct {
	db *database.DB
}

// NewSQLiteJobStore creates and initializes a SQLite-backed JobStore.
func NewSQLiteJobStore(db *database.DB) (*SQLiteJobStore, error) {
	if db == nil || db.DB == nil {
		return nil, errors.New("database connection is not initialized")
	}

	s := &SQLiteJobStore{db: db}
	if err := s.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize job_history schema: %w", err)
	}
	return s, nil
}

func (s *SQLiteJobStore) initSchema() error {
	const createSQL = `
	CREATE TABLE IF NOT EXISTS job_history (
		id TEXT NOT NULL PRIMARY KEY,
		type TEXT NOT NULL,
		action TEXT NOT NULL,
		plugin_id TEXT,
		params TEXT,
		priority TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		started_at DATETIME,
		completed_at DATETIME,
		duration_ms INTEGER DEFAULT 0,
		timeout INTEGER DEFAULT 0,
		actor_type TEXT,
		actor_id TEXT,
		source_ip TEXT,
		error TEXT,
		result_data TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_job_history_status ON job_history(status);
	CREATE INDEX IF NOT EXISTS idx_job_history_action ON job_history(action);
	CREATE INDEX IF NOT EXISTS idx_job_history_actor_id ON job_history(actor_id);
	CREATE INDEX IF NOT EXISTS idx_job_history_created_at ON job_history(created_at DESC);
	`
	_, err := s.db.Exec(createSQL)
	return err
}

func (s *SQLiteJobStore) SaveJob(job *Job) error {
	if job == nil {
		return errors.New("cannot save nil job")
	}
	if s.db == nil || s.db.DB == nil {
		return errors.New("database not available")
	}

	snap := job.Snapshot()

	var paramsJSON sql.NullString
	if snap.Params != nil {
		if b, err := json.Marshal(snap.Params); err == nil {
			paramsJSON = sql.NullString{String: string(b), Valid: true}
		}
	}

	var resultJSON sql.NullString
	if snap.ResultData != nil {
		if b, err := json.Marshal(snap.ResultData); err == nil {
			resultJSON = sql.NullString{String: string(b), Valid: true}
		}
	}

	var startedAt sql.NullTime
	if snap.StartedAt != nil {
		startedAt = sql.NullTime{Time: *snap.StartedAt, Valid: true}
	}

	var completedAt sql.NullTime
	if snap.CompletedAt != nil {
		completedAt = sql.NullTime{Time: *snap.CompletedAt, Valid: true}
	}

	const upsertSQL = `
	INSERT INTO job_history (
		id, type, action, plugin_id, params, priority, status,
		created_at, started_at, completed_at, duration_ms, timeout,
		actor_type, actor_id, source_ip, error, result_data
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		status = excluded.status,
		started_at = excluded.started_at,
		completed_at = excluded.completed_at,
		duration_ms = excluded.duration_ms,
		error = excluded.error,
		result_data = excluded.result_data;
	`
	_, err := s.db.Exec(
		upsertSQL,
		snap.ID,
		string(snap.Type),
		snap.Action,
		snap.PluginID,
		paramsJSON,
		string(snap.Priority),
		string(snap.Status),
		snap.CreatedAt,
		startedAt,
		completedAt,
		snap.DurationMs,
		int64(snap.Timeout),
		snap.ActorType,
		snap.ActorID,
		snap.SourceIP,
		snap.Error,
		resultJSON,
	)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanJob(scanner rowScanner) (*Job, error) {
	var (
		id          string
		jobType     string
		action      string
		pluginID    sql.NullString
		paramsJSON  sql.NullString
		priority    string
		status      string
		createdAt   time.Time
		startedAt   sql.NullTime
		completedAt sql.NullTime
		durationMs  int64
		timeoutNano int64
		actorType   sql.NullString
		actorID     sql.NullString
		sourceIP    sql.NullString
		errMsg      sql.NullString
		resultJSON  sql.NullString
	)

	err := scanner.Scan(
		&id, &jobType, &action, &pluginID, &paramsJSON, &priority, &status,
		&createdAt, &startedAt, &completedAt, &durationMs, &timeoutNano,
		&actorType, &actorID, &sourceIP, &errMsg, &resultJSON,
	)
	if err != nil {
		return nil, err
	}

	job := &Job{
		ID:         id,
		Type:       JobType(jobType),
		Action:     action,
		PluginID:   pluginID.String,
		Priority:   Priority(priority),
		Status:     JobStatus(status),
		CreatedAt:  createdAt,
		DurationMs: durationMs,
		Timeout:    time.Duration(timeoutNano),
		ActorType:  actorType.String,
		ActorID:    actorID.String,
		SourceIP:   sourceIP.String,
		Error:      errMsg.String,
	}

	if startedAt.Valid {
		t := startedAt.Time
		job.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		job.CompletedAt = &t
	}
	if paramsJSON.Valid && paramsJSON.String != "" {
		var params map[string]any
		if err := json.Unmarshal([]byte(paramsJSON.String), &params); err == nil {
			job.Params = params
		}
	}
	if resultJSON.Valid && resultJSON.String != "" {
		var res any
		if err := json.Unmarshal([]byte(resultJSON.String), &res); err == nil {
			job.ResultData = res
		} else {
			job.ResultData = resultJSON.String
		}
	}

	return job, nil
}

func (s *SQLiteJobStore) GetJob(id string) (*Job, bool) {
	if s.db == nil || s.db.DB == nil {
		return nil, false
	}
	const querySQL = `
	SELECT id, type, action, plugin_id, params, priority, status,
	       created_at, started_at, completed_at, duration_ms, timeout,
	       actor_type, actor_id, source_ip, error, result_data
	FROM job_history WHERE id = ? LIMIT 1
	`
	row := s.db.QueryRow(querySQL, id)
	job, err := scanJob(row)
	if err != nil {
		return nil, false
	}
	return job, true
}

func (s *SQLiteJobStore) ListJobs(filter JobFilter) ([]*Job, int) {
	if s.db == nil || s.db.DB == nil {
		return nil, 0
	}

	var whereClauses []string
	var args []any

	if filter.Status != "" {
		whereClauses = append(whereClauses, "status = ?")
		args = append(args, string(filter.Status))
	}
	if filter.Type != "" {
		whereClauses = append(whereClauses, "type = ?")
		args = append(args, string(filter.Type))
	}
	if filter.Action != "" {
		whereClauses = append(whereClauses, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.ActorID != "" {
		whereClauses = append(whereClauses, "actor_id = ?")
		args = append(args, filter.ActorID)
	}
	if filter.ActorType != "" {
		whereClauses = append(whereClauses, "actor_type = ?")
		args = append(args, filter.ActorType)
	}
	if filter.Since != nil {
		whereClauses = append(whereClauses, "created_at >= ?")
		args = append(args, *filter.Since)
	}

	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = " WHERE " + strings.Join(whereClauses, " AND ")
	}

	countSQL := "SELECT COUNT(*) FROM job_history" + whereSQL
	var total int
	if err := s.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0
	}

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	querySQL := fmt.Sprintf(`
	SELECT id, type, action, plugin_id, params, priority, status,
	       created_at, started_at, completed_at, duration_ms, timeout,
	       actor_type, actor_id, source_ip, error, result_data
	FROM job_history%s ORDER BY created_at DESC LIMIT %d OFFSET %d`, whereSQL, limit, offset)

	rows, err := s.db.Query(querySQL, args...)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()

	var jobsList []*Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, 0
		}
		jobsList = append(jobsList, job)
	}
	return jobsList, total
}

func (s *SQLiteJobStore) Prune(maxAge time.Duration, maxCount int) error {
	if s.db == nil || s.db.DB == nil {
		return nil
	}

	if maxAge > 0 {
		cutoff := time.Now().UTC().Add(-maxAge)
		const pruneAgeSQL = `
		DELETE FROM job_history
		WHERE status IN ('completed', 'failed', 'cancelled', 'timed_out')
		  AND (completed_at < ? OR (completed_at IS NULL AND created_at < ?))
		`
		if _, err := s.db.Exec(pruneAgeSQL, cutoff, cutoff); err != nil {
			return err
		}
	}

	if maxCount > 0 {
		const pruneCountSQL = `
		DELETE FROM job_history
		WHERE id IN (
			SELECT id FROM job_history
			WHERE status IN ('completed', 'failed', 'cancelled', 'timed_out')
			ORDER BY created_at DESC
			LIMIT -1 OFFSET ?
		)
		`
		if _, err := s.db.Exec(pruneCountSQL, maxCount); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteJobStore) Close() error {
	return nil
}
