package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// Default SQLite connection pool and timeout parameters
const (
	// DefaultMaxOpenConns is the safe SQLite single-writer connection limit to prevent concurrency locking.
	DefaultMaxOpenConns = 1
	// DefaultMaxIdleConns is the idle connection pool limit.
	DefaultMaxIdleConns = 1
	// DefaultConnMaxLifetime is the maximum lifetime of an idle connection.
	DefaultConnMaxLifetime = time.Hour
	// DefaultBusyTimeoutMs is the SQLite busy handler wait duration in milliseconds before returning busy.
	DefaultBusyTimeoutMs = 5000
)

type ActionHistory struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
	Status    string    `json:"status"` // e.g., "success", "failure", "error"
	Output    string    `json:"output"`
}

type DB struct {
	*sql.DB
	mu       sync.RWMutex
	inMemory bool
	dsn      string
	records  []ActionHistory
}

// BuildDSN formats and augments a SQLite data source name with WAL mode, busy timeout,
// synchronous, and foreign keys parameters if not already present.
func BuildDSN(dataSourceName string) string {
	trimmed := strings.TrimSpace(dataSourceName)
	if trimmed == "" {
		return trimmed
	}
	if trimmed == ":memory:" {
		return trimmed
	}

	separator := "?"
	if strings.Contains(trimmed, "?") {
		separator = "&"
	}

	params := make([]string, 0, 4)
	if !strings.Contains(trimmed, "_journal_mode=") && !strings.Contains(trimmed, "_journal=") {
		params = append(params, "_journal_mode=WAL")
	}
	if !strings.Contains(trimmed, "_busy_timeout=") && !strings.Contains(trimmed, "_timeout=") {
		params = append(params, fmt.Sprintf("_busy_timeout=%d", DefaultBusyTimeoutMs))
	}
	if !strings.Contains(trimmed, "_synchronous=") && !strings.Contains(trimmed, "_sync=") {
		params = append(params, "_synchronous=NORMAL")
	}
	if !strings.Contains(trimmed, "_foreign_keys=") && !strings.Contains(trimmed, "_fk=") {
		params = append(params, "_foreign_keys=ON")
	}

	if len(params) == 0 {
		return trimmed
	}
	return trimmed + separator + strings.Join(params, "&")
}

// ConfigurePool applies connection pool limits onto *sql.DB for safe SQLite single-writer WAL operation.
func ConfigurePool(db *sql.DB) {
	if db == nil {
		return
	}
	db.SetMaxOpenConns(DefaultMaxOpenConns)
	db.SetMaxIdleConns(DefaultMaxIdleConns)
	db.SetConnMaxLifetime(DefaultConnMaxLifetime)
}

func NewDB(dataSourceName string) (*DB, error) {
	trimmed := strings.TrimSpace(dataSourceName)
	if trimmed == "" {
		return nil, errors.New("database path cannot be empty")
	}
	dsn := BuildDSN(trimmed)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	// Apply safe connection pool limits for SQLite single-writer architecture
	ConfigurePool(db)

	if err = db.Ping(); err != nil {
		_ = db.Close()
		// Fallback to thread-safe in-memory storage when compiled with CGO_ENABLED=0
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			return &DB{inMemory: true, dsn: trimmed}, nil
		}
		return nil, err
	}

	res := &DB{DB: db, dsn: trimmed}
	if err := res.applyPragmas(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to configure sqlite pragmas: %w", err)
	}
	return res, nil
}

// IsInMemory reports whether the DB is operating in pure-Go in-memory fallback mode (when CGO_ENABLED=0).
func (db *DB) IsInMemory() bool {
	if db == nil {
		return true
	}
	return db.inMemory
}

// DSN returns the configured data source name / file path.
func (db *DB) DSN() string {
	if db == nil {
		return ""
	}
	return db.dsn
}

func (db *DB) Close() error {
	if db == nil || db.DB == nil {
		return nil
	}
	return db.DB.Close()
}

// applyPragmas executes SQLite PRAGMA statements to configure WAL mode, busy timeout,
// synchronous NORMAL, and foreign keys ON on the active database connection.
func (db *DB) applyPragmas() error {
	if db == nil || db.inMemory || db.DB == nil {
		return nil
	}
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		fmt.Sprintf("PRAGMA busy_timeout=%d;", DefaultBusyTimeoutMs),
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
	}
	for _, pragma := range pragmas {
		if _, err := db.DB.Exec(pragma); err != nil {
			return fmt.Errorf("failed to execute %s: %w", pragma, err)
		}
	}
	return nil
}

// GetPragma queries the active value of a SQLite PRAGMA (journal_mode, busy_timeout, synchronous, foreign_keys).
func (db *DB) GetPragma(name string) (string, error) {
	if db == nil {
		return "", errors.New("database is not initialized")
	}
	cleanName := strings.ToLower(strings.TrimSpace(name))
	switch cleanName {
	case "journal_mode", "busy_timeout", "synchronous", "foreign_keys":
	default:
		return "", fmt.Errorf("unsupported pragma: %s", name)
	}

	if db.inMemory || db.DB == nil {
		switch cleanName {
		case "journal_mode":
			return "memory", nil
		case "busy_timeout":
			return fmt.Sprintf("%d", DefaultBusyTimeoutMs), nil
		case "synchronous":
			return "1", nil
		case "foreign_keys":
			return "1", nil
		}
	}

	var val string
	err := db.QueryRow(fmt.Sprintf("PRAGMA %s;", cleanName)).Scan(&val)
	return val, err
}

// PoolStats returns the connection pool statistics from the underlying *sql.DB.
func (db *DB) PoolStats() sql.DBStats {
	if db == nil || db.DB == nil {
		return sql.DBStats{}
	}
	return db.DB.Stats()
}

// MaxOpenConns returns the configured max open connections limit.
func (db *DB) MaxOpenConns() int {
	return DefaultMaxOpenConns
}

// MaxIdleConns returns the configured max idle connections limit.
func (db *DB) MaxIdleConns() int {
	return DefaultMaxIdleConns
}

// ConnMaxLifetime returns the configured connection max lifetime.
func (db *DB) ConnMaxLifetime() time.Duration {
	return DefaultConnMaxLifetime
}

// BusyTimeout returns the configured SQLite busy timeout duration.
func (db *DB) BusyTimeout() time.Duration {
	return time.Duration(DefaultBusyTimeoutMs) * time.Millisecond
}

func (db *DB) Init() error {
	if db == nil {
		return errors.New("database is not initialized")
	}
	if db.inMemory || db.DB == nil {
		return nil
	}
	if err := db.applyPragmas(); err != nil {
		return err
	}
	const sqlStmt = `
	CREATE TABLE IF NOT EXISTS action_history (
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		command TEXT NOT NULL,
		status TEXT NOT NULL,
		output TEXT
	);
	`
	_, err := db.Exec(sqlStmt)
	return err
}

func (db *DB) RecordAction(command, status, output string) (int64, error) {
	if db.inMemory {
		db.mu.Lock()
		defer db.mu.Unlock()
		id := int64(len(db.records) + 1)
		db.records = append(db.records, ActionHistory{
			ID:        id,
			Timestamp: time.Now().UTC(),
			Command:   command,
			Status:    status,
			Output:    output,
		})
		return id, nil
	}

	res, err := db.Exec("INSERT INTO action_history(timestamp, command, status, output) VALUES(?, ?, ?, ?)", time.Now().UTC(), command, status, output)
	if err != nil {
		return 0, err
	}

	return res.LastInsertId()
}

// ListActions returns the most recent action history entries up to limit (newest first).
func (db *DB) ListActions(limit int) ([]ActionHistory, error) {
	if db == nil {
		return nil, errors.New("database is not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	if db.inMemory {
		db.mu.RLock()
		defer db.mu.RUnlock()
		out := make([]ActionHistory, 0, limit)
		for i := len(db.records) - 1; i >= 0 && len(out) < limit; i-- {
			out = append(out, db.records[i])
		}
		return out, nil
	}

	rows, err := db.Query(fmt.Sprintf("SELECT id, timestamp, command, status, output FROM action_history ORDER BY id DESC LIMIT %d", limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ActionHistory
	for rows.Next() {
		var rec ActionHistory
		if err := rows.Scan(&rec.ID, &rec.Timestamp, &rec.Command, &rec.Status, &rec.Output); err != nil {
			return nil, err
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

// CountActions returns the total number of recorded actions.
func (db *DB) CountActions() (int, error) {
	if db == nil {
		return 0, nil
	}
	if db.inMemory {
		db.mu.RLock()
		defer db.mu.RUnlock()
		return len(db.records), nil
	}
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM action_history").Scan(&count)
	return count, err
}
