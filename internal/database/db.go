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

func NewDB(dataSourceName string) (*DB, error) {
	trimmed := strings.TrimSpace(dataSourceName)
	if trimmed == "" {
		return nil, errors.New("database path cannot be empty")
	}
	db, err := sql.Open("sqlite3", trimmed)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		_ = db.Close()
		// Fallback to thread-safe in-memory storage when compiled with CGO_ENABLED=0
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			return &DB{inMemory: true, dsn: trimmed}, nil
		}
		return nil, err
	}
	return &DB{DB: db, dsn: trimmed}, nil
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

func (db *DB) Init() error {
	if db.inMemory {
		return nil
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

	stmt, err := db.Prepare("INSERT INTO action_history(timestamp, command, status, output) VALUES(?, ?, ?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	res, err := stmt.Exec(time.Now().UTC(), command, status, output)
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
