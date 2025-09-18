package database

import (
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

type ActionHistory struct {
	ID        int64
	Timestamp time.Time
	Command   string
	Status    string // e.g., "success", "failure"
	Output    string
}

type DB struct {
	*sql.DB
}

func NewDB(dataSourceName string) (*DB, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

func (db *DB) Init() error {
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
