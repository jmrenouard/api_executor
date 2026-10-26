package database

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockSQLDriver struct {
	mu        sync.Mutex
	failPing  bool
	failPrep  bool
	failExec  bool
	failQuery bool
	badScan   bool
	rows      []ActionHistory
}

type mockSQLConn struct {
	drv *mockSQLDriver
}

type mockSQLStmt struct {
	drv   *mockSQLDriver
	query string
}

type mockSQLResult struct {
	id int64
}

func (r mockSQLResult) LastInsertId() (int64, error) { return r.id, nil }
func (r mockSQLResult) RowsAffected() (int64, error) { return 1, nil }

type mockSQLRows struct {
	cols    []string
	values  [][]driver.Value
	idx     int
	badScan bool
}

func (r *mockSQLRows) Columns() []string { return r.cols }
func (r *mockSQLRows) Close() error      { return nil }
func (r *mockSQLRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.values) {
		return io.EOF
	}
	if r.badScan {
		dest[0] = "not-an-int64"
		r.idx++
		return nil
	}
	row := r.values[r.idx]
	for i := range dest {
		if i < len(row) {
			dest[i] = row[i]
		}
	}
	r.idx++
	return nil
}

var (
	registerMockDriverOnce sync.Once
	activeMockDriver       = &mockSQLDriver{}
)

func (d *mockSQLDriver) Open(_ string) (driver.Conn, error) {
	return &mockSQLConn{drv: d}, nil
}

func (c *mockSQLConn) Prepare(query string) (driver.Stmt, error) {
	c.drv.mu.Lock()
	defer c.drv.mu.Unlock()
	if c.drv.failPrep {
		return nil, errors.New("mock prepare failure")
	}
	return &mockSQLStmt{drv: c.drv, query: query}, nil
}

func (c *mockSQLConn) Close() error              { return nil }
func (c *mockSQLConn) Begin() (driver.Tx, error) { return nil, errors.New("not supported") }

func (s *mockSQLStmt) Close() error  { return nil }
func (s *mockSQLStmt) NumInput() int { return -1 }

func (s *mockSQLStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.drv.mu.Lock()
	defer s.drv.mu.Unlock()
	if s.drv.failExec {
		return nil, errors.New("mock exec failure")
	}
	if strings.Contains(strings.ToUpper(s.query), "INSERT INTO ACTION_HISTORY") && len(args) >= 4 {
		id := int64(len(s.drv.rows) + 1)
		ts, _ := args[0].(time.Time)
		cmd, _ := args[1].(string)
		st, _ := args[2].(string)
		out, _ := args[3].(string)
		s.drv.rows = append(s.drv.rows, ActionHistory{
			ID:        id,
			Timestamp: ts,
			Command:   cmd,
			Status:    st,
			Output:    out,
		})
		return mockSQLResult{id: id}, nil
	}
	return mockSQLResult{id: 1}, nil
}

func (s *mockSQLStmt) Query(_ []driver.Value) (driver.Rows, error) {
	s.drv.mu.Lock()
	defer s.drv.mu.Unlock()
	if s.drv.failQuery {
		return nil, errors.New("mock query failure")
	}
	upper := strings.ToUpper(s.query)
	if strings.Contains(upper, "SELECT COUNT(*)") {
		return &mockSQLRows{
			cols:   []string{"count"},
			values: [][]driver.Value{{int64(len(s.drv.rows))}},
		}, nil
	}
	vals := make([][]driver.Value, 0, len(s.drv.rows))
	for i := len(s.drv.rows) - 1; i >= 0; i-- {
		rec := s.drv.rows[i]
		vals = append(vals, []driver.Value{rec.ID, rec.Timestamp, rec.Command, rec.Status, rec.Output})
	}
	return &mockSQLRows{
		cols:    []string{"id", "timestamp", "command", "status", "output"},
		values:  vals,
		badScan: s.drv.badScan,
	}, nil
}

func newMockSQLBackedDB(t *testing.T) (*DB, *mockSQLDriver) {
	t.Helper()
	registerMockDriverOnce.Do(func() {
		sql.Register("mock_sqlite_test", activeMockDriver)
	})
	activeMockDriver.mu.Lock()
	activeMockDriver.failPing = false
	activeMockDriver.failPrep = false
	activeMockDriver.failExec = false
	activeMockDriver.failQuery = false
	activeMockDriver.badScan = false
	activeMockDriver.rows = nil
	activeMockDriver.mu.Unlock()

	rawDB, err := sql.Open("mock_sqlite_test", "test.db")
	if err != nil {
		t.Fatalf("sql.Open mock_sqlite_test failed: %v", err)
	}
	return &DB{
		DB:       rawDB,
		inMemory: false,
		dsn:      "mock://test.db",
	}, activeMockDriver
}

func TestDatabaseRecordActionAndValidation(t *testing.T) {
	if _, err := NewDB("   "); err == nil {
		t.Errorf("expected error for empty database path")
	}

	// Verify nil receiver safety across all methods
	var nilDB *DB
	if !nilDB.IsInMemory() {
		t.Errorf("expected nil DB IsInMemory() to return true")
	}
	if nilDB.DSN() != "" {
		t.Errorf("expected nil DB DSN() to return empty string, got %q", nilDB.DSN())
	}
	if err := nilDB.Close(); err != nil {
		t.Errorf("expected nil DB Close() to return nil, got %v", err)
	}
	if _, err := nilDB.ListActions(10); err == nil {
		t.Errorf("expected nil DB ListActions() to return error")
	}
	if cnt, err := nilDB.CountActions(); err != nil || cnt != 0 {
		t.Errorf("expected nil DB CountActions() to return (0, nil), got (%d, %v)", cnt, err)
	}

	tmpDir := t.TempDir()
	dsn := filepath.Join(tmpDir, "history.db")
	db, err := NewDB(dsn)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	if db.DSN() != dsn {
		t.Errorf("expected DSN %q, got %q", dsn, db.DSN())
	}
	_ = db.IsInMemory()

	if err := db.Init(); err != nil {
		t.Fatalf("db.Init() failed: %v", err)
	}

	id1, err := db.RecordAction("list-processes", "success", "pid 1")
	if err != nil {
		t.Fatalf("RecordAction failed: %v", err)
	}
	if id1 <= 0 {
		t.Errorf("expected positive row ID, got %d", id1)
	}

	id2, err := db.RecordAction("disk-usage", "failure", "exit status 1")
	if err != nil {
		t.Fatalf("second RecordAction failed: %v", err)
	}
	if id2 <= id1 {
		t.Errorf("expected monotonically increasing IDs, got id1=%d id2=%d", id1, id2)
	}

	// Verify CountActions and ListActions with default, bounded, and out-of-range limits
	cnt, err := db.CountActions()
	if err != nil {
		t.Fatalf("CountActions failed: %v", err)
	}
	if cnt != 2 {
		t.Errorf("expected CountActions=2, got %d", cnt)
	}

	actionsDefault, err := db.ListActions(0)
	if err != nil {
		t.Fatalf("ListActions(0) failed: %v", err)
	}
	if len(actionsDefault) != 2 || actionsDefault[0].Command != "disk-usage" {
		t.Errorf("expected newest action first in ListActions(0), got %+v", actionsDefault)
	}

	actionsCapped, err := db.ListActions(5000)
	if err != nil || len(actionsCapped) != 2 {
		t.Errorf("expected ListActions(5000) to return 2 records, got %d (err=%v)", len(actionsCapped), err)
	}

	actionsOne, err := db.ListActions(1)
	if err != nil || len(actionsOne) != 1 || actionsOne[0].ID != id2 {
		t.Errorf("expected ListActions(1) to return single newest record id=%d, got %+v", id2, actionsOne)
	}
}

func TestDatabaseSQLDriverBackedExecutionAndErrors(t *testing.T) {
	sqlDB, drv := newMockSQLBackedDB(t)
	defer sqlDB.Close()

	if sqlDB.IsInMemory() {
		t.Fatalf("expected SQL-backed DB IsInMemory() to be false")
	}
	if sqlDB.DSN() != "mock://test.db" {
		t.Fatalf("expected DSN mock://test.db, got %q", sqlDB.DSN())
	}

	if err := sqlDB.Init(); err != nil {
		t.Fatalf("sqlDB.Init() failed: %v", err)
	}

	id1, err := sqlDB.RecordAction("cmd-one", "success", "out-1")
	if err != nil || id1 != 1 {
		t.Fatalf("RecordAction 1 failed: id=%d err=%v", id1, err)
	}
	id2, err := sqlDB.RecordAction("cmd-two", "failure", "out-2")
	if err != nil || id2 != 2 {
		t.Fatalf("RecordAction 2 failed: id=%d err=%v", id2, err)
	}

	cnt, err := sqlDB.CountActions()
	if err != nil || cnt != 2 {
		t.Fatalf("expected CountActions=2 on SQL-backed DB, got %d (err=%v)", cnt, err)
	}

	listed, err := sqlDB.ListActions(10)
	if err != nil || len(listed) != 2 || listed[0].Command != "cmd-two" {
		t.Fatalf("expected 2 listed actions newest first, got %+v (err=%v)", listed, err)
	}

	// Test error branches on SQL-backed DB
	drv.mu.Lock()
	drv.failPrep = true
	drv.mu.Unlock()
	if _, err := sqlDB.RecordAction("cmd-fail-prep", "error", ""); err == nil {
		t.Errorf("expected RecordAction error when Prepare fails")
	}

	drv.mu.Lock()
	drv.failPrep = false
	drv.failExec = true
	drv.mu.Unlock()
	if _, err := sqlDB.RecordAction("cmd-fail-exec", "error", ""); err == nil {
		t.Errorf("expected RecordAction error when Exec fails")
	}
	if err := sqlDB.Init(); err == nil {
		t.Errorf("expected Init error when Exec fails")
	}

	drv.mu.Lock()
	drv.failExec = false
	drv.failQuery = true
	drv.mu.Unlock()
	if _, err := sqlDB.ListActions(10); err == nil {
		t.Errorf("expected ListActions error when Query fails")
	}

	drv.mu.Lock()
	drv.failQuery = false
	drv.badScan = true
	drv.mu.Unlock()
	if _, err := sqlDB.ListActions(10); err == nil {
		t.Errorf("expected ListActions error when rows.Scan fails")
	}
}
