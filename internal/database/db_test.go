package database

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockSQLDriver struct {
	mu          sync.Mutex
	failPing    bool
	failPrep    bool
	failExec    bool
	failQuery   bool
	badScan     bool
	rows        []ActionHistory
	pragmas     map[string]string
	executedSQL []string
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
	activeMockDriver       = &mockSQLDriver{
		pragmas: make(map[string]string),
	}
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
	upper := strings.ToUpper(strings.TrimSpace(s.query))
	s.drv.executedSQL = append(s.drv.executedSQL, s.query)
	if strings.HasPrefix(upper, "PRAGMA ") {
		clean := strings.TrimSuffix(strings.TrimSpace(s.query[7:]), ";")
		parts := strings.SplitN(clean, "=", 2)
		if len(parts) == 2 {
			k := strings.ToLower(strings.TrimSpace(parts[0]))
			v := strings.TrimSpace(parts[1])
			s.drv.pragmas[k] = v
		}
		return mockSQLResult{id: 1}, nil
	}
	if strings.Contains(upper, "INSERT INTO ACTION_HISTORY") && len(args) >= 4 {
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
	upper := strings.ToUpper(strings.TrimSpace(s.query))
	if strings.HasPrefix(upper, "PRAGMA ") {
		clean := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.query[7:]), ";"))
		val := s.drv.pragmas[clean]
		if val == "" {
			switch clean {
			case "journal_mode":
				val = "WAL"
			case "busy_timeout":
				val = "5000"
			case "synchronous":
				val = "NORMAL"
			case "foreign_keys":
				val = "ON"
			default:
				val = "1"
			}
		}
		return &mockSQLRows{
			cols:    []string{clean},
			values:  [][]driver.Value{{val}},
			badScan: s.drv.badScan,
		}, nil
	}
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
	activeMockDriver.pragmas = make(map[string]string)
	activeMockDriver.executedSQL = nil
	activeMockDriver.mu.Unlock()

	rawDB, err := sql.Open("mock_sqlite_test", "test.db")
	if err != nil {
		t.Fatalf("sql.Open mock_sqlite_test failed: %v", err)
	}
	ConfigurePool(rawDB)
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

func TestBuildDSN(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
		contains []string
	}{
		{
			name:     "empty",
			input:    "   ",
			expected: "",
		},
		{
			name:     "in_memory",
			input:    ":memory:",
			expected: ":memory:",
		},
		{
			name:  "plain_file",
			input: "history.db",
			contains: []string{
				"history.db?",
				"_journal_mode=WAL",
				"_busy_timeout=5000",
				"_synchronous=NORMAL",
				"_foreign_keys=ON",
			},
		},
		{
			name:  "existing_query_params",
			input: "file:history.db?cache=shared",
			contains: []string{
				"file:history.db?cache=shared&",
				"_journal_mode=WAL",
				"_busy_timeout=5000",
				"_synchronous=NORMAL",
				"_foreign_keys=ON",
			},
		},
		{
			name:     "existing_overrides_not_duplicated",
			input:    "history.db?_journal_mode=DELETE&_timeout=1000&_sync=FULL&_fk=0",
			expected: "history.db?_journal_mode=DELETE&_timeout=1000&_sync=FULL&_fk=0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildDSN(tc.input)
			if tc.expected != "" && got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
			for _, exp := range tc.contains {
				if !strings.Contains(got, exp) {
					t.Errorf("expected DSN %q to contain %q", got, exp)
				}
			}
		})
	}
}

func TestDatabaseConnectionPoolAndGetters(t *testing.T) {
	// Nil receiver safety
	var nilDB *DB
	stats := nilDB.PoolStats()
	if stats.MaxOpenConnections != 0 {
		t.Errorf("expected 0 max open connections on nil DB, got %d", stats.MaxOpenConnections)
	}
	if nilDB.MaxOpenConns() != DefaultMaxOpenConns {
		t.Errorf("expected %d, got %d", DefaultMaxOpenConns, nilDB.MaxOpenConns())
	}
	if nilDB.MaxIdleConns() != DefaultMaxIdleConns {
		t.Errorf("expected %d, got %d", DefaultMaxIdleConns, nilDB.MaxIdleConns())
	}
	if nilDB.ConnMaxLifetime() != DefaultConnMaxLifetime {
		t.Errorf("expected %v, got %v", DefaultConnMaxLifetime, nilDB.ConnMaxLifetime())
	}
	if nilDB.BusyTimeout() != 5*time.Second {
		t.Errorf("expected 5s, got %v", nilDB.BusyTimeout())
	}
	if err := nilDB.Init(); err == nil {
		t.Errorf("expected error calling Init on nil DB")
	}

	// ConfigurePool with nil
	ConfigurePool(nil)

	// SQL-backed DB
	sqlDB, _ := newMockSQLBackedDB(t)
	defer sqlDB.Close()

	if sqlDB.MaxOpenConns() != 1 {
		t.Errorf("expected MaxOpenConns=1, got %d", sqlDB.MaxOpenConns())
	}
	if sqlDB.MaxIdleConns() != 1 {
		t.Errorf("expected MaxIdleConns=1, got %d", sqlDB.MaxIdleConns())
	}
	if sqlDB.ConnMaxLifetime() != time.Hour {
		t.Errorf("expected ConnMaxLifetime=1h, got %v", sqlDB.ConnMaxLifetime())
	}
	if sqlDB.BusyTimeout() != 5*time.Second {
		t.Errorf("expected BusyTimeout=5s, got %v", sqlDB.BusyTimeout())
	}

	poolStats := sqlDB.PoolStats()
	if poolStats.MaxOpenConnections != 1 {
		t.Errorf("expected poolStats.MaxOpenConnections=1, got %d", poolStats.MaxOpenConnections)
	}
}

func TestDatabasePragmasAppliedAndQueryable(t *testing.T) {
	// 1. SQL-backed DB
	sqlDB, drv := newMockSQLBackedDB(t)
	defer sqlDB.Close()

	if err := sqlDB.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	// Verify all 4 required pragmas
	jMode, err := sqlDB.GetPragma("journal_mode")
	if err != nil || strings.ToUpper(jMode) != "WAL" {
		t.Errorf("expected journal_mode WAL, got %q (err=%v)", jMode, err)
	}

	busyTimeout, err := sqlDB.GetPragma("busy_timeout")
	if err != nil || busyTimeout != "5000" {
		t.Errorf("expected busy_timeout 5000, got %q (err=%v)", busyTimeout, err)
	}

	fk, err := sqlDB.GetPragma("foreign_keys")
	if err != nil || (fk != "1" && strings.ToUpper(fk) != "ON") {
		t.Errorf("expected foreign_keys 1 or ON, got %q (err=%v)", fk, err)
	}

	syncMode, err := sqlDB.GetPragma("synchronous")
	if err != nil || (syncMode != "1" && strings.ToUpper(syncMode) != "NORMAL") {
		t.Errorf("expected synchronous 1 or NORMAL, got %q (err=%v)", syncMode, err)
	}

	// Case insensitivity
	if _, err := sqlDB.GetPragma("JOURNAL_MODE"); err != nil {
		t.Errorf("expected case-insensitive pragma query to succeed, got %v", err)
	}

	// Unsupported pragma
	if _, err := sqlDB.GetPragma("unsupported_pragma"); err == nil {
		t.Errorf("expected error for unsupported pragma")
	}

	// Failure branch on query
	drv.mu.Lock()
	drv.failQuery = true
	drv.mu.Unlock()
	if _, err := sqlDB.GetPragma("journal_mode"); err == nil {
		t.Errorf("expected error querying pragma when query fails")
	}

	// Failure branch on applyPragmas
	drv.mu.Lock()
	drv.failQuery = false
	drv.failExec = true
	drv.mu.Unlock()
	if err := sqlDB.applyPragmas(); err == nil {
		t.Errorf("expected error in applyPragmas when Exec fails")
	}

	// 2. In-memory DB
	memDB, err := NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB(:memory:) failed: %v", err)
	}
	defer memDB.Close()

	if err := memDB.Init(); err != nil {
		t.Fatalf("memDB.Init() failed: %v", err)
	}

	if val, err := memDB.GetPragma("journal_mode"); err != nil || val != "memory" {
		t.Errorf("expected in-memory journal_mode=memory, got %q (err=%v)", val, err)
	}
	if val, err := memDB.GetPragma("busy_timeout"); err != nil || val != "5000" {
		t.Errorf("expected in-memory busy_timeout=5000, got %q (err=%v)", val, err)
	}
	if val, err := memDB.GetPragma("synchronous"); err != nil || val != "1" {
		t.Errorf("expected in-memory synchronous=1, got %q (err=%v)", val, err)
	}
	if val, err := memDB.GetPragma("foreign_keys"); err != nil || val != "1" {
		t.Errorf("expected in-memory foreign_keys=1, got %q (err=%v)", val, err)
	}
	if _, err := memDB.GetPragma("unsupported"); err == nil {
		t.Errorf("expected error for unsupported pragma on in-memory DB")
	}

	// 3. Nil DB
	var nilDB *DB
	if _, err := nilDB.GetPragma("journal_mode"); err == nil {
		t.Errorf("expected error querying pragma on nil DB")
	}
	if err := nilDB.applyPragmas(); err != nil {
		t.Errorf("expected nilDB.applyPragmas() to return nil, got %v", err)
	}
}

func TestConcurrentActionHistoryAccessInMemory(t *testing.T) {
	db, err := NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB(:memory:) failed: %v", err)
	}
	defer db.Close()

	if err := db.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	const numWriters = 20
	const writesPerWorker = 10
	const numReaders = 20

	var wg sync.WaitGroup
	errCh := make(chan error, numWriters+numReaders)

	// Launch concurrent writers
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < writesPerWorker; i++ {
				cmd := fmt.Sprintf("worker-%d-cmd-%d", workerID, i)
				_, err := db.RecordAction(cmd, "success", fmt.Sprintf("output-%d", i))
				if err != nil {
					errCh <- fmt.Errorf("writer %d write %d failed: %w", workerID, i, err)
					return
				}
			}
		}(w)
	}

	// Launch concurrent readers
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				_, err := db.ListActions(50)
				if err != nil {
					errCh <- fmt.Errorf("reader %d list failed: %w", readerID, err)
					return
				}
				cnt, err := db.CountActions()
				if err != nil {
					errCh <- fmt.Errorf("reader %d count failed: %w", readerID, err)
					return
				}
				if cnt < 0 {
					errCh <- fmt.Errorf("reader %d saw negative count: %d", readerID, cnt)
					return
				}
			}
		}(r)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent access error: %v", err)
	}

	finalCount, err := db.CountActions()
	if err != nil {
		t.Fatalf("CountActions failed: %v", err)
	}
	expectedTotal := numWriters * writesPerWorker
	if finalCount != expectedTotal {
		t.Errorf("expected final count %d, got %d", expectedTotal, finalCount)
	}

	listed, err := db.ListActions(expectedTotal)
	if err != nil {
		t.Fatalf("ListActions failed: %v", err)
	}
	if len(listed) != expectedTotal {
		t.Errorf("expected %d listed items, got %d", expectedTotal, len(listed))
	}
	for i := 0; i < len(listed)-1; i++ {
		if listed[i].ID <= listed[i+1].ID {
			t.Errorf("expected newest first order, but ID %d is <= ID %d", listed[i].ID, listed[i+1].ID)
			break
		}
	}
}

func TestConcurrentActionHistoryAccessSQLBacked(t *testing.T) {
	sqlDB, _ := newMockSQLBackedDB(t)
	defer sqlDB.Close()

	if err := sqlDB.Init(); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	const numWriters = 20
	const writesPerWorker = 10
	const numReaders = 20

	var wg sync.WaitGroup
	errCh := make(chan error, numWriters+numReaders)

	// Launch concurrent writers
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < writesPerWorker; i++ {
				cmd := fmt.Sprintf("sql-worker-%d-cmd-%d", workerID, i)
				_, err := sqlDB.RecordAction(cmd, "success", fmt.Sprintf("out-%d", i))
				if err != nil {
					errCh <- fmt.Errorf("sql writer %d write %d failed: %w", workerID, i, err)
					return
				}
			}
		}(w)
	}

	// Launch concurrent readers
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				_, err := sqlDB.ListActions(50)
				if err != nil {
					errCh <- fmt.Errorf("sql reader %d list failed: %w", readerID, err)
					return
				}
				cnt, err := sqlDB.CountActions()
				if err != nil {
					errCh <- fmt.Errorf("sql reader %d count failed: %w", readerID, err)
					return
				}
				if cnt < 0 {
					errCh <- fmt.Errorf("sql reader %d saw negative count: %d", readerID, cnt)
					return
				}
			}
		}(r)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent access error on SQL-backed DB: %v", err)
	}

	finalCount, err := sqlDB.CountActions()
	if err != nil {
		t.Fatalf("CountActions failed: %v", err)
	}
	expectedTotal := numWriters * writesPerWorker
	if finalCount != expectedTotal {
		t.Errorf("expected final count %d, got %d", expectedTotal, finalCount)
	}

	listed, err := sqlDB.ListActions(expectedTotal)
	if err != nil {
		t.Fatalf("ListActions failed: %v", err)
	}
	if len(listed) != expectedTotal {
		t.Errorf("expected %d listed items, got %d", expectedTotal, len(listed))
	}
	for i := 0; i < len(listed)-1; i++ {
		if listed[i].ID <= listed[i+1].ID {
			t.Errorf("expected newest first order, but ID %d <= ID %d", listed[i].ID, listed[i+1].ID)
			break
		}
	}
}


