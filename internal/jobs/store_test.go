package jobs

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

	"go-admin-tool/internal/database"
)

type mockJobsDriver struct {
	mu       sync.Mutex
	rows     map[string][]driver.Value
	order    []string
	failInit bool
}

type mockJobsConn struct {
	drv *mockJobsDriver
}

type mockJobsStmt struct {
	drv   *mockJobsDriver
	query string
}

func (d *mockJobsDriver) Open(_ string) (driver.Conn, error) {
	return &mockJobsConn{drv: d}, nil
}

func (c *mockJobsConn) Prepare(query string) (driver.Stmt, error) {
	return &mockJobsStmt{drv: c.drv, query: query}, nil
}

func (c *mockJobsConn) Close() error              { return nil }
func (c *mockJobsConn) Begin() (driver.Tx, error) { return nil, errors.New("tx not supported") }

func (s *mockJobsStmt) Close() error  { return nil }
func (s *mockJobsStmt) NumInput() int { return -1 }

type mockJobResult struct {
	id int64
}

func (r mockJobResult) LastInsertId() (int64, error) { return r.id, nil }
func (r mockJobResult) RowsAffected() (int64, error) { return 1, nil }

func (s *mockJobsStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.drv.mu.Lock()
	defer s.drv.mu.Unlock()

	upper := strings.ToUpper(strings.TrimSpace(s.query))
	if strings.Contains(upper, "INSERT INTO JOB_HISTORY") && len(args) >= 17 {
		id, _ := args[0].(string)
		if _, exists := s.drv.rows[id]; !exists {
			s.drv.order = append(s.drv.order, id)
		}
		s.drv.rows[id] = args
		return mockJobResult{id: 1}, nil
	}
	if strings.Contains(upper, "DELETE FROM JOB_HISTORY") {
		s.drv.rows = make(map[string][]driver.Value)
		s.drv.order = nil
		return mockJobResult{id: 1}, nil
	}
	return mockJobResult{id: 1}, nil
}

type mockJobRows struct {
	cols   []string
	values [][]driver.Value
	idx    int
}

func (r *mockJobRows) Columns() []string { return r.cols }
func (r *mockJobRows) Close() error      { return nil }
func (r *mockJobRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.values) {
		return io.EOF
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

func (s *mockJobsStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.drv.mu.Lock()
	defer s.drv.mu.Unlock()

	upper := strings.ToUpper(strings.TrimSpace(s.query))
	if strings.Contains(upper, "COUNT(*)") {
		return &mockJobRows{
			cols:   []string{"count"},
			values: [][]driver.Value{{int64(len(s.drv.rows))}},
		}, nil
	}

	cols := []string{
		"id", "type", "action", "plugin_id", "params", "priority", "status",
		"created_at", "started_at", "completed_at", "duration_ms", "timeout",
		"actor_type", "actor_id", "source_ip", "error", "result_data",
	}

	var vals [][]driver.Value
	if strings.Contains(upper, "WHERE ID = ?") && len(args) > 0 {
		id, _ := args[0].(string)
		if row, ok := s.drv.rows[id]; ok {
			vals = append(vals, row)
		}
		return &mockJobRows{cols: cols, values: vals}, nil
	}

	for i := len(s.drv.order) - 1; i >= 0; i-- {
		id := s.drv.order[i]
		if row, ok := s.drv.rows[id]; ok {
			vals = append(vals, row)
		}
	}
	return &mockJobRows{cols: cols, values: vals}, nil
}

var (
	registerJobsMockDriverOnce sync.Once
	activeJobsMockDriver       = &mockJobsDriver{
		rows: make(map[string][]driver.Value),
	}
)

func newMockSQLiteBackedDB(t *testing.T) (*database.DB, *mockJobsDriver) {
	registerJobsMockDriverOnce.Do(func() {
		sql.Register("mock_sqlite_jobs", activeJobsMockDriver)
	})

	activeJobsMockDriver.mu.Lock()
	activeJobsMockDriver.rows = make(map[string][]driver.Value)
	activeJobsMockDriver.order = nil
	activeJobsMockDriver.mu.Unlock()

	rawDB, err := sql.Open("mock_sqlite_jobs", "jobs_test.db")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}

	return &database.DB{
		DB: rawDB,
	}, activeJobsMockDriver
}

func TestMemoryJobStoreCRUDAndFilter(t *testing.T) {
	store := NewMemoryJobStore()

	now := time.Now().UTC()
	j1 := &Job{
		ID:        "mem_j1",
		Type:      TypeCommand,
		Action:    "action-a",
		Priority:  PriorityHigh,
		Status:    StatusCompleted,
		ActorID:   "alice",
		ActorType: "user",
		CreatedAt: now.Add(-10 * time.Minute),
		Params:    map[string]any{"arg": 1},
	}
	j2 := &Job{
		ID:        "mem_j2",
		Type:      TypePlugin,
		Action:    "action-b",
		Priority:  PriorityNormal,
		Status:    StatusRunning,
		ActorID:   "bob",
		ActorType: "user",
		CreatedAt: now.Add(-5 * time.Minute),
	}
	j3 := &Job{
		ID:        "mem_j3",
		Type:      TypeCommand,
		Action:    "action-a",
		Priority:  PriorityLow,
		Status:    StatusFailed,
		ActorID:   "alice",
		ActorType: "user",
		CreatedAt: now,
	}

	_ = store.SaveJob(j1)
	_ = store.SaveJob(j2)
	_ = store.SaveJob(j3)

	// GetJob
	retrieved, found := store.GetJob("mem_j1")
	if !found || retrieved.Action != "action-a" {
		t.Fatalf("GetJob(mem_j1) failed: %+v (found=%v)", retrieved, found)
	}
	if retrieved.Params["arg"] != 1 {
		t.Errorf("expected param arg == 1, got %v", retrieved.Params["arg"])
	}

	// Mutating retrieved job does not affect store
	retrieved.Params["arg"] = 999
	reRead, _ := store.GetJob("mem_j1")
	if reRead.Params["arg"] == 999 {
		t.Errorf("store item was mutated through retrieved pointer")
	}

	// Non-existent GetJob
	if _, found := store.GetJob("nonexistent"); found {
		t.Errorf("expected false for nonexistent job")
	}

	// Filter by action
	listActionA, totalA := store.ListJobs(JobFilter{Action: "action-a"})
	if totalA != 2 || len(listActionA) != 2 {
		t.Errorf("expected 2 items for action-a, got total=%d len=%d", totalA, len(listActionA))
	}
	if listActionA[0].ID != "mem_j3" || listActionA[1].ID != "mem_j1" {
		t.Errorf("expected mem_j3 then mem_j1, got %s, %s", listActionA[0].ID, listActionA[1].ID)
	}

	// Filter by status
	listRunning, totalRunning := store.ListJobs(JobFilter{Status: StatusRunning})
	if totalRunning != 1 || listRunning[0].ID != "mem_j2" {
		t.Errorf("expected 1 running job (mem_j2), got %v", listRunning)
	}

	// Filter by actor
	listBob, totalBob := store.ListJobs(JobFilter{ActorID: "bob"})
	if totalBob != 1 || listBob[0].ID != "mem_j2" {
		t.Errorf("expected 1 bob job, got %v", listBob)
	}

	// Pagination
	paged, totalAll := store.ListJobs(JobFilter{Limit: 2, Offset: 1})
	if totalAll != 3 || len(paged) != 2 {
		t.Errorf("expected total=3, len=2, got total=%d len=%d", totalAll, len(paged))
	}
	if paged[0].ID != "mem_j2" || paged[1].ID != "mem_j1" {
		t.Errorf("expected page items mem_j2, mem_j1, got %s, %s", paged[0].ID, paged[1].ID)
	}
}

func TestMemoryJobStorePruning(t *testing.T) {
	store := NewMemoryJobStore()
	now := time.Now().UTC()

	oldTime := now.Add(-3 * time.Hour)
	recentTime := now.Add(-10 * time.Minute)

	jOld1 := &Job{ID: "old1", Status: StatusCompleted, CreatedAt: oldTime, CompletedAt: &oldTime}
	jOld2 := &Job{ID: "old2", Status: StatusFailed, CreatedAt: oldTime, CompletedAt: &oldTime}
	jRec := &Job{ID: "rec1", Status: StatusCompleted, CreatedAt: recentTime, CompletedAt: &recentTime}
	jActive := &Job{ID: "active1", Status: StatusRunning, CreatedAt: oldTime, StartedAt: &oldTime}

	_ = store.SaveJob(jOld1)
	_ = store.SaveJob(jOld2)
	_ = store.SaveJob(jRec)
	_ = store.SaveJob(jActive)

	if err := store.Prune(1*time.Hour, 0); err != nil {
		t.Fatalf("Prune failed: %v", err)
	}

	if _, found := store.GetJob("old1"); found {
		t.Errorf("expected old1 to be pruned")
	}
	if _, found := store.GetJob("old2"); found {
		t.Errorf("expected old2 to be pruned")
	}
	if _, found := store.GetJob("rec1"); !found {
		t.Errorf("expected rec1 to be retained")
	}
	if _, found := store.GetJob("active1"); !found {
		t.Errorf("expected active1 to be retained")
	}

	for i := 1; i <= 5; i++ {
		tComp := now.Add(time.Duration(i) * time.Minute)
		_ = store.SaveJob(&Job{
			ID:          fmt.Sprintf("cap_%d", i),
			Status:      StatusCompleted,
			CreatedAt:   tComp,
			CompletedAt: &tComp,
		})
	}

	if err := store.Prune(24*time.Hour, 3); err != nil {
		t.Fatalf("Prune maxCount failed: %v", err)
	}

	list, _ := store.ListJobs(JobFilter{Status: StatusCompleted})
	if len(list) != 3 {
		t.Errorf("expected exactly 3 terminal jobs after cap, got %d", len(list))
	}
	if _, found := store.GetJob("active1"); !found {
		t.Errorf("active1 unexpectedly pruned during maxCount cap")
	}
}

func TestSQLiteJobStoreCRUDAndFilter(t *testing.T) {
	db, _ := newMockSQLiteBackedDB(t)
	defer db.Close()

	store, err := NewSQLiteJobStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteJobStore failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	j1 := &Job{
		ID:        "sql_j1",
		Type:      TypeCommand,
		Action:    "backup-db",
		Priority:  PriorityHigh,
		Status:    StatusQueued,
		CreatedAt: now,
		Timeout:   15 * time.Second,
		ActorID:   "admin-user",
		ActorType: "user",
		SourceIP:  "127.0.0.1",
		Params:    map[string]any{"target": "/var/backups"},
	}

	if err := store.SaveJob(j1); err != nil {
		t.Fatalf("SaveJob failed: %v", err)
	}

	retrieved, found := store.GetJob("sql_j1")
	if !found {
		t.Fatalf("expected sql_j1 to be found")
	}
	if retrieved.Action != "backup-db" || retrieved.Priority != PriorityHigh || retrieved.Status != StatusQueued {
		t.Errorf("field mismatch: %+v", retrieved)
	}
	if retrieved.Params["target"] != "/var/backups" {
		t.Errorf("expected param target == '/var/backups', got %v", retrieved.Params["target"])
	}

	startTime := now.Add(1 * time.Second)
	compTime := now.Add(3 * time.Second)
	retrieved.Status = StatusCompleted
	retrieved.StartedAt = &startTime
	retrieved.CompletedAt = &compTime
	retrieved.DurationMs = 2000
	retrieved.ResultData = map[string]any{"bytes": 10240}

	if err := store.SaveJob(retrieved); err != nil {
		t.Fatalf("SaveJob upsert failed: %v", err)
	}

	updated, found := store.GetJob("sql_j1")
	if !found || updated.Status != StatusCompleted || updated.DurationMs != 2000 {
		t.Errorf("expected updated status completed and duration 2000, got %+v", updated)
	}

	list, total := store.ListJobs(JobFilter{Action: "backup-db", Status: StatusCompleted})
	if total != 1 || len(list) != 1 || list[0].ID != "sql_j1" {
		t.Errorf("unexpected ListJobs result: total=%d, len=%d", total, len(list))
	}
}

func TestSQLiteJobStorePruning(t *testing.T) {
	db, _ := newMockSQLiteBackedDB(t)
	defer db.Close()

	store, err := NewSQLiteJobStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteJobStore failed: %v", err)
	}

	now := time.Now().UTC()
	oldTime := now.Add(-3 * time.Hour)
	recTime := now.Add(-5 * time.Minute)

	jOld := &Job{ID: "sql_old", Status: StatusCompleted, CreatedAt: oldTime, CompletedAt: &oldTime}
	jRec := &Job{ID: "sql_rec", Status: StatusCompleted, CreatedAt: recTime, CompletedAt: &recTime}
	jRun := &Job{ID: "sql_run", Status: StatusRunning, CreatedAt: oldTime, StartedAt: &oldTime}

	_ = store.SaveJob(jOld)
	_ = store.SaveJob(jRec)
	_ = store.SaveJob(jRun)

	if err := store.Prune(1*time.Hour, 0); err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if err := store.Prune(0, 10); err != nil {
		t.Fatalf("Prune maxCount failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestSQLiteJobStore_ErrorPaths(t *testing.T) {
	if _, err := NewSQLiteJobStore(nil); err == nil {
		t.Errorf("expected error for nil db")
	}
	if _, err := NewSQLiteJobStore(&database.DB{}); err == nil {
		t.Errorf("expected error for db with nil DB")
	}

	store := &SQLiteJobStore{db: nil}
	if err := store.SaveJob(nil); err == nil {
		t.Errorf("expected error saving nil job")
	}
	if err := store.SaveJob(&Job{ID: "test"}); err == nil {
		t.Errorf("expected error saving with nil db")
	}
	if _, found := store.GetJob("test"); found {
		t.Errorf("expected false for GetJob with nil db")
	}
	if _, total := store.ListJobs(JobFilter{}); total != 0 {
		t.Errorf("expected 0 for ListJobs with nil db")
	}
	if err := store.Prune(time.Hour, 0); err != nil {
		t.Errorf("expected nil error for Prune with nil db")
	}
}

func TestNewJobStore_Fallback(t *testing.T) {
	storeNil, err := NewJobStore(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil db: %v", err)
	}
	if _, ok := storeNil.(*MemoryJobStore); !ok {
		t.Errorf("expected *MemoryJobStore for nil DB")
	}

	tmpDir := t.TempDir()
	dsn := filepath.Join(tmpDir, "test_job_fallback.db")
	db, err := database.NewDB(dsn)
	if err != nil {
		t.Fatalf("database.NewDB failed: %v", err)
	}
	defer db.Close()

	storeFromDB, err := NewJobStore(db)
	if err != nil {
		t.Fatalf("NewJobStore(db) failed: %v", err)
	}
	if db.IsInMemory() {
		if _, ok := storeFromDB.(*MemoryJobStore); !ok {
			t.Errorf("expected *MemoryJobStore when db.IsInMemory() == true")
		}
	} else {
		if _, ok := storeFromDB.(*SQLiteJobStore); !ok {
			t.Errorf("expected *SQLiteJobStore when db has real SQL connection")
		}
	}
}
