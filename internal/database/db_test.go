package database

import (
	"path/filepath"
	"testing"
)

func TestDatabaseRecordActionAndValidation(t *testing.T) {
	if _, err := NewDB("   "); err == nil {
		t.Errorf("expected error for empty database path")
	}

	tmpDir := t.TempDir()
	db, err := NewDB(filepath.Join(tmpDir, "history.db"))
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

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
}
