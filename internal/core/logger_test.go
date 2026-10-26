package core

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestLoggerLevelsStructuredOutputAndRingBuffer(t *testing.T) {
	// 1. Test levelFromString mappings
	if levelFromString("debug") != LevelDebug {
		t.Errorf("expected LevelDebug for 'debug'")
	}
	if levelFromString("INFO") != LevelInfo {
		t.Errorf("expected LevelInfo for 'INFO'")
	}
	if levelFromString("warn") != LevelWarn || levelFromString("warning") != LevelWarn {
		t.Errorf("expected LevelWarn for 'warn'/'warning'")
	}
	if levelFromString("error") != LevelError {
		t.Errorf("expected LevelError for 'error'")
	}
	if levelFromString("unknown-level") != LevelInfo {
		t.Errorf("expected default LevelInfo for unknown level")
	}

	// 2. Test nil Logger safety
	var nilLogger *Logger
	nilLogger.Debug("ignored")
	nilLogger.Info("ignored")
	nilLogger.Warn("ignored")
	nilLogger.Error("ignored")
	nilLogger.LogStructured("info", "test", "tr_1", "ignored", nil)
	_ = nilLogger.Close()
	if entries := nilLogger.RecentEntries(10, ""); entries != nil {
		t.Errorf("expected nil RecentEntries from nil Logger, got %+v", entries)
	}

	// 3. Test invalid file path error
	tmpDir := t.TempDir()
	if _, err := NewLogger(LoggingConfig{Level: "info", Path: tmpDir}); err == nil {
		t.Errorf("expected error when opening directory as log file")
	}

	// 4. Test stdout logger (empty Path) and level filtering
	stdoutLogger, err := NewLogger(LoggingConfig{Level: "warn", Path: ""})
	if err != nil {
		t.Fatalf("NewLogger stdout failed: %v", err)
	}
	defer stdoutLogger.Close()
	stdoutLogger.Debug("debug-filtered-out")
	stdoutLogger.Info("info-filtered-out")
	stdoutLogger.Warn("warn-kept")
	stdoutLogger.Error("error-kept")
	entries := stdoutLogger.RecentEntries(0, "")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries at warn threshold, got %d", len(entries))
	}
	if entries[0].Level != "ERROR" || entries[1].Level != "WARN" {
		t.Errorf("expected newest first [ERROR, WARN], got [%s, %s]", entries[0].Level, entries[1].Level)
	}

	// 5. Test file-backed logger, LogStructured, minimum level filter, and ring buffer capacity eviction
	logFile := filepath.Join(tmpDir, "app.log")
	fileLogger, err := NewLogger(LoggingConfig{Level: "debug", Path: logFile})
	if err != nil {
		t.Fatalf("NewLogger file failed: %v", err)
	}
	defer fileLogger.Close()
	fileLogger.capacity = 0 // test fallback to defaultLogBufferCapacity when <= 0
	fileLogger.Debug("debug-msg")
	fileLogger.Info("info-msg")
	fileLogger.Warn("warn-msg")
	fileLogger.Error("error-msg")
	fileLogger.LogStructured("", "auth", "tr_abc", "default-info-structured", map[string]any{"user": "admin"})
	fileLogger.LogStructured("error", "mcp", "tr_xyz", "error-structured", map[string]any{"code": 500})

	errOnly := fileLogger.RecentEntries(100, "error")
	if len(errOnly) != 2 {
		t.Errorf("expected 2 ERROR entries when filtering by minLevel='error', got %d", len(errOnly))
	}

	// Test ring buffer eviction with small capacity
	fileLogger.capacity = 3
	fileLogger.records = nil
	for i := 1; i <= 5; i++ {
		fileLogger.Info(fmt.Sprintf("msg-%d", i))
	}
	retained := fileLogger.RecentEntries(10, "")
	if len(retained) != 3 {
		t.Fatalf("expected ring buffer capacity 3, got %d", len(retained))
	}
	if retained[0].Message != "msg-5" || retained[2].Message != "msg-3" {
		t.Errorf("expected messages [msg-5, msg-4, msg-3], got [%s, %s, %s]", retained[0].Message, retained[1].Message, retained[2].Message)
	}
}
