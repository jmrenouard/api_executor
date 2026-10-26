package core

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

const defaultLogBufferCapacity = 500

func levelFromString(levelStr string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// LogRecord represents a structured log entry stored in the in-memory ring buffer and written as JSON.
type LogRecord struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Component string         `json:"component,omitempty"`
	TraceID   string         `json:"trace_id,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

type Logger struct {
	mu       sync.RWMutex
	logger   *log.Logger
	level    LogLevel
	records  []LogRecord
	capacity int
}

func NewLogger(config LoggingConfig) (*Logger, error) {
	var output io.Writer
	if config.Path != "" {
		file, err := os.OpenFile(config.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, err
		}
		output = file
	} else {
		output = os.Stdout
	}

	return &Logger{
		logger:   log.New(output, "", 0),
		level:    levelFromString(config.Level),
		records:  make([]LogRecord, 0, 64),
		capacity: defaultLogBufferCapacity,
	}, nil
}

func (l *Logger) log(level LogLevel, levelStr string, message string, component string, traceID string, fields map[string]any) {
	if l == nil {
		return
	}
	if l.level <= level {
		entry := LogRecord{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     levelStr,
			Message:   message,
			Component: component,
			TraceID:   traceID,
			Fields:    fields,
		}

		l.mu.Lock()
		if l.capacity <= 0 {
			l.capacity = defaultLogBufferCapacity
		}
		if len(l.records) >= l.capacity {
			l.records = append(l.records[1:], entry)
		} else {
			l.records = append(l.records, entry)
		}
		encoder := json.NewEncoder(l.logger.Writer())
		err := encoder.Encode(entry)
		l.mu.Unlock()

		if err != nil {
			log.Printf("Logger failed to encode log entry: %v", err)
		}
	}
}

func (l *Logger) Debug(message string) {
	l.log(LevelDebug, "DEBUG", message, "", "", nil)
}

func (l *Logger) Info(message string) {
	l.log(LevelInfo, "INFO", message, "", "", nil)
}

func (l *Logger) Warn(message string) {
	l.log(LevelWarn, "WARN", message, "", "", nil)
}

func (l *Logger) Error(message string) {
	l.log(LevelError, "ERROR", message, "", "", nil)
}

// LogStructured writes a structured log entry with component, trace_id, and arbitrary key-value metadata.
func (l *Logger) LogStructured(levelStr, component, traceID, message string, fields map[string]any) {
	lvl := levelFromString(levelStr)
	upper := strings.ToUpper(strings.TrimSpace(levelStr))
	if upper == "" {
		upper = "INFO"
	}
	l.log(lvl, upper, message, component, traceID, fields)
}

// RecentEntries returns up to limit recent log entries (newest first), optionally filtered by minimum level.
func (l *Logger) RecentEntries(limit int, minLevelStr string) []LogRecord {
	if l == nil {
		return nil
	}
	if limit <= 0 || limit > defaultLogBufferCapacity {
		limit = 100
	}
	hasFilter := strings.TrimSpace(minLevelStr) != ""
	minLvl := levelFromString(minLevelStr)

	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]LogRecord, 0, limit)
	for i := len(l.records) - 1; i >= 0 && len(result) < limit; i-- {
		rec := l.records[i]
		if hasFilter && levelFromString(rec.Level) < minLvl {
			continue
		}
		result = append(result, rec)
	}
	return result
}

// Close closes the underlying log file if one was opened by NewLogger.
func (l *Logger) Close() error {
	if l == nil || l.logger == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if f, ok := l.logger.Writer().(*os.File); ok && f != os.Stdout && f != os.Stderr {
		return f.Close()
	}
	return nil
}

