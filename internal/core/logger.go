package core

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

func levelFromString(levelStr string) LogLevel {
	switch strings.ToLower(levelStr) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

type Logger struct {
	logger *log.Logger
	level  LogLevel
}

func NewLogger(config LoggingConfig) (*Logger, error) {
	var output io.Writer
	if config.Path != "" {
		file, err := os.OpenFile(config.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, err
		}
		output = file
	} else {
		output = os.Stdout
	}

	return &Logger{
		logger: log.New(output, "", 0),
		level:  levelFromString(config.Level),
	}, nil
}

type logEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

func (l *Logger) log(level LogLevel, levelStr string, message string) {
	if l.level <= level {
		entry := logEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     levelStr,
			Message:   message,
		}
		// Using json.NewEncoder to write structured logs
		encoder := json.NewEncoder(l.logger.Writer())
		if err := encoder.Encode(entry); err != nil {
			// Fallback: print error to stderr
			log.Printf("Logger failed to encode log entry: %v", err)
		}
	}
}

func (l *Logger) Debug(message string) {
	l.log(LevelDebug, "DEBUG", message)
}

func (l *Logger) Info(message string) {
	l.log(LevelInfo, "INFO", message)
}

func (l *Logger) Warn(message string) {
	l.log(LevelWarn, "WARN", message)
}

func (l *Logger) Error(message string) {
	l.log(LevelError, "ERROR", message)
}
