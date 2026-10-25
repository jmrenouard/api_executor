package core

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultCommandTimeout is the default execution timeout applied to commands when not overridden.
	DefaultCommandTimeout = 30 * time.Second
	// DefaultTimeoutSeconds is the default execution timeout in seconds.
	DefaultTimeoutSeconds = 30
)

type Config struct {
	Server     ServerConfig     `yaml:"server" json:"server"`
	Logging    LoggingConfig    `yaml:"logging" json:"logging"`
	Database   DatabaseConfig   `yaml:"database" json:"database"`
	FileServer FileServerConfig `yaml:"file_server" json:"file_server"`
	Executor   ExecutorConfig   `yaml:"command_executor" json:"command_executor"`
}

type ServerConfig struct {
	Port int       `yaml:"port" json:"port"`
	Host string    `yaml:"host" json:"host"`
	TLS  TLSConfig `yaml:"tls" json:"tls"`
}

type TLSConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	AutoGenerate bool     `yaml:"auto_generate" json:"auto_generate"`
	CertFile     string   `yaml:"cert_file" json:"cert_file"`
	KeyFile      string   `yaml:"key_file" json:"key_file"`
	ClientCAFile string   `yaml:"client_ca_file,omitempty" json:"client_ca_file,omitempty"`
	Organization string   `yaml:"organization" json:"organization"`
	ValidityDays int      `yaml:"validity_days" json:"validity_days"`
	MinVersion   string   `yaml:"min_version" json:"min_version"`
	Hosts        []string `yaml:"hosts" json:"hosts"`
}

type LoggingConfig struct {
	Level string `yaml:"level" json:"level"`
	Path  string `yaml:"path" json:"path"`
}

type DatabaseConfig struct {
	Path string `yaml:"path" json:"path"`
}

type FileServerConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	SecureDir string `yaml:"secure_dir" json:"secure_dir"`
}

type ExecutorConfig struct {
	Enabled               bool                `yaml:"enabled" json:"enabled"`
	DefaultTimeoutSeconds int                 `yaml:"default_timeout_seconds,omitempty" json:"default_timeout_seconds,omitempty"`
	DefaultTimeout        string              `yaml:"default_timeout,omitempty" json:"default_timeout,omitempty"`
	MaxTimeoutSeconds     int                 `yaml:"max_timeout_seconds,omitempty" json:"max_timeout_seconds,omitempty"`
	EnableOSPresets       bool                `yaml:"enable_os_presets,omitempty" json:"enable_os_presets,omitempty"`
	OSPresets             []string            `yaml:"os_presets,omitempty" json:"os_presets,omitempty"`
	Commands              []CommandDefinition `yaml:"commands" json:"commands"`
}

type CommandDefinition struct {
	Name           string   `yaml:"name" json:"name"`
	Description    string   `yaml:"description,omitempty" json:"description,omitempty"`
	OSFamily       string   `yaml:"os_family,omitempty" json:"os_family,omitempty"`
	Category       string   `yaml:"category,omitempty" json:"category,omitempty"`
	Command        string   `yaml:"command" json:"command"`
	Args           []string `yaml:"args" json:"args"`
	TimeoutSeconds int      `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
	Timeout        string   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Preset         bool     `yaml:"preset,omitempty" json:"preset,omitempty"`
}

// DefaultTLSConfig returns the default secure HTTPS/TLS settings.
func DefaultTLSConfig() TLSConfig {
	return TLSConfig{
		Enabled:      true,
		AutoGenerate: true,
		CertFile:     "certs/server.crt",
		KeyFile:      "certs/server.key",
		Organization: "Go Admin Tool",
		ValidityDays: 365,
		MinVersion:   "1.2",
		Hosts:        []string{"localhost", "127.0.0.1"},
	}
}

// DefaultConfig returns a Config initialized with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port: 8080,
			Host: "0.0.0.0",
			TLS:  DefaultTLSConfig(),
		},
		Logging: LoggingConfig{
			Level: "info",
		},
		Database: DatabaseConfig{
			Path: "history.db",
		},
		FileServer: FileServerConfig{
			Enabled:   false,
			SecureDir: "/var/log/secure_files",
		},
		Executor: ExecutorConfig{
			Enabled:               true,
			DefaultTimeoutSeconds: DefaultTimeoutSeconds,
			DefaultTimeout:        DefaultCommandTimeout.String(),
		},
	}
}

// ParseTimeoutDuration parses a timeout string which may be a Go duration (e.g. "30s", "500ms", "2m")
// or a positive number representing seconds (e.g. "30", "0.5").
// An empty string returns (0, nil) to indicate no override was provided.
func ParseTimeoutDuration(raw string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}

	if d, err := time.ParseDuration(trimmed); err == nil {
		if d <= 0 {
			return 0, fmt.Errorf("timeout must be strictly positive, got %q", raw)
		}
		return d, nil
	}

	if secs, err := strconv.ParseFloat(trimmed, 64); err == nil {
		if math.IsNaN(secs) || math.IsInf(secs, 0) {
			return 0, fmt.Errorf("invalid timeout value %q", raw)
		}
		if secs <= 0 {
			return 0, fmt.Errorf("timeout must be strictly positive, got %q", raw)
		}
		maxSeconds := float64(math.MaxInt64 / int64(time.Second))
		if secs > maxSeconds {
			return 0, fmt.Errorf("timeout %q exceeds maximum representable duration", raw)
		}
		d := time.Duration(secs * float64(time.Second))
		if d <= 0 {
			return 0, fmt.Errorf("timeout is too small: %q", raw)
		}
		return d, nil
	}

	return 0, fmt.Errorf("invalid timeout format %q (expected duration like '30s', '500ms' or positive seconds)", raw)
}

// EffectiveDefaultTimeout returns the configured default timeout for the executor,
// falling back to DefaultCommandTimeout (30s) when unset or invalid.
func (e ExecutorConfig) EffectiveDefaultTimeout() time.Duration {
	if e.DefaultTimeout == DefaultCommandTimeout.String() && e.DefaultTimeoutSeconds > 0 && e.DefaultTimeoutSeconds != DefaultTimeoutSeconds {
		return time.Duration(e.DefaultTimeoutSeconds) * time.Second
	}
	if e.DefaultTimeout != "" {
		if d, err := ParseTimeoutDuration(e.DefaultTimeout); err == nil && d > 0 {
			return d
		}
	}
	if e.DefaultTimeoutSeconds > 0 {
		return time.Duration(e.DefaultTimeoutSeconds) * time.Second
	}
	return DefaultCommandTimeout
}

// EffectiveTimeout returns the command's configured timeout, or defaultTimeout if none is set on the command.
func (c CommandDefinition) EffectiveTimeout(defaultTimeout time.Duration) time.Duration {
	if c.Timeout != "" {
		if d, err := ParseTimeoutDuration(c.Timeout); err == nil && d > 0 {
			return d
		}
	}
	if c.TimeoutSeconds > 0 {
		return time.Duration(c.TimeoutSeconds) * time.Second
	}
	if defaultTimeout > 0 {
		return defaultTimeout
	}
	return DefaultCommandTimeout
}

// ResolveTimeout resolves the effective timeout for a command execution using the priority:
// 1. Per-call override (if > 0)
// 2. Per-command configured timeout (if > 0)
// 3. Executor default timeout (if > 0)
// 4. Global DefaultCommandTimeout (30s)
func (e ExecutorConfig) ResolveTimeout(cmd CommandDefinition, callOverride time.Duration) time.Duration {
	if callOverride > 0 {
		return callOverride
	}
	return cmd.EffectiveTimeout(e.EffectiveDefaultTimeout())
}

func LoadConfig(path string) (*Config, error) {
	config := DefaultConfig()

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config.Executor.DefaultTimeout = ""
	config.Executor.DefaultTimeoutSeconds = 0

	err = yaml.Unmarshal(file, config)
	if err != nil {
		return nil, err
	}

	effective := config.Executor.EffectiveDefaultTimeout()
	if _, parseErr := ParseTimeoutDuration(config.Executor.DefaultTimeout); config.Executor.DefaultTimeout == "" || parseErr != nil {
		config.Executor.DefaultTimeout = effective.String()
	}
	if config.Executor.DefaultTimeoutSeconds <= 0 {
		config.Executor.DefaultTimeoutSeconds = int(effective.Seconds())
	}

	if config.Executor.EnableOSPresets {
		families := config.Executor.OSPresets
		if len(families) == 0 {
			families = []string{"ubuntu", "redhat", "common"}
		}
		config.Executor.Commands = MergeOSPresets(config.Executor.Commands, families...)
	}

	return config, nil
}
