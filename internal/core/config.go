package core

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	Server      ServerConfig     `yaml:"server" json:"server"`
	Logging     LoggingConfig    `yaml:"logging" json:"logging"`
	Database    DatabaseConfig   `yaml:"database" json:"database"`
	FileServer  FileServerConfig `yaml:"file_server" json:"file_server"`
	Executor    ExecutorConfig   `yaml:"command_executor" json:"command_executor"`
	Auth        AuthConfig       `yaml:"auth,omitempty" json:"auth"`
	Plugins     PluginsConfig    `yaml:"plugins,omitempty" json:"plugins"`
	MCP         MCPConfig        `yaml:"mcp,omitempty" json:"mcp"`
	Audit       AuditConfig      `yaml:"audit,omitempty" json:"audit"`
	MultiConfig MultiConfig      `yaml:"multi_config,omitempty" json:"multi_config,omitempty"`
	OTLPExport  OTLPExportConfig `yaml:"otlp_export,omitempty" json:"otlp_export,omitempty"`
}

// OTLPExportConfig configures the native OpenTelemetry (OTLP) metrics export subsystem.
type OTLPExportConfig struct {
	Enabled             bool              `yaml:"enabled" json:"enabled"`
	Endpoint            string            `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	PushInterval        string            `yaml:"push_interval,omitempty" json:"push_interval,omitempty"`
	PushIntervalSeconds int               `yaml:"push_interval_seconds,omitempty" json:"push_interval_seconds,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	ResourceAttributes  map[string]string `yaml:"resource_attributes,omitempty" json:"resource_attributes,omitempty"`
	Timeout             string            `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	TimeoutSeconds      int               `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
	InsecureSkipVerify  bool              `yaml:"insecure_skip_verify,omitempty" json:"insecure_skip_verify,omitempty"`
}

// EffectivePushInterval returns the push interval duration, defaulting to 30s.
func (c OTLPExportConfig) EffectivePushInterval() time.Duration {
	if c.PushInterval != "" {
		if d, err := ParseTimeoutDuration(c.PushInterval); err == nil && d > 0 {
			return d
		}
	}
	if c.PushIntervalSeconds > 0 {
		return time.Duration(c.PushIntervalSeconds) * time.Second
	}
	return 30 * time.Second
}

// EffectiveTimeout returns the HTTP client push timeout, defaulting to 10s.
func (c OTLPExportConfig) EffectiveTimeout() time.Duration {
	if c.Timeout != "" {
		if d, err := ParseTimeoutDuration(c.Timeout); err == nil && d > 0 {
			return d
		}
	}
	if c.TimeoutSeconds > 0 {
		return time.Duration(c.TimeoutSeconds) * time.Second
	}
	return 10 * time.Second
}

// MultiConfig configures the native multi-configuration and backward compatibility subsystem.
type MultiConfig struct {
	Enabled        bool                    `yaml:"enabled" json:"enabled"`
	Endpoint       string                  `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	DefaultProfile string                  `yaml:"default_profile" json:"default_profile"`
	Profiles       []ConfigProfileMetadata `yaml:"profiles" json:"profiles"`
}

// ConfigProfileMetadata declares a named configuration profile and its backing file path.
type ConfigProfileMetadata struct {
	Name        string `yaml:"name" json:"name"`
	Path        string `yaml:"path" json:"path"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// ConfigProfileSummary provides client-facing metadata for a configuration profile.
type ConfigProfileSummary struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	Description   string `json:"description,omitempty"`
	CommandsCount int    `json:"commands_count"`
	IsDefault     bool   `json:"is_default"`
}

// SanitizedConfigView represents the client-facing view of a configuration with sensitive credentials masked.
type SanitizedConfigView struct {
	ActiveProfile   string                    `json:"active_profile"`
	ConfigFile      string                    `json:"config_file"`
	Profiles        []ConfigProfileSummary    `json:"profiles"`
	Server          SanitizedServerConfig     `json:"server"`
	Logging         LoggingConfig             `json:"logging"`
	FileServer      FileServerConfig          `json:"file_server"`
	CommandExecutor SanitizedExecutorConfig   `json:"command_executor"`
	Auth            SanitizedAuthConfig       `json:"auth"`
	Plugins         PluginsConfig             `json:"plugins"`
	MCP             MCPConfig                 `json:"mcp"`
	OTLPExport      SanitizedOTLPExportConfig `json:"otlp_export,omitempty"`
}

// SanitizedOTLPExportConfig represents the client-facing view of OTLP export with sensitive headers masked.
type SanitizedOTLPExportConfig struct {
	Enabled            bool              `json:"enabled"`
	Endpoint           string            `json:"endpoint,omitempty"`
	PushInterval       string            `json:"push_interval,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	ResourceAttributes map[string]string `json:"resource_attributes,omitempty"`
	Timeout            string            `json:"timeout,omitempty"`
}

// SanitizedServerConfig represents the sanitized server configuration.
type SanitizedServerConfig struct {
	Port                int             `json:"port"`
	Host                string          `json:"host"`
	TLSEnabled          bool            `json:"tls_enabled"`
	TLS                 SanitizedTLS    `json:"tls,omitempty"`
	RateLimit           RateLimitConfig `json:"rate_limit,omitempty"`
	MaxRequestBodyBytes int64           `json:"max_request_body_bytes,omitempty"`
}

// SanitizedTLS represents the sanitized TLS parameters.
type SanitizedTLS struct {
	Enabled      bool     `json:"enabled"`
	AutoGenerate bool     `json:"auto_generate"`
	CertFile     string   `json:"cert_file"`
	KeyFile      string   `json:"key_file"`
	Organization string   `json:"organization"`
	ValidityDays int      `json:"validity_days"`
	MinVersion   string   `json:"min_version"`
	Hosts        []string `json:"hosts"`
}

// SanitizedExecutorConfig represents the sanitized command executor configuration.
type SanitizedExecutorConfig struct {
	Enabled               bool     `json:"enabled"`
	DefaultTimeout        string   `json:"default_timeout"`
	DefaultTimeoutSeconds int      `json:"default_timeout_seconds,omitempty"`
	MaxTimeoutSeconds     int      `json:"max_timeout_seconds,omitempty"`
	EnableOSPresets       bool     `json:"enable_os_presets,omitempty"`
	OSPresets             []string `json:"os_presets,omitempty"`
	CommandsCount         int      `json:"commands_count"`
}

// SanitizedAuthConfig represents the sanitized authentication settings with credentials redacted.
type SanitizedAuthConfig struct {
	Enabled           bool   `json:"enabled"`
	RequireAuth       bool   `json:"require_auth"`
	BootstrapUsername string `json:"bootstrap_username,omitempty"`
	BootstrapPassword string `json:"bootstrap_password,omitempty"`
	BootstrapToken    string `json:"bootstrap_token,omitempty"`
	StorePath         string `json:"store_path,omitempty"`
}

type ServerConfig struct {
	Port                int             `yaml:"port" json:"port"`
	Host                string          `yaml:"host" json:"host"`
	TLS                 TLSConfig       `yaml:"tls" json:"tls"`
	RateLimit           RateLimitConfig `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
	MaxRequestBodyBytes int64           `yaml:"max_request_body_bytes,omitempty" json:"max_request_body_bytes,omitempty"`
}

// RateLimitConfig configures per-IP token-bucket HTTP rate limiting against DDoS and brute-force floods.
type RateLimitConfig struct {
	Enabled           bool    `yaml:"enabled" json:"enabled"`
	RequestsPerSecond float64 `yaml:"requests_per_second" json:"requests_per_second"`
	Burst             int     `yaml:"burst" json:"burst"`
}

// DefaultRateLimitConfig returns the default per-IP rate limiting parameters.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 500,
		Burst:             2000,
	}
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

// AuthConfig configures user authentication, personal access tokens, and third-party service accounts.
type AuthConfig struct {
	Enabled           bool   `yaml:"enabled" json:"enabled"`
	RequireAuth       bool   `yaml:"require_auth" json:"require_auth"`
	BootstrapUsername string `yaml:"bootstrap_username,omitempty" json:"bootstrap_username,omitempty"`
	BootstrapPassword string `yaml:"bootstrap_password,omitempty" json:"bootstrap_password,omitempty"`
	BootstrapToken    string `yaml:"bootstrap_token,omitempty" json:"bootstrap_token,omitempty"`
	StorePath         string `yaml:"store_path,omitempty" json:"store_path,omitempty"`
}

// PluginsConfig configures declarative and native advanced plugin modules.
type PluginsConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	EnableDBExposure bool     `yaml:"enable_db_exposure" json:"enable_db_exposure"`
	EnableSysDiag    bool     `yaml:"enable_sys_diagnostics" json:"enable_sys_diagnostics"`
	DeclarativeDir   string   `yaml:"declarative_dir,omitempty" json:"declarative_dir,omitempty"`
	AllowedDBPaths   []string `yaml:"allowed_db_paths,omitempty" json:"allowed_db_paths,omitempty"`
	MaxQueryRows     int      `yaml:"max_query_rows,omitempty" json:"max_query_rows,omitempty"`
}

// MCPConfig configures the Model Context Protocol (MCP) server and trace retention.
type MCPConfig struct {
	Enabled       bool   `yaml:"enabled" json:"enabled"`
	ServerName    string `yaml:"server_name,omitempty" json:"server_name,omitempty"`
	ServerVersion string `yaml:"server_version,omitempty" json:"server_version,omitempty"`
	RetainTraces  bool   `yaml:"retain_traces" json:"retain_traces"`
	MaxTraces     int    `yaml:"max_traces,omitempty" json:"max_traces,omitempty"`
	TraceFilePath string `yaml:"trace_file_path,omitempty" json:"trace_file_path,omitempty"`
}

// AuditConfig configures the tamper-evident SHA-256 hash-chained audit trail.
type AuditConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	FilePath     string `yaml:"file_path,omitempty" json:"file_path,omitempty"`
	MaxMemoryLog int    `yaml:"max_memory_log,omitempty" json:"max_memory_log,omitempty"`
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
			Port:      8080,
			Host:      "0.0.0.0",
			TLS:       DefaultTLSConfig(),
			RateLimit: DefaultRateLimitConfig(),
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
		Auth: AuthConfig{
			Enabled:           true,
			RequireAuth:       false,
			BootstrapUsername: "admin",
			BootstrapPassword: "admin-change-me",
		},
		Plugins: PluginsConfig{
			Enabled:          true,
			EnableDBExposure: true,
			EnableSysDiag:    true,
			DeclarativeDir:   "plugins",
			MaxQueryRows:     200,
		},
		MCP: MCPConfig{
			Enabled:       true,
			ServerName:    "api-executor-mcp",
			ServerVersion: "2.0.0",
			RetainTraces:  true,
			MaxTraces:     500,
		},
		Audit: AuditConfig{
			Enabled:      true,
			MaxMemoryLog: 1000,
		},
		MultiConfig: MultiConfig{
			Enabled:        false,
			Endpoint:       "/api/v1/config",
			DefaultProfile: "default",
		},
		OTLPExport: OTLPExportConfig{
			Enabled:      true,
			PushInterval: "30s",
			Timeout:      "10s",
			ResourceAttributes: map[string]string{
				"service.name": "api-executor",
			},
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

// MultiConfigManager manages a thread-safe registry of named configuration profiles,
// providing profile resolution based on query parameters or headers with default fallback.
type MultiConfigManager struct {
	mu             sync.RWMutex
	defaultProfile string
	masterPath     string
	configs        map[string]*Config
	profiles       []ConfigProfileMetadata
	pathMap        map[string]string
}

// resolveProfileFilePath attempts to locate a profile file relative to the working directory,
// the master configuration directory, or common parent repository roots.
func resolveProfileFilePath(masterPath, profilePath string) string {
	if filepath.IsAbs(profilePath) {
		return profilePath
	}
	candidates := []string{
		profilePath,
		filepath.Join(filepath.Dir(masterPath), profilePath),
		filepath.Join("..", profilePath),
		filepath.Join("..", "..", profilePath),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return profilePath
}

// NewMultiConfigManager initializes a MultiConfigManager from a master configuration.
// If masterCfg is nil, it falls back to DefaultConfig().
func NewMultiConfigManager(masterPath string, masterCfg *Config) (*MultiConfigManager, error) {
	if masterCfg == nil {
		masterCfg = DefaultConfig()
	}
	defaultProfile := strings.TrimSpace(masterCfg.MultiConfig.DefaultProfile)
	if defaultProfile == "" {
		defaultProfile = "default"
	}
	if masterPath == "" {
		masterPath = "config.yaml"
	}

	mgr := &MultiConfigManager{
		defaultProfile: defaultProfile,
		masterPath:     masterPath,
		configs:        make(map[string]*Config),
		profiles:       make([]ConfigProfileMetadata, 0),
		pathMap:        make(map[string]string),
	}

	// Register default profile with the master configuration
	mgr.configs[defaultProfile] = masterCfg
	mgr.pathMap[defaultProfile] = masterPath

	hasDefaultInProfiles := false
	for _, p := range masterCfg.MultiConfig.Profiles {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		if name == defaultProfile {
			hasDefaultInProfiles = true
			if p.Path != "" {
				mgr.pathMap[defaultProfile] = p.Path
			}
			mgr.profiles = append(mgr.profiles, ConfigProfileMetadata{
				Name:        defaultProfile,
				Path:        mgr.pathMap[defaultProfile],
				Description: p.Description,
			})
			continue
		}

		resolvedPath := resolveProfileFilePath(masterPath, p.Path)
		cfg, err := LoadConfig(resolvedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load multi-config profile %q from %q: %w", name, p.Path, err)
		}
		mgr.configs[name] = cfg
		mgr.pathMap[name] = p.Path
		mgr.profiles = append(mgr.profiles, ConfigProfileMetadata{
			Name:        name,
			Path:        p.Path,
			Description: p.Description,
		})
	}

	if !hasDefaultInProfiles {
		mgr.profiles = append([]ConfigProfileMetadata{{
			Name:        defaultProfile,
			Path:        masterPath,
			Description: "Default configuration profile",
		}}, mgr.profiles...)
	}

	return mgr, nil
}

// DefaultProfile returns the name of the active default profile.
func (m *MultiConfigManager) DefaultProfile() string {
	if m == nil {
		return "default"
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultProfile
}

// GetProfile retrieves a configuration profile by name.
func (m *MultiConfigManager) GetProfile(name string) (*Config, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.configs[name]
	return cfg, ok
}

// RegisterProfile dynamically registers or overrides a named configuration profile.
func (m *MultiConfigManager) RegisterProfile(name, path, description string, cfg *Config) {
	if m == nil || name == "" || cfg == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.configs[name] = cfg
	m.pathMap[name] = path

	updated := false
	for i, p := range m.profiles {
		if p.Name == name {
			m.profiles[i] = ConfigProfileMetadata{Name: name, Path: path, Description: description}
			updated = true
			break
		}
	}
	if !updated {
		m.profiles = append(m.profiles, ConfigProfileMetadata{Name: name, Path: path, Description: description})
	}
}

// ResolveProfileName inspects HTTP request query parameters and headers to identify the targeted profile.
// If the requested profile does not exist or none is specified, it returns the default profile name.
func (m *MultiConfigManager) ResolveProfileName(r *http.Request) string {
	if m == nil {
		return "default"
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if r != nil {
		if q := strings.TrimSpace(r.URL.Query().Get("profile")); q != "" {
			if _, ok := m.configs[q]; ok {
				return q
			}
		}
		if h := strings.TrimSpace(r.Header.Get("X-Config-Profile")); h != "" {
			if _, ok := m.configs[h]; ok {
				return h
			}
		}
		if h := strings.TrimSpace(r.Header.Get("X-API-Config")); h != "" {
			if _, ok := m.configs[h]; ok {
				return h
			}
		}
	}
	if m.defaultProfile != "" {
		return m.defaultProfile
	}
	return "default"
}

// ResolveConfig resolves the active configuration for an HTTP request based on query parameters or headers.
func (m *MultiConfigManager) ResolveConfig(r *http.Request) *Config {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	profileName := m.defaultProfile
	if r != nil {
		if q := strings.TrimSpace(r.URL.Query().Get("profile")); q != "" {
			if cfg, ok := m.configs[q]; ok {
				return cfg
			}
		}
		if h := strings.TrimSpace(r.Header.Get("X-Config-Profile")); h != "" {
			if cfg, ok := m.configs[h]; ok {
				return cfg
			}
		}
		if h := strings.TrimSpace(r.Header.Get("X-API-Config")); h != "" {
			if cfg, ok := m.configs[h]; ok {
				return cfg
			}
		}
	}

	if cfg, ok := m.configs[profileName]; ok {
		return cfg
	}
	for _, cfg := range m.configs {
		return cfg
	}
	return nil
}

// ListProfiles returns client-facing summaries for all declared configuration profiles.
func (m *MultiConfigManager) ListProfiles() []ConfigProfileSummary {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	summaries := make([]ConfigProfileSummary, 0, len(m.profiles))
	for _, p := range m.profiles {
		cmdCount := 0
		if cfg, ok := m.configs[p.Name]; ok {
			cmdCount = len(cfg.Executor.Commands)
		}
		summaries = append(summaries, ConfigProfileSummary{
			Name:          p.Name,
			Path:          p.Path,
			Description:   p.Description,
			CommandsCount: cmdCount,
			IsDefault:     p.Name == m.defaultProfile,
		})
	}
	return summaries
}

// SanitizedView returns a sanitized view of the requested profile with credentials redacted.
func (m *MultiConfigManager) SanitizedView(profileName string) (*SanitizedConfigView, error) {
	if m == nil {
		return nil, fmt.Errorf("multi-config manager is uninitialized")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	targetName := strings.TrimSpace(profileName)
	if targetName == "" {
		targetName = m.defaultProfile
	}

	cfg, exists := m.configs[targetName]
	if !exists {
		return nil, fmt.Errorf("configuration profile %q not found", targetName)
	}

	configPath := m.pathMap[targetName]
	if configPath == "" {
		configPath = m.masterPath
	}

	summaries := make([]ConfigProfileSummary, 0, len(m.profiles))
	for _, p := range m.profiles {
		cmdCount := 0
		if c, ok := m.configs[p.Name]; ok {
			cmdCount = len(c.Executor.Commands)
		}
		summaries = append(summaries, ConfigProfileSummary{
			Name:          p.Name,
			Path:          p.Path,
			Description:   p.Description,
			CommandsCount: cmdCount,
			IsDefault:     p.Name == m.defaultProfile,
		})
	}

	var sanitizedHeaders map[string]string
	if cfg.OTLPExport.Headers != nil {
		sanitizedHeaders = make(map[string]string, len(cfg.OTLPExport.Headers))
		for k := range cfg.OTLPExport.Headers {
			sanitizedHeaders[k] = "[REDACTED]"
		}
	}

	view := &SanitizedConfigView{
		ActiveProfile: targetName,
		ConfigFile:    configPath,
		Profiles:      summaries,
		Server: SanitizedServerConfig{
			Port:       cfg.Server.Port,
			Host:       cfg.Server.Host,
			TLSEnabled: cfg.Server.TLS.Enabled,
			TLS: SanitizedTLS{
				Enabled:      cfg.Server.TLS.Enabled,
				AutoGenerate: cfg.Server.TLS.AutoGenerate,
				CertFile:     cfg.Server.TLS.CertFile,
				KeyFile:      cfg.Server.TLS.KeyFile,
				Organization: cfg.Server.TLS.Organization,
				ValidityDays: cfg.Server.TLS.ValidityDays,
				MinVersion:   cfg.Server.TLS.MinVersion,
				Hosts:        cfg.Server.TLS.Hosts,
			},
			RateLimit:           cfg.Server.RateLimit,
			MaxRequestBodyBytes: cfg.Server.MaxRequestBodyBytes,
		},
		Logging:    cfg.Logging,
		FileServer: cfg.FileServer,
		CommandExecutor: SanitizedExecutorConfig{
			Enabled:               cfg.Executor.Enabled,
			DefaultTimeout:        cfg.Executor.EffectiveDefaultTimeout().String(),
			DefaultTimeoutSeconds: cfg.Executor.DefaultTimeoutSeconds,
			MaxTimeoutSeconds:     cfg.Executor.MaxTimeoutSeconds,
			EnableOSPresets:       cfg.Executor.EnableOSPresets,
			OSPresets:             cfg.Executor.OSPresets,
			CommandsCount:         len(cfg.Executor.Commands),
		},
		Auth: SanitizedAuthConfig{
			Enabled:           cfg.Auth.Enabled,
			RequireAuth:       cfg.Auth.RequireAuth,
			BootstrapUsername: cfg.Auth.BootstrapUsername,
			BootstrapPassword: "[REDACTED]",
			BootstrapToken:    "[REDACTED]",
			StorePath:         cfg.Auth.StorePath,
		},
		Plugins: cfg.Plugins,
		MCP:     cfg.MCP,
		OTLPExport: SanitizedOTLPExportConfig{
			Enabled:            cfg.OTLPExport.Enabled,
			Endpoint:           cfg.OTLPExport.Endpoint,
			PushInterval:       cfg.OTLPExport.EffectivePushInterval().String(),
			Headers:            sanitizedHeaders,
			ResourceAttributes: cfg.OTLPExport.ResourceAttributes,
			Timeout:            cfg.OTLPExport.EffectiveTimeout().String(),
		},
	}

	return view, nil
}
