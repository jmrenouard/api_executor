package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go-admin-tool/internal/core"
)

// buildFallbackSanitizedView constructs a sanitized view directly from a Config instance
// when MultiConfigManager is not initialized.
func buildFallbackSanitizedView(cfg *core.Config) *core.SanitizedConfigView {
	commandsCount := 0
	if cfg.Executor.Commands != nil {
		commandsCount = len(cfg.Executor.Commands)
	}

	var sanitizedHeaders map[string]string
	if cfg.OTLPExport.Headers != nil {
		sanitizedHeaders = make(map[string]string, len(cfg.OTLPExport.Headers))
		for k := range cfg.OTLPExport.Headers {
			sanitizedHeaders[k] = "[REDACTED]"
		}
	}

	return &core.SanitizedConfigView{
		ActiveProfile: "default",
		ConfigFile:    "config.yaml",
		Profiles: []core.ConfigProfileSummary{
			{
				Name:          "default",
				Path:          "config.yaml",
				Description:   "Default configuration profile",
				CommandsCount: commandsCount,
				IsDefault:     true,
			},
		},
		Server: core.SanitizedServerConfig{
			Port:       cfg.Server.Port,
			Host:       cfg.Server.Host,
			TLSEnabled: cfg.Server.TLS.Enabled,
			TLS: core.SanitizedTLS{
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
		CommandExecutor: core.SanitizedExecutorConfig{
			Enabled:               cfg.Executor.Enabled,
			DefaultTimeout:        cfg.Executor.EffectiveDefaultTimeout().String(),
			DefaultTimeoutSeconds: cfg.Executor.DefaultTimeoutSeconds,
			MaxTimeoutSeconds:     cfg.Executor.MaxTimeoutSeconds,
			EnableOSPresets:       cfg.Executor.EnableOSPresets,
			OSPresets:             cfg.Executor.OSPresets,
			CommandsCount:         commandsCount,
		},
		Auth: core.SanitizedAuthConfig{
			Enabled:           cfg.Auth.Enabled,
			RequireAuth:       cfg.Auth.RequireAuth,
			BootstrapUsername: cfg.Auth.BootstrapUsername,
			BootstrapPassword: "[REDACTED]",
			BootstrapToken:    "[REDACTED]",
			StorePath:         cfg.Auth.StorePath,
		},
		Plugins: cfg.Plugins,
		MCP:     cfg.MCP,
		OTLPExport: core.SanitizedOTLPExportConfig{
			Enabled:            cfg.OTLPExport.Enabled,
			Endpoint:           cfg.OTLPExport.Endpoint,
			PushInterval:       cfg.OTLPExport.EffectivePushInterval().String(),
			Headers:            sanitizedHeaders,
			ResourceAttributes: cfg.OTLPExport.ResourceAttributes,
			Timeout:            cfg.OTLPExport.EffectiveTimeout().String(),
		},
	}
}

// ConfigHandler godoc
// @Summary Inspect active configuration and multi-config profiles
// @Description Exposes a sanitized representation of the server configuration and available backward-compatible profiles.
// @Tags config
// @Produce json
// @Param profile query string false "Specific profile name to inspect"
// @Success 200 {object} core.SanitizedConfigView
// @Failure 404 {object} ErrorResponse
// @Failure 405 {object} ErrorResponse
// @Router /api/v1/config [get]
func (env *APIEnv) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestedProfile := ""

	// Check if profile is embedded in the URL path, e.g. /api/v1/configs/{profile} or /api/v1/config/{profile}
	path := strings.TrimSuffix(r.URL.Path, "/")
	if strings.HasPrefix(path, "/api/v1/configs/") {
		requestedProfile = strings.TrimPrefix(path, "/api/v1/configs/")
	} else if strings.HasPrefix(path, "/api/v1/config/") {
		requestedProfile = strings.TrimPrefix(path, "/api/v1/config/")
	}

	if requestedProfile == "" && r.URL != nil {
		requestedProfile = strings.TrimSpace(r.URL.Query().Get("profile"))
	}
	if requestedProfile == "" {
		requestedProfile = strings.TrimSpace(r.Header.Get("X-Config-Profile"))
	}
	if requestedProfile == "" {
		requestedProfile = strings.TrimSpace(r.Header.Get("X-API-Config"))
	}

	mgr := env.MultiConfigManager
	if mgr != nil {
		view, err := mgr.SanitizedView(requestedProfile)
		if err != nil {
			writeJSONError(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(view)
		return
	}

	// Fallback when MultiConfigManager is not initialized
	if requestedProfile != "" && requestedProfile != "default" {
		writeJSONError(w, fmt.Sprintf("configuration profile %q not found", requestedProfile), http.StatusNotFound)
		return
	}

	activeCfg := env.Config
	if activeCfg == nil {
		writeJSONError(w, "Configuration unavailable", http.StatusInternalServerError)
		return
	}

	view := buildFallbackSanitizedView(activeCfg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(view)
}
