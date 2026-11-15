package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go-admin-tool/internal/core"
	"go-admin-tool/internal/version"
)

var defaultServerStartTime = time.Now()

// ConfigVersionResponse represents the JSON payload returned by conditional config version probes.
type ConfigVersionResponse struct {
	Version       string `json:"version"`
	ConfigVersion string `json:"config_version"`
	Profile       string `json:"profile"`
	ConfigFile    string `json:"config_file"`
	Path          string `json:"path"`
	AppVersion    string `json:"app_version"`
}

// parseConfigVersionPath recognizes /api/v1/config/version, /api/v1/configs/version,
// /api/v1/config/{profile}/version, and /api/v1/configs/{profile}/version (with or without trailing slash).
func parseConfigVersionPath(rawPath string) (string, bool) {
	path := strings.TrimSuffix(rawPath, "/")
	if path == "/api/v1/config/version" || path == "/api/v1/configs/version" {
		return "", true
	}
	var sub string
	switch {
	case strings.HasPrefix(path, "/api/v1/configs/"):
		sub = strings.TrimPrefix(path, "/api/v1/configs/")
	case strings.HasPrefix(path, "/api/v1/config/"):
		sub = strings.TrimPrefix(path, "/api/v1/config/")
	default:
		return "", false
	}
	parts := strings.Split(sub, "/")
	if len(parts) == 2 && parts[0] != "" && parts[1] == "version" {
		return parts[0], true
	}
	return "", false
}

func effectiveConfigVersionPathForProfile(cfg *core.Config, profile string, isDefault bool) string {
	if cfg == nil || cfg.EffectiveVersion() == "" {
		return ""
	}
	if !isDefault && strings.TrimSpace(cfg.ConfigVersionPath) == "" && profile != "" {
		return fmt.Sprintf("/api/v1/configs/%s/version", profile)
	}
	return cfg.EffectiveVersionPath()
}

// resolveConfigVersionTarget resolves the target profile name, config object, config file path,
// and effective version endpoint path from URL path, query parameters, headers, or custom mounted paths.
func (env *APIEnv) resolveConfigVersionTarget(r *http.Request) (profile string, cfg *core.Config, configFile string, versionPath string, found bool) {
	requestedProfile := ""
	requestPath := ""
	if r != nil && r.URL != nil {
		requestPath = strings.TrimSuffix(r.URL.Path, "/")
		if pathProfile, ok := parseConfigVersionPath(r.URL.Path); ok && pathProfile != "" {
			requestedProfile = pathProfile
		}
		if requestedProfile == "" {
			requestedProfile = strings.TrimSpace(r.URL.Query().Get("profile"))
		}
	}
	if requestedProfile == "" && r != nil {
		requestedProfile = strings.TrimSpace(r.Header.Get("X-Config-Profile"))
	}
	if requestedProfile == "" && r != nil {
		requestedProfile = strings.TrimSpace(r.Header.Get("X-API-Config"))
	}

	if env == nil {
		if requestedProfile == "" {
			return "default", nil, "", "", true
		}
		return requestedProfile, nil, "", "", false
	}

	if env.MultiConfigManager != nil {
		defaultProfile := env.MultiConfigManager.DefaultProfile()
		targetProfile := requestedProfile

		// When no explicit profile is supplied and the request targets a custom ConfigVersionPath,
		// match the profile whose EffectiveVersionPath matches the request path.
		if targetProfile == "" && requestPath != "" &&
			requestPath != "/api/v1/config/version" && requestPath != "/api/v1/configs/version" {
			if defCfg, ok := env.MultiConfigManager.GetProfile(defaultProfile); ok && defCfg != nil &&
				strings.TrimSuffix(defCfg.EffectiveVersionPath(), "/") == requestPath {
				targetProfile = defaultProfile
			} else {
				for _, summary := range env.MultiConfigManager.ListProfiles() {
					if pCfg, ok := env.MultiConfigManager.GetProfile(summary.Name); ok && pCfg != nil &&
						strings.TrimSuffix(pCfg.EffectiveVersionPath(), "/") == requestPath {
						targetProfile = summary.Name
						break
					}
				}
			}
		}

		if targetProfile == "" {
			targetProfile = defaultProfile
		}

		resolvedCfg, ok := env.MultiConfigManager.GetProfile(targetProfile)
		if !ok {
			if requestedProfile == "" && env.Config != nil {
				resolvedCfg = env.Config
			} else {
				return targetProfile, nil, "", "", false
			}
		}

		cfgPath := env.MultiConfigManager.GetProfilePath(targetProfile)
		if cfgPath == "" && resolvedCfg != nil {
			cfgPath = strings.TrimSpace(resolvedCfg.SourcePath)
		}
		if cfgPath == "" {
			cfgPath = "config.yaml"
		}

		isDefault := targetProfile == defaultProfile
		return targetProfile, resolvedCfg, cfgPath, effectiveConfigVersionPathForProfile(resolvedCfg, targetProfile, isDefault), true
	}

	if requestedProfile != "" && requestedProfile != "default" {
		return requestedProfile, nil, "", "", false
	}

	if env.Config == nil {
		return "default", nil, "", "", true
	}

	cfgPath := strings.TrimSpace(env.Config.SourcePath)
	if cfgPath == "" {
		cfgPath = "config.yaml"
	}
	return "default", env.Config, cfgPath, effectiveConfigVersionPathForProfile(env.Config, "default", true), true
}

// VersionHandler godoc
// @Summary Certified native version & build metadata endpoint
// @Description Returns official source version, Git commit SHA, build date, integrity status, uptime, and Go runtime version directly from source truth without intermediaries.
// @Tags system
// @Produce json
// @Success 200 {object} version.VersionResponse
// @Failure 405 {object} ErrorResponse
// @Router /api/v1/version [get]
func (env *APIEnv) VersionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	st := defaultServerStartTime
	if env != nil && !env.StartTime.IsZero() {
		st = env.StartTime
	}

	resp := version.Get().Response(st)
	if env != nil {
		if _, cfg, configFile, versionPath, ok := env.resolveConfigVersionTarget(r); ok && cfg != nil {
			if cfgVer := cfg.EffectiveVersion(); cfgVer != "" {
				resp.ConfigVersion = cfgVer
				resp.ConfigVersionPath = versionPath
				resp.ConfigFile = configFile
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ConfigVersionHandler godoc
// @Summary Conditional configuration version probe endpoint
// @Description Returns configuration version metadata for the active or requested profile when a config version is defined, or 404 when unversioned.
// @Tags config
// @Produce json
// @Param profile query string false "Specific profile name to inspect"
// @Success 200 {object} ConfigVersionResponse
// @Failure 404 {object} ErrorResponse
// @Failure 405 {object} ErrorResponse
// @Router /api/v1/config/version [get]
func (env *APIEnv) ConfigVersionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if env == nil {
		writeJSONError(w, fmt.Sprintf("configuration version not defined for profile %q", "default"), http.StatusNotFound)
		return
	}

	profile, cfg, configFile, versionPath, ok := env.resolveConfigVersionTarget(r)
	if !ok {
		writeJSONError(w, fmt.Sprintf("configuration profile %q not found", profile), http.StatusNotFound)
		return
	}

	if cfg == nil || cfg.EffectiveVersion() == "" {
		writeJSONError(w, fmt.Sprintf("configuration version not defined for profile %q", profile), http.StatusNotFound)
		return
	}

	cfgVer := cfg.EffectiveVersion()
	resp := ConfigVersionResponse{
		Version:       cfgVer,
		ConfigVersion: cfgVer,
		Profile:       profile,
		ConfigFile:    configFile,
		Path:          versionPath,
		AppVersion:    version.Get().Version,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
