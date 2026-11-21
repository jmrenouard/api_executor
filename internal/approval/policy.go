package approval

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"go-admin-tool/internal/core"
)

// Status represents the lifecycle state of a HITL approval request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
	StatusExpired  Status = "expired"
	StatusConsumed Status = "consumed"
)

// IsTerminal reports whether the status is a final state that cannot transition further.
func (s Status) IsTerminal() bool {
	return s == StatusRejected || s == StatusExpired || s == StatusConsumed
}

// Channel identifies the ingress channel that triggered an approval check.
type Channel string

const (
	ChannelCommand Channel = "command"
	ChannelPlugin  Channel = "plugin"
	ChannelJob     Channel = "job"
	ChannelMCP     Channel = "mcp"
)

// Target uniquely identifies the operation and parameters bound to an approval request.
type Target struct {
	Channel    Channel        `json:"channel"`
	Action     string         `json:"action"`
	PluginID   string         `json:"plugin_id,omitempty"`
	ToolName   string         `json:"tool_name,omitempty"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

// ComputePayloadSHA256 returns a deterministic lowercase SHA-256 hex digest over the
// canonical JSON encoding of target. Identical targets always yield identical digests.
func ComputePayloadSHA256(target Target) (string, error) {
	normalized := Target{
		Channel:  Channel(strings.ToLower(strings.TrimSpace(string(target.Channel)))),
		Action:   strings.TrimSpace(target.Action),
		PluginID: strings.TrimSpace(target.PluginID),
		ToolName: strings.TrimSpace(target.ToolName),
	}
	if len(target.Parameters) > 0 {
		normalized.Parameters = target.Parameters
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("failed to marshal canonical approval payload: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ConstantTimeDigestEqual compares two 64-character hex SHA-256 digests in constant time.
func ConstantTimeDigestEqual(a, b string) bool {
	if len(a) != 64 || len(b) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Policy evaluates whether a command, plugin, job, or MCP tool invocation requires HITL approval.
type Policy struct {
	cfg core.ApprovalConfig
}

// NewPolicy creates a Policy from ApprovalConfig.
func NewPolicy(cfg core.ApprovalConfig) *Policy {
	return &Policy{cfg: cfg}
}

// Enabled reports whether HITL approval enforcement is enabled.
func (p *Policy) Enabled() bool {
	return p != nil && p.cfg.Enabled
}

// Config returns a copy of the policy configuration.
func (p *Policy) Config() core.ApprovalConfig {
	if p == nil {
		return core.DefaultApprovalConfig()
	}
	return p.cfg
}

// RequiresApproval reports whether target requires HITL approval under the active policy.
// commandFlag reflects a CommandDefinition's explicit require_approval: true setting.
func (p *Policy) RequiresApproval(target Target, commandFlag bool) bool {
	if p == nil || !p.cfg.Enabled {
		return false
	}
	if commandFlag {
		return true
	}

	channel := Channel(strings.ToLower(strings.TrimSpace(string(target.Channel))))
	action := strings.TrimSpace(target.Action)
	pluginID := strings.TrimSpace(target.PluginID)
	toolName := strings.TrimSpace(target.ToolName)

	switch channel {
	case ChannelCommand:
		return matchPattern(p.cfg.CriticalCommands, action)
	case ChannelPlugin:
		return matchPluginPatterns(p.cfg.CriticalPlugins, pluginID, action)
	case ChannelJob:
		if pluginID != "" {
			return matchPluginPatterns(p.cfg.CriticalPlugins, pluginID, action)
		}
		return matchPattern(p.cfg.CriticalCommands, action)
	case ChannelMCP:
		if matchPattern(p.cfg.CriticalMCPTools, toolName) {
			return true
		}
		if strings.EqualFold(toolName, "execute_command") && action != "" {
			return matchPattern(p.cfg.CriticalCommands, action)
		}
		if strings.EqualFold(toolName, "execute_plugin") && pluginID != "" {
			return matchPluginPatterns(p.cfg.CriticalPlugins, pluginID, action)
		}
		return false
	default:
		return false
	}
}

func matchPluginPatterns(patterns []string, pluginID, action string) bool {
	if len(patterns) == 0 || pluginID == "" {
		return false
	}
	candidates := []string{
		pluginID,
		fmt.Sprintf("%s:%s", pluginID, action),
		fmt.Sprintf("plugin:%s:%s", pluginID, action),
	}
	if action != "" {
		candidates = append(candidates, action)
	}
	for _, c := range candidates {
		if matchPattern(patterns, c) {
			return true
		}
	}
	return false
}

func matchPattern(patterns []string, value string) bool {
	val := strings.ToLower(strings.TrimSpace(value))
	if val == "" {
		return false
	}
	for _, raw := range patterns {
		pat := strings.ToLower(strings.TrimSpace(raw))
		if pat == "" {
			continue
		}
		if pat == "*" || pat == val {
			return true
		}
		if strings.HasSuffix(pat, "*") {
			prefix := strings.TrimSuffix(pat, "*")
			if strings.HasPrefix(val, prefix) {
				return true
			}
		}
	}
	return false
}
