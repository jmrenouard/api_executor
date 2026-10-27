package plugins

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type PluginKind string

const (
	KindDeclarative PluginKind = "declarative"
	KindAdvanced    PluginKind = "advanced"
)

var (
	ErrPluginNotFound    = errors.New("plugin not found")
	ErrActionNotFound    = errors.New("plugin action not found")
	ErrDuplicatePlugin   = errors.New("plugin already registered")
)

// ActionParameter describes an input parameter accepted by a plugin action.
type ActionParameter struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"` // string, int, bool
	Required    bool   `json:"required" yaml:"required"`
	Default     string `json:"default,omitempty" yaml:"default,omitempty"`
	Pattern     string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// PluginAction describes a callable operation exposed by a plugin.
type PluginAction struct {
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Timeout     string            `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Parameters  []ActionParameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// PluginInfo holds serializable metadata about a registered plugin.
type PluginInfo struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Kind        PluginKind     `json:"kind"`
	Type        string         `json:"type"`
	Category    string         `json:"category"`
	Description string         `json:"description"`
	Actions     []PluginAction `json:"actions"`
}

// PluginResult represents the structured output of a plugin execution.
type PluginResult struct {
	PluginID   string `json:"plugin_id"`
	Action     string `json:"action"`
	Status     string `json:"status"` // ok, error, failure
	Output     string `json:"output,omitempty"`
	Data       any    `json:"data,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// Plugin is the common interface implemented by both declarative command modules and complex native plugins.
type Plugin interface {
	ID() string
	Name() string
	Version() string
	Kind() PluginKind
	Type() string
	Category() string
	Description() string
	Actions() []PluginAction
	Execute(ctx context.Context, action string, params map[string]any, timeout time.Duration) (PluginResult, error)
}

// Registry manages all registered declarative and advanced plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
}

// NewRegistry creates a plugin registry populated with default native Go plugins.
func NewRegistry() *Registry {
	r := &Registry{
		plugins: make(map[string]Plugin),
	}
	RegisterDefaultNativePlugins(r, nil, 200)
	return r
}

// NewEmptyRegistry creates an empty plugin registry with no default plugins.
func NewEmptyRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

// Register adds a plugin to the registry, detecting duplicate IDs to prevent silent overwriting.
func (r *Registry) Register(p Plugin) error {
	if p == nil {
		return errors.New("cannot register nil plugin")
	}
	id := strings.TrimSpace(p.ID())
	if id == "" {
		return errors.New("plugin ID cannot be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.plugins[id]; exists {
		// Allow updating DatabaseExposurePlugin when binding a non-nil database instance
		if dbExp, ok := p.(*DatabaseExposurePlugin); ok && dbExp.db != nil {
			r.plugins[id] = p
			return nil
		}
		// Allow re-registering SystemDiagnosticsPlugin
		if _, ok := p.(*SystemDiagnosticsPlugin); ok {
			r.plugins[id] = p
			return nil
		}
		return fmt.Errorf("%w: plugin with ID %q is already registered", ErrDuplicatePlugin, id)
	}
	r.plugins[id] = p
	return nil
}

// RegisterOrReplace adds or forcibly updates a plugin in the registry without duplicate check.
func (r *Registry) RegisterOrReplace(p Plugin) error {
	if p == nil {
		return errors.New("cannot register nil plugin")
	}
	id := strings.TrimSpace(p.ID())
	if id == "" {
		return errors.New("plugin ID cannot be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[id] = p
	return nil
}

// Unregister removes a plugin by ID from the registry.
func (r *Registry) Unregister(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	id = strings.TrimSpace(id)
	if _, exists := r.plugins[id]; exists {
		delete(r.plugins, id)
		return true
	}
	return false
}

// Get retrieves a plugin by ID.
func (r *Registry) Get(id string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[strings.TrimSpace(id)]
	return p, ok
}

// List returns metadata for all registered plugins sorted by ID.
func (r *Registry) List() []PluginInfo {
	return r.ListFiltered("", "", "")
}

// ListFiltered returns metadata for registered plugins matching optional category, query, and pluginType filters, sorted by ID.
func (r *Registry) ListFiltered(category, query, pluginType string) []PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	category = strings.TrimSpace(strings.ToLower(category))
	query = strings.TrimSpace(strings.ToLower(query))
	pluginType = strings.TrimSpace(strings.ToLower(pluginType))

	out := make([]PluginInfo, 0, len(r.plugins))
	for _, p := range r.plugins {
		pType := p.Type()
		if pType == "" {
			if p.Kind() == KindDeclarative {
				pType = "declarative"
			} else {
				pType = "native"
			}
		}

		info := PluginInfo{
			ID:          p.ID(),
			Name:        p.Name(),
			Version:     p.Version(),
			Kind:        p.Kind(),
			Type:        pType,
			Category:    p.Category(),
			Description: p.Description(),
			Actions:     p.Actions(),
		}

		// Filter by category
		if category != "" && category != "all" {
			pCat := strings.ToLower(info.Category)
			if !strings.Contains(pCat, category) && !strings.EqualFold(info.Category, category) {
				continue
			}
		}

		// Filter by type ("native" vs "declarative")
		if pluginType != "" && pluginType != "all" {
			pTypeLower := strings.ToLower(info.Type)
			pKindLower := strings.ToLower(string(info.Kind))
			switch pluginType {
			case "native", "advanced":
				if pTypeLower != "native" && pKindLower != "advanced" {
					continue
				}
			case "declarative":
				if pTypeLower != "declarative" && pKindLower != "declarative" {
					continue
				}
			default:
				// Unrecognized or invalid plugin type filter matches nothing
				continue
			}
		}

		// Filter by query (case-insensitive substring in ID, Name, Description, Category, or Action names)
		if query != "" {
			match := strings.Contains(strings.ToLower(info.ID), query) ||
				strings.Contains(strings.ToLower(info.Name), query) ||
				strings.Contains(strings.ToLower(info.Description), query) ||
				strings.Contains(strings.ToLower(info.Category), query)

			if !match {
				for _, act := range info.Actions {
					if strings.Contains(strings.ToLower(act.Name), query) ||
						strings.Contains(strings.ToLower(act.Description), query) {
						match = true
						break
					}
				}
			}
			if !match {
				continue
			}
		}

		out = append(out, info)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

// Execute invokes a specific action on a registered plugin.
func (r *Registry) Execute(ctx context.Context, pluginID, action string, params map[string]any, timeout time.Duration) (PluginResult, error) {
	p, ok := r.Get(pluginID)
	if !ok {
		return PluginResult{
			PluginID: pluginID,
			Action:   action,
			Status:   "error",
			Error:    fmt.Sprintf("plugin %q not found", pluginID),
		}, ErrPluginNotFound
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return p.Execute(ctx, action, params, timeout)
}
