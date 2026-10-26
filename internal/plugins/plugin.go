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
	ErrPluginNotFound = errors.New("plugin not found")
	ErrActionNotFound = errors.New("plugin action not found")
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
	Description() string
	Actions() []PluginAction
	Execute(ctx context.Context, action string, params map[string]any, timeout time.Duration) (PluginResult, error)
}

// Registry manages all registered declarative and advanced plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
}

// NewRegistry creates an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

// Register adds or updates a plugin in the registry.
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
	r.plugins[id] = p
	return nil
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PluginInfo, 0, len(r.plugins))
	for _, p := range r.plugins {
		out = append(out, PluginInfo{
			ID:          p.ID(),
			Name:        p.Name(),
			Version:     p.Version(),
			Kind:        p.Kind(),
			Description: p.Description(),
			Actions:     p.Actions(),
		})
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
