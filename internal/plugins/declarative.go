package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"go-admin-tool/internal/core"
	"gopkg.in/yaml.v3"
)

var defaultSafeParamRegex = regexp.MustCompile(`^[a-zA-Z0-9._:/-]+$`)

// DeclarativeActionSpec defines a single command action within a declarative plugin module.
type DeclarativeActionSpec struct {
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Command     string            `json:"command" yaml:"command"`
	Args        []string          `json:"args" yaml:"args"`
	Timeout     string            `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Parameters  []ActionParameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// DeclarativeModuleSpec defines a complete declarative command plugin module loadable from YAML or JSON.
type DeclarativeModuleSpec struct {
	ID          string                  `json:"id" yaml:"id"`
	Name        string                  `json:"name" yaml:"name"`
	Version     string                  `json:"version" yaml:"version"`
	Description string                  `json:"description" yaml:"description"`
	OSFamily    string                  `json:"os_family,omitempty" yaml:"os_family,omitempty"`
	Actions     []DeclarativeActionSpec `json:"actions" yaml:"actions"`
}

// DeclarativePlugin executes declaratively configured command actions with strict parameter validation.
type DeclarativePlugin struct {
	spec DeclarativeModuleSpec
}

// NewDeclarativePlugin validates a DeclarativeModuleSpec and constructs a DeclarativePlugin.
func NewDeclarativePlugin(spec DeclarativeModuleSpec) (*DeclarativePlugin, error) {
	spec.ID = strings.TrimSpace(spec.ID)
	spec.Name = strings.TrimSpace(spec.Name)
	if spec.ID == "" {
		return nil, errors.New("declarative plugin id is required")
	}
	if spec.Name == "" {
		spec.Name = spec.ID
	}
	if strings.TrimSpace(spec.Version) == "" {
		spec.Version = "1.0.0"
	}
	if len(spec.Actions) == 0 {
		return nil, fmt.Errorf("declarative plugin %q must define at least one action", spec.ID)
	}
	for _, a := range spec.Actions {
		if strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Command) == "" {
			return nil, fmt.Errorf("declarative plugin %q has an action with empty name or command", spec.ID)
		}
		for _, p := range a.Parameters {
			if p.Pattern != "" {
				if _, err := regexp.Compile(p.Pattern); err != nil {
					return nil, fmt.Errorf("invalid regex pattern %q on parameter %q: %w", p.Pattern, p.Name, err)
				}
			}
		}
	}
	return &DeclarativePlugin{spec: spec}, nil
}

func (p *DeclarativePlugin) ID() string          { return p.spec.ID }
func (p *DeclarativePlugin) Name() string        { return p.spec.Name }
func (p *DeclarativePlugin) Version() string     { return p.spec.Version }
func (p *DeclarativePlugin) Kind() PluginKind    { return KindDeclarative }
func (p *DeclarativePlugin) Description() string { return p.spec.Description }

func (p *DeclarativePlugin) Actions() []PluginAction {
	out := make([]PluginAction, 0, len(p.spec.Actions))
	for _, a := range p.spec.Actions {
		out = append(out, PluginAction{
			Name:        a.Name,
			Description: a.Description,
			Timeout:     a.Timeout,
			Parameters:  a.Parameters,
		})
	}
	return out
}

func (p *DeclarativePlugin) Execute(_ context.Context, actionName string, params map[string]any, timeout time.Duration) (PluginResult, error) {
	start := time.Now()
	var spec *DeclarativeActionSpec
	for _, a := range p.spec.Actions {
		if a.Name == actionName {
			aCopy := a
			spec = &aCopy
			break
		}
	}
	if spec == nil {
		return PluginResult{
			PluginID: p.ID(),
			Action:   actionName,
			Status:   "error",
			Error:    fmt.Sprintf("action %q not found in plugin %q", actionName, p.ID()),
		}, ErrActionNotFound
	}

	// Resolve and validate parameters
	resolvedParams := make(map[string]string, len(spec.Parameters))
	for _, paramDef := range spec.Parameters {
		var rawVal string
		if params != nil {
			if v, exists := params[paramDef.Name]; exists && v != nil {
				rawVal = fmt.Sprintf("%v", v)
			}
		}
		if rawVal == "" {
			rawVal = paramDef.Default
		}
		if rawVal == "" && paramDef.Required {
			return PluginResult{
				PluginID: p.ID(),
				Action:   actionName,
				Status:   "error",
				Error:    fmt.Sprintf("missing required parameter %q", paramDef.Name),
			}, fmt.Errorf("missing required parameter %q", paramDef.Name)
		}
		if rawVal != "" {
			re := defaultSafeParamRegex
			if paramDef.Pattern != "" {
				compiled, err := regexp.Compile(paramDef.Pattern)
				if err != nil {
					return PluginResult{PluginID: p.ID(), Action: actionName, Status: "error", Error: err.Error()}, err
				}
				re = compiled
			}
			// Reject shell metacharacters or unsafe tokens
			if strings.ContainsAny(rawVal, ";&|$`><\n\r") || !re.MatchString(rawVal) {
				err := fmt.Errorf("parameter %q value %q failed security validation", paramDef.Name, rawVal)
				return PluginResult{
					PluginID: p.ID(),
					Action:   actionName,
					Status:   "error",
					Error:    err.Error(),
				}, err
			}
			resolvedParams[paramDef.Name] = rawVal
		}
	}

	// Substitute {{param}} tokens inside individual argument elements (no shell concatenation)
	interpolatedArgs := make([]string, len(spec.Args))
	for i, arg := range spec.Args {
		val := arg
		for k, v := range resolvedParams {
			val = strings.ReplaceAll(val, "{{"+k+"}}", v)
		}
		interpolatedArgs[i] = val
	}

	cmdDef := core.CommandDefinition{
		Name:    fmt.Sprintf("%s:%s", p.ID(), actionName),
		Command: spec.Command,
		Args:    interpolatedArgs,
		Timeout: spec.Timeout,
	}
	effTimeout := cmdDef.EffectiveTimeout(timeout)
	output, err := core.ExecuteCommandWithTimeout(cmdDef, effTimeout)
	durMs := time.Since(start).Milliseconds()

	if err != nil {
		timedOut := core.IsCommandTimeout(err)
		status := "failure"
		if core.IsCommandSystemError(err) {
			status = "error"
		}
		return PluginResult{
			PluginID:   p.ID(),
			Action:     actionName,
			Status:     status,
			Output:     output,
			TimedOut:   timedOut,
			DurationMs: durMs,
			Error:      err.Error(),
		}, err
	}

	return PluginResult{
		PluginID:   p.ID(),
		Action:     actionName,
		Status:     "ok",
		Output:     output,
		DurationMs: durMs,
		Data: map[string]any{
			"output":     strings.TrimSpace(output),
			"parameters": resolvedParams,
		},
	}, nil
}

// RegisterDeclarativeModule parses and registers a DeclarativeModuleSpec on the Registry.
func (r *Registry) RegisterDeclarativeModule(spec DeclarativeModuleSpec) (*DeclarativePlugin, error) {
	p, err := NewDeclarativePlugin(spec)
	if err != nil {
		return nil, err
	}
	if err := r.Register(p); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadDeclarativeDirectory loads all .yaml, .yml, and .json declarative plugin files from dir.
func (r *Registry) LoadDeclarativeDirectory(dir string) (int, error) {
	if strings.TrimSpace(dir) == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return loaded, err
		}
		var spec DeclarativeModuleSpec
		if ext == ".json" {
			err = json.Unmarshal(raw, &spec)
		} else {
			err = yaml.Unmarshal(raw, &spec)
		}
		if err != nil {
			return loaded, fmt.Errorf("failed to parse declarative plugin %s: %w", entry.Name(), err)
		}
		if _, err := r.RegisterDeclarativeModule(spec); err != nil {
			return loaded, err
		}
		loaded++
	}
	return loaded, nil
}

// DefaultDeclarativeOpsPlugin returns a built-in cross-platform declarative command module.
func DefaultDeclarativeOpsPlugin() (*DeclarativePlugin, error) {
	var echoCmd string
	var echoArgs []string
	var whoamiCmd string
	var whoamiArgs []string

	if runtime.GOOS == "windows" {
		echoCmd = "cmd"
		echoArgs = []string{"/C", "echo", "target={{target}}"}
		whoamiCmd = "whoami"
		whoamiArgs = []string{}
	} else {
		echoCmd = "echo"
		echoArgs = []string{"target={{target}}"}
		whoamiCmd = "id"
		whoamiArgs = []string{}
	}

	spec := DeclarativeModuleSpec{
		ID:          "ops-quick-tools",
		Name:        "Declarative Quick Operations Module",
		Version:     "1.0.0",
		Description: "Declarative command module providing parameterized target ping/echo and identity verification.",
		Actions: []DeclarativeActionSpec{
			{
				Name:        "probe-target",
				Description: "Verify parameterized target identifier via declarative command execution",
				Command:     echoCmd,
				Args:        echoArgs,
				Timeout:     "10s",
				Parameters: []ActionParameter{
					{
						Name:        "target",
						Type:        "string",
						Required:    false,
						Default:     "localhost",
						Pattern:     `^[a-zA-Z0-9._-]+$`,
						Description: "Hostname or IPv4 target to probe",
					},
				},
			},
			{
				Name:        "process-identity",
				Description: "Report the OS user identity running the executor daemon",
				Command:     whoamiCmd,
				Args:        whoamiArgs,
				Timeout:     "5s",
			},
		},
	}
	return NewDeclarativePlugin(spec)
}
