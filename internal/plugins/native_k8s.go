package plugins

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// K8sManifestLinterPlugin parses and audits Kubernetes manifests for best practices, deprecated APIs, and resource limits.
type K8sManifestLinterPlugin struct{}

func (p *K8sManifestLinterPlugin) ID() string          { return "k8s-manifest-linter" }
func (p *K8sManifestLinterPlugin) Name() string        { return "Kubernetes Resource Manifest & Policy Linter" }
func (p *K8sManifestLinterPlugin) Version() string     { return "1.0.0" }
func (p *K8sManifestLinterPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *K8sManifestLinterPlugin) Type() string        { return "native" }
func (p *K8sManifestLinterPlugin) Category() string    { return "Kubernetes" }
func (p *K8sManifestLinterPlugin) Description() string {
	return "Lints Kubernetes resource manifests, detects deprecated API versions, and validates CPU/memory limits."
}

func (p *K8sManifestLinterPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "lint_manifest",
			Description: "Parse and audit Kubernetes YAML/JSON manifest structure",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "manifest_yaml", Type: "string", Required: true, Description: "Kubernetes YAML manifest content"},
			},
		},
		{
			Name:        "check_api_versions",
			Description: "Detect deprecated or removed Kubernetes API groups and versions",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "manifest_yaml", Type: "string", Required: true, Description: "Kubernetes YAML manifest content"},
			},
		},
		{
			Name:        "validate_limits",
			Description: "Validate that all workload containers define resource limits and requests",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "manifest_yaml", Type: "string", Required: true, Description: "Kubernetes YAML manifest content"},
			},
		},
	}
}

var deprecatedAPIs = map[string]string{
	"extensions/v1beta1":             "apps/v1",
	"apps/v1beta1":                   "apps/v1",
	"apps/v1beta2":                   "apps/v1",
	"networking.k8s.io/v1beta1":      "networking.k8s.io/v1",
	"rbac.authorization.k8s.io/v1beta1": "rbac.authorization.k8s.io/v1",
	"policy/v1beta1":                 "policy/v1",
}

func (p *K8sManifestLinterPlugin) Execute(_ context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	manifest := getStringParam(params, "manifest_yaml", "")

	if manifest == "" {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: "parameter 'manifest_yaml' is required",
		}, fmt.Errorf("parameter 'manifest_yaml' is required")
	}

	// Support passing path to manifest file
	if !strings.Contains(manifest, "\n") && (strings.HasSuffix(manifest, ".yaml") || strings.HasSuffix(manifest, ".yml")) {
		if b, err := os.ReadFile(manifest); err == nil {
			manifest = string(b)
		}
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(manifest), &parsed); err != nil {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: fmt.Sprintf("YAML parse error: %v", err),
		}, err
	}

	apiVersion, _ := parsed["apiVersion"].(string)
	kind, _ := parsed["kind"].(string)
	metadata, _ := parsed["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)

	switch normalized {
	case "lint_manifest":
		var issues []string
		if apiVersion == "" {
			issues = append(issues, "Missing 'apiVersion' field")
		}
		if kind == "" {
			issues = append(issues, "Missing 'kind' field")
		}
		if name == "" {
			issues = append(issues, "Missing 'metadata.name' field")
		}

		data := map[string]any{
			"api_version": apiVersion,
			"kind":        kind,
			"name":        name,
			"valid":       len(issues) == 0,
			"issues":      issues,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "check_api_versions":
		deprecated := false
		replacement := ""
		if rep, ok := deprecatedAPIs[apiVersion]; ok {
			deprecated = true
			replacement = rep
		}

		data := map[string]any{
			"api_version":          apiVersion,
			"kind":                 kind,
			"name":                 name,
			"is_deprecated":        deprecated,
			"recommended_api":      replacement,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "validate_limits":
		var missingLimits []string
		var missingRequests []string

		// Inspect containers inside spec.template.spec.containers
		if spec, ok := parsed["spec"].(map[string]any); ok {
			var containers []any
			if tpl, ok := spec["template"].(map[string]any); ok {
				if tplSpec, ok := tpl["spec"].(map[string]any); ok {
					if cList, ok := tplSpec["containers"].([]any); ok {
						containers = cList
					}
				}
			} else if cList, ok := spec["containers"].([]any); ok {
				containers = cList
			}

			for idx, c := range containers {
				if cMap, ok := c.(map[string]any); ok {
					cName, _ := cMap["name"].(string)
					if cName == "" {
						cName = fmt.Sprintf("container-%d", idx)
					}
					res, _ := cMap["resources"].(map[string]any)
					if res == nil {
						missingLimits = append(missingLimits, cName)
						missingRequests = append(missingRequests, cName)
					} else {
						if _, ok := res["limits"].(map[string]any); !ok {
							missingLimits = append(missingLimits, cName)
						}
						if _, ok := res["requests"].(map[string]any); !ok {
							missingRequests = append(missingRequests, cName)
						}
					}
				}
			}
		}

		compliant := (len(missingLimits) == 0 && len(missingRequests) == 0)
		data := map[string]any{
			"kind":             kind,
			"name":             name,
			"missing_limits":   missingLimits,
			"missing_requests": missingRequests,
			"compliant":        compliant,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	default:
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: fmt.Sprintf("action %q not found in plugin %q", action, p.ID()),
		}, ErrActionNotFound
	}
}

// HelmChartInspectorPlugin inspects Chart.yaml, values schemas, and dependency locks.
type HelmChartInspectorPlugin struct{}

func (p *HelmChartInspectorPlugin) ID() string          { return "helm-chart-inspector" }
func (p *HelmChartInspectorPlugin) Name() string        { return "Helm Chart Metadata & Values Schema Inspector" }
func (p *HelmChartInspectorPlugin) Version() string     { return "1.0.0" }
func (p *HelmChartInspectorPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *HelmChartInspectorPlugin) Type() string        { return "native" }
func (p *HelmChartInspectorPlugin) Category() string    { return "Kubernetes" }
func (p *HelmChartInspectorPlugin) Description() string {
	return "Inspects Helm Chart.yaml definitions, verifies chart version constraints, and audits values schemas."
}

func (p *HelmChartInspectorPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "inspect_chart",
			Description: "Parse Chart.yaml and validate schema and semantic version",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "chart_yaml", Type: "string", Required: true, Description: "Chart.yaml content or file path"},
			},
		},
		{
			Name:        "validate_values",
			Description: "Audit values.yaml structure for common security and resource defaults",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "values_yaml", Type: "string", Required: true, Description: "values.yaml content or file path"},
			},
		},
		{
			Name:        "check_dependencies",
			Description: "Verify Helm chart declared sub-charts and repositories",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "chart_yaml", Type: "string", Required: true, Description: "Chart.yaml content"},
			},
		},
	}
}

func (p *HelmChartInspectorPlugin) Execute(_ context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")

	switch normalized {
	case "inspect_chart", "check_dependencies":
		chartContent := getStringParam(params, "chart_yaml", "")
		if chartContent == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'chart_yaml' is required",
			}, fmt.Errorf("parameter 'chart_yaml' is required")
		}

		if !strings.Contains(chartContent, "\n") && strings.HasSuffix(chartContent, ".yaml") {
			if b, err := os.ReadFile(chartContent); err == nil {
				chartContent = string(b)
			}
		}

		var chart map[string]any
		if err := yaml.Unmarshal([]byte(chartContent), &chart); err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("YAML parse error: %v", err),
			}, err
		}

		name, _ := chart["name"].(string)
		version, _ := chart["version"].(string)
		appVersion, _ := chart["appVersion"].(string)
		apiVersion, _ := chart["apiVersion"].(string)
		deps, _ := chart["dependencies"].([]any)

		if normalized == "check_dependencies" {
			data := map[string]any{
				"chart_name":       name,
				"dependencies":     deps,
				"dependency_count": len(deps),
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
			}, nil
		}

		isValid := name != "" && version != "" && (apiVersion == "v2" || apiVersion == "v1")
		data := map[string]any{
			"name":        name,
			"version":     version,
			"app_version": appVersion,
			"api_version": apiVersion,
			"valid_v2":    apiVersion == "v2",
			"valid":       isValid,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "validate_values":
		valContent := getStringParam(params, "values_yaml", "")
		if valContent == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'values_yaml' is required",
			}, fmt.Errorf("parameter 'values_yaml' is required")
		}

		var values map[string]any
		if err := yaml.Unmarshal([]byte(valContent), &values); err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("YAML parse error: %v", err),
			}, err
		}

		hasReplicaCount := false
		if _, ok := values["replicaCount"]; ok {
			hasReplicaCount = true
		}
		hasImage := false
		if _, ok := values["image"]; ok {
			hasImage = true
		}
		hasResources := false
		if _, ok := values["resources"]; ok {
			hasResources = true
		}

		data := map[string]any{
			"key_count":         len(values),
			"has_replica_count": hasReplicaCount,
			"has_image":         hasImage,
			"has_resources":     hasResources,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	default:
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: fmt.Sprintf("action %q not found in plugin %q", action, p.ID()),
		}, ErrActionNotFound
	}
}
