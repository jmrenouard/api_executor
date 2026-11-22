package mcp

import (
	"strings"

	"go-admin-tool/internal/plugins"
)

const (
	// CISContractSchemaVersion identifies the finalized cis_benchmarks_tools MCP contract schema.
	CISContractSchemaVersion = "cis.mcp.contract.v1"
	// CISPluginID is the declarative plugin ID implementing read-only CIS compliance presets.
	CISPluginID = "cis-benchmarks-audit"
	// CISResourceURI is the read-only MCP resource URI exposing the CIS Benchmarks preset schema.
	CISResourceURI = "executor://cis-benchmarks/preset"
	// CISPromptName is the MCP prompt name for guided read-only CIS compliance audits.
	CISPromptName = "cis-benchmark-audit"
)

// CISPresetActionSpec describes one strictly read-only CLI preset from cis.mcp.contract.v1.
type CISPresetActionSpec struct {
	Name         string   `json:"name"`
	ReadOnly     bool     `json:"read_only"`
	Mutating     bool     `json:"mutating"`
	Command      string   `json:"command"`
	ArgsTemplate []string `json:"args_template"`
	Description  string   `json:"description"`
}

// CISBenchmarksPresetResource is the JSON payload returned by MCP resource executor://cis-benchmarks/preset.
type CISBenchmarksPresetResource struct {
	SchemaVersion        string                `json:"schema_version"`
	PluginID             string                `json:"plugin_id"`
	ConfigProfile        string                `json:"config_profile"`
	ConfigPath           string                `json:"config_path"`
	Entrypoint           string                `json:"entrypoint"`
	ReadOnly             bool                  `json:"read_only"`
	Mutating             bool                  `json:"mutating"`
	CanonicalTargets     []string              `json:"canonical_targets"`
	AllowedOptionalFlags []string              `json:"allowed_optional_flags"`
	ForbiddenFlags       []string              `json:"forbidden_flags"`
	ComplianceStates     []string              `json:"compliance_states"`
	ExitCodes            map[string]string     `json:"exit_codes"`
	CredentialBoundary   string                `json:"credential_boundary"`
	Actions              []CISPresetActionSpec `json:"actions"`
	PluginLoaded         bool                  `json:"plugin_loaded"`
	PluginSchema         *plugins.PluginInfo   `json:"plugin_schema,omitempty"`
}

var cisCanonicalTargets = [...]string{
	"mariadb106",
	"mariadb1011",
	"mysql80",
	"mysql-community84",
	"mysql-enterprise84",
	"mysql-community97",
	"mysql-enterprise97",
	"postgresql16",
	"postgresql17",
	"postgresql18",
	"mongodb7",
	"mongodb8",
	"cassandra40",
	"cassandra41",
	"cassandra50",
	"rhel8",
	"rhel9",
	"rhel10",
}

// CISCanonicalTargets returns the 18 canonical benchmark targets defined by cis.mcp.contract.v1.
func CISCanonicalTargets() []string {
	out := make([]string, len(cisCanonicalTargets))
	copy(out, cisCanonicalTargets[:])
	return out
}

// IsValidCISTarget reports whether target belongs to the 18 canonical cis.mcp.contract.v1 targets.
func IsValidCISTarget(target string) bool {
	trimmed := strings.TrimSpace(target)
	for _, allowed := range cisCanonicalTargets {
		if trimmed == allowed {
			return true
		}
	}
	return false
}

// CISAllowedOptionalFlags returns the optional read-only connection flags documented by cis.mcp.contract.v1.
func CISAllowedOptionalFlags() []string {
	return []string{
		"--docker",
		"--remote",
		"--ssh-port",
		"--ssh-key",
		"--db-host",
		"--db-port",
		"--db-user",
		"--db-name",
		"--defaults-file",
		"--auth-db",
		"--sudo",
	}
}

// CISForbiddenFlags returns the mutating, remediation-apply, and credential-leak flags rejected by this preset.
func CISForbiddenFlags() []string {
	return []string{
		"-p",
		"--password",
		"--db-password",
		"--apply",
		"--allow-ephemeral-apply",
		"--force",
		"--sync-cis",
		"--all",
		"--auto-detect",
		"--fix",
		"--remediate",
		"--write",
	}
}

// CISComplianceStates returns the 5-state compliance taxonomy defined by cis.mcp.contract.v1.
func CISComplianceStates() []string {
	return []string{
		"Pass",
		"Fail",
		"Error",
		"Manual",
		"Not Applicable",
	}
}

// BuildCISBenchmarksPresetResource constructs the read-only CIS preset descriptor exposed via MCP resources/read.
func BuildCISBenchmarksPresetResource(reg *plugins.Registry) CISBenchmarksPresetResource {
	res := CISBenchmarksPresetResource{
		SchemaVersion:        CISContractSchemaVersion,
		PluginID:             CISPluginID,
		ConfigProfile:        "cis-benchmarks",
		ConfigPath:           "configs/cis-benchmarks-audit.yaml",
		Entrypoint:           "audit-cis",
		ReadOnly:             true,
		Mutating:             false,
		CanonicalTargets:     CISCanonicalTargets(),
		AllowedOptionalFlags: CISAllowedOptionalFlags(),
		ForbiddenFlags:       CISForbiddenFlags(),
		ComplianceStates:     CISComplianceStates(),
		ExitCodes: map[string]string{
			"0": "success",
			"1": "audit_or_runtime_error",
			"2": "invalid_cli_arguments",
		},
		CredentialBoundary: "Pass database passwords strictly via the CIS_DB_PASSWORD environment variable; never pass credentials on CLI argv.",
		Actions: []CISPresetActionSpec{
			{
				Name:         "cis_list_targets",
				ReadOnly:     true,
				Mutating:     false,
				Command:      "audit-cis",
				ArgsTemplate: []string{"--list-targets"},
				Description:  "List all 18 canonical CIS benchmark targets and 887 compliance controls",
			},
			{
				Name:         "cis_audit_json",
				ReadOnly:     true,
				Mutating:     false,
				Command:      "audit-cis",
				ArgsTemplate: []string{"--target", "{{target}}", "--format", "json", "--lang", "{{lang}}", "--mode", "{{mode}}", "--output", "{{output_path}}"},
				Description:  "Execute a strictly read-only CIS compliance audit and emit a JSON report",
			},
			{
				Name:         "cis_audit_sarif",
				ReadOnly:     true,
				Mutating:     false,
				Command:      "audit-cis",
				ArgsTemplate: []string{"--target", "{{target}}", "--format", "sarif", "--lang", "{{lang}}", "--mode", "{{mode}}", "--output", "{{output_path}}"},
				Description:  "Execute a strictly read-only CIS compliance audit and emit a SARIF v2.1.0 report",
			},
			{
				Name:         "cis_remediate_dry_run",
				ReadOnly:     true,
				Mutating:     false,
				Command:      "audit-cis",
				ArgsTemplate: []string{"--remediate-dry-run", "--from-report", "{{report_path}}", "--remediation-format", "{{remediation_format}}", "--remediation-output", "{{output_path}}"},
				Description:  "Generate a strictly read-only dry-run remediation plan from an existing CIS JSON audit report (executes zero system commands)",
			},
		},
	}

	if reg != nil {
		if p, ok := reg.Get(CISPluginID); ok && p != nil {
			res.PluginLoaded = true
			res.PluginSchema = &plugins.PluginInfo{
				ID:          p.ID(),
				Name:        p.Name(),
				Version:     p.Version(),
				Kind:        p.Kind(),
				Type:        p.Type(),
				Category:    p.Category(),
				Description: p.Description(),
				Actions:     p.Actions(),
			}
		}
	}

	return res
}
