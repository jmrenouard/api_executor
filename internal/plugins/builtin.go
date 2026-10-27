package plugins

import (
	"go-admin-tool/internal/database"
)

// RegisterDefaultNativePlugins registers all 24 built-in native Go plugins across the 10 operational domains into r.
// If db is nil, a placeholder DatabaseExposurePlugin is registered.
func RegisterDefaultNativePlugins(r *Registry, db *database.DB, maxRows int) {
	// 1. SysAdmin
	_ = r.Register(NewSystemDiagnosticsPlugin())
	_ = r.Register(&HostStorageStatsPlugin{})
	_ = r.Register(&ProcessTreeAnalyzerPlugin{})

	// 2. NetOps
	_ = r.Register(&TCPUDPPortProbePlugin{})
	_ = r.Register(&DNSResolverAuditPlugin{})

	// 3. SecOps
	_ = r.Register(&FileIntegrityCheckerPlugin{})
	_ = r.Register(&PasswordPolicyAuditPlugin{})

	// 4. ContainerOps
	_ = r.Register(&DockerSocketClientPlugin{})
	_ = r.Register(&ContainerSpecValidatorPlugin{})

	// 5. Kubernetes
	_ = r.Register(&K8sManifestLinterPlugin{})
	_ = r.Register(&HelmChartInspectorPlugin{})

	// 6. DataOps
	_ = r.Register(NewDatabaseExposurePlugin(db, maxRows))
	_ = r.Register(&SQLiteSchemaAnalyzerPlugin{})
	_ = r.Register(&RedisProtocolProbePlugin{})

	// 7. DevOps
	_ = r.Register(&GitRepoInspectorPlugin{})
	_ = r.Register(&SemverReleaseCheckerPlugin{})

	// 8. SRE
	_ = r.Register(&PrometheusScraperPlugin{})
	_ = r.Register(&LogRegexAnalyzerPlugin{})

	// 9. AIOps
	_ = r.Register(&MCPEndpointTesterPlugin{})
	_ = r.Register(&ModelArtifactVerifierPlugin{})

	// 10. Web & Crypto Utilities
	_ = r.Register(&TLSCertInspectorPlugin{})
	_ = r.Register(&HTTPLatencyProbePlugin{})
	_ = r.Register(&CryptoHashUtilityPlugin{})
	_ = r.Register(&JWTTokenInspectorPlugin{})
}
