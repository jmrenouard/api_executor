package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"go-admin-tool/internal/core"
)

// SystemDiagnosticsPlugin is a complex native Go plugin providing zero-spawn runtime, memory, OS, and network telemetry.
type SystemDiagnosticsPlugin struct{}

func NewSystemDiagnosticsPlugin() *SystemDiagnosticsPlugin {
	return &SystemDiagnosticsPlugin{}
}

func (p *SystemDiagnosticsPlugin) ID() string          { return "sys-diagnostics" }
func (p *SystemDiagnosticsPlugin) Name() string        { return "System Telemetry & Host Diagnostics" }
func (p *SystemDiagnosticsPlugin) Version() string     { return "2.0.0" }
func (p *SystemDiagnosticsPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *SystemDiagnosticsPlugin) Description() string {
	return "Native Go diagnostics plugin providing host OS detection, memory/goroutine telemetry, network interface inspection, and sanitized environment auditing."
}

func (p *SystemDiagnosticsPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "runtime_stats",
			Description: "Collect Go runtime, CPU, goroutine, heap allocation, and detected OS family telemetry",
			Timeout:     "5s",
		},
		{
			Name:        "network_interfaces",
			Description: "Inspect host network interfaces, hardware MAC addresses, MTU, and IP/CIDR bindings",
			Timeout:     "5s",
		},
		{
			Name:        "env_summary",
			Description: "Audit non-sensitive process environment variables with automatic secret masking",
			Timeout:     "5s",
		},
	}
}

func (p *SystemDiagnosticsPlugin) Execute(_ context.Context, action string, _ map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	switch action {
	case "runtime_stats":
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		hostname, _ := os.Hostname()
		data := map[string]any{
			"hostname":         hostname,
			"go_version":       runtime.Version(),
			"goos":             runtime.GOOS,
			"goarch":           runtime.GOARCH,
			"detected_os":      core.DetectHostOSFamily(),
			"num_cpu":          runtime.NumCPU(),
			"num_goroutine":    runtime.NumGoroutine(),
			"heap_alloc_bytes": mem.HeapAlloc,
			"heap_sys_bytes":   mem.HeapSys,
			"num_gc":           mem.NumGC,
		}
		raw, _ := json.MarshalIndent(data, "", "  ")
		return PluginResult{
			PluginID:   p.ID(),
			Action:     action,
			Status:     "ok",
			Output:     string(raw),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "network_interfaces":
		ifaces, err := net.Interfaces()
		if err != nil {
			return PluginResult{PluginID: p.ID(), Action: action, Status: "error", Error: err.Error()}, err
		}
		var list []map[string]any
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			var addrStrs []string
			for _, a := range addrs {
				addrStrs = append(addrStrs, a.String())
			}
			list = append(list, map[string]any{
				"name":      iface.Name,
				"mtu":       iface.MTU,
				"mac":       iface.HardwareAddr.String(),
				"flags":     iface.Flags.String(),
				"addresses": addrStrs,
			})
		}
		data := map[string]any{"interfaces": list}
		raw, _ := json.MarshalIndent(data, "", "  ")
		return PluginResult{
			PluginID:   p.ID(),
			Action:     action,
			Status:     "ok",
			Output:     string(raw),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "env_summary":
		masked := make(map[string]string)
		for _, kv := range os.Environ() {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			k, v := parts[0], parts[1]
			upper := strings.ToUpper(k)
			if strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "KEY") {
				masked[k] = "***REDACTED***"
			} else if len(v) <= 120 {
				masked[k] = v
			}
		}
		data := map[string]any{"environment": masked}
		raw, _ := json.MarshalIndent(data, "", "  ")
		return PluginResult{
			PluginID:   p.ID(),
			Action:     action,
			Status:     "ok",
			Output:     string(raw),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil

	default:
		return PluginResult{
			PluginID: p.ID(),
			Action:   action,
			Status:   "error",
			Error:    fmt.Sprintf("unknown action %q on plugin %q", action, p.ID()),
		}, ErrActionNotFound
	}
}
