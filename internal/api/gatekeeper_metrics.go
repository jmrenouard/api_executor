package api

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	gatekeeperDecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gatekeeper_decisions_total",
			Help: "Total System-1 gatekeeper decisions partitioned by canonical decision and channel.",
		},
		[]string{"decision", "channel"},
	)
	gatekeeperLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gatekeeper_latency_seconds",
			Help:    "System-1 gatekeeper evaluation latency in seconds partitioned by adapter mode.",
			Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"mode"},
	)
)

func init() {
	prometheus.MustRegister(gatekeeperDecisionsTotal)
	prometheus.MustRegister(gatekeeperLatencySeconds)
}

// ResetGatekeeperMetrics resets System-1 gatekeeper Prometheus metrics for isolated tests.
func ResetGatekeeperMetrics() {
	gatekeeperDecisionsTotal.Reset()
	gatekeeperLatencySeconds.Reset()
}

func normalizeGatekeeperDecision(decision string) string {
	switch decision {
	case "allow":
		return "allow"
	case "deny", "block":
		return "deny"
	case "x_abstain", "escalate", "abstain":
		return "x_abstain"
	}
	trimmed := strings.TrimSpace(decision)
	switch {
	case strings.EqualFold(trimmed, "allow"):
		return "allow"
	case strings.EqualFold(trimmed, "deny"), strings.EqualFold(trimmed, "block"):
		return "deny"
	default:
		return "x_abstain"
	}
}

func normalizeGatekeeperChannel(channel string) string {
	switch channel {
	case "command":
		return "command"
	case "plugin":
		return "plugin"
	case "job":
		return "job"
	case "mcp":
		return "mcp"
	}
	trimmed := strings.TrimSpace(channel)
	switch {
	case strings.EqualFold(trimmed, "command"):
		return "command"
	case strings.EqualFold(trimmed, "plugin"):
		return "plugin"
	case strings.EqualFold(trimmed, "job"):
		return "job"
	case strings.EqualFold(trimmed, "mcp"):
		return "mcp"
	default:
		return "other"
	}
}

func normalizeGatekeeperMode(mode string) string {
	switch mode {
	case "http":
		return "http"
	case "cli":
		return "cli"
	case "noop":
		return "noop"
	}
	trimmed := strings.TrimSpace(mode)
	switch {
	case strings.EqualFold(trimmed, "http"):
		return "http"
	case strings.EqualFold(trimmed, "cli"):
		return "cli"
	case strings.EqualFold(trimmed, "noop"):
		return "noop"
	default:
		return "other"
	}
}

// RecordGatekeeperEvaluation records a System-1 gatekeeper verdict with strictly bounded
// compile-time Prometheus labels and zero steady-state heap allocations.
func RecordGatekeeperEvaluation(mode, channel, decision string, duration time.Duration) {
	gatekeeperDecisionsTotal.WithLabelValues(
		normalizeGatekeeperDecision(decision),
		normalizeGatekeeperChannel(channel),
	).Inc()
	if duration >= 0 {
		gatekeeperLatencySeconds.WithLabelValues(normalizeGatekeeperMode(mode)).Observe(duration.Seconds())
	}
}

// GetGatekeeperDecisionCount returns the current counter value for a normalized decision and channel.
func GetGatekeeperDecisionCount(decision, channel string) float64 {
	c, err := gatekeeperDecisionsTotal.GetMetricWithLabelValues(
		normalizeGatekeeperDecision(decision),
		normalizeGatekeeperChannel(channel),
	)
	if err != nil {
		return 0
	}
	return readCounterValue(c)
}
