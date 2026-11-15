package api

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go-admin-tool/internal/jobs"
)

var (
	jobQueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "job_queue_depth",
			Help: "Current depth of the asynchronous job queue.",
		},
	)

	jobWorkersActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "job_workers_active",
			Help: "Current number of active worker goroutines executing jobs.",
		},
	)

	jobWorkersTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "job_workers_total",
			Help: "Total number of configured worker goroutines in the pool.",
		},
	)

	jobExecutionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "job_executions_total",
			Help: "Total number of asynchronous job executions.",
		},
		[]string{"status", "action"},
	)

	jobExecutionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "job_execution_duration_seconds",
			Help:    "Histogram of asynchronous job execution durations in seconds.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"action"},
	)
)

func init() {
	prometheus.MustRegister(jobQueueDepth)
	prometheus.MustRegister(jobWorkersActive)
	prometheus.MustRegister(jobWorkersTotal)
	prometheus.MustRegister(jobExecutionsTotal)
	prometheus.MustRegister(jobExecutionDuration)
}

// UpdateJobQueueMetrics updates the Prometheus gauges for queue depth and active workers.
func UpdateJobQueueMetrics(queued, active int) {
	jobQueueDepth.Set(float64(queued))
	jobWorkersActive.Set(float64(active))
}

// UpdateJobWorkersTotal updates the Prometheus gauge for total workers in the pool.
func UpdateJobWorkersTotal(total int) {
	jobWorkersTotal.Set(float64(total))
}

// normalizeJobStatus maps arbitrary status inputs to strictly bounded job_executions_total
// and action_mode_calls_total status literals without heap allocations.
func normalizeJobStatus(status string) (jobStatus, modeStatus string) {
	switch status {
	case string(jobs.StatusCompleted):
		return string(jobs.StatusCompleted), "ok"
	case string(jobs.StatusFailed):
		return string(jobs.StatusFailed), "failure"
	case string(jobs.StatusTimedOut), "timeout":
		return string(jobs.StatusTimedOut), "timeout"
	case string(jobs.StatusCancelled), "canceled":
		return string(jobs.StatusCancelled), "cancelled"
	case string(jobs.StatusQueued):
		return string(jobs.StatusQueued), "error"
	case string(jobs.StatusRunning):
		return string(jobs.StatusRunning), "error"
	case "", "unknown":
		return "unknown", "error"
	}

	trimmed := strings.TrimSpace(status)
	switch {
	case strings.EqualFold(trimmed, string(jobs.StatusCompleted)):
		return string(jobs.StatusCompleted), "ok"
	case strings.EqualFold(trimmed, string(jobs.StatusFailed)):
		return string(jobs.StatusFailed), "failure"
	case strings.EqualFold(trimmed, string(jobs.StatusTimedOut)), strings.EqualFold(trimmed, "timeout"):
		return string(jobs.StatusTimedOut), "timeout"
	case strings.EqualFold(trimmed, string(jobs.StatusCancelled)), strings.EqualFold(trimmed, "canceled"):
		return string(jobs.StatusCancelled), "cancelled"
	case strings.EqualFold(trimmed, string(jobs.StatusQueued)):
		return string(jobs.StatusQueued), "error"
	case strings.EqualFold(trimmed, string(jobs.StatusRunning)):
		return string(jobs.StatusRunning), "error"
	default:
		return "unknown", "error"
	}
}

// RecordJobExecution increments the executions counter and records duration in the histogram,
// and forwards unified asynchronous mode telemetry using single-pass normalized labels.
func RecordJobExecution(action, status string, dur time.Duration) {
	normAction := normalizeActionLabel(action)
	jobStatus, modeStatus := normalizeJobStatus(status)

	jobExecutionsTotal.WithLabelValues(jobStatus, normAction).Inc()
	if dur > 0 {
		jobExecutionDuration.WithLabelValues(normAction).Observe(dur.Seconds())
	}
	recordActionModeNormalized(normAction, "async", modeStatus, dur)
}

// ResetJobMetrics resets all async job Prometheus metric vectors (useful for isolated tests).
func ResetJobMetrics() {
	jobQueueDepth.Set(0)
	jobWorkersActive.Set(0)
	jobWorkersTotal.Set(0)
	jobExecutionsTotal.Reset()
	jobExecutionDuration.Reset()
}

// apiJobMetricsReporter bridges the Engine's MetricsReporter interface to Prometheus.
type apiJobMetricsReporter struct{}

var defaultJobMetricsReporter jobs.MetricsReporter = apiJobMetricsReporter{}

func (apiJobMetricsReporter) RecordJobExecution(action string, status jobs.JobStatus, duration time.Duration) {
	RecordJobExecution(action, string(status), duration)
}

func (apiJobMetricsReporter) RecordQueueStats(queuedJobs, activeWorkers int) {
	UpdateJobQueueMetrics(queuedJobs, activeWorkers)
}

// NewJobMetricsReporter returns a zero-escape MetricsReporter implementation for jobs.Engine.
func NewJobMetricsReporter() jobs.MetricsReporter {
	return defaultJobMetricsReporter
}

// Testing helper to read a Gauge value
func readGaugeValue(g prometheus.Gauge) float64 {
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// GetJobQueueDepth returns current job_queue_depth gauge value for tests.
func GetJobQueueDepth() float64 {
	return readGaugeValue(jobQueueDepth)
}

// GetJobWorkersActive returns current job_workers_active gauge value for tests.
func GetJobWorkersActive() float64 {
	return readGaugeValue(jobWorkersActive)
}

// GetJobWorkersTotal returns current job_workers_total gauge value for tests.
func GetJobWorkersTotal() float64 {
	return readGaugeValue(jobWorkersTotal)
}

// GetJobExecutionCount returns current counter value for status and action.
func GetJobExecutionCount(status, action string) float64 {
	act := strings.TrimSpace(action)
	if act == "" {
		act = "unknown"
	}
	if !isKnownActionLabel(act) {
		return 0
	}
	jobStatus, _ := normalizeJobStatus(status)
	counter, err := jobExecutionsTotal.GetMetricWithLabelValues(jobStatus, act)
	if err != nil {
		return 0
	}
	return readCounterValue(counter)
}
