package version

import (
	"encoding/json"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func TestResolveInfoFrom_LinkerFlagsPrecedence(t *testing.T) {
	fakeBI := func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Version: "v1.0.0"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "rev-from-bi"},
				{Key: "vcs.time", Value: "time-from-bi"},
				{Key: "vcs.modified", Value: "true"},
			},
		}, true
	}

	info := resolveInfoFrom("3.0.0", "custom-commit", "2026-11-12T00:00:00Z", "custom-integrity", fakeBI)
	if info.Version != "3.0.0" {
		t.Errorf("expected version 3.0.0, got %s", info.Version)
	}
	if info.GitCommit != "custom-commit" {
		t.Errorf("expected commit custom-commit, got %s", info.GitCommit)
	}
	if info.BuildDate != "2026-11-12T00:00:00Z" {
		t.Errorf("expected build date 2026-11-12T00:00:00Z, got %s", info.BuildDate)
	}
	if info.IntegrityStatus != "custom-integrity" || info.Integrity != "custom-integrity" {
		t.Errorf("expected integrity custom-integrity, got %s", info.IntegrityStatus)
	}
}

func TestResolveInfoFrom_BuildInfoFallback(t *testing.T) {
	fakeBIClean := func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Version: "v2.2.0-module"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abc1234567890abcdef1234567890abcdef1234"},
				{Key: "vcs.time", Value: "2026-11-12T18:10:58Z"},
				{Key: "vcs.modified", Value: "false"},
			},
		}, true
	}

	info := resolveInfoFrom("", "", "", "", fakeBIClean)
	if info.Version != "v2.2.0-module" {
		t.Errorf("expected module version, got %s", info.Version)
	}
	if info.GitCommit != "abc1234567890abcdef1234567890abcdef1234" {
		t.Errorf("expected commit hash from build info, got %s", info.GitCommit)
	}
	if info.BuildDate != "2026-11-12T18:10:58Z" {
		t.Errorf("expected build date from build info, got %s", info.BuildDate)
	}
	if info.IntegrityStatus != "clean" || info.Integrity != "clean" {
		t.Errorf("expected integrity clean, got %s", info.IntegrityStatus)
	}
}

func TestResolveInfoFrom_BuildInfoModified(t *testing.T) {
	fakeBIModified := func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Settings: []debug.BuildSetting{
				{Key: "vcs.modified", Value: "true"},
			},
		}, true
	}

	info := resolveInfoFrom("", "", "", "", fakeBIModified)
	if info.IntegrityStatus != "modified" || info.Integrity != "modified" {
		t.Errorf("expected integrity modified, got %s", info.IntegrityStatus)
	}
}

func TestResolveInfoFrom_CompleteEmptyFallbacks(t *testing.T) {
	fakeNoBI := func() (*debug.BuildInfo, bool) {
		return nil, false
	}

	info := resolveInfoFrom("", "", "", "", fakeNoBI)
	// VERSION file should resolve to 2.2.0 or DefaultVersion
	if info.Version != "2.2.0" {
		t.Errorf("expected version 2.2.0 from VERSION file/default, got %s", info.Version)
	}
	if info.GitCommit != "unknown" {
		t.Errorf("expected unknown commit fallback, got %s", info.GitCommit)
	}
	if info.BuildDate != "unknown" {
		t.Errorf("expected unknown build date fallback, got %s", info.BuildDate)
	}
	if info.IntegrityStatus != "untracked" || info.Integrity != "untracked" {
		t.Errorf("expected untracked integrity fallback, got %s", info.IntegrityStatus)
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("expected go version %s, got %s", runtime.Version(), info.GoVersion)
	}
	if info.OS != runtime.GOOS {
		t.Errorf("expected os %s, got %s", runtime.GOOS, info.OS)
	}
	if info.Arch != runtime.GOARCH {
		t.Errorf("expected arch %s, got %s", runtime.GOARCH, info.Arch)
	}
	if info.Compiler != runtime.Compiler {
		t.Errorf("expected compiler %s, got %s", runtime.Compiler, info.Compiler)
	}
}

func TestGet_ReturnsConsistentCachedInfo(t *testing.T) {
	info1 := Get()
	info2 := Get()

	if info1.Version != info2.Version || info1.GitCommit != info2.GitCommit {
		t.Errorf("expected cached Get() to return consistent info, got %+v and %+v", info1, info2)
	}
	if info1.Version == "" {
		t.Errorf("expected non-empty version from Get()")
	}
}

func TestResolveInfo_ReturnsNonEmptyRuntimeMetadata(t *testing.T) {
	info := ResolveInfo()
	if info.Version == "" {
		t.Errorf("expected non-empty Version")
	}
	if info.GoVersion == "" {
		t.Errorf("expected non-empty GoVersion")
	}
	if info.OS == "" {
		t.Errorf("expected non-empty OS")
	}
	if info.Arch == "" {
		t.Errorf("expected non-empty Arch")
	}
	if info.Compiler == "" {
		t.Errorf("expected non-empty Compiler")
	}
}

func TestResponse_UptimeCalculationAndClamping(t *testing.T) {
	info := Info{
		Version:         "2.2.0",
		GitCommit:       "commit-sha",
		BuildDate:       "2026-11-12T18:00:00Z",
		IntegrityStatus: "clean",
		Integrity:       "clean",
		GoVersion:       "go1.24.3",
		OS:              "linux",
		Arch:            "amd64",
		Compiler:        "gc",
	}

	// 1. Normal duration: 15.5 seconds ago
	start := time.Now().Add(-15500 * time.Millisecond)
	resp := info.Response(start)
	if resp.UptimeSeconds < 15.4 || resp.UptimeSeconds > 16.0 {
		t.Errorf("expected ~15.5s uptime_seconds, got %f", resp.UptimeSeconds)
	}
	if resp.Uptime == "" {
		t.Errorf("expected non-empty uptime string")
	}
	if resp.StartTime != start.UTC().Format(time.RFC3339) {
		t.Errorf("expected start_time %s, got %s", start.UTC().Format(time.RFC3339), resp.StartTime)
	}

	// 2. Future start time (negative duration clamped to 0)
	futureStart := time.Now().Add(1 * time.Hour)
	respFuture := info.Response(futureStart)
	if respFuture.UptimeSeconds != 0 {
		t.Errorf("expected 0 uptime_seconds for future start time, got %f", respFuture.UptimeSeconds)
	}

	// 3. Zero start time defaults to time.Now()
	respZero := info.Response(time.Time{})
	if respZero.UptimeSeconds < 0 || respZero.UptimeSeconds > 1 {
		t.Errorf("expected small positive uptime_seconds for zero time, got %f", respZero.UptimeSeconds)
	}

	// 4. JSON serialization roundtrip
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal VersionResponse: %v", err)
	}
	var decoded VersionResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal VersionResponse: %v", err)
	}
	if decoded.Version != "2.2.0" || decoded.IntegrityStatus != "clean" || decoded.Integrity != "clean" {
		t.Errorf("unexpected decoded values: %+v", decoded)
	}
}
