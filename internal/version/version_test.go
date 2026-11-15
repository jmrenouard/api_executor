package version

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
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

func TestResolveInfo_TempVersionFile(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "VERSION"), []byte("2.1.0\n"), 0644); err != nil {
		t.Fatalf("failed to write temp VERSION file: %v", err)
	}
	t.Chdir(tmpDir)

	info := ResolveInfo()
	if info.Version != "2.1.0" {
		t.Errorf("expected Version '2.1.0' from temp VERSION file, got %q", info.Version)
	}
}

func TestResolveInfo_RealRepoGitCommit(t *testing.T) {
	info := ResolveInfo()
	if len(info.GitCommit) != 40 {
		t.Fatalf("expected 40-char git commit in repo, got %q (len=%d)", info.GitCommit, len(info.GitCommit))
	}
	for i := 0; i < len(info.GitCommit); i++ {
		c := info.GitCommit[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			t.Fatalf("expected hex git commit, got %q", info.GitCommit)
		}
	}
}

func TestResolveGitCommitFromDir(t *testing.T) {
	const shaDirect = "0123456789abcdef0123456789abcdef01234567"
	const shaLoose = "fedcba9876543210fedcba9876543210fedcba98"
	const shaPacked = "abcdef0123456789abcdef0123456789abcdef01"

	t.Run("direct SHA in HEAD", func(t *testing.T) {
		gitDir := filepath.Join(t.TempDir(), ".git")
		if err := os.MkdirAll(gitDir, 0755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(shaDirect+"\n"), 0644); err != nil {
			t.Fatalf("write HEAD failed: %v", err)
		}
		if got := resolveGitCommitFromDir(gitDir); got != shaDirect {
			t.Errorf("expected %q, got %q", shaDirect, got)
		}
	})

	t.Run("symbolic ref loose file", func(t *testing.T) {
		gitDir := filepath.Join(t.TempDir(), ".git")
		refDir := filepath.Join(gitDir, "refs", "heads")
		if err := os.MkdirAll(refDir, 0755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
			t.Fatalf("write HEAD failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(refDir, "main"), []byte(shaLoose+"\n"), 0644); err != nil {
			t.Fatalf("write ref failed: %v", err)
		}
		if got := resolveGitCommitFromDir(gitDir); got != shaLoose {
			t.Errorf("expected %q, got %q", shaLoose, got)
		}
	})

	t.Run("packed-refs fallback", func(t *testing.T) {
		gitDir := filepath.Join(t.TempDir(), ".git")
		if err := os.MkdirAll(gitDir, 0755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/release/v2\n"), 0644); err != nil {
			t.Fatalf("write HEAD failed: %v", err)
		}
		packed := strings.Join([]string{
			"# pack-refs with: peeled fully-peeled sorted",
			shaDirect + " refs/tags/v2.2.0",
			"^" + shaLoose,
			shaPacked + " refs/heads/release/v2",
		}, "\n") + "\n"
		if err := os.WriteFile(filepath.Join(gitDir, "packed-refs"), []byte(packed), 0644); err != nil {
			t.Fatalf("write packed-refs failed: %v", err)
		}
		if got := resolveGitCommitFromDir(gitDir); got != shaPacked {
			t.Errorf("expected %q, got %q", shaPacked, got)
		}
	})

	t.Run("worktree gitdir file with commondir", func(t *testing.T) {
		root := t.TempDir()
		mainGit := filepath.Join(root, "main", ".git")
		wtDir := filepath.Join(mainGit, "worktrees", "feature-wt")
		wtRoot := filepath.Join(root, "wt")
		if err := os.MkdirAll(filepath.Join(mainGit, "refs", "heads"), 0755); err != nil {
			t.Fatalf("mkdir mainGit failed: %v", err)
		}
		if err := os.MkdirAll(wtDir, 0755); err != nil {
			t.Fatalf("mkdir wtDir failed: %v", err)
		}
		if err := os.MkdirAll(wtRoot, 0755); err != nil {
			t.Fatalf("mkdir wtRoot failed: %v", err)
		}
		// Worktree .git file pointing to wtDir using relative forward-slash path
		dotGitFile := filepath.Join(wtRoot, ".git")
		if err := os.WriteFile(dotGitFile, []byte("gitdir: ../main/.git/worktrees/feature-wt\n"), 0644); err != nil {
			t.Fatalf("write .git file failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(wtDir, "HEAD"), []byte("ref: refs/heads/feat/wt\n"), 0644); err != nil {
			t.Fatalf("write wt HEAD failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(wtDir, "commondir"), []byte("../..\n"), 0644); err != nil {
			t.Fatalf("write commondir failed: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(mainGit, "refs", "heads", "feat"), 0755); err != nil {
			t.Fatalf("mkdir feat ref dir failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(mainGit, "refs", "heads", "feat", "wt"), []byte(shaLoose+"\n"), 0644); err != nil {
			t.Fatalf("write branch ref failed: %v", err)
		}
		if got := resolveGitCommitFromDir(dotGitFile); got != shaLoose {
			t.Errorf("expected %q, got %q", shaLoose, got)
		}
	})

	t.Run("missing or invalid path returns empty", func(t *testing.T) {
		if got := resolveGitCommitFromDir(filepath.Join(t.TempDir(), "missing.git")); got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})
}

func TestVersionResponse_ConfigFieldsJSON(t *testing.T) {
	base := Info{
		Version:         "2.2.0",
		GitCommit:       "0123456789abcdef0123456789abcdef01234567",
		BuildDate:       "2026-11-15T20:00:00Z",
		IntegrityStatus: "clean",
		Integrity:       "clean",
		GoVersion:       runtime.Version(),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Compiler:        runtime.Compiler,
	}.Response(time.Now().Add(-5 * time.Second))

	rawOmitted, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal without config fields failed: %v", err)
	}
	var mOmitted map[string]any
	if err := json.Unmarshal(rawOmitted, &mOmitted); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	for _, key := range []string{"config_version", "config_version_path", "config_file"} {
		if _, ok := mOmitted[key]; ok {
			t.Errorf("expected %q to be omitted when empty", key)
		}
	}

	base.ConfigVersion = "2.2.0"
	base.ConfigVersionPath = "/api/v1/config/version"
	base.ConfigFile = "config.yaml"

	rawWithCfg, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal with config fields failed: %v", err)
	}
	var decoded VersionResponse
	if err := json.Unmarshal(rawWithCfg, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.ConfigVersion != "2.2.0" || decoded.ConfigVersionPath != "/api/v1/config/version" || decoded.ConfigFile != "config.yaml" {
		t.Errorf("unexpected config fields in decoded response: %+v", decoded)
	}
}
