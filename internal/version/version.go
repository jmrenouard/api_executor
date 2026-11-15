package version

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

var (
	// DefaultVersion is the fallback source version matching the repository VERSION file.
	DefaultVersion = "2.2.0"

	// Linker-injected build metadata (can be overridden at build time via -ldflags -X).
	Version         = ""
	GitCommit       = ""
	BuildDate       = ""
	IntegrityStatus = ""

	initOnce      sync.Once
	cached        Info
	readBuildInfo = debug.ReadBuildInfo
)

// Info encapsulates the certified native build and source metadata.
type Info struct {
	Version         string `json:"version"`
	GitCommit       string `json:"git_commit"`
	BuildDate       string `json:"build_date"`
	IntegrityStatus string `json:"integrity_status"`
	Integrity       string `json:"integrity"`
	GoVersion       string `json:"go_version"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	Compiler        string `json:"compiler"`
}

// VersionResponse represents the payload returned by GET /api/v1/version.
type VersionResponse struct {
	Version           string  `json:"version"`
	GitCommit         string  `json:"git_commit"`
	BuildDate         string  `json:"build_date"`
	IntegrityStatus   string  `json:"integrity_status"`
	Integrity         string  `json:"integrity"`
	Uptime            string  `json:"uptime"`
	UptimeSeconds     float64 `json:"uptime_seconds"`
	GoVersion         string  `json:"go_version"`
	StartTime         string  `json:"start_time"`
	OS                string  `json:"os,omitempty"`
	Arch              string  `json:"arch,omitempty"`
	Compiler          string  `json:"compiler,omitempty"`
	ConfigVersion     string  `json:"config_version,omitempty"`
	ConfigVersionPath string  `json:"config_version_path,omitempty"`
	ConfigFile        string  `json:"config_file,omitempty"`
}

// Get returns the cached Info resolved from build metadata and source truth.
func Get() Info {
	initOnce.Do(func() {
		cached = resolveInfo()
	})
	return cached
}

// ResolveInfo resolves build and source information applying the fallback hierarchy.
func ResolveInfo() Info {
	return resolveInfo()
}

func resolveInfo() Info {
	info := resolveInfoFrom(Version, GitCommit, BuildDate, IntegrityStatus, readBuildInfo)
	if info.GitCommit == "" || info.GitCommit == "unknown" {
		if commit := resolveGitCommitFromDotGit(); commit != "" {
			info.GitCommit = commit
		}
	}
	return info
}

func resolveGitCommitFromDotGit() string {
	for _, candidate := range []string{".git", "../.git", "../../.git", "../../../.git"} {
		if commit := resolveGitCommitFromDir(candidate); commit != "" {
			return commit
		}
	}
	return ""
}

func resolveGitCommitFromDir(gitPath string) string {
	stat, err := os.Stat(gitPath)
	if err != nil {
		return ""
	}

	gitDir := gitPath
	commonDir := ""
	if !stat.IsDir() {
		raw, err := os.ReadFile(gitPath)
		if err != nil {
			return ""
		}
		var parsedDir string
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) >= len("gitdir:") && strings.EqualFold(trimmed[:len("gitdir:")], "gitdir:") {
				parsedDir = strings.TrimSpace(trimmed[len("gitdir:"):])
				break
			}
		}
		if parsedDir == "" {
			return ""
		}
		parsedDir = filepath.FromSlash(parsedDir)
		if filepath.IsAbs(parsedDir) {
			gitDir = filepath.Clean(parsedDir)
		} else {
			gitDir = filepath.Clean(filepath.Join(filepath.Dir(gitPath), parsedDir))
		}

		if commonRaw, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
			c := strings.TrimSpace(string(commonRaw))
			if c != "" {
				c = filepath.FromSlash(c)
				if filepath.IsAbs(c) {
					commonDir = filepath.Clean(c)
				} else {
					commonDir = filepath.Clean(filepath.Join(gitDir, c))
				}
			}
		}
	}

	headBytes, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return ""
	}
	head := strings.TrimSpace(string(headBytes))
	if head == "" {
		return ""
	}
	if isHexSHA(head) {
		return head
	}
	if !strings.HasPrefix(head, "ref:") {
		return ""
	}

	ref := strings.TrimSpace(strings.TrimPrefix(head, "ref:"))
	if ref == "" || strings.Contains(ref, "..") {
		return ""
	}

	searchDirs := []string{gitDir}
	if commonDir != "" && commonDir != gitDir {
		searchDirs = append(searchDirs, commonDir)
	}

	relRef := filepath.FromSlash(ref)
	for _, dir := range searchDirs {
		if refBytes, err := os.ReadFile(filepath.Join(dir, relRef)); err == nil {
			if sha := strings.TrimSpace(string(refBytes)); isHexSHA(sha) {
				return sha
			}
		}
	}
	for _, dir := range searchDirs {
		if sha := lookupPackedRef(filepath.Join(dir, "packed-refs"), ref); sha != "" {
			return sha
		}
	}
	return ""
}

func lookupPackedRef(packedRefsPath, targetRef string) string {
	data, err := os.ReadFile(packedRefsPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "^") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[1] == targetRef && isHexSHA(fields[0]) {
			return fields[0]
		}
	}
	return ""
}

func isHexSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func resolveInfoFrom(v, commit, bDate, integrity string, readBI func() (*debug.BuildInfo, bool)) Info {
	v = strings.TrimSpace(v)
	commit = strings.TrimSpace(commit)
	bDate = strings.TrimSpace(bDate)
	integrity = strings.TrimSpace(integrity)

	if readBI != nil {
		if bi, ok := readBI(); ok && bi != nil {
			if v == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				v = bi.Main.Version
			}
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if commit == "" {
						commit = s.Value
					}
				case "vcs.time":
					if bDate == "" {
						bDate = s.Value
					}
				case "vcs.modified":
					if integrity == "" {
						if s.Value == "false" {
							integrity = "clean"
						} else if s.Value == "true" {
							integrity = "modified"
						}
					}
				}
			}
		}
	}

	if v == "" {
		for _, candidate := range []string{"VERSION", "../VERSION", "../../VERSION", "../../../VERSION"} {
			if data, err := os.ReadFile(candidate); err == nil {
				trimmed := strings.TrimSpace(string(data))
				if trimmed != "" {
					v = trimmed
					break
				}
			}
		}
	}
	if v == "" {
		v = DefaultVersion
	}
	if commit == "" {
		commit = "unknown"
	}
	if bDate == "" {
		bDate = "unknown"
	}
	if integrity == "" {
		integrity = "untracked"
	}

	return Info{
		Version:         v,
		GitCommit:       commit,
		BuildDate:       bDate,
		IntegrityStatus: integrity,
		Integrity:       integrity,
		GoVersion:       runtime.Version(),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Compiler:        runtime.Compiler,
	}
}

// Response generates the dynamic VersionResponse for the current request.
func (i Info) Response(startTime time.Time) VersionResponse {
	if startTime.IsZero() {
		startTime = time.Now()
	}
	dur := time.Since(startTime)
	if dur < 0 {
		dur = 0
	}
	sec := math.Round(dur.Seconds()*100) / 100

	return VersionResponse{
		Version:         i.Version,
		GitCommit:       i.GitCommit,
		BuildDate:       i.BuildDate,
		IntegrityStatus: i.IntegrityStatus,
		Integrity:       i.Integrity,
		Uptime:          dur.Round(time.Second).String(),
		UptimeSeconds:   sec,
		GoVersion:       i.GoVersion,
		StartTime:       startTime.UTC().Format(time.RFC3339),
		OS:              i.OS,
		Arch:            i.Arch,
		Compiler:        i.Compiler,
	}
}
