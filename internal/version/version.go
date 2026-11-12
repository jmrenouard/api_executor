package version

import (
	"math"
	"os"
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
	Version         string  `json:"version"`
	GitCommit       string  `json:"git_commit"`
	BuildDate       string  `json:"build_date"`
	IntegrityStatus string  `json:"integrity_status"`
	Integrity       string  `json:"integrity"`
	Uptime          string  `json:"uptime"`
	UptimeSeconds   float64 `json:"uptime_seconds"`
	GoVersion       string  `json:"go_version"`
	StartTime       string  `json:"start_time"`
	OS              string  `json:"os,omitempty"`
	Arch            string  `json:"arch,omitempty"`
	Compiler        string  `json:"compiler,omitempty"`
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
	return resolveInfoFrom(Version, GitCommit, BuildDate, IntegrityStatus, readBuildInfo)
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
