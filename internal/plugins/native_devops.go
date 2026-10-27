package plugins

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// GitRepoInspectorPlugin inspects .git repository metadata directly from the filesystem without git CLI dependencies.
type GitRepoInspectorPlugin struct{}

func (p *GitRepoInspectorPlugin) ID() string          { return "git-repo-inspector" }
func (p *GitRepoInspectorPlugin) Name() string        { return "Pure-Go Git Repository & HEAD Metadata Inspector" }
func (p *GitRepoInspectorPlugin) Version() string     { return "1.0.0" }
func (p *GitRepoInspectorPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *GitRepoInspectorPlugin) Type() string        { return "native" }
func (p *GitRepoInspectorPlugin) Category() string    { return "DevOps" }
func (p *GitRepoInspectorPlugin) Description() string {
	return "Inspects .git metadata, HEAD branches, recent commit logs, and remotes directly from local filesystem."
}

func (p *GitRepoInspectorPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "repo_status",
			Description: "Inspect current Git branch, HEAD reference, and repository status",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "repo_path", Type: "string", Required: false, Default: ".", Description: "Repository root path"},
			},
		},
		{
			Name:        "commit_history",
			Description: "Parse recent commits from .git/logs/HEAD",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "repo_path", Type: "string", Required: false, Default: ".", Description: "Repository root path"},
				{Name: "limit", Type: "int", Required: false, Default: "10", Description: "Number of commits to return"},
			},
		},
		{
			Name:        "remote_branches",
			Description: "List configured Git remote branch references",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "repo_path", Type: "string", Required: false, Default: ".", Description: "Repository root path"},
			},
		},
	}
}

func (p *GitRepoInspectorPlugin) Execute(_ context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	repoPath := getStringParam(params, "repo_path", ".")
	gitDir := filepath.Join(repoPath, ".git")

	// Verify .git exists
	if _, err := os.Stat(gitDir); err != nil {
		data := map[string]any{
			"repo_path": repoPath,
			"is_git":    false,
			"error":     ".git directory not found",
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil
	}

	headPath := filepath.Join(gitDir, "HEAD")
	headRaw, _ := os.ReadFile(headPath)
	headContent := strings.TrimSpace(string(headRaw))

	currentBranch := ""
	isDetached := true
	latestSHA := ""

	if strings.HasPrefix(headContent, "ref: ") {
		refPath := strings.TrimSpace(headContent[5:])
		currentBranch = filepath.Base(refPath)
		isDetached = false
		refFile := filepath.Join(gitDir, filepath.FromSlash(refPath))
		if b, err := os.ReadFile(refFile); err == nil {
			latestSHA = strings.TrimSpace(string(b))
		}
	} else {
		latestSHA = headContent
	}

	switch normalized {
	case "repo_status":
		data := map[string]any{
			"repo_path":       repoPath,
			"is_git":          true,
			"head_raw":        headContent,
			"current_branch":  currentBranch,
			"detached":        isDetached,
			"latest_commit":   latestSHA,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "commit_history":
		limit := getIntParam(params, "limit", 10)
		if limit <= 0 {
			limit = 10
		}

		logFile := filepath.Join(gitDir, "logs", "HEAD")
		var commits []map[string]any

		if f, err := os.Open(logFile); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			var lines []string
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}
			// Reverse order to show newest commits first
			for i := len(lines) - 1; i >= 0 && len(commits) < limit; i-- {
				line := lines[i]
				parts := strings.SplitN(line, "\t", 2)
				if len(parts) >= 2 {
					hdr := strings.Fields(parts[0])
					msg := parts[1]
					sha := ""
					if len(hdr) >= 2 {
						sha = hdr[1]
					}
					commits = append(commits, map[string]any{
						"commit":  sha,
						"message": msg,
					})
				}
			}
		}

		data := map[string]any{
			"repo_path":     repoPath,
			"commit_count":  len(commits),
			"recent_commits": commits,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "remote_branches":
		remotesDir := filepath.Join(gitDir, "refs", "remotes")
		var branches []string
		_ = filepath.WalkDir(remotesDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(remotesDir, path)
			branches = append(branches, filepath.ToSlash(rel))
			return nil
		})

		data := map[string]any{
			"repo_path":       repoPath,
			"remote_branches": branches,
			"count":           len(branches),
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

// SemverReleaseCheckerPlugin validates semantic versions, compares release tags, and calculates version bumps.
type SemverReleaseCheckerPlugin struct{}

func (p *SemverReleaseCheckerPlugin) ID() string          { return "semver-release-checker" }
func (p *SemverReleaseCheckerPlugin) Name() string        { return "Semantic Versioning & Tag Compliance Checker" }
func (p *SemverReleaseCheckerPlugin) Version() string     { return "1.0.0" }
func (p *SemverReleaseCheckerPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *SemverReleaseCheckerPlugin) Type() string        { return "native" }
func (p *SemverReleaseCheckerPlugin) Category() string    { return "DevOps" }
func (p *SemverReleaseCheckerPlugin) Description() string {
	return "Validates SemVer 2.0.0 compliance, compares release tags, and calculates next semantic version bumps."
}

func (p *SemverReleaseCheckerPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "validate_semver",
			Description: "Validate semantic version string syntax (v?X.Y.Z[-prerelease])",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "version", Type: "string", Required: true, Description: "Version string to validate"},
			},
		},
		{
			Name:        "compare_versions",
			Description: "Compare two semantic versions (-1, 0, 1)",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "version_a", Type: "string", Required: true, Description: "First version"},
				{Name: "version_b", Type: "string", Required: true, Description: "Second version"},
			},
		},
		{
			Name:        "next_version",
			Description: "Calculate next version based on bump type (major, minor, patch)",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "version", Type: "string", Required: true, Description: "Base version"},
				{Name: "bump", Type: "string", Required: false, Default: "patch", Description: "Bump type: major, minor, patch"},
			},
		},
	}
}

var semverRegex = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)

type semverTuple struct {
	Major int
	Minor int
	Patch int
	Pre   string
}

func parseSemver(v string) (*semverTuple, bool) {
	v = strings.TrimSpace(v)
	matches := semverRegex.FindStringSubmatch(v)
	if matches == nil {
		return nil, false
	}
	maj, _ := strconv.Atoi(matches[1])
	min, _ := strconv.Atoi(matches[2])
	pat, _ := strconv.Atoi(matches[3])
	return &semverTuple{
		Major: maj,
		Minor: min,
		Patch: pat,
		Pre:   matches[4],
	}, true
}

func (p *SemverReleaseCheckerPlugin) Execute(_ context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")

	switch normalized {
	case "validate_semver":
		vStr := getStringParam(params, "version", "")
		if vStr == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'version' is required",
			}, fmt.Errorf("parameter 'version' is required")
		}

		t, valid := parseSemver(vStr)
		data := map[string]any{
			"version": vStr,
			"valid":   valid,
		}
		if valid {
			data["major"] = t.Major
			data["minor"] = t.Minor
			data["patch"] = t.Patch
			data["prerelease"] = t.Pre
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "compare_versions":
		vaStr := getStringParam(params, "version_a", "")
		vbStr := getStringParam(params, "version_b", "")
		ta, okA := parseSemver(vaStr)
		tb, okB := parseSemver(vbStr)

		if !okA || !okB {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "both version_a and version_b must be valid SemVer strings",
			}, fmt.Errorf("invalid semver string")
		}

		diff := 0
		if ta.Major != tb.Major {
			if ta.Major > tb.Major {
				diff = 1
			} else {
				diff = -1
			}
		} else if ta.Minor != tb.Minor {
			if ta.Minor > tb.Minor {
				diff = 1
			} else {
				diff = -1
			}
		} else if ta.Patch != tb.Patch {
			if ta.Patch > tb.Patch {
				diff = 1
			} else {
				diff = -1
			}
		}

		data := map[string]any{
			"version_a":  vaStr,
			"version_b":  vbStr,
			"comparison": diff, // 1 (a > b), 0 (a == b), -1 (a < b)
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "next_version":
		vStr := getStringParam(params, "version", "")
		bump := strings.ToLower(getStringParam(params, "bump", "patch"))
		t, ok := parseSemver(vStr)
		if !ok {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'version' must be a valid SemVer string",
			}, fmt.Errorf("invalid semver string")
		}

		hasVPrefix := strings.HasPrefix(strings.TrimSpace(vStr), "v")
		switch bump {
		case "major":
			t.Major++
			t.Minor = 0
			t.Patch = 0
		case "minor":
			t.Minor++
			t.Patch = 0
		default: // patch
			t.Patch++
		}

		next := fmt.Sprintf("%d.%d.%d", t.Major, t.Minor, t.Patch)
		if hasVPrefix {
			next = "v" + next
		}

		data := map[string]any{
			"base_version": vStr,
			"bump_type":    bump,
			"next_version": next,
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
