package plugins

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HostStorageStatsPlugin inspects filesystem storage, mount roots, and directory usage.
type HostStorageStatsPlugin struct{}

func (p *HostStorageStatsPlugin) ID() string          { return "host-storage-stats" }
func (p *HostStorageStatsPlugin) Name() string        { return "Native Disk & Mount Storage Explorer" }
func (p *HostStorageStatsPlugin) Version() string     { return "1.0.0" }
func (p *HostStorageStatsPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *HostStorageStatsPlugin) Type() string        { return "native" }
func (p *HostStorageStatsPlugin) Category() string    { return "SysAdmin" }
func (p *HostStorageStatsPlugin) Description() string {
	return "Inspects host storage metrics, drive/mount roots, and recursive directory file size distributions."
}

func (p *HostStorageStatsPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "disk_usage",
			Description: "Report storage statistics and file count for target path",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "path", Type: "string", Required: false, Default: ".", Description: "Target directory path"},
			},
		},
		{
			Name:        "mount_points",
			Description: "Discover available host drive letters or filesystem mount points",
			Timeout:     "5s",
		},
		{
			Name:        "dir_summary",
			Description: "Recursively summarize directory size distribution and top files",
			Timeout:     "15s",
			Parameters: []ActionParameter{
				{Name: "path", Type: "string", Required: false, Default: ".", Description: "Target directory path"},
				{Name: "top_n", Type: "int", Required: false, Default: "10", Description: "Number of largest files to return"},
				{Name: "max_depth", Type: "int", Required: false, Default: "4", Description: "Maximum directory depth to traverse"},
			},
		},
	}
}

type fileEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size_bytes"`
}

func (p *HostStorageStatsPlugin) Execute(ctx context.Context, action string, params map[string]any, timeout time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")

	switch normalized {
	case "disk_usage":
		targetPath := getStringParam(params, "path", ".")
		info, err := os.Stat(targetPath)
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(), Error: err.Error(),
			}, err
		}

		var totalSize int64
		var fileCount int64
		var dirCount int64

		if info.IsDir() {
			_ = filepath.WalkDir(targetPath, func(_ string, d os.DirEntry, err error) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err != nil {
					return nil
				}
				if d.IsDir() {
					dirCount++
				} else {
					fileCount++
					if fi, err := d.Info(); err == nil {
						totalSize += fi.Size()
					}
				}
				return nil
			})
		} else {
			fileCount = 1
			totalSize = info.Size()
		}

		data := map[string]any{
			"target_path":      targetPath,
			"is_dir":           info.IsDir(),
			"total_size_bytes": totalSize,
			"total_size_mb":    fmt.Sprintf("%.2f MB", float64(totalSize)/(1024*1024)),
			"file_count":       fileCount,
			"dir_count":        dirCount,
			"platform":         runtime.GOOS,
		}

		return PluginResult{
			PluginID:   p.ID(),
			Action:     action,
			Status:     "ok",
			Output:     formatJSON(data),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "mount_points":
		mounts := make([]map[string]any, 0)
		if runtime.GOOS == "windows" {
			// Probe common Windows drive letters
			for c := 'A'; c <= 'Z'; c++ {
				drive := fmt.Sprintf("%c:\\", c)
				if _, err := os.Stat(drive); err == nil {
					mounts = append(mounts, map[string]any{
						"mount": drive,
						"type":  "local_volume",
					})
				}
			}
		} else {
			// Unix standard root and mounts
			for _, m := range []string{"/", "/home", "/var", "/tmp", "/etc"} {
				if _, err := os.Stat(m); err == nil {
					mounts = append(mounts, map[string]any{
						"mount": m,
						"type":  "posix_directory",
					})
				}
			}
		}

		data := map[string]any{
			"platform":     runtime.GOOS,
			"mount_points": mounts,
			"count":        len(mounts),
		}

		return PluginResult{
			PluginID:   p.ID(),
			Action:     action,
			Status:     "ok",
			Output:     formatJSON(data),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "dir_summary":
		targetPath := getStringParam(params, "path", ".")
		topN := getIntParam(params, "top_n", 10)
		maxDepth := getIntParam(params, "max_depth", 4)
		if topN <= 0 {
			topN = 10
		}
		if maxDepth <= 0 {
			maxDepth = 4
		}

		var totalSize int64
		var fileCount int64
		var entries []fileEntry
		buckets := map[string]int64{
			"under_1kb": 0,
			"1kb_to_1mb": 0,
			"1mb_to_100mb": 0,
			"over_100mb": 0,
		}

		baseClean := filepath.Clean(targetPath)
		baseDepth := len(strings.Split(filepath.ToSlash(baseClean), "/"))

		_ = filepath.WalkDir(targetPath, func(path string, d os.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return nil
			}
			curDepth := len(strings.Split(filepath.ToSlash(path), "/")) - baseDepth
			if d.IsDir() {
				if curDepth > maxDepth {
					return filepath.SkipDir
				}
				return nil
			}

			fi, err := d.Info()
			if err != nil {
				return nil
			}
			size := fi.Size()
			totalSize += size
			fileCount++

			if size < 1024 {
				buckets["under_1kb"]++
			} else if size < 1024*1024 {
				buckets["1kb_to_1mb"]++
			} else if size < 100*1024*1024 {
				buckets["1mb_to_100mb"]++
			} else {
				buckets["over_100mb"]++
			}

			entries = append(entries, fileEntry{Path: path, Size: size})
			return nil
		})

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Size > entries[j].Size
		})

		limit := topN
		if len(entries) < limit {
			limit = len(entries)
		}
		topFiles := entries[:limit]

		data := map[string]any{
			"target_path":       targetPath,
			"total_files":       fileCount,
			"total_size_bytes":  totalSize,
			"size_distribution": buckets,
			"top_files":         topFiles,
		}

		return PluginResult{
			PluginID:   p.ID(),
			Action:     action,
			Status:     "ok",
			Output:     formatJSON(data),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil

	default:
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: fmt.Sprintf("action %q not found in plugin %q", action, p.ID()),
		}, ErrActionNotFound
	}
}

// ProcessTreeAnalyzerPlugin audits host processes and resource consumption.
type ProcessTreeAnalyzerPlugin struct{}

func (p *ProcessTreeAnalyzerPlugin) ID() string          { return "process-tree-analyzer" }
func (p *ProcessTreeAnalyzerPlugin) Name() string        { return "Host Process Tree & Resource Auditor" }
func (p *ProcessTreeAnalyzerPlugin) Version() string     { return "1.0.0" }
func (p *ProcessTreeAnalyzerPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *ProcessTreeAnalyzerPlugin) Type() string        { return "native" }
func (p *ProcessTreeAnalyzerPlugin) Category() string    { return "SysAdmin" }
func (p *ProcessTreeAnalyzerPlugin) Description() string {
	return "Audits host process tree hierarchy, process metrics, and memory consumption."
}

func (p *ProcessTreeAnalyzerPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "process_list",
			Description: "List running host processes with PID, parent PID, and executable name",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "limit", Type: "int", Required: false, Default: "20", Description: "Max processes to list"},
			},
		},
		{
			Name:        "process_info",
			Description: "Query details for a specific PID",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "pid", Type: "int", Required: true, Description: "Process ID to inspect"},
			},
		},
		{
			Name:        "top_memory",
			Description: "Report top memory-consuming processes",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "limit", Type: "int", Required: false, Default: "10", Description: "Max processes to return"},
			},
		},
	}
}

type procItem struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Name string `json:"name"`
	Mem  string `json:"memory,omitempty"`
}

func (p *ProcessTreeAnalyzerPlugin) Execute(ctx context.Context, action string, params map[string]any, timeout time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")

	switch normalized {
	case "process_list", "top_memory":
		limit := getIntParam(params, "limit", 20)
		if limit <= 0 {
			limit = 20
		}

		procs := p.gatherProcesses(ctx, limit)
		data := map[string]any{
			"total_collected": len(procs),
			"limit":           limit,
			"processes":       procs,
			"current_pid":     os.Getpid(),
			"current_ppid":    os.Getppid(),
		}

		return PluginResult{
			PluginID:   p.ID(),
			Action:     action,
			Status:     "ok",
			Output:     formatJSON(data),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "process_info":
		pid := getIntParam(params, "pid", 0)
		if pid <= 0 {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'pid' must be a positive integer",
			}, fmt.Errorf("parameter 'pid' must be a positive integer")
		}

		curPID := os.Getpid()
		isCurrent := (pid == curPID)
		proc, err := os.FindProcess(pid)
		data := map[string]any{
			"pid":        pid,
			"is_current": isCurrent,
			"found":      err == nil && proc != nil,
		}
		if isCurrent {
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			data["ppid"] = os.Getppid()
			data["alloc_bytes"] = mem.Alloc
			data["sys_bytes"] = mem.Sys
			data["goroutines"] = runtime.NumGoroutine()
			if execPath, err := os.Executable(); err == nil {
				data["executable"] = execPath
			}
		}

		return PluginResult{
			PluginID:   p.ID(),
			Action:     action,
			Status:     "ok",
			Output:     formatJSON(data),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil

	default:
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: fmt.Sprintf("action %q not found in plugin %q", action, p.ID()),
		}, ErrActionNotFound
	}
}

func (p *ProcessTreeAnalyzerPlugin) gatherProcesses(ctx context.Context, limit int) []procItem {
	var procs []procItem
	curPID := os.Getpid()
	curPPID := os.Getppid()

	procs = append(procs, procItem{
		PID:  curPID,
		PPID: curPPID,
		Name: filepath.Base(os.Args[0]),
		Mem:  "in-process",
	})

	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH")
		if out, err := cmd.Output(); err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, "\",\"")
				if len(parts) >= 5 {
					name := strings.Trim(parts[0], "\"")
					pidStr := strings.Trim(parts[1], "\"")
					mem := strings.Trim(parts[4], "\"")
					if pid, err := strconv.Atoi(pidStr); err == nil && pid != curPID {
						procs = append(procs, procItem{
							PID:  pid,
							Name: name,
							Mem:  mem,
						})
					}
				}
				if len(procs) >= limit {
					break
				}
			}
		}
	} else {
		// Unix /proc scan or fallback
		if entries, err := os.ReadDir("/proc"); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				pid, err := strconv.Atoi(entry.Name())
				if err != nil || pid == curPID {
					continue
				}
				comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				name := strings.TrimSpace(string(comm))
				if name == "" {
					name = fmt.Sprintf("proc-%d", pid)
				}
				procs = append(procs, procItem{
					PID:  pid,
					Name: name,
				})
				if len(procs) >= limit {
					break
				}
			}
		}
	}

	return procs
}
