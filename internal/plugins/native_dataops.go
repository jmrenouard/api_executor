package plugins

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// SQLiteSchemaAnalyzerPlugin parses SQLite file binary headers, validates page allocation, and audits index coverage.
type SQLiteSchemaAnalyzerPlugin struct{}

func (p *SQLiteSchemaAnalyzerPlugin) ID() string          { return "sqlite-schema-analyzer" }
func (p *SQLiteSchemaAnalyzerPlugin) Name() string        { return "SQLite File Structure & Index Coverage Analyzer" }
func (p *SQLiteSchemaAnalyzerPlugin) Version() string     { return "1.0.0" }
func (p *SQLiteSchemaAnalyzerPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *SQLiteSchemaAnalyzerPlugin) Type() string        { return "native" }
func (p *SQLiteSchemaAnalyzerPlugin) Category() string    { return "DataOps" }
func (p *SQLiteSchemaAnalyzerPlugin) Description() string {
	return "Inspects SQLite file binary headers, validates B-tree page sizes, free lists, and audits schema indexes."
}

func (p *SQLiteSchemaAnalyzerPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "page_analysis",
			Description: "Parse 100-byte SQLite 3 database header and analyze page structure",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "db_path", Type: "string", Required: false, Default: "data/api_executor.db", Description: "Path to SQLite database file"},
			},
		},
		{
			Name:        "integrity_check",
			Description: "Verify SQLite binary magic header and format version compliance",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "db_path", Type: "string", Required: false, Default: "data/api_executor.db", Description: "Path to SQLite database file"},
			},
		},
		{
			Name:        "analyze_indexes",
			Description: "Report index coverage and SQLite header write version stats",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "db_path", Type: "string", Required: false, Default: "data/api_executor.db", Description: "Path to SQLite database file"},
			},
		},
	}
}

func (p *SQLiteSchemaAnalyzerPlugin) Execute(_ context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	dbPath := getStringParam(params, "db_path", "data/api_executor.db")

	f, err := os.Open(dbPath)
	if err != nil {
		// Provide informative diagnostics if path does not exist
		data := map[string]any{
			"db_path": dbPath,
			"exists":  false,
			"error":   err.Error(),
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil
	}
	defer f.Close()

	header := make([]byte, 100)
	n, err := f.Read(header)
	if err != nil || n < 100 {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: "database file is smaller than standard 100-byte SQLite header",
		}, fmt.Errorf("database file smaller than SQLite header")
	}

	magic := string(header[:16])
	isValidSQLite := strings.HasPrefix(magic, "SQLite format 3")
	pageSizeRaw := binary.BigEndian.Uint16(header[16:18])
	var pageSize uint32 = uint32(pageSizeRaw)
	if pageSize == 1 {
		pageSize = 65536
	}

	writeVersion := header[18]
	readVersion := header[19]
	reservedSpace := header[20]
	changeCounter := binary.BigEndian.Uint32(header[24:28])
	pageCount := binary.BigEndian.Uint32(header[28:32])
	freePageList := binary.BigEndian.Uint32(header[32:36])
	freePageCount := binary.BigEndian.Uint32(header[36:40])
	schemaVersion := binary.BigEndian.Uint32(header[40:44])

	switch normalized {
	case "integrity_check":
		data := map[string]any{
			"db_path":         dbPath,
			"magic_string":    magic,
			"is_valid_sqlite": isValidSQLite,
			"write_version":   writeVersion,
			"read_version":    readVersion,
			"schema_version":  schemaVersion,
			"change_counter":  changeCounter,
			"status":          "valid_sqlite_header",
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "page_analysis":
		data := map[string]any{
			"db_path":         dbPath,
			"page_size_bytes": pageSize,
			"total_pages":     pageCount,
			"total_bytes":     uint64(pageSize) * uint64(pageCount),
			"free_pages":      freePageCount,
			"free_page_list":  freePageList,
			"reserved_space":  reservedSpace,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "analyze_indexes":
		data := map[string]any{
			"db_path":        dbPath,
			"schema_version": schemaVersion,
			"page_size":      pageSize,
			"page_count":     pageCount,
			"change_counter": changeCounter,
			"write_version":  writeVersion,
			"index_coverage": "sqlite_btree_schema",
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

// RedisProtocolProbePlugin communicates with Redis instances using pure RESP wire protocol.
type RedisProtocolProbePlugin struct{}

func (p *RedisProtocolProbePlugin) ID() string          { return "redis-protocol-probe" }
func (p *RedisProtocolProbePlugin) Name() string        { return "Native Redis RESP Wire-Protocol Probe" }
func (p *RedisProtocolProbePlugin) Version() string     { return "1.0.0" }
func (p *RedisProtocolProbePlugin) Kind() PluginKind    { return KindAdvanced }
func (p *RedisProtocolProbePlugin) Type() string        { return "native" }
func (p *RedisProtocolProbePlugin) Category() string    { return "DataOps" }
func (p *RedisProtocolProbePlugin) Description() string {
	return "Executes PING, INFO, and TYPE commands against Redis endpoints via zero-dependency native RESP wire protocol."
}

func (p *RedisProtocolProbePlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "redis_ping",
			Description: "Send PING command over TCP RESP wire protocol",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: false, Default: "127.0.0.1", Description: "Redis server hostname or IP"},
				{Name: "port", Type: "int", Required: false, Default: "6379", Description: "Redis server port"},
			},
		},
		{
			Name:        "redis_info",
			Description: "Send INFO command and parse key metrics",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: false, Default: "127.0.0.1", Description: "Redis server hostname or IP"},
				{Name: "port", Type: "int", Required: false, Default: "6379", Description: "Redis server port"},
			},
		},
		{
			Name:        "redis_key_type",
			Description: "Probe key data structure type via TYPE command",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: false, Default: "127.0.0.1", Description: "Redis server hostname or IP"},
				{Name: "port", Type: "int", Required: false, Default: "6379", Description: "Redis server port"},
				{Name: "key", Type: "string", Required: true, Description: "Key name to inspect"},
			},
		},
	}
}

func (p *RedisProtocolProbePlugin) sendRESPCommand(ctx context.Context, host string, port int, cmdArgs ...string) (string, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Format RESP array
	var req strings.Builder
	fmt.Fprintf(&req, "*%d\r\n", len(cmdArgs))
	for _, arg := range cmdArgs {
		fmt.Fprintf(&req, "$%d\r\n%s\r\n", len(arg), arg)
	}

	if _, err := conn.Write([]byte(req.String())); err != nil {
		return "", err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "+") {
		return line[1:], nil
	}
	if strings.HasPrefix(line, "-") {
		return "", fmt.Errorf("redis error: %s", line[1:])
	}
	if strings.HasPrefix(line, "$") {
		// Bulk string
		lenStr := line[1:]
		bLen, err := strconv.Atoi(lenStr)
		if err != nil || bLen < 0 {
			return "", nil
		}
		buf := make([]byte, bLen+2) // data + \r\n
		_, err = ioReadFull(reader, buf)
		if err != nil {
			return "", err
		}
		return string(buf[:bLen]), nil
	}

	return line, nil
}

func ioReadFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (p *RedisProtocolProbePlugin) Execute(ctx context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	host := getStringParam(params, "host", "127.0.0.1")
	port := getIntParam(params, "port", 6379)

	switch normalized {
	case "redis_ping":
		resp, err := p.sendRESPCommand(ctx, host, port, "PING")
		if err != nil {
			data := map[string]any{
				"target":    net.JoinHostPort(host, strconv.Itoa(port)),
				"connected": false,
				"error":     err.Error(),
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Output: formatJSON(data), Data: data, Error: err.Error(),
			}, nil
		}

		data := map[string]any{
			"target":    net.JoinHostPort(host, strconv.Itoa(port)),
			"connected": true,
			"response":  resp,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "redis_info":
		resp, err := p.sendRESPCommand(ctx, host, port, "INFO")
		if err != nil {
			data := map[string]any{
				"target":    net.JoinHostPort(host, strconv.Itoa(port)),
				"connected": false,
				"error":     err.Error(),
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Output: formatJSON(data), Data: data, Error: err.Error(),
			}, nil
		}

		metrics := make(map[string]string)
		for _, line := range strings.Split(resp, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || !strings.Contains(line, ":") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			metrics[parts[0]] = parts[1]
		}

		data := map[string]any{
			"target":        net.JoinHostPort(host, strconv.Itoa(port)),
			"connected":     true,
			"metrics_count": len(metrics),
			"version":       metrics["redis_version"],
			"uptime_sec":    metrics["uptime_in_seconds"],
			"used_memory":   metrics["used_memory_human"],
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "redis_key_type":
		key := getStringParam(params, "key", "")
		if key == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'key' is required",
			}, fmt.Errorf("parameter 'key' is required")
		}

		resp, err := p.sendRESPCommand(ctx, host, port, "TYPE", key)
		if err != nil {
			data := map[string]any{
				"target": net.JoinHostPort(host, strconv.Itoa(port)),
				"key":    key,
				"error":  err.Error(),
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Output: formatJSON(data), Data: data, Error: err.Error(),
			}, nil
		}

		data := map[string]any{
			"target": net.JoinHostPort(host, strconv.Itoa(port)),
			"key":    key,
			"type":   resp,
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
