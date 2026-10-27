package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go-admin-tool/internal/database"
)

var (
	ErrForbiddenSQL = errors.New("SQL query rejected by read-only security policy")
	identRegex      = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	forbiddenSQLRe  = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|TRUNCATE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|GRANT|REVOKE)\b`)
)

// ValidateReadOnlySQL enforces that a SQL string is a single, comment-free, read-only SELECT statement.
func ValidateReadOnlySQL(rawSQL string) (string, error) {
	trimmed := strings.TrimSpace(rawSQL)
	if trimmed == "" {
		return "", fmt.Errorf("%w: query cannot be empty", ErrForbiddenSQL)
	}
	// Strip single trailing semicolon if present
	trimmed = strings.TrimSuffix(trimmed, ";")
	trimmed = strings.TrimSpace(trimmed)

	// Reject multi-statement queries or SQL comments
	if strings.Contains(trimmed, ";") || strings.Contains(trimmed, "--") || strings.Contains(trimmed, "/*") || strings.Contains(trimmed, "*/") {
		return "", fmt.Errorf("%w: multi-statement queries and SQL comments are prohibited", ErrForbiddenSQL)
	}

	upper := strings.ToUpper(trimmed)
	if !strings.HasPrefix(upper, "SELECT ") && !strings.HasPrefix(upper, "SELECT\t") && !strings.HasPrefix(upper, "SELECT\n") {
		return "", fmt.Errorf("%w: only SELECT statements are permitted", ErrForbiddenSQL)
	}

	if forbiddenSQLRe.MatchString(trimmed) {
		return "", fmt.Errorf("%w: query contains prohibited DDL/DML/administrative keyword", ErrForbiddenSQL)
	}

	return trimmed, nil
}

// DatabaseExposurePlugin is an advanced native plugin that safely exposes database inspection and read-only SQL querying.
type DatabaseExposurePlugin struct {
	db      *database.DB
	maxRows int
}

// NewDatabaseExposurePlugin creates a new DatabaseExposurePlugin bound to the application database.
func NewDatabaseExposurePlugin(db *database.DB, maxRows int) *DatabaseExposurePlugin {
	if maxRows <= 0 || maxRows > 1000 {
		maxRows = 200
	}
	return &DatabaseExposurePlugin{
		db:      db,
		maxRows: maxRows,
	}
}

func (p *DatabaseExposurePlugin) ID() string          { return "db-exposure" }
func (p *DatabaseExposurePlugin) Name() string        { return "Database Exposure & Read-Only SQL Explorer" }
func (p *DatabaseExposurePlugin) Version() string     { return "2.0.0" }
func (p *DatabaseExposurePlugin) Kind() PluginKind    { return KindAdvanced }
func (p *DatabaseExposurePlugin) Type() string        { return "native" }
func (p *DatabaseExposurePlugin) Category() string    { return "DataOps" }
func (p *DatabaseExposurePlugin) Description() string {
	return "Advanced native plugin exposing database table discovery, schema inspection, paginated sampling, telemetry stats, and guarded read-only SELECT queries."
}

func (p *DatabaseExposurePlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "list_tables",
			Description: "List all exposed tables in the database along with row counts and storage engine status",
			Timeout:     "10s",
		},
		{
			Name:        "describe_table",
			Description: "Inspect column definitions and primary keys for a specific database table",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "table", Type: "string", Required: false, Default: "action_history", Description: "Table name to inspect"},
			},
		},
		{
			Name:        "table_sample",
			Description: "Retrieve recent or paginated rows from an exposed database table",
			Timeout:     "15s",
			Parameters: []ActionParameter{
				{Name: "table", Type: "string", Required: false, Default: "action_history", Description: "Table name to sample"},
				{Name: "limit", Type: "int", Required: false, Default: "25", Description: "Maximum number of rows to return"},
			},
		},
		{
			Name:        "query_readonly",
			Description: "Execute a strictly validated read-only SQL SELECT query with automatic row bounding",
			Timeout:     "15s",
			Parameters: []ActionParameter{
				{Name: "sql", Type: "string", Required: true, Description: "Read-only SELECT query to execute"},
				{Name: "max_rows", Type: "int", Required: false, Default: "100", Description: "Row cap applied to the result set"},
			},
		},
		{
			Name:        "db_stats",
			Description: "Compute aggregate statistics across recorded command executions in the database",
			Timeout:     "10s",
		},
	}
}

func (p *DatabaseExposurePlugin) Execute(ctx context.Context, action string, params map[string]any, timeout time.Duration) (PluginResult, error) {
	start := time.Now()
	if p.db == nil {
		err := errors.New("database connection is not configured")
		return PluginResult{PluginID: p.ID(), Action: action, Status: "error", Error: err.Error()}, err
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	switch action {
	case "list_tables":
		return p.execListTables(ctx, start)
	case "describe_table":
		return p.execDescribeTable(ctx, params, start)
	case "table_sample":
		return p.execTableSample(ctx, params, start)
	case "query_readonly":
		return p.execQueryReadOnly(ctx, params, start)
	case "db_stats":
		return p.execDBStats(ctx, start)
	default:
		return PluginResult{
			PluginID: p.ID(),
			Action:   action,
			Status:   "error",
			Error:    fmt.Sprintf("unknown db-exposure action %q", action),
		}, ErrActionNotFound
	}
}

func (p *DatabaseExposurePlugin) execListTables(ctx context.Context, start time.Time) (PluginResult, error) {
	type tableMeta struct {
		Name     string `json:"name"`
		RowCount int    `json:"row_count"`
		Engine   string `json:"engine"`
	}

	var tables []tableMeta
	if p.db.IsInMemory() {
		count, _ := p.db.CountActions()
		tables = append(tables, tableMeta{
			Name:     "action_history",
			RowCount: count,
			Engine:   "in_memory",
		})
	} else {
		rows, err := p.db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
		if err != nil {
			return PluginResult{PluginID: p.ID(), Action: "list_tables", Status: "error", Error: err.Error()}, err
		}
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err == nil {
				names = append(names, name)
			}
		}
		rows.Close()

		for _, name := range names {
			if !identRegex.MatchString(name) {
				continue
			}
			var cnt int
			_ = p.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", name)).Scan(&cnt)
			tables = append(tables, tableMeta{
				Name:     name,
				RowCount: cnt,
				Engine:   "sqlite3",
			})
		}
	}

	data := map[string]any{
		"dsn":       p.db.DSN(),
		"in_memory": p.db.IsInMemory(),
		"tables":    tables,
	}
	rawJSON, _ := json.MarshalIndent(data, "", "  ")
	return PluginResult{
		PluginID:   p.ID(),
		Action:     "list_tables",
		Status:     "ok",
		Output:     string(rawJSON),
		Data:       data,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

func (p *DatabaseExposurePlugin) execDescribeTable(ctx context.Context, params map[string]any, start time.Time) (PluginResult, error) {
	tableName := "action_history"
	if params != nil {
		if v, ok := params["table"]; ok && strings.TrimSpace(fmt.Sprintf("%v", v)) != "" {
			tableName = strings.TrimSpace(fmt.Sprintf("%v", v))
		}
	}
	if !identRegex.MatchString(tableName) {
		err := fmt.Errorf("invalid table identifier %q", tableName)
		return PluginResult{PluginID: p.ID(), Action: "describe_table", Status: "error", Error: err.Error()}, err
	}

	type colMeta struct {
		CID        int    `json:"cid"`
		Name       string `json:"name"`
		Type       string `json:"type"`
		NotNull    bool   `json:"not_null"`
		PrimaryKey bool   `json:"primary_key"`
	}

	var cols []colMeta
	if p.db.IsInMemory() {
		if tableName != "action_history" {
			err := fmt.Errorf("table %q does not exist in in-memory database", tableName)
			return PluginResult{PluginID: p.ID(), Action: "describe_table", Status: "error", Error: err.Error()}, err
		}
		cols = []colMeta{
			{CID: 0, Name: "id", Type: "INTEGER", NotNull: true, PrimaryKey: true},
			{CID: 1, Name: "timestamp", Type: "DATETIME", NotNull: true, PrimaryKey: false},
			{CID: 2, Name: "command", Type: "TEXT", NotNull: true, PrimaryKey: false},
			{CID: 3, Name: "status", Type: "TEXT", NotNull: true, PrimaryKey: false},
			{CID: 4, Name: "output", Type: "TEXT", NotNull: false, PrimaryKey: false},
		}
	} else {
		rows, err := p.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err != nil {
			return PluginResult{PluginID: p.ID(), Action: "describe_table", Status: "error", Error: err.Error()}, err
		}
		defer rows.Close()
		for rows.Next() {
			var cid, notNull, pk int
			var name, colType string
			var dflt any
			if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err == nil {
				cols = append(cols, colMeta{
					CID:        cid,
					Name:       name,
					Type:       colType,
					NotNull:    notNull != 0,
					PrimaryKey: pk != 0,
				})
			}
		}
		if len(cols) == 0 {
			err := fmt.Errorf("table %q not found", tableName)
			return PluginResult{PluginID: p.ID(), Action: "describe_table", Status: "error", Error: err.Error()}, err
		}
	}

	data := map[string]any{
		"table":   tableName,
		"columns": cols,
	}
	rawJSON, _ := json.MarshalIndent(data, "", "  ")
	return PluginResult{
		PluginID:   p.ID(),
		Action:     "describe_table",
		Status:     "ok",
		Output:     string(rawJSON),
		Data:       data,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

func (p *DatabaseExposurePlugin) execTableSample(ctx context.Context, params map[string]any, start time.Time) (PluginResult, error) {
	tableName := "action_history"
	limit := 25
	if params != nil {
		if v, ok := params["table"]; ok && strings.TrimSpace(fmt.Sprintf("%v", v)) != "" {
			tableName = strings.TrimSpace(fmt.Sprintf("%v", v))
		}
		if v, ok := params["limit"]; ok {
			if n, err := strconv.Atoi(fmt.Sprintf("%v", v)); err == nil && n > 0 && n <= p.maxRows {
				limit = n
			}
		}
	}
	if !identRegex.MatchString(tableName) {
		err := fmt.Errorf("invalid table name %q", tableName)
		return PluginResult{PluginID: p.ID(), Action: "table_sample", Status: "error", Error: err.Error()}, err
	}

	if p.db.IsInMemory() {
		if tableName != "action_history" {
			err := fmt.Errorf("table %q not found", tableName)
			return PluginResult{PluginID: p.ID(), Action: "table_sample", Status: "error", Error: err.Error()}, err
		}
		records, err := p.db.ListActions(limit)
		if err != nil {
			return PluginResult{PluginID: p.ID(), Action: "table_sample", Status: "error", Error: err.Error()}, err
		}
		data := map[string]any{
			"table":     tableName,
			"row_count": len(records),
			"rows":      records,
		}
		rawJSON, _ := json.MarshalIndent(data, "", "  ")
		return PluginResult{
			PluginID:   p.ID(),
			Action:     "table_sample",
			Status:     "ok",
			Output:     string(rawJSON),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil
	}

	query := fmt.Sprintf("SELECT * FROM %s ORDER BY id DESC LIMIT %d", tableName, limit)
	return p.runSQLiteSelect(ctx, "table_sample", query, limit, start)
}

func (p *DatabaseExposurePlugin) execQueryReadOnly(ctx context.Context, params map[string]any, start time.Time) (PluginResult, error) {
	rawSQL := ""
	if params != nil {
		if v, ok := params["sql"]; ok && v != nil {
			rawSQL = fmt.Sprintf("%v", v)
		}
	}
	validatedSQL, err := ValidateReadOnlySQL(rawSQL)
	if err != nil {
		return PluginResult{
			PluginID:   p.ID(),
			Action:     "query_readonly",
			Status:     "error",
			Error:      err.Error(),
			DurationMs: time.Since(start).Milliseconds(),
		}, err
	}

	maxRows := p.maxRows
	if params != nil {
		if v, ok := params["max_rows"]; ok {
			if n, convErr := strconv.Atoi(fmt.Sprintf("%v", v)); convErr == nil && n > 0 && n <= p.maxRows {
				maxRows = n
			}
		}
	}

	// Support in-memory fallback when CGO_ENABLED=0
	if p.db.IsInMemory() {
		records, err := p.db.ListActions(maxRows)
		if err != nil {
			return PluginResult{PluginID: p.ID(), Action: "query_readonly", Status: "error", Error: err.Error()}, err
		}
		rows := make([]map[string]any, 0, len(records))
		for _, rec := range records {
			rows = append(rows, map[string]any{
				"id":        rec.ID,
				"timestamp": rec.Timestamp.Format(time.RFC3339),
				"command":   rec.Command,
				"status":    rec.Status,
				"output":    rec.Output,
			})
		}
		data := map[string]any{
			"query":     validatedSQL,
			"columns":   []string{"id", "timestamp", "command", "status", "output"},
			"row_count": len(rows),
			"rows":      rows,
			"engine":    "in_memory",
		}
		rawJSON, _ := json.MarshalIndent(data, "", "  ")
		return PluginResult{
			PluginID:   p.ID(),
			Action:     "query_readonly",
			Status:     "ok",
			Output:     string(rawJSON),
			Data:       data,
			DurationMs: time.Since(start).Milliseconds(),
		}, nil
	}

	return p.runSQLiteSelect(ctx, "query_readonly", validatedSQL, maxRows, start)
}

func (p *DatabaseExposurePlugin) runSQLiteSelect(ctx context.Context, actionName, query string, maxRows int, start time.Time) (PluginResult, error) {
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return PluginResult{
			PluginID:   p.ID(),
			Action:     actionName,
			Status:     "error",
			Error:      err.Error(),
			DurationMs: time.Since(start).Milliseconds(),
		}, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return PluginResult{PluginID: p.ID(), Action: actionName, Status: "error", Error: err.Error()}, err
	}

	resultRows := make([]map[string]any, 0)
	for rows.Next() && len(resultRows) < maxRows {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return PluginResult{PluginID: p.ID(), Action: actionName, Status: "error", Error: err.Error()}, err
		}
		rowMap := make(map[string]any, len(cols))
		for i, colName := range cols {
			val := values[i]
			if b, ok := val.([]byte); ok {
				rowMap[colName] = string(b)
			} else {
				rowMap[colName] = val
			}
		}
		resultRows = append(resultRows, rowMap)
	}

	data := map[string]any{
		"query":     query,
		"columns":   cols,
		"row_count": len(resultRows),
		"rows":      resultRows,
		"engine":    "sqlite3",
	}
	rawJSON, _ := json.MarshalIndent(data, "", "  ")
	return PluginResult{
		PluginID:   p.ID(),
		Action:     actionName,
		Status:     "ok",
		Output:     string(rawJSON),
		Data:       data,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

func (p *DatabaseExposurePlugin) execDBStats(_ context.Context, start time.Time) (PluginResult, error) {
	records, err := p.db.ListActions(1000)
	if err != nil {
		return PluginResult{PluginID: p.ID(), Action: "db_stats", Status: "error", Error: err.Error()}, err
	}
	total, _ := p.db.CountActions()

	byStatus := map[string]int{
		"success": 0,
		"failure": 0,
		"error":   0,
	}
	byCommand := make(map[string]int)
	for _, rec := range records {
		byStatus[rec.Status]++
		byCommand[rec.Command]++
	}

	data := map[string]any{
		"dsn":            p.db.DSN(),
		"in_memory":      p.db.IsInMemory(),
		"total_actions":  total,
		"sampled_count":  len(records),
		"status_counts":  byStatus,
		"command_counts": byCommand,
	}
	rawJSON, _ := json.MarshalIndent(data, "", "  ")
	return PluginResult{
		PluginID:   p.ID(),
		Action:     "db_stats",
		Status:     "ok",
		Output:     string(rawJSON),
		Data:       data,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}
