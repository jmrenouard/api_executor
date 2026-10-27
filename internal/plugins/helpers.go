package plugins

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// getStringParam extracts a string value from params map or returns defaultVal.
func getStringParam(params map[string]any, key, defaultVal string) string {
	if params == nil {
		return defaultVal
	}
	v, exists := params[key]
	if !exists || v == nil {
		return defaultVal
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "" {
		return defaultVal
	}
	return s
}

// getIntParam extracts an integer value from params map (supporting float64, int, string) or returns defaultVal.
func getIntParam(params map[string]any, key string, defaultVal int) int {
	if params == nil {
		return defaultVal
	}
	v, exists := params[key]
	if !exists || v == nil {
		return defaultVal
	}
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
			return i
		}
	}
	return defaultVal
}

// getBoolParam extracts a boolean value from params map or returns defaultVal.
func getBoolParam(params map[string]any, key string, defaultVal bool) bool {
	if params == nil {
		return defaultVal
	}
	v, exists := params[key]
	if !exists || v == nil {
		return defaultVal
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		lower := strings.ToLower(strings.TrimSpace(val))
		if lower == "true" || lower == "1" || lower == "yes" {
			return true
		}
		if lower == "false" || lower == "0" || lower == "no" {
			return false
		}
	case float64:
		return val != 0
	case int:
		return val != 0
	}
	return defaultVal
}

// formatJSON formats any data structure as indented JSON string.
func formatJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", v)
	}
	return string(b)
}
