package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// MCPEndpointTesterPlugin tests Model Context Protocol endpoints via standard JSON-RPC 2.0.
type MCPEndpointTesterPlugin struct{}

func (p *MCPEndpointTesterPlugin) ID() string          { return "mcp-endpoint-tester" }
func (p *MCPEndpointTesterPlugin) Name() string        { return "Model Context Protocol JSON-RPC 2.0 Client" }
func (p *MCPEndpointTesterPlugin) Version() string     { return "1.0.0" }
func (p *MCPEndpointTesterPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *MCPEndpointTesterPlugin) Type() string        { return "native" }
func (p *MCPEndpointTesterPlugin) Category() string    { return "AIOps" }
func (p *MCPEndpointTesterPlugin) Description() string {
	return "Tests JSON-RPC 2.0 MCP servers, queries tools/resources, and benchmarks response latencies."
}

func (p *MCPEndpointTesterPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "ping_mcp",
			Description: "Send JSON-RPC 2.0 initialize request to target MCP endpoint",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "endpoint", Type: "string", Required: false, Default: "http://localhost:8080/api/v1/mcp", Description: "Target MCP HTTP endpoint URL"},
			},
		},
		{
			Name:        "list_tools",
			Description: "Query tools/list on MCP server",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "endpoint", Type: "string", Required: false, Default: "http://localhost:8080/api/v1/mcp", Description: "Target MCP HTTP endpoint URL"},
			},
		},
		{
			Name:        "list_resources",
			Description: "Query resources/list on MCP server",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "endpoint", Type: "string", Required: false, Default: "http://localhost:8080/api/v1/mcp", Description: "Target MCP HTTP endpoint URL"},
			},
		},
		{
			Name:        "benchmark_call",
			Description: "Benchmark latency of tools/list call on MCP endpoint",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "endpoint", Type: "string", Required: false, Default: "http://localhost:8080/api/v1/mcp", Description: "Target MCP HTTP endpoint URL"},
			},
		},
	}
}

func (p *MCPEndpointTesterPlugin) callMCP(ctx context.Context, endpoint, method string, params any) (map[string]any, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		payload["params"] = params
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (p *MCPEndpointTesterPlugin) Execute(ctx context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	endpoint := getStringParam(params, "endpoint", "http://localhost:8080/api/v1/mcp")

	switch normalized {
	case "ping_mcp":
		initParams := map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":   map[string]any{},
			"clientInfo": map[string]any{
				"name":    "native-mcp-tester",
				"version": "1.0.0",
			},
		}

		res, err := p.callMCP(ctx, endpoint, "initialize", initParams)
		if err != nil {
			data := map[string]any{
				"endpoint":  endpoint,
				"connected": false,
				"error":     err.Error(),
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Output: formatJSON(data), Data: data, Error: err.Error(),
			}, nil
		}

		data := map[string]any{
			"endpoint":  endpoint,
			"connected": true,
			"response":  res,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "list_tools", "benchmark_call":
		callStart := time.Now()
		res, err := p.callMCP(ctx, endpoint, "tools/list", nil)
		callLatency := time.Since(callStart)

		if err != nil {
			data := map[string]any{
				"endpoint":   endpoint,
				"connected":  false,
				"latency_ms": callLatency.Milliseconds(),
				"error":      err.Error(),
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Output: formatJSON(data), Data: data, Error: err.Error(),
			}, nil
		}

		data := map[string]any{
			"endpoint":   endpoint,
			"connected":  true,
			"latency_ms": callLatency.Milliseconds(),
			"response":   res,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "list_resources":
		res, err := p.callMCP(ctx, endpoint, "resources/list", nil)
		if err != nil {
			data := map[string]any{
				"endpoint":  endpoint,
				"connected": false,
				"error":     err.Error(),
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Output: formatJSON(data), Data: data, Error: err.Error(),
			}, nil
		}

		data := map[string]any{
			"endpoint":  endpoint,
			"connected": true,
			"response":  res,
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

// ModelArtifactVerifierPlugin inspects SafeTensors JSON metadata headers, GGUF magic numbers, and weights integrity.
type ModelArtifactVerifierPlugin struct{}

func (p *ModelArtifactVerifierPlugin) ID() string          { return "model-artifact-verifier" }
func (p *ModelArtifactVerifierPlugin) Name() string        { return "AI/ML Model Artifact Header & Tensor Verifier" }
func (p *ModelArtifactVerifierPlugin) Version() string     { return "1.0.0" }
func (p *ModelArtifactVerifierPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *ModelArtifactVerifierPlugin) Type() string        { return "native" }
func (p *ModelArtifactVerifierPlugin) Category() string    { return "AIOps" }
func (p *ModelArtifactVerifierPlugin) Description() string {
	return "Inspects SafeTensors 8-byte JSON headers, GGUF binary headers (0x46554747), and computes artifact digests."
}

func (p *ModelArtifactVerifierPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "inspect_safetensors",
			Description: "Parse SafeTensors 8-byte length prefix and extract JSON tensor metadata header",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "path", Type: "string", Required: true, Description: "Path to .safetensors file"},
			},
		},
		{
			Name:        "inspect_gguf",
			Description: "Inspect GGUF binary magic number, version, and tensor counts",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "path", Type: "string", Required: true, Description: "Path to .gguf model file"},
			},
		},
		{
			Name:        "verify_checksum",
			Description: "Compute SHA-256 digest of AI model artifact file",
			Timeout:     "15s",
			Parameters: []ActionParameter{
				{Name: "path", Type: "string", Required: true, Description: "Path to model artifact file"},
			},
		},
	}
}

func (p *ModelArtifactVerifierPlugin) Execute(_ context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	targetPath := getStringParam(params, "path", "")

	if targetPath == "" {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: "parameter 'path' is required",
		}, fmt.Errorf("parameter 'path' is required")
	}

	f, err := os.Open(targetPath)
	if err != nil {
		data := map[string]any{
			"path":   targetPath,
			"exists": false,
			"error":  err.Error(),
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil
	}
	defer f.Close()

	switch normalized {
	case "inspect_safetensors":
		// SafeTensors format: first 8 bytes (little endian uint64) = header length, followed by utf-8 JSON header
		var headerLen uint64
		if err := binary.Read(f, binary.LittleEndian, &headerLen); err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("failed to read 8-byte SafeTensors header length: %v", err),
			}, err
		}

		if headerLen == 0 || headerLen > 100*1024*1024 {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("invalid SafeTensors header length: %d", headerLen),
			}, fmt.Errorf("invalid SafeTensors header length")
		}

		headerBytes := make([]byte, headerLen)
		if _, err := io.ReadFull(f, headerBytes); err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("failed to read SafeTensors JSON header: %v", err),
			}, err
		}

		var meta map[string]any
		_ = json.Unmarshal(headerBytes, &meta)

		data := map[string]any{
			"path":          targetPath,
			"format":        "safetensors",
			"header_length": headerLen,
			"tensor_count":  len(meta),
			"metadata":      meta,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "inspect_gguf":
		// GGUF format: 4 bytes magic "GGUF" (0x46554747), 4 bytes uint32 version, 8 bytes uint64 tensor_count, 8 bytes uint64 metadata_kv_count
		magic := make([]byte, 4)
		if _, err := io.ReadFull(f, magic); err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, err
		}

		isGGUF := string(magic) == "GGUF"
		var version uint32
		var tensorCount uint64
		var kvCount uint64

		if isGGUF {
			_ = binary.Read(f, binary.LittleEndian, &version)
			_ = binary.Read(f, binary.LittleEndian, &tensorCount)
			_ = binary.Read(f, binary.LittleEndian, &kvCount)
		}

		data := map[string]any{
			"path":          targetPath,
			"is_gguf":       isGGUF,
			"magic":         string(magic),
			"version":       version,
			"tensor_count":  tensorCount,
			"metadata_kv":   kvCount,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "verify_checksum":
		h := sha256.New()
		copied, err := io.Copy(h, f)
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, err
		}

		data := map[string]any{
			"path":       targetPath,
			"size_bytes": copied,
			"sha256":     hex.EncodeToString(h.Sum(nil)),
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
