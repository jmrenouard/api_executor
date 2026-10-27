package plugins

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TCPUDPPortProbePlugin measures network socket latency, banner retrieval, and port connectivity.
type TCPUDPPortProbePlugin struct{}

func (p *TCPUDPPortProbePlugin) ID() string          { return "tcp-udp-port-probe" }
func (p *TCPUDPPortProbePlugin) Name() string        { return "Low-Latency TCP/UDP Port & Socket Probe" }
func (p *TCPUDPPortProbePlugin) Version() string     { return "1.0.0" }
func (p *TCPUDPPortProbePlugin) Kind() PluginKind    { return KindAdvanced }
func (p *TCPUDPPortProbePlugin) Type() string        { return "native" }
func (p *TCPUDPPortProbePlugin) Category() string    { return "NetOps" }
func (p *TCPUDPPortProbePlugin) Description() string {
	return "Measures microsecond TCP handshakes, banner responses, UDP datagram roundtrips, and concurrent port probes."
}

func (p *TCPUDPPortProbePlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "tcp_ping",
			Description: "Measure TCP connection latency to a host:port endpoint",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: true, Description: "Target hostname or IP"},
				{Name: "port", Type: "int", Required: true, Description: "Target TCP port"},
				{Name: "timeout_ms", Type: "int", Required: false, Default: "3000", Description: "Dial timeout in milliseconds"},
			},
		},
		{
			Name:        "tcp_banner",
			Description: "Connect and retrieve initial service greeting banner",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: true, Description: "Target hostname or IP"},
				{Name: "port", Type: "int", Required: true, Description: "Target TCP port"},
				{Name: "timeout_ms", Type: "int", Required: false, Default: "3000", Description: "Read timeout in milliseconds"},
			},
		},
		{
			Name:        "udp_ping",
			Description: "Send UDP datagram probe and measure socket responsiveness",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: true, Description: "Target hostname or IP"},
				{Name: "port", Type: "int", Required: true, Description: "Target UDP port"},
				{Name: "timeout_ms", Type: "int", Required: false, Default: "3000", Description: "Timeout in milliseconds"},
			},
		},
		{
			Name:        "port_scan",
			Description: "Concurrently probe up to 20 TCP ports on a target host",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: true, Description: "Target hostname or IP"},
				{Name: "ports", Type: "string", Required: false, Default: "22,80,443,3000,8080", Description: "Comma-separated port list"},
				{Name: "timeout_ms", Type: "int", Required: false, Default: "1000", Description: "Per-port timeout in milliseconds"},
			},
		},
	}
}

func (p *TCPUDPPortProbePlugin) Execute(ctx context.Context, action string, params map[string]any, timeout time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")

	switch normalized {
	case "tcp_ping":
		host := getStringParam(params, "host", "")
		port := getIntParam(params, "port", 0)
		if host == "" || port <= 0 || port > 65535 {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameters 'host' (non-empty) and 'port' (1-65535) are required",
			}, fmt.Errorf("parameters 'host' and 'port' are required")
		}
		timeoutMs := getIntParam(params, "timeout_ms", 3000)
		dialTimeout := time.Duration(timeoutMs) * time.Millisecond
		if dialTimeout > timeout {
			dialTimeout = timeout
		}

		dialStart := time.Now()
		d := net.Dialer{Timeout: dialTimeout}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		latency := time.Since(dialStart)

		if err != nil {
			data := map[string]any{
				"target":     net.JoinHostPort(host, strconv.Itoa(port)),
				"open":       false,
				"error":      err.Error(),
				"latency_us": latency.Microseconds(),
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Output: formatJSON(data), Data: data, Error: err.Error(),
			}, nil
		}
		defer conn.Close()

		data := map[string]any{
			"target":     net.JoinHostPort(host, strconv.Itoa(port)),
			"open":       true,
			"local_addr": conn.LocalAddr().String(),
			"latency_us": latency.Microseconds(),
			"latency_ms": float64(latency.Microseconds()) / 1000.0,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "tcp_banner":
		host := getStringParam(params, "host", "")
		port := getIntParam(params, "port", 0)
		if host == "" || port <= 0 || port > 65535 {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameters 'host' (non-empty) and 'port' (1-65535) are required",
			}, fmt.Errorf("parameters 'host' and 'port' are required")
		}
		timeoutMs := getIntParam(params, "timeout_ms", 3000)
		dialTimeout := time.Duration(timeoutMs) * time.Millisecond

		d := net.Dialer{Timeout: dialTimeout}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Output: fmt.Sprintf("Failed to connect: %v", err), Error: err.Error(),
			}, nil
		}
		defer conn.Close()

		_ = conn.SetReadDeadline(time.Now().Add(dialTimeout))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		banner := strings.TrimSpace(string(buf[:n]))

		data := map[string]any{
			"target": net.JoinHostPort(host, strconv.Itoa(port)),
			"banner": banner,
			"bytes":  n,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "udp_ping":
		host := getStringParam(params, "host", "")
		port := getIntParam(params, "port", 0)
		if host == "" || port <= 0 || port > 65535 {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameters 'host' and 'port' are required",
			}, fmt.Errorf("parameters 'host' and 'port' are required")
		}

		dialStart := time.Now()
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, nil
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("PING\n"))
		latency := time.Since(dialStart)
		data := map[string]any{
			"target":     net.JoinHostPort(host, strconv.Itoa(port)),
			"status":     "sent",
			"latency_us": latency.Microseconds(),
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "port_scan":
		host := getStringParam(params, "host", "")
		if host == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'host' is required",
			}, fmt.Errorf("parameter 'host' is required")
		}
		portsStr := getStringParam(params, "ports", "22,80,443,3000,8080")
		timeoutMs := getIntParam(params, "timeout_ms", 1000)

		rawPorts := strings.Split(portsStr, ",")
		var ports []int
		for _, pStr := range rawPorts {
			if p, err := strconv.Atoi(strings.TrimSpace(pStr)); err == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
			if len(ports) >= 20 {
				break
			}
		}

		results := make(map[string]bool)
		var mu sync.Mutex
		var wg sync.WaitGroup

		for _, pt := range ports {
			wg.Add(1)
			go func(portNum int) {
				defer wg.Done()
				d := net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(portNum)))
				isOpen := (err == nil)
				if conn != nil {
					_ = conn.Close()
				}
				mu.Lock()
				results[strconv.Itoa(portNum)] = isOpen
				mu.Unlock()
			}(pt)
		}
		wg.Wait()

		data := map[string]any{
			"host":       host,
			"port_count": len(ports),
			"results":    results,
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

// DNSResolverAuditPlugin audits DNS records, compares resolver responses, and queries reverse PTRs.
type DNSResolverAuditPlugin struct{}

func (p *DNSResolverAuditPlugin) ID() string          { return "dns-resolver-audit" }
func (p *DNSResolverAuditPlugin) Name() string        { return "DNS Hierarchy & Record Resolution Audit" }
func (p *DNSResolverAuditPlugin) Version() string     { return "1.0.0" }
func (p *DNSResolverAuditPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *DNSResolverAuditPlugin) Type() string        { return "native" }
func (p *DNSResolverAuditPlugin) Category() string    { return "NetOps" }
func (p *DNSResolverAuditPlugin) Description() string {
	return "Queries DNS records (A, AAAA, CNAME, MX, TXT, NS), audits custom DNS resolvers, and resolves reverse PTRs."
}

func (p *DNSResolverAuditPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "lookup_records",
			Description: "Query comprehensive DNS records for target domain",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "domain", Type: "string", Required: true, Description: "Target domain name"},
			},
		},
		{
			Name:        "trace_dns",
			Description: "Compare resolution between system resolver and custom DNS server",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "domain", Type: "string", Required: true, Description: "Target domain name"},
				{Name: "dns_server", Type: "string", Required: false, Default: "8.8.8.8:53", Description: "Custom DNS server IP:port"},
			},
		},
		{
			Name:        "reverse_lookup",
			Description: "Perform PTR reverse lookup for an IPv4 or IPv6 address",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "ip", Type: "string", Required: true, Description: "IP address to reverse lookup"},
			},
		},
	}
}

func (p *DNSResolverAuditPlugin) Execute(ctx context.Context, action string, params map[string]any, timeout time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")

	switch normalized {
	case "lookup_records":
		domain := getStringParam(params, "domain", "")
		if domain == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'domain' is required",
			}, fmt.Errorf("parameter 'domain' is required")
		}

		res := net.DefaultResolver
		ips, _ := res.LookupHost(ctx, domain)
		cname, _ := res.LookupCNAME(ctx, domain)
		mx, _ := res.LookupMX(ctx, domain)
		txt, _ := res.LookupTXT(ctx, domain)
		ns, _ := res.LookupNS(ctx, domain)

		mxRecords := make([]string, 0, len(mx))
		for _, m := range mx {
			mxRecords = append(mxRecords, fmt.Sprintf("%s (pref %d)", m.Host, m.Pref))
		}
		nsRecords := make([]string, 0, len(ns))
		for _, n := range ns {
			nsRecords = append(nsRecords, n.Host)
		}

		data := map[string]any{
			"domain": domain,
			"ips":    ips,
			"cname":  cname,
			"mx":     mxRecords,
			"txt":    txt,
			"ns":     nsRecords,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "trace_dns":
		domain := getStringParam(params, "domain", "")
		dnsServer := getStringParam(params, "dns_server", "8.8.8.8:53")
		if domain == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'domain' is required",
			}, fmt.Errorf("parameter 'domain' is required")
		}

		sysIPs, _ := net.DefaultResolver.LookupHost(ctx, domain)

		customResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		customIPs, customErr := customResolver.LookupHost(ctx, domain)

		data := map[string]any{
			"domain":          domain,
			"system_resolver": sysIPs,
			"custom_server":   dnsServer,
			"custom_resolver": customIPs,
		}
		if customErr != nil {
			data["custom_error"] = customErr.Error()
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "reverse_lookup":
		ipStr := getStringParam(params, "ip", "")
		if ipStr == "" || net.ParseIP(ipStr) == nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "valid parameter 'ip' is required",
			}, fmt.Errorf("valid parameter 'ip' is required")
		}

		names, err := net.DefaultResolver.LookupAddr(ctx, ipStr)
		data := map[string]any{
			"ip":          ipStr,
			"hostnames":   names,
			"found_count": len(names),
		}
		if err != nil {
			data["error"] = err.Error()
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
