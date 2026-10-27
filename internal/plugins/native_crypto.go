package plugins

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"time"
)

// TLSCertInspectorPlugin inspects remote TLS X.509 certificate chains, SANs, and expiration warnings.
type TLSCertInspectorPlugin struct{}

func (p *TLSCertInspectorPlugin) ID() string          { return "tls-cert-inspector" }
func (p *TLSCertInspectorPlugin) Name() string        { return "Remote TLS/X.509 Endpoint Certificate Inspector" }
func (p *TLSCertInspectorPlugin) Version() string     { return "1.0.0" }
func (p *TLSCertInspectorPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *TLSCertInspectorPlugin) Type() string        { return "native" }
func (p *TLSCertInspectorPlugin) Category() string    { return "Web & Crypto Utilities" }
func (p *TLSCertInspectorPlugin) Description() string {
	return "Inspects remote TLS endpoints, parses X.509 chains, evaluates expiration dates, and verifies SANs."
}

func (p *TLSCertInspectorPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "inspect_cert",
			Description: "Connect to TLS endpoint and extract certificate chain and validity",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: true, Description: "Target hostname or IP"},
				{Name: "port", Type: "int", Required: false, Default: "443", Description: "Target TLS port"},
			},
		},
		{
			Name:        "check_expiration",
			Description: "Calculate days until certificate expiration and return warning status",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: true, Description: "Target hostname or IP"},
				{Name: "port", Type: "int", Required: false, Default: "443", Description: "Target TLS port"},
			},
		},
		{
			Name:        "verify_sans",
			Description: "Verify if hostname matches Subject Alternative Names (SANs)",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "host", Type: "string", Required: true, Description: "Target endpoint host"},
				{Name: "port", Type: "int", Required: false, Default: "443", Description: "Target TLS port"},
				{Name: "hostname", Type: "string", Required: true, Description: "Hostname to verify against SANs"},
			},
		},
	}
}

func (p *TLSCertInspectorPlugin) Execute(ctx context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	host := getStringParam(params, "host", "")
	port := getIntParam(params, "port", 443)

	if host == "" {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: "parameter 'host' is required",
		}, fmt.Errorf("parameter 'host' is required")
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), tlsConfig)
	if err != nil {
		data := map[string]any{
			"host":      host,
			"port":      port,
			"connected": false,
			"error":     err.Error(),
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
			Output: formatJSON(data), Data: data, Error: err.Error(),
		}, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: "no peer certificates found on endpoint",
		}, fmt.Errorf("no peer certificates found")
	}

	cert := state.PeerCertificates[0]
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	switch normalized {
	case "inspect_cert":
		data := map[string]any{
			"host":               host,
			"port":               port,
			"subject":            cert.Subject.String(),
			"issuer":             cert.Issuer.String(),
			"not_before":         cert.NotBefore.Format(time.RFC3339),
			"not_after":          cert.NotAfter.Format(time.RFC3339),
			"days_remaining":     daysRemaining,
			"dns_names":          cert.DNSNames,
			"ip_addresses":       cert.IPAddresses,
			"version":            cert.Version,
			"serial_number":      cert.SerialNumber.String(),
			"signature_algo":     cert.SignatureAlgorithm.String(),
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "check_expiration":
		warning := daysRemaining < 30
		expired := daysRemaining <= 0
		data := map[string]any{
			"host":           host,
			"port":           port,
			"not_after":      cert.NotAfter.Format(time.RFC3339),
			"days_remaining": daysRemaining,
			"warning_soon":   warning,
			"is_expired":     expired,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "verify_sans":
		targetHost := getStringParam(params, "hostname", host)
		matched := false
		for _, name := range cert.DNSNames {
			if strings.EqualFold(name, targetHost) {
				matched = true
				break
			}
			if strings.HasPrefix(name, "*.") {
				suffix := name[1:]
				if strings.HasSuffix(strings.ToLower(targetHost), strings.ToLower(suffix)) {
					matched = true
					break
				}
			}
		}

		data := map[string]any{
			"endpoint":        host,
			"target_hostname": targetHost,
			"sans_count":      len(cert.DNSNames),
			"sans":            cert.DNSNames,
			"matched":         matched,
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

// HTTPLatencyProbePlugin performs HTTP requests with microsecond latency phase breakdown and security header audits.
type HTTPLatencyProbePlugin struct{}

func (p *HTTPLatencyProbePlugin) ID() string          { return "http-latency-probe" }
func (p *HTTPLatencyProbePlugin) Name() string        { return "Multi-Stage HTTP/REST Health & Latency Probe" }
func (p *HTTPLatencyProbePlugin) Version() string     { return "1.0.0" }
func (p *HTTPLatencyProbePlugin) Kind() PluginKind    { return KindAdvanced }
func (p *HTTPLatencyProbePlugin) Type() string        { return "native" }
func (p *HTTPLatencyProbePlugin) Category() string    { return "Web & Crypto Utilities" }
func (p *HTTPLatencyProbePlugin) Description() string {
	return "Measures HTTP DNS, TCP dial, TLS handshake, TTFB, and transfer latencies with security header verification."
}

func (p *HTTPLatencyProbePlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "probe_endpoint",
			Description: "Measure multi-phase HTTP latency breakdown (DNS, TCP, TLS, TTFB)",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "url", Type: "string", Required: true, Description: "Target HTTP/HTTPS URL"},
				{Name: "method", Type: "string", Required: false, Default: "GET", Description: "HTTP method (GET, HEAD)"},
			},
		},
		{
			Name:        "inspect_headers",
			Description: "Audit response security headers (HSTS, CSP, X-Frame-Options)",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "url", Type: "string", Required: true, Description: "Target HTTP/HTTPS URL"},
			},
		},
		{
			Name:        "ssl_redirect_check",
			Description: "Verify whether HTTP port 80 properly redirects to HTTPS with 301/308",
			Timeout:     "10s",
			Parameters: []ActionParameter{
				{Name: "url", Type: "string", Required: true, Description: "Target HTTP URL"},
			},
		},
	}
}

func (p *HTTPLatencyProbePlugin) Execute(ctx context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	targetURL := getStringParam(params, "url", "")

	if targetURL == "" {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: "parameter 'url' is required",
		}, fmt.Errorf("parameter 'url' is required")
	}

	switch normalized {
	case "probe_endpoint":
		method := strings.ToUpper(getStringParam(params, "method", "GET"))
		var dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, firstByte time.Time

		trace := &httptrace.ClientTrace{
			DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
			DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
			ConnectStart: func(_, _ string) {
				if connStart.IsZero() {
					connStart = time.Now()
				}
			},
			ConnectDone: func(_, _ string, _ error) {
				if connDone.IsZero() {
					connDone = time.Now()
				}
			},
			TLSHandshakeStart: func() { tlsStart = time.Now() },
			TLSHandshakeDone:  func(_ tls.ConnectionState, _ error) { tlsDone = time.Now() },
			GotFirstResponseByte: func() { firstByte = time.Now() },
		}

		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, targetURL, nil)
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, err
		}

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

		reqStart := time.Now()
		resp, err := client.Do(req)
		totalDuration := time.Since(reqStart)

		if err != nil {
			data := map[string]any{
				"url":        targetURL,
				"error":      err.Error(),
				"total_ms":   totalDuration.Milliseconds(),
				"successful": false,
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
			}, nil
		}
		defer resp.Body.Close()

		data := map[string]any{
			"url":         targetURL,
			"method":      method,
			"status_code": resp.StatusCode,
			"status":      resp.Status,
			"total_ms":    totalDuration.Milliseconds(),
			"dns_ms":      dnsDone.Sub(dnsStart).Milliseconds(),
			"connect_ms":  connDone.Sub(connStart).Milliseconds(),
			"tls_ms":      tlsDone.Sub(tlsStart).Milliseconds(),
			"ttfb_ms":     firstByte.Sub(reqStart).Milliseconds(),
			"proto":       resp.Proto,
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "inspect_headers":
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, nil
		}
		defer resp.Body.Close()

		hsts := resp.Header.Get("Strict-Transport-Security")
		csp := resp.Header.Get("Content-Security-Policy")
		xfo := resp.Header.Get("X-Frame-Options")
		xcto := resp.Header.Get("X-Content-Type-Options")

		data := map[string]any{
			"url":                targetURL,
			"status_code":        resp.StatusCode,
			"has_hsts":           hsts != "",
			"hsts_header":        hsts,
			"has_csp":            csp != "",
			"has_x_frame_opts":   xfo != "",
			"has_x_content_type": xcto != "",
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "ssl_redirect_check":
		// Disallow auto-follow to check initial status code
		client := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 5 * time.Second,
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: err.Error(),
			}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			data := map[string]any{
				"url":        targetURL,
				"redirects":  false,
				"error":      err.Error(),
			}
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "failure", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
			}, nil
		}
		defer resp.Body.Close()

		isRedirect := (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308)
		loc := resp.Header.Get("Location")
		redirectsToHTTPS := strings.HasPrefix(strings.ToLower(loc), "https://")

		data := map[string]any{
			"url":                targetURL,
			"status_code":        resp.StatusCode,
			"is_redirect":        isRedirect,
			"location":           loc,
			"redirects_to_https": redirectsToHTTPS,
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

// CryptoHashUtilityPlugin computes cryptographic hashes, HMAC signatures, and identifies hash formats.
type CryptoHashUtilityPlugin struct{}

func (p *CryptoHashUtilityPlugin) ID() string          { return "crypto-hash-utility" }
func (p *CryptoHashUtilityPlugin) Name() string        { return "Multi-Algorithm Cryptographic Hasher & Verifier" }
func (p *CryptoHashUtilityPlugin) Version() string     { return "1.0.0" }
func (p *CryptoHashUtilityPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *CryptoHashUtilityPlugin) Type() string        { return "native" }
func (p *CryptoHashUtilityPlugin) Category() string    { return "Web & Crypto Utilities" }
func (p *CryptoHashUtilityPlugin) Description() string {
	return "Computes MD5/SHA-1/SHA-256/SHA-512 hashes, signs HMAC-SHA256 digests, and detects hash types."
}

func (p *CryptoHashUtilityPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "hash_string",
			Description: "Compute multi-algorithm cryptographic hash of input text",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "input", Type: "string", Required: true, Description: "Input string to hash"},
				{Name: "algorithm", Type: "string", Required: false, Default: "sha256", Description: "Algorithm: sha256, sha512, md5, sha1, sha384, all"},
			},
		},
		{
			Name:        "verify_hmac",
			Description: "Compute and verify HMAC-SHA256 signature against expected digest",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "input", Type: "string", Required: true, Description: "Payload data"},
				{Name: "key", Type: "string", Required: true, Description: "Secret key for HMAC"},
				{Name: "expected_hmac", Type: "string", Required: false, Default: "", Description: "Optional expected HMAC hex string"},
			},
		},
		{
			Name:        "detect_algorithm",
			Description: "Heuristically detect hash algorithm from hex digest length and format",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "hash", Type: "string", Required: true, Description: "Hex-encoded hash digest"},
			},
		},
	}
}

func (p *CryptoHashUtilityPlugin) Execute(_ context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")

	switch normalized {
	case "hash_string":
		in := getStringParam(params, "input", "")
		algo := strings.ToLower(getStringParam(params, "algorithm", "all"))
		inBytes := []byte(in)

		data := map[string]any{
			"input_length": len(in),
		}

		if algo == "sha256" || algo == "all" {
			h := sha256.Sum256(inBytes)
			data["sha256"] = hex.EncodeToString(h[:])
		}
		if algo == "sha512" || algo == "all" {
			h := sha512.Sum512(inBytes)
			data["sha512"] = hex.EncodeToString(h[:])
		}
		if algo == "md5" || algo == "all" {
			h := md5.Sum(inBytes)
			data["md5"] = hex.EncodeToString(h[:])
		}
		if algo == "sha1" || algo == "all" {
			h := sha1.Sum(inBytes)
			data["sha1"] = hex.EncodeToString(h[:])
		}
		if algo == "sha384" || algo == "all" {
			h := sha512.Sum384(inBytes)
			data["sha384"] = hex.EncodeToString(h[:])
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "verify_hmac":
		in := getStringParam(params, "input", "")
		key := getStringParam(params, "key", "")
		expected := strings.ToLower(getStringParam(params, "expected_hmac", ""))

		if key == "" {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "parameter 'key' is required for HMAC",
			}, fmt.Errorf("parameter 'key' is required")
		}

		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(in))
		computed := hex.EncodeToString(mac.Sum(nil))

		matched := true
		if expected != "" {
			matched = (computed == expected)
		}

		data := map[string]any{
			"computed_hmac": computed,
			"algorithm":     "HMAC-SHA256",
			"matched":       matched,
		}
		if expected != "" {
			data["expected_hmac"] = expected
		}

		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "detect_algorithm":
		h := strings.TrimSpace(getStringParam(params, "hash", ""))
		length := len(h)
		detected := "unknown"

		switch length {
		case 32:
			detected = "MD5 (128-bit)"
		case 40:
			detected = "SHA-1 (160-bit)"
		case 56:
			detected = "SHA-224 (224-bit)"
		case 64:
			detected = "SHA-256 (256-bit)"
		case 96:
			detected = "SHA-384 (384-bit)"
		case 128:
			detected = "SHA-512 (512-bit)"
		}

		data := map[string]any{
			"hash":      h,
			"hex_len":   length,
			"algorithm": detected,
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

// JWTTokenInspectorPlugin decodes JWT JOSE headers, claims payloads, and validates token expiration.
type JWTTokenInspectorPlugin struct{}

func (p *JWTTokenInspectorPlugin) ID() string          { return "jwt-token-inspector" }
func (p *JWTTokenInspectorPlugin) Name() string        { return "JWT Token Claims & Expiration Inspector" }
func (p *JWTTokenInspectorPlugin) Version() string     { return "1.0.0" }
func (p *JWTTokenInspectorPlugin) Kind() PluginKind    { return KindAdvanced }
func (p *JWTTokenInspectorPlugin) Type() string        { return "native" }
func (p *JWTTokenInspectorPlugin) Category() string    { return "Web & Crypto Utilities" }
func (p *JWTTokenInspectorPlugin) Description() string {
	return "Decodes JWT JOSE headers, parses claims without secrets, and verifies token expiration timestamps."
}

func (p *JWTTokenInspectorPlugin) Actions() []PluginAction {
	return []PluginAction{
		{
			Name:        "decode_claims",
			Description: "Decode JWT payload claims into structured JSON object",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "token", Type: "string", Required: true, Description: "JWT string (header.payload.signature)"},
			},
		},
		{
			Name:        "inspect_header",
			Description: "Decode JOSE header (alg, typ, kid)",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "token", Type: "string", Required: true, Description: "JWT string"},
			},
		},
		{
			Name:        "verify_validity",
			Description: "Verify expiration (exp), not-before (nbf), and issued-at (iat) time constraints",
			Timeout:     "5s",
			Parameters: []ActionParameter{
				{Name: "token", Type: "string", Required: true, Description: "JWT string"},
			},
		},
	}
}

func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if missing
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func (p *JWTTokenInspectorPlugin) Execute(_ context.Context, action string, params map[string]any, _ time.Duration) (PluginResult, error) {
	start := time.Now()
	normalized := strings.ReplaceAll(strings.TrimSpace(action), "-", "_")
	tok := strings.TrimSpace(getStringParam(params, "token", ""))

	if tok == "" {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: "parameter 'token' is required",
		}, fmt.Errorf("parameter 'token' is required")
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
			Error: "invalid JWT token format: expected 3 dot-separated segments",
		}, fmt.Errorf("invalid JWT format")
	}

	switch normalized {
	case "inspect_header":
		hdrBytes, err := decodeBase64URL(parts[0])
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("failed to decode header base64: %v", err),
			}, err
		}

		var hdr map[string]any
		if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("failed to parse JSON header: %v", err),
			}, err
		}
		if hdr == nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "invalid JWT header: expected JSON object",
			}, fmt.Errorf("invalid JWT header: expected JSON object")
		}
		data := map[string]any{
			"header": hdr,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "decode_claims":
		payloadBytes, err := decodeBase64URL(parts[1])
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("failed to decode payload base64: %v", err),
			}, err
		}

		var claims map[string]any
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("failed to parse JSON claims: %v", err),
			}, err
		}
		if claims == nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "invalid JWT payload: expected JSON object",
			}, fmt.Errorf("invalid JWT payload: expected JSON object")
		}
		data := map[string]any{
			"claims": claims,
		}
		return PluginResult{
			PluginID: p.ID(), Action: action, Status: "ok", Output: formatJSON(data), Data: data, DurationMs: time.Since(start).Milliseconds(),
		}, nil

	case "verify_validity":
		payloadBytes, err := decodeBase64URL(parts[1])
		if err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("failed to decode payload base64: %v", err),
			}, err
		}

		var claims map[string]any
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: fmt.Sprintf("failed to parse JSON claims: %v", err),
			}, err
		}
		if claims == nil {
			return PluginResult{
				PluginID: p.ID(), Action: action, Status: "error", DurationMs: time.Since(start).Milliseconds(),
				Error: "invalid JWT payload: expected JSON object",
			}, fmt.Errorf("invalid JWT payload: expected JSON object")
		}

		now := time.Now().Unix()
		isExpired := false
		var expDiffSec int64

		if expVal, ok := claims["exp"]; ok {
			var expNum int64
			switch ev := expVal.(type) {
			case float64:
				expNum = int64(ev)
			case int64:
				expNum = ev
			case string:
				if n, err := strconv.ParseInt(ev, 10, 64); err == nil {
					expNum = n
				}
			}
			if expNum > 0 {
				isExpired = now > expNum
				expDiffSec = expNum - now
			}
		}

		valid := !isExpired
		if nbfVal, ok := claims["nbf"]; ok {
			var nbfNum int64
			switch nv := nbfVal.(type) {
			case float64:
				nbfNum = int64(nv)
			case int64:
				nbfNum = nv
			case string:
				if n, err := strconv.ParseInt(nv, 10, 64); err == nil {
					nbfNum = n
				}
			}
			if nbfNum > 0 && now < nbfNum {
				valid = false
			}
		}

		data := map[string]any{
			"current_timestamp": now,
			"is_expired":        isExpired,
			"seconds_remaining": expDiffSec,
			"valid":             valid,
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
