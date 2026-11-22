package gatekeeper

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go-admin-tool/internal/core"
)

// HTTPGatekeeper evaluates requests against MicroLLM's local POST /v1/guard/evaluate endpoint.
type HTTPGatekeeper struct {
	cfg           core.GatekeeperConfig
	endpoint      string
	timeout       time.Duration
	minConfidence float64
	failMode      string
	headers       map[string]string
	transport     *http.Transport
	client        *http.Client
}

// NewHTTPGatekeeper validates endpoint confinement (loopback by default) and builds a keep-alive HTTP client.
func NewHTTPGatekeeper(cfg core.GatekeeperConfig) (*HTTPGatekeeper, error) {
	rawURL := strings.TrimSpace(cfg.Endpoint)
	if rawURL == "" {
		rawURL = "http://127.0.0.1:8000/v1/guard/evaluate"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("%w: %q", ErrInvalidEndpoint, rawURL)
	}

	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if !cfg.AllowRemoteEndpoint && !isLoopbackHost(host) {
		return nil, fmt.Errorf("%w: host %q", ErrRemoteEndpointForbidden, host)
	}

	timeout := cfg.EffectiveTimeout()
	transport := &http.Transport{
		Proxy:               nil, // Never silently proxy localhost traffic externally
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     60 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	headersCopy := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headersCopy[k] = v
	}

	return &HTTPGatekeeper{
		cfg:           cfg,
		endpoint:      parsed.String(),
		timeout:       timeout,
		minConfidence: cfg.EffectiveMinConfidence(),
		failMode:      cfg.EffectiveFailMode(),
		headers:       headersCopy,
		transport:     transport,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Mode returns "http".
func (h *HTTPGatekeeper) Mode() string { return "http" }

// Close releases idle keep-alive connections.
func (h *HTTPGatekeeper) Close() error {
	if h != nil && h.transport != nil {
		h.transport.CloseIdleConnections()
	}
	return nil
}

// Evaluate posts a strict microllm.guard.v1 request and normalizes the bounded response fail-closed.
func (h *HTTPGatekeeper) Evaluate(ctx context.Context, req EvalRequest) EvalResponse {
	start := time.Now()
	payload, err := buildWireRequest(req, h.cfg)
	if err != nil {
		return failClosedResponse(h.failMode, fmt.Sprintf("failed to encode gatekeeper request: %v", err), elapsedMs(start))
	}

	evalCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(evalCtx, http.MethodPost, h.endpoint, bytes.NewReader(payload))
	if err != nil {
		return failClosedResponse(h.failMode, fmt.Sprintf("failed to construct gatekeeper HTTP request: %v", err), elapsedMs(start))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	for k, v := range h.headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return failClosedResponse(h.failMode, fmt.Sprintf("gatekeeper HTTP request failed: %v", err), elapsedMs(start))
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	lat := elapsedMs(start)
	if readErr != nil {
		return failClosedResponse(h.failMode, fmt.Sprintf("failed to read gatekeeper HTTP response: %v", readErr), lat)
	}
	if len(body) > MaxResponseBytes {
		return failClosedResponse(h.failMode, "gatekeeper HTTP response exceeded 64 KiB cap", lat)
	}
	if resp.StatusCode != http.StatusOK {
		return failClosedResponse(h.failMode, fmt.Sprintf("gatekeeper HTTP status %d", resp.StatusCode), lat)
	}

	return NormalizeWireResponse(body, h.minConfidence, h.failMode, lat)
}

func elapsedMs(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}
