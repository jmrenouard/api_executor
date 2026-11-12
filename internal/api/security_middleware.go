package api

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-admin-tool/internal/audit"
)

const (
	// MaxRequestBodyBytes is the default maximum allowed HTTP request body size (1 MiB)
	// to protect JSON decoders and server memory against oversized payload DDoS attacks.
	MaxRequestBodyBytes = 1 << 20

	// MaxTrackedRateLimitIPs bounds the number of concurrent client IP token buckets retained
	// in memory to prevent spoofed-IP DDoS floods from exhausting heap memory.
	MaxTrackedRateLimitIPs = 10000
)

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

// IPRateLimiter implements a zero-dependency, concurrency-safe per-IP token-bucket rate limiter
// with bounded IP map eviction against volumetric DDoS and credential brute-force floods.
type IPRateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   int
	buckets map[string]*tokenBucket
}

// NewIPRateLimiter constructs a per-IP token-bucket rate limiter.
func NewIPRateLimiter(requestsPerSec float64, burst int) *IPRateLimiter {
	if requestsPerSec <= 0 {
		requestsPerSec = 200
	}
	if burst <= 0 {
		burst = 500
	}
	return &IPRateLimiter{
		rate:    requestsPerSec,
		burst:   burst,
		buckets: make(map[string]*tokenBucket),
	}
}

// Allow evaluates whether a request from clientIP is permitted under the token bucket.
func (rl *IPRateLimiter) Allow(clientIP string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, exists := rl.buckets[clientIP]
	if !exists {
		if len(rl.buckets) >= MaxTrackedRateLimitIPs {
			rl.evictStaleLocked(now)
		}
		rl.buckets[clientIP] = &tokenBucket{
			tokens:     float64(rl.burst - 1),
			lastRefill: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.rate
		if b.tokens > float64(rl.burst) {
			b.tokens = float64(rl.burst)
		}
		b.lastRefill = now
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// TrackedIPCount returns the current number of active IP buckets in memory.
func (rl *IPRateLimiter) TrackedIPCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

func (rl *IPRateLimiter) evictStaleLocked(now time.Time) {
	cutoff := now.Add(-2 * time.Minute)
	for ip, b := range rl.buckets {
		if b.lastRefill.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
	if len(rl.buckets) >= MaxTrackedRateLimitIPs {
		// Evict oldest entries if all entries are recent (spoofed-IP flood)
		evictTarget := MaxTrackedRateLimitIPs / 4
		count := 0
		for ip := range rl.buckets {
			delete(rl.buckets, ip)
			count++
			if count >= evictTarget {
				break
			}
		}
	}
}

func extractClientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if trimmed := strings.TrimSpace(r.RemoteAddr); trimmed != "" {
		return trimmed
	}
	return "unknown"
}

type maxBytesTrackingReader struct {
	rc       io.ReadCloser
	exceeded *bool
}

func (m *maxBytesTrackingReader) Read(p []byte) (int, error) {
	n, err := m.rc.Read(p)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			*m.exceeded = true
		}
	}
	return n, err
}

func (m *maxBytesTrackingReader) Close() error {
	return m.rc.Close()
}

type maxBytesResponseWriter struct {
	http.ResponseWriter
	exceeded *bool
}

func (w *maxBytesResponseWriter) WriteHeader(code int) {
	if *w.exceeded && code == http.StatusBadRequest {
		code = http.StatusRequestEntityTooLarge
	}
	w.ResponseWriter.WriteHeader(code)
}

// securityMiddleware applies defensive HTTP response headers, per-IP token-bucket rate limiting,
// and request body size bounding (http.MaxBytesReader) across all API routes.
func securityMiddleware(env *APIEnv, next http.Handler) http.Handler {
	var limiter *IPRateLimiter
	var burstLimit int
	maxBodyBytes := int64(MaxRequestBodyBytes)

	if env != nil && env.Config != nil {
		if env.Config.Server.MaxRequestBodyBytes > 0 {
			maxBodyBytes = env.Config.Server.MaxRequestBodyBytes
		}
		rlCfg := env.Config.Server.RateLimit
		if rlCfg.Enabled {
			burstLimit = rlCfg.Burst
			if burstLimit <= 0 {
				burstLimit = 2000
			}
			limiter = NewIPRateLimiter(rlCfg.RequestsPerSecond, burstLimit)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Defensive HTTP security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		if r.TLS != nil || (r.URL != nil && strings.EqualFold(r.URL.Scheme, "https")) || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// 2. Per-IP Token-Bucket Rate Limiting (DDoS & Brute-Force Mitigation)
		if limiter != nil {
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(burstLimit))
			clientIP := extractClientIP(r)
			if !limiter.Allow(clientIP) {
				w.Header().Set("Retry-After", "1")
				if env != nil && env.AuditLogger != nil {
					_, _ = env.AuditLogger.Record(audit.AuditEvent{
						Category:  "security",
						Action:    "rate_limit.exceeded",
						ActorType: "ip",
						ActorID:   clientIP,
						SourceIP:  r.RemoteAddr,
						Status:    "denied",
						Summary:   fmt.Sprintf("Rate limit exceeded for client IP %s on %s %s", clientIP, r.Method, r.URL.Path),
					})
				}
				writeJSONError(w, "Rate limit exceeded: too many requests", http.StatusTooManyRequests)
				return
			}
		}

		// 3. Request Body Size Bounding (HTTP 413 Request Entity Too Large against payload DDoS)
		if r.Body != nil && r.Body != http.NoBody {
			if r.ContentLength > maxBodyBytes {
				writeJSONError(w, fmt.Sprintf("Request body too large (exceeds maximum allowed size of %d bytes)", maxBodyBytes), http.StatusRequestEntityTooLarge)
				return
			}
			exceeded := false
			wrappedWriter := &maxBytesResponseWriter{
				ResponseWriter: w,
				exceeded:       &exceeded,
			}
			r.Body = &maxBytesTrackingReader{
				rc:       http.MaxBytesReader(wrappedWriter, r.Body, maxBodyBytes),
				exceeded: &exceeded,
			}
			next.ServeHTTP(wrappedWriter, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}
