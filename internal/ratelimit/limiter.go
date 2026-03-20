// Package ratelimit provides a sliding-window adaptive rate limiter.
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter implements per-IP per-endpoint sliding window rate limiting.
type Limiter struct {
	mu       sync.Mutex
	windows  map[string]*window // key: "ip:endpoint_class"
	global   int                // req/min global
	login    int                // req/min login endpoints
	api      int                // req/min API endpoints
	throttle bool               // progressive delay instead of block
	loginPaths []string
	stopCh   chan struct{}
}

type window struct {
	timestamps []time.Time
	lastAccess time.Time
}

// New creates a rate limiter.
func New(globalLimit, loginLimit, apiLimit int, throttle bool, loginPaths []string) *Limiter {
	l := &Limiter{
		windows:    make(map[string]*window),
		global:     globalLimit,
		login:      loginLimit,
		api:        apiLimit,
		throttle:   throttle,
		loginPaths: loginPaths,
		stopCh:     make(chan struct{}),
	}
	go l.cleanup()
	return l
}

// Middleware returns an HTTP middleware that enforces rate limits.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		class := l.classifyEndpoint(r.URL.Path)
		limit := l.limitForClass(class)

		key := ip + ":" + class
		if !l.allow(key, limit) {
			if l.throttle {
				// Progressive delay: sleep proportional to overage
				time.Sleep(500 * time.Millisecond)
				// Still allow through but delayed
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow checks if a request under the given key is within its rate limit.
func (l *Limiter) allow(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	w, ok := l.windows[key]
	if !ok {
		w = &window{}
		l.windows[key] = w
	}

	// Slide the window: remove entries older than 1 minute
	valid := w.timestamps[:0]
	for _, ts := range w.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	w.timestamps = valid

	if len(w.timestamps) >= limit {
		return false
	}

	w.timestamps = append(w.timestamps, now)
	w.lastAccess = now
	return true
}

// Count returns the current request count in the window for a key.
func (l *Limiter) Count(ip, path string) int {
	class := l.classifyEndpoint(path)
	key := ip + ":" + class

	l.mu.Lock()
	defer l.mu.Unlock()

	w, ok := l.windows[key]
	if !ok {
		return 0
	}

	cutoff := time.Now().Add(-1 * time.Minute)
	count := 0
	for _, ts := range w.timestamps {
		if ts.After(cutoff) {
			count++
		}
	}
	return count
}

func (l *Limiter) classifyEndpoint(path string) string {
	lower := strings.ToLower(path)
	for _, lp := range l.loginPaths {
		if strings.HasPrefix(lower, strings.ToLower(lp)) {
			return "login"
		}
	}
	if strings.HasPrefix(lower, "/api/") || strings.HasPrefix(lower, "/api.") {
		return "api"
	}
	return "global"
}

func (l *Limiter) limitForClass(class string) int {
	switch class {
	case "login":
		return l.login
	case "api":
		return l.api
	default:
		return l.global
	}
}

// cleanup removes expired windows every 5 minutes.
func (l *Limiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-2 * time.Minute)
			for key, w := range l.windows {
				if w.lastAccess.Before(cutoff) {
					delete(l.windows, key)
				}
			}
			l.mu.Unlock()
		case <-l.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine.
func (l *Limiter) Stop() {
	close(l.stopCh)
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
