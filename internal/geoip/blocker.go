package geoip

import (
	"net"
	"net/http"
	"strings"
)

// Blocker is a middleware that blocks or allows requests based on country.
type Blocker struct {
	db        *DB
	mode      string   // "blocklist" or "allowlist"
	countries []string // ISO country codes
}

// NewBlocker creates a GeoIP country blocker.
//   - mode "blocklist": block requests from listed countries
//   - mode "allowlist": only allow requests from listed countries
func NewBlocker(db *DB, mode string, countries []string) *Blocker {
	upper := make([]string, len(countries))
	for i, c := range countries {
		upper[i] = strings.ToUpper(strings.TrimSpace(c))
	}
	return &Blocker{db: db, mode: mode, countries: upper}
}

// Middleware returns an http middleware that enforces country blocking.
func (b *Blocker) Middleware(next http.Handler) http.Handler {
	if b == nil || b.db == nil || len(b.countries) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteHost(r)
		result := b.db.Lookup(ip)
		code := strings.ToUpper(result.CountryCode)

		switch b.mode {
		case "allowlist":
			if !b.contains(code) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		default: // blocklist
			if b.contains(code) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (b *Blocker) contains(code string) bool {
	for _, c := range b.countries {
		if c == code {
			return true
		}
	}
	return false
}

// SetCountries replaces the country list at runtime.
func (b *Blocker) SetCountries(countries []string) {
	upper := make([]string, len(countries))
	for i, c := range countries {
		upper[i] = strings.ToUpper(strings.TrimSpace(c))
	}
	b.countries = upper
}

// GetCountries returns the current country list.
func (b *Blocker) GetCountries() []string {
	return b.countries
}

func remoteHost(r *http.Request) string {
	// Check X-Forwarded-For first
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
