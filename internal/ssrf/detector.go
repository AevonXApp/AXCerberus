// Package ssrf provides Server-Side Request Forgery prevention.
package ssrf

import (
	"net"
	"net/http"
	"regexp"
	"strings"
)

// Detector inspects requests for SSRF attack indicators.
type Detector struct {
	enabled bool
}

// New creates an SSRF detector.
func New(enabled bool) *Detector {
	return &Detector{enabled: enabled}
}

// Middleware returns an HTTP middleware that blocks SSRF attempts.
func (d *Detector) Middleware(next http.Handler) http.Handler {
	if !d.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check URL parameters for SSRF indicators
		query := r.URL.RawQuery
		if d.hasSuspiciousURL(query) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Check common parameter names in query string
		for _, val := range r.URL.Query() {
			for _, v := range val {
				if d.isSuspiciousValue(v) {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// hasSuspiciousURL checks the raw query for dangerous URL schemes.
func (d *Detector) hasSuspiciousURL(query string) bool {
	lower := strings.ToLower(query)
	dangerousSchemes := []string{
		"file://", "gopher://", "dict://", "ftp://",
		"ldap://", "tftp://", "jar://",
	}
	for _, scheme := range dangerousSchemes {
		if strings.Contains(lower, scheme) {
			return true
		}
	}
	return false
}

// isSuspiciousValue checks a parameter value for SSRF indicators.
func (d *Detector) isSuspiciousValue(value string) bool {
	lower := strings.ToLower(value)

	// Cloud metadata endpoints
	metadataTargets := []string{
		"169.254.169.254",
		"metadata.google.internal",
		"metadata.google.com",
		"100.100.100.200", // Alibaba Cloud
	}
	for _, target := range metadataTargets {
		if strings.Contains(lower, target) {
			return true
		}
	}

	// Internal IP addresses
	if containsInternalIP(value) {
		return true
	}

	// Dangerous URL schemes in values
	dangerousSchemes := []string{
		"file://", "gopher://", "dict://",
	}
	for _, scheme := range dangerousSchemes {
		if strings.Contains(lower, scheme) {
			return true
		}
	}

	return false
}

// IsSuspicious exports the check for testing.
func (d *Detector) IsSuspicious(value string) bool {
	return d.isSuspiciousValue(value)
}

var internalIPRegex = regexp.MustCompile(
	`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)\b`,
)

// containsInternalIP checks if a string contains private/loopback IPs.
func containsInternalIP(s string) bool {
	matches := internalIPRegex.FindAllString(s, -1)
	for _, m := range matches {
		ip := net.ParseIP(m)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

// IsInternalIP exports the IP check for testing.
func IsInternalIP(s string) bool {
	return containsInternalIP(s)
}
