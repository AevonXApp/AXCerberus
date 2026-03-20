package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"axcerberus/internal/ssrf"
)

func TestSSRFCleanRequest(t *testing.T) {
	det := ssrf.New(true)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	req := httptest.NewRequest("GET", "/api/data?url=https://example.com", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clean request should pass, got %d", rec.Code)
	}
}

func TestSSRFDisabled(t *testing.T) {
	det := ssrf.New(false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	req := httptest.NewRequest("GET", "/api?url=file:///etc/passwd", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled SSRF should pass, got %d", rec.Code)
	}
}

func TestSSRFFileScheme(t *testing.T) {
	det := ssrf.New(true)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	req := httptest.NewRequest("GET", "/api?url=file:///etc/passwd", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("file:// scheme should be blocked, got %d", rec.Code)
	}
}

func TestSSRFGopherScheme(t *testing.T) {
	det := ssrf.New(true)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	req := httptest.NewRequest("GET", "/fetch?target=gopher://evil.com/xHELO", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("gopher:// scheme should be blocked, got %d", rec.Code)
	}
}

func TestSSRFMetadataEndpoint(t *testing.T) {
	det := ssrf.New(true)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	req := httptest.NewRequest("GET", "/proxy?url=http://169.254.169.254/latest/meta-data/", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("metadata endpoint should be blocked, got %d", rec.Code)
	}
}

func TestSSRFInternalIP(t *testing.T) {
	det := ssrf.New(true)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	tests := []struct {
		name string
		url  string
	}{
		{"10.x", "/proxy?url=http://10.0.0.1/admin"},
		{"172.16.x", "/proxy?url=http://172.16.0.1/admin"},
		{"192.168.x", "/proxy?url=http://192.168.1.1/admin"},
		{"127.x", "/proxy?url=http://127.0.0.1:8080/internal"},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", tc.url, nil)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: internal IP should be blocked, got %d", tc.name, rec.Code)
		}
	}
}

func TestSSRFIsSuspicious(t *testing.T) {
	det := ssrf.New(true)

	tests := []struct {
		value    string
		expected bool
	}{
		{"https://example.com/page", false},
		{"http://169.254.169.254/meta", true},
		{"file:///etc/shadow", true},
		{"http://10.0.0.1/internal", true},
		{"http://192.168.1.1/admin", true},
		{"http://metadata.google.internal/v1", true},
		{"gopher://evil.com", true},
		{"dict://attacker.com/info", true},
		{"http://google.com", false},
	}

	for _, tc := range tests {
		if got := det.IsSuspicious(tc.value); got != tc.expected {
			t.Errorf("IsSuspicious(%q) = %v, want %v", tc.value, got, tc.expected)
		}
	}
}

func TestSSRFIsInternalIP(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"0.0.0.0", true},
	}

	for _, tc := range tests {
		if got := ssrf.IsInternalIP(tc.input); got != tc.expected {
			t.Errorf("IsInternalIP(%q) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}

func TestSSRFGoogleMetadata(t *testing.T) {
	det := ssrf.New(true)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	req := httptest.NewRequest("GET", "/fetch?host=metadata.google.internal", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("google metadata should be blocked, got %d", rec.Code)
	}
}
