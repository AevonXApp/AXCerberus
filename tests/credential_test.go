package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"axcerberus/internal/credential"
)

func TestCredentialNormalGETPassthrough(t *testing.T) {
	det := credential.New([]string{"/login"}, 5, 5)
	defer det.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	// GET requests should always pass
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET should pass through, got %d", rec.Code)
	}
}

func TestCredentialNonLoginPath(t *testing.T) {
	det := credential.New([]string{"/login"}, 5, 5)
	defer det.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	// POST to non-login path should pass
	req := httptest.NewRequest("POST", "/api/data", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("non-login POST should pass, got %d", rec.Code)
	}
}

func TestCredentialBruteForceBlock(t *testing.T) {
	det := credential.New([]string{"/login"}, 3, 3)
	defer det.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mw := det.Middleware(handler)

	// 3 attempts should pass
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/login", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d should pass", i+1)
		}
	}

	// 4th attempt should be blocked
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th attempt should be blocked, got %d", rec.Code)
	}
}

func TestCredentialOnBlockCallback(t *testing.T) {
	ch := make(chan [2]string, 1)

	det := credential.New([]string{"/login"}, 2, 2)
	defer det.Stop()
	det.OnBlock = func(ip string, reason string) {
		ch <- [2]string{ip, reason}
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/login", nil)
		req.RemoteAddr = "10.0.0.9:1234"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
	}

	select {
	case result := <-ch:
		if result[0] != "10.0.0.9" {
			t.Fatalf("expected blocked IP 10.0.0.9, got %q", result[0])
		}
		if result[1] != "credential_stuffing" {
			t.Fatalf("expected reason credential_stuffing, got %q", result[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnBlock callback was not called within timeout")
	}
}

func TestCredentialGetStats(t *testing.T) {
	det := credential.New([]string{"/login"}, 100, 100)
	defer det.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		mw.ServeHTTP(httptest.NewRecorder(), req)
	}

	stats := det.GetStats()
	if stats.TotalAttempts != 5 {
		t.Fatalf("expected 5 total attempts, got %d", stats.TotalAttempts)
	}
	if stats.ActiveTrackedIPs != 1 {
		t.Fatalf("expected 1 tracked IP, got %d", stats.ActiveTrackedIPs)
	}
}

func TestCredentialMultipleLoginPaths(t *testing.T) {
	det := credential.New([]string{"/login", "/signin", "/wp-login.php"}, 2, 2)
	defer det.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	// Test different login paths
	paths := []string{"/login", "/signin", "/wp-login.php"}
	for _, p := range paths {
		req := httptest.NewRequest("POST", p, nil)
		req.RemoteAddr = "10.0.0.20:1234"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
	}

	stats := det.GetStats()
	if stats.TotalAttempts != 3 {
		t.Fatalf("expected 3 attempts across paths, got %d", stats.TotalAttempts)
	}
}

func TestCredentialBlockedIPStaysBlocked(t *testing.T) {
	det := credential.New([]string{"/login"}, 1, 1)
	defer det.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := det.Middleware(handler)

	// First request passes, second blocks
	req1 := httptest.NewRequest("POST", "/login", nil)
	req1.RemoteAddr = "10.0.0.30:1234"
	mw.ServeHTTP(httptest.NewRecorder(), req1)

	req2 := httptest.NewRequest("POST", "/login", nil)
	req2.RemoteAddr = "10.0.0.30:1234"
	rec2 := httptest.NewRecorder()
	mw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("should be blocked after exceeding limit, got %d", rec2.Code)
	}

	// Subsequent requests should also be blocked (IP is blocked)
	req3 := httptest.NewRequest("POST", "/login", nil)
	req3.RemoteAddr = "10.0.0.30:1234"
	rec3 := httptest.NewRecorder()
	mw.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked IP should stay blocked, got %d", rec3.Code)
	}
}
