package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"axcerberus/internal/ratelimit"
)

func TestRateLimiterBasic(t *testing.T) {
	lim := ratelimit.New(5, 3, 10, false, []string{"/login"})
	defer lim.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := lim.Middleware(handler)

	// 5 requests should pass
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/page", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d should pass, got %d", i+1, rec.Code)
		}
	}

	// 6th should be blocked
	req := httptest.NewRequest("GET", "/page", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th request should be blocked, got %d", rec.Code)
	}
}

func TestRateLimiterLoginEndpoint(t *testing.T) {
	lim := ratelimit.New(100, 3, 100, false, []string{"/login", "/signin"})
	defer lim.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := lim.Middleware(handler)

	// Login endpoint has limit of 3
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/login", nil)
		req.RemoteAddr = "10.0.0.2:1234"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("login request %d should pass, got %d", i+1, rec.Code)
		}
	}

	// 4th login should be blocked
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th login should be blocked, got %d", rec.Code)
	}
}

func TestRateLimiterAPIEndpoint(t *testing.T) {
	lim := ratelimit.New(100, 100, 2, false, nil)
	defer lim.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := lim.Middleware(handler)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/api/data", nil)
		req.RemoteAddr = "10.0.0.3:1234"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("api request %d should pass, got %d", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.RemoteAddr = "10.0.0.3:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd api request should be blocked, got %d", rec.Code)
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	lim := ratelimit.New(2, 2, 2, false, nil)
	defer lim.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := lim.Middleware(handler)

	// IP1: 2 requests
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.1.1.1:1234"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ip1 request %d should pass", i+1)
		}
	}

	// IP2 should still be allowed
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "2.2.2.2:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal("different IP should not be affected")
	}
}

func TestRateLimiterThrottleMode(t *testing.T) {
	lim := ratelimit.New(1, 1, 1, true, nil) // throttle=true
	defer lim.Stop()

	called := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	mw := lim.Middleware(handler)

	// First request
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "3.3.3.3:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	// Second request in throttle mode should still go through (with delay)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "3.3.3.3:1234"
	rec2 := httptest.NewRecorder()
	mw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("throttle mode should pass through, got %d", rec2.Code)
	}
	if called != 2 {
		t.Fatalf("handler should be called twice in throttle mode, got %d", called)
	}
}

func TestRateLimiterCount(t *testing.T) {
	lim := ratelimit.New(100, 100, 100, false, nil)
	defer lim.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := lim.Middleware(handler)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/page", nil)
		req.RemoteAddr = "4.4.4.4:1234"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
	}

	count := lim.Count("4.4.4.4", "/page")
	if count != 5 {
		t.Fatalf("expected count 5, got %d", count)
	}
}

func TestRateLimiterXForwardedFor(t *testing.T) {
	lim := ratelimit.New(2, 2, 2, false, nil)
	defer lim.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := lim.Middleware(handler)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "5.5.5.5")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
	}

	// 3rd from same forwarded IP should be blocked
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "5.5.5.5")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request from same XFF IP should be blocked, got %d", rec.Code)
	}
}
