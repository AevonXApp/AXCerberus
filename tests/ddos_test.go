package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"axcerberus/internal/ddos"
)

func TestDDoSShieldBasic(t *testing.T) {
	// Disabled shield should pass everything
	shield := ddos.New(false, false, 3.0, 100)
	defer shield.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := shield.Middleware(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled shield should pass, got %d", rec.Code)
	}
}

func TestDDoSShieldEnabled(t *testing.T) {
	shield := ddos.New(true, false, 3.0, 100)
	defer shield.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := shield.Middleware(handler)

	// Normal request should pass (no attack detected)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("normal request should pass, got %d", rec.Code)
	}
}

func TestDDoSShieldConnLimit(t *testing.T) {
	shield := ddos.New(true, false, 3.0, 2) // max 2 conns per IP
	defer shield.Stop()

	insideHandler := make(chan struct{}, 2)
	blockCh := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		insideHandler <- struct{}{} // signal we entered
		<-blockCh                   // block until released
		w.WriteHeader(http.StatusOK)
	})
	mw := shield.Middleware(handler)

	// Start 2 concurrent requests (will block in handler)
	done := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "10.0.0.5:1234"
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			done <- rec.Code
		}()
	}

	// Wait for both goroutines to be inside the handler
	<-insideHandler
	<-insideHandler

	// 3rd concurrent connection should be rejected
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd concurrent conn should be rejected, got %d", rec.Code)
	}

	// Release blocked handlers
	close(blockCh)
	<-done
	<-done
}

func TestDDoSShieldSetLevel(t *testing.T) {
	shield := ddos.New(true, false, 3.0, 100)
	defer shield.Stop()

	if shield.GetLevel() != ddos.LevelNone {
		t.Fatalf("initial level should be None, got %d", shield.GetLevel())
	}

	shield.SetLevel(ddos.LevelHigh)
	if shield.GetLevel() != ddos.LevelHigh {
		t.Fatalf("expected LevelHigh, got %d", shield.GetLevel())
	}

	// With LevelHigh, requests should be blocked
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := shield.Middleware(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("LevelHigh should block requests, got %d", rec.Code)
	}

	// De-escalate
	shield.SetLevel(ddos.LevelNone)
	rec2 := httptest.NewRecorder()
	mw.ServeHTTP(rec2, httptest.NewRequest("GET", "/", nil))
	// After clearing, RemoteAddr may need setting
}

func TestDDoSShieldStatus(t *testing.T) {
	shield := ddos.New(true, true, 3.0, 100)
	defer shield.Stop()

	status := shield.GetStatus()
	if status.UnderAttack {
		t.Fatal("should not be under attack initially")
	}
	if status.Level != ddos.LevelNone {
		t.Fatalf("initial level should be None, got %d", status.Level)
	}

	shield.SetLevel(ddos.LevelMedium)
	status2 := shield.GetStatus()
	if !status2.UnderAttack {
		t.Fatal("should be under attack after SetLevel")
	}
	if status2.Since == nil {
		t.Fatal("attack since should be set")
	}
}

func TestDDoSShieldActiveConnections(t *testing.T) {
	shield := ddos.New(true, false, 3.0, 100)
	defer shield.Stop()

	conns := shield.ActiveConnections()
	if len(conns) != 0 {
		t.Fatalf("expected 0 active connections, got %d", len(conns))
	}
}
