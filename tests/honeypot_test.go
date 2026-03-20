package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axcerberus/internal/honeypot"
)

func TestHoneypotTrapDetection(t *testing.T) {
	eng := honeypot.New([]string{"/wp-admin", "/.env", "/phpmyadmin"}, false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := eng.Middleware(handler)

	// Normal path should pass through
	req := httptest.NewRequest("GET", "/index.html", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("normal path should pass, got %d", rec.Code)
	}

	// Trap path should be intercepted
	req2 := httptest.NewRequest("GET", "/wp-admin", nil)
	req2.RemoteAddr = "10.0.0.2:1234"
	rec2 := httptest.NewRecorder()
	mw.ServeHTTP(rec2, req2)
	// Should get a fake page, not the upstream
	body := rec2.Body.String()
	if rec2.Code == http.StatusOK && body == "" {
		t.Fatal("trap should serve fake content")
	}
}

func TestHoneypotAutoBlock(t *testing.T) {
	blocked := make(map[string]bool)
	eng := honeypot.New([]string{"/wp-admin"}, true)
	eng.OnBlock = func(ip string) {
		blocked[ip] = true
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := eng.Middleware(handler)

	req := httptest.NewRequest("GET", "/wp-admin", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if !blocked["10.0.0.5"] {
		t.Fatal("IP should be auto-blocked")
	}
}

func TestHoneypotHitRecording(t *testing.T) {
	eng := honeypot.New([]string{"/.env"}, false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := eng.Middleware(handler)

	req := httptest.NewRequest("GET", "/.env", nil)
	req.RemoteAddr = "10.0.0.3:1234"
	req.Header.Set("User-Agent", "evil-scanner/1.0")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	hits := eng.GetHits(10)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if hits[0].IP != "10.0.0.3" {
		t.Fatalf("expected IP 10.0.0.3, got %s", hits[0].IP)
	}
	if hits[0].Path != "/.env" {
		t.Fatalf("expected path /.env, got %s", hits[0].Path)
	}
}

func TestHoneypotTotalHits(t *testing.T) {
	eng := honeypot.New([]string{"/wp-login.php"}, false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := eng.Middleware(handler)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/wp-login.php", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		mw.ServeHTTP(httptest.NewRecorder(), req)
	}

	if eng.TotalHits() != 5 {
		t.Fatalf("expected 5 total hits, got %d", eng.TotalHits())
	}
}

func TestHoneypotAddTrap(t *testing.T) {
	eng := honeypot.New([]string{"/wp-admin"}, false)
	eng.AddTrap("/secret-trap")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream"))
	})
	mw := eng.Middleware(handler)

	req := httptest.NewRequest("GET", "/secret-trap", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "upstream") {
		t.Fatal("trap path should not reach upstream")
	}
}

func TestHoneypotFakePages(t *testing.T) {
	eng := honeypot.New([]string{"/wp-admin", "/.env", "/.git/config", "/phpmyadmin"}, false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := eng.Middleware(handler)

	paths := []string{"/wp-admin", "/.env", "/.git/config", "/phpmyadmin"}
	for _, p := range paths {
		req := httptest.NewRequest("GET", p, nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)

		if rec.Body.Len() == 0 {
			t.Fatalf("expected fake page for %s, got empty body", p)
		}
	}
}

func TestHoneypotPrefixMatch(t *testing.T) {
	eng := honeypot.New([]string{"/wp-admin"}, false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream"))
	})
	mw := eng.Middleware(handler)

	// /wp-admin/setup-config.php should also match
	req := httptest.NewRequest("GET", "/wp-admin/setup-config.php", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "upstream") {
		t.Fatal("/wp-admin/ subpath should also be a trap")
	}
}

func TestHoneypotGetBlockedIPs(t *testing.T) {
	eng := honeypot.New([]string{"/wp-admin"}, true)
	eng.OnBlock = func(ip string) {}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := eng.Middleware(handler)

	req := httptest.NewRequest("GET", "/wp-admin", nil)
	req.RemoteAddr = "10.0.0.99:1234"
	mw.ServeHTTP(httptest.NewRecorder(), req)

	blocked := eng.GetBlockedIPs()
	if _, ok := blocked["10.0.0.99"]; !ok {
		t.Fatal("10.0.0.99 should be in blocked IPs")
	}
}
