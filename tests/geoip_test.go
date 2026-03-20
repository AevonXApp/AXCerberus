package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"axcerberus/internal/geoip"
)

func TestGeoIPBlockerNilSafe(t *testing.T) {
	// Nil blocker should pass through
	var b *geoip.Blocker
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := b.Middleware(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("nil blocker should pass, got %d", rec.Code)
	}
}

func TestGeoIPBlockerNoCountries(t *testing.T) {
	// Empty country list should pass everything
	b := geoip.NewBlocker(nil, "blocklist", []string{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := b.Middleware(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty countries should pass, got %d", rec.Code)
	}
}

func TestGeoIPBlockerSetCountries(t *testing.T) {
	b := geoip.NewBlocker(nil, "blocklist", []string{"CN"})
	if countries := b.GetCountries(); len(countries) != 1 || countries[0] != "CN" {
		t.Fatalf("expected [CN], got %v", countries)
	}

	b.SetCountries([]string{"ru", "ir"})
	countries := b.GetCountries()
	if len(countries) != 2 {
		t.Fatalf("expected 2 countries, got %d", len(countries))
	}
	if countries[0] != "RU" || countries[1] != "IR" {
		t.Fatalf("expected [RU IR], got %v", countries)
	}
}

// TestGeoIPLookupNoDatabase tests that Lookup handles missing DB gracefully.
// Full GeoIP tests require a real MaxMind .mmdb file, which isn't included in tests.
// These tests verify the blocker middleware logic with mock scenarios.

func TestGeoIPBlockerModeUppercase(t *testing.T) {
	b := geoip.NewBlocker(nil, "blocklist", []string{"cn", " ru "})
	countries := b.GetCountries()
	for _, c := range countries {
		if c != "CN" && c != "RU" {
			t.Fatalf("countries should be uppercased, got %s", c)
		}
	}
}
