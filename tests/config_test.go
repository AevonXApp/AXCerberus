package tests

import (
	"os"
	"path/filepath"
	"testing"

	"axcerberus/internal/config"
)

func TestDefaultConfig(t *testing.T) {
	cfg := config.Default()
	if cfg.Listen != ":80" {
		t.Fatalf("expected listen :80, got %s", cfg.Listen)
	}
	if cfg.Upstream != "http://127.0.0.1:8181" {
		t.Fatalf("expected upstream http://127.0.0.1:8181, got %s", cfg.Upstream)
	}
	if !cfg.WAFEnabled {
		t.Fatal("WAF should be enabled by default")
	}
	if !cfg.RateLimitEnabled {
		t.Fatal("rate limiting should be enabled by default")
	}
	if cfg.GlobalRateLimit != 300 {
		t.Fatalf("expected global rate limit 300, got %d", cfg.GlobalRateLimit)
	}
	if cfg.DLPMode != "log" {
		t.Fatalf("expected DLP mode log, got %s", cfg.DLPMode)
	}
}

func TestValidateOK(t *testing.T) {
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestValidateEmptyListen(t *testing.T) {
	cfg := config.Default()
	cfg.Listen = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for empty listen")
	}
}

func TestValidateEmptyUpstream(t *testing.T) {
	cfg := config.Default()
	cfg.Upstream = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for empty upstream")
	}
}

func TestValidateBadTimeout(t *testing.T) {
	cfg := config.Default()
	cfg.ReadTimeoutSecs = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero read timeout")
	}
}

func TestValidateBadDLPMode(t *testing.T) {
	cfg := config.Default()
	cfg.DLPMode = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid DLP mode")
	}
}

func TestValidateBadGeoBlockMode(t *testing.T) {
	cfg := config.Default()
	cfg.GeoBlockMode = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid geo block mode")
	}
}

func TestLoadFlatConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.avx")
	data := `{"listen":":8080","upstream":"http://localhost:3000","waf_enabled":false,"global_rate_limit":500}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" {
		t.Fatalf("expected :8080, got %s", cfg.Listen)
	}
	if cfg.Upstream != "http://localhost:3000" {
		t.Fatalf("expected http://localhost:3000, got %s", cfg.Upstream)
	}
	if cfg.WAFEnabled {
		t.Fatal("WAF should be disabled")
	}
	if cfg.GlobalRateLimit != 500 {
		t.Fatalf("expected 500, got %d", cfg.GlobalRateLimit)
	}
}

func TestLoadSchemaConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.avx")
	data := `{
		"config_schema": [
			{
				"section": "network",
				"fields": [
					{"key": "listen", "value": ":9090"},
					{"key": "upstream", "value": "http://app:8080"}
				]
			},
			{
				"section": "waf",
				"fields": [
					{"key": "waf_enabled", "value": true}
				]
			}
		]
	}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9090" {
		t.Fatalf("expected :9090, got %s", cfg.Listen)
	}
	if cfg.Upstream != "http://app:8080" {
		t.Fatalf("expected http://app:8080, got %s", cfg.Upstream)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/config.avx")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.avx")
	if err := os.WriteFile(path, []byte(`{invalid`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSplitHelpers(t *testing.T) {
	cfg := config.Default()

	paths := cfg.SplitLoginPaths()
	if len(paths) == 0 {
		t.Fatal("expected non-empty login paths")
	}
	if paths[0] != "/login" {
		t.Fatalf("expected first login path /login, got %s", paths[0])
	}

	hp := cfg.SplitHoneypotPaths()
	if len(hp) == 0 {
		t.Fatal("expected non-empty honeypot paths")
	}

	// Empty geo block countries
	cfg.GeoBlockCountries = ""
	if gbc := cfg.SplitGeoBlockCountries(); gbc != nil {
		t.Fatalf("expected nil for empty geo block countries, got %v", gbc)
	}

	cfg.GeoBlockCountries = "CN, RU, IR"
	gbc := cfg.SplitGeoBlockCountries()
	if len(gbc) != 3 {
		t.Fatalf("expected 3 countries, got %d", len(gbc))
	}
	if gbc[0] != "CN" || gbc[1] != "RU" || gbc[2] != "IR" {
		t.Fatalf("unexpected countries: %v", gbc)
	}
}
