package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"axcerberus/internal/proxy"
)

func TestIPGuardAllowAndRelease(t *testing.T) {
	g := proxy.NewIPGuard(2, 300, false)

	ip, _, blocked, _ := g.Allow("10.0.0.1")
	if blocked {
		t.Fatal("first request should not be blocked")
	}
	if ip != "10.0.0.1" {
		t.Fatalf("expected IP 10.0.0.1, got %s", ip)
	}

	ip2, _, blocked2, _ := g.Allow("10.0.0.1")
	if blocked2 {
		t.Fatal("second request should not be blocked")
	}
	_ = ip2

	// Third should be blocked (max 2 concurrent)
	_, _, blocked3, _ := g.Allow("10.0.0.1")
	if !blocked3 {
		t.Fatal("third concurrent request should be blocked")
	}

	// After exceeding concurrency, IP gets a timed block.
	// Remove the block, release slots, then retry.
	g.RemoveBlock("10.0.0.1")
	g.Release("10.0.0.1")
	g.Release("10.0.0.1")

	_, _, blocked4, _ := g.Allow("10.0.0.1")
	if blocked4 {
		t.Fatal("after release + unblock, request should be allowed")
	}
}

func TestIPGuardBlocklist(t *testing.T) {
	dir := t.TempDir()
	blockFile := filepath.Join(dir, "blocklist.avx")
	os.WriteFile(blockFile, []byte("1.2.3.4\n# comment\n10.0.0.0/8\n"), 0o644)

	g := proxy.NewIPGuard(50, 300, false)
	if err := g.LoadBlocklist(blockFile); err != nil {
		t.Fatal(err)
	}

	_, _, blocked, _ := g.Allow("1.2.3.4")
	if !blocked {
		t.Fatal("blocklisted IP should be blocked")
	}

	_, _, blocked2, _ := g.Allow("10.5.5.5")
	if !blocked2 {
		t.Fatal("IP in blocklisted CIDR should be blocked")
	}

	_, _, blocked3, _ := g.Allow("8.8.8.8")
	if blocked3 {
		t.Fatal("non-blocklisted IP should not be blocked")
	}
}

func TestIPGuardAllowlist(t *testing.T) {
	dir := t.TempDir()
	allowFile := filepath.Join(dir, "allowlist.avx")
	os.WriteFile(allowFile, []byte("5.5.5.5\n"), 0o644)

	g := proxy.NewIPGuard(1, 300, false)
	if err := g.LoadAllowlist(allowFile); err != nil {
		t.Fatal(err)
	}

	// Allowlisted IP bypasses concurrency limit
	for i := 0; i < 10; i++ {
		_, _, blocked, _ := g.Allow("5.5.5.5")
		if blocked {
			t.Fatalf("allowlisted IP should never be blocked (iteration %d)", i)
		}
	}
}

func TestIPGuardEscalation(t *testing.T) {
	g := proxy.NewIPGuard(1, 300, true) // escalation enabled

	// First request OK
	ip, _, _, _ := g.Allow("9.9.9.9")
	if ip == "" {
		t.Fatal("first request should be allowed")
	}

	// Second concurrent → blocked (offense 1: 5 min)
	_, _, blocked, retryAfter := g.Allow("9.9.9.9")
	if !blocked {
		t.Fatal("should be blocked on concurrency exceeded")
	}
	if retryAfter.IsZero() {
		t.Fatal("should have retryAfter for first offense")
	}
	// Verify ~5 min block
	expectedDur := 5 * time.Minute
	actualDur := time.Until(retryAfter)
	if actualDur < expectedDur-2*time.Second || actualDur > expectedDur+2*time.Second {
		t.Fatalf("expected ~5min block, got %v", actualDur)
	}
}

func TestIPGuardManualBlock(t *testing.T) {
	g := proxy.NewIPGuard(50, 300, false)
	g.AddBlock("6.6.6.6", 3600, "test")

	_, _, blocked, _ := g.Allow("6.6.6.6")
	if !blocked {
		t.Fatal("manually blocked IP should be blocked")
	}

	g.RemoveBlock("6.6.6.6")
	_, _, blocked2, _ := g.Allow("6.6.6.6")
	if blocked2 {
		t.Fatal("unblocked IP should not be blocked")
	}
}

func TestIPGuardPermanentBlock(t *testing.T) {
	g := proxy.NewIPGuard(50, 300, false)
	g.AddBlock("7.7.7.7", -1, "permanent")

	_, _, blocked, _ := g.Allow("7.7.7.7")
	if !blocked {
		t.Fatal("permanently blocked IP should be blocked")
	}
}

func TestIPGuardGetBlockedIPs(t *testing.T) {
	g := proxy.NewIPGuard(50, 300, false)
	g.AddBlock("1.1.1.1", 3600, "test")
	g.AddBlock("2.2.2.2", -1, "perm")

	blocked := g.GetBlockedIPs()
	if len(blocked) < 2 {
		t.Fatalf("expected at least 2 blocked IPs, got %d", len(blocked))
	}
}

func TestIPGuardMissingFile(t *testing.T) {
	g := proxy.NewIPGuard(50, 300, false)
	// Non-existent files should not error (treated as empty)
	if err := g.LoadAllowlist("/nonexistent/file"); err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if err := g.LoadBlocklist("/nonexistent/file"); err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
}
