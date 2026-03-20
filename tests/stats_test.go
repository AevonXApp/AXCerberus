package tests

import (
	"testing"

	"axcerberus/internal/stats"
)

func TestStatsRecordRequest(t *testing.T) {
	eng := stats.New()

	eng.RecordRequest("example.com", false, 200, 100, 500)
	eng.RecordRequest("example.com", true, 403, 50, 0)
	eng.RecordRequest("other.com", false, 200, 200, 1000)

	ov := eng.GetOverview()
	if ov.TotalRequests != 3 {
		t.Fatalf("expected 3 total, got %d", ov.TotalRequests)
	}
	if ov.BlockedRequests != 1 {
		t.Fatalf("expected 1 blocked, got %d", ov.BlockedRequests)
	}
	if ov.AllowedRequests != 2 {
		t.Fatalf("expected 2 allowed, got %d", ov.AllowedRequests)
	}
	if ov.BytesIn != 350 {
		t.Fatalf("expected 350 bytes in, got %d", ov.BytesIn)
	}
	if ov.BytesOut != 1500 {
		t.Fatalf("expected 1500 bytes out, got %d", ov.BytesOut)
	}
}

func TestStatsProtectionRate(t *testing.T) {
	eng := stats.New()

	eng.RecordRequest("host", true, 403, 0, 0)
	eng.RecordRequest("host", true, 403, 0, 0)
	eng.RecordRequest("host", false, 200, 0, 0)
	eng.RecordRequest("host", false, 200, 0, 0)

	ov := eng.GetOverview()
	if ov.ProtectionRate != 50.0 {
		t.Fatalf("expected 50%% protection rate, got %.1f%%", ov.ProtectionRate)
	}
}

func TestStatsRecordAttack(t *testing.T) {
	eng := stats.New()

	eng.RecordAttack("1.2.3.4", "China", "CN", "SQL Injection", "/login")
	eng.RecordAttack("1.2.3.4", "China", "CN", "SQL Injection", "/admin")
	eng.RecordAttack("5.6.7.8", "Russia", "RU", "XSS", "/search")

	types := eng.GetAttackTypes()
	if len(types) != 2 {
		t.Fatalf("expected 2 attack types, got %d", len(types))
	}

	countries := eng.GetCountries()
	if len(countries) != 2 {
		t.Fatalf("expected 2 countries, got %d", len(countries))
	}

	attackers := eng.GetTopAttackers(10)
	if len(attackers) != 2 {
		t.Fatalf("expected 2 attackers, got %d", len(attackers))
	}
	// First should be the one with more attacks
	if attackers[0].Attacks != 2 {
		t.Fatalf("top attacker should have 2 attacks, got %d", attackers[0].Attacks)
	}

	uris := eng.GetTopURIs(10)
	if len(uris) != 3 {
		t.Fatalf("expected 3 URIs, got %d", len(uris))
	}
}

func TestStatsDomains(t *testing.T) {
	eng := stats.New()

	eng.RecordRequest("a.com", false, 200, 100, 200)
	eng.RecordRequest("a.com", true, 403, 50, 0)
	eng.RecordRequest("b.com", false, 200, 300, 600)

	domains := eng.GetDomains()
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	a := domains["a.com"]
	if a.TotalRequests != 2 {
		t.Fatalf("a.com should have 2 requests, got %d", a.TotalRequests)
	}
	if a.BlockedRequests != 1 {
		t.Fatalf("a.com should have 1 blocked, got %d", a.BlockedRequests)
	}
}

func TestStatsRecordBot(t *testing.T) {
	eng := stats.New()

	eng.RecordBot(true)
	eng.RecordBot(true)
	eng.RecordBot(false)

	ov := eng.GetOverview()
	if ov.BotRequests != 2 {
		t.Fatalf("expected 2 bot requests, got %d", ov.BotRequests)
	}
	if ov.HumanRequests != 1 {
		t.Fatalf("expected 1 human request, got %d", ov.HumanRequests)
	}
}

func TestStatsModuleCounters(t *testing.T) {
	eng := stats.New()

	eng.RecordHoneypotHit()
	eng.RecordHoneypotHit()
	eng.RecordCredentialAttack()
	eng.RecordDLPEvent()
	eng.RecordDLPEvent()
	eng.RecordDLPEvent()
	eng.SetDDoSLevel(2)

	ov := eng.GetOverview()
	if ov.HoneypotHitsToday != 2 {
		t.Fatalf("expected 2 honeypot hits, got %d", ov.HoneypotHitsToday)
	}
	if ov.CredentialAttacks != 1 {
		t.Fatalf("expected 1 credential attack, got %d", ov.CredentialAttacks)
	}
	if ov.DLPEventsToday != 3 {
		t.Fatalf("expected 3 DLP events, got %d", ov.DLPEventsToday)
	}
	if ov.DDoSLevel != 2 {
		t.Fatalf("expected DDoS level 2, got %d", ov.DDoSLevel)
	}
}

func TestStatsTimeline(t *testing.T) {
	eng := stats.New()

	eng.RecordRequest("host", false, 200, 0, 0)
	eng.RecordRequest("host", true, 403, 0, 0)

	timeline := eng.GetTimeline()
	if len(timeline) != 24 {
		t.Fatalf("expected 24 hour buckets, got %d", len(timeline))
	}

	// At least the current hour should have data
	var totalInTimeline int64
	for _, b := range timeline {
		totalInTimeline += b.Total
	}
	if totalInTimeline != 2 {
		t.Fatalf("expected 2 total in timeline, got %d", totalInTimeline)
	}
}

func TestStatsTopAttackersLimit(t *testing.T) {
	eng := stats.New()

	for i := 0; i < 20; i++ {
		eng.RecordAttack("10.0.0."+string(rune('0'+i%10)), "US", "US", "XSS", "/")
	}

	top5 := eng.GetTopAttackers(5)
	if len(top5) > 5 {
		t.Fatalf("expected max 5 attackers, got %d", len(top5))
	}
}

func TestStatsUptime(t *testing.T) {
	eng := stats.New()
	ov := eng.GetOverview()
	if ov.UptimeSeconds < 0 {
		t.Fatal("uptime should not be negative")
	}
}
