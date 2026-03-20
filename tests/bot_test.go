package tests

import (
	"testing"

	"axcerberus/internal/bot"
)

func TestBotDetectHuman(t *testing.T) {
	d := bot.NewDetector()
	r := d.Detect("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	if r.IsBot {
		t.Fatal("normal browser UA should be classified as human")
	}
	if r.Classification != bot.ClassHuman {
		t.Fatalf("expected human, got %s", r.Classification)
	}
}

func TestBotDetectGooglebot(t *testing.T) {
	d := bot.NewDetector()
	r := d.Detect("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	if !r.IsBot {
		t.Fatal("Googlebot should be classified as bot")
	}
	if r.Classification != bot.ClassVerifiedBot {
		t.Fatalf("expected verified_bot, got %s", r.Classification)
	}
	if r.BotName != "Googlebot" {
		t.Fatalf("expected name Googlebot, got %s", r.BotName)
	}
}

func TestBotDetectBingbot(t *testing.T) {
	d := bot.NewDetector()
	r := d.Detect("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)")
	if r.Classification != bot.ClassVerifiedBot {
		t.Fatalf("expected verified_bot, got %s", r.Classification)
	}
}

func TestBotDetectMalicious(t *testing.T) {
	d := bot.NewDetector()

	malicious := []struct {
		name string
		ua   string
	}{
		{"SQLmap", "sqlmap/1.5"},
		{"Nikto", "Nikto/2.1.6"},
		{"Nmap", "Nmap Scripting Engine"},
		{"DirBuster", "DirBuster-1.0-RC1"},
		{"Nuclei", "Nuclei - Open-source project"},
		{"curl", "curl/7.68.0"},
		{"python-requests", "python-requests/2.25.1"},
	}

	for _, tc := range malicious {
		r := d.Detect(tc.ua)
		if !r.IsBot {
			t.Fatalf("%s should be classified as bot", tc.name)
		}
		if r.Classification != bot.ClassMalicious {
			t.Fatalf("%s: expected malicious, got %s", tc.name, r.Classification)
		}
	}
}

func TestBotDetectSuspicious(t *testing.T) {
	d := bot.NewDetector()

	// Empty UA
	r := d.Detect("")
	if !r.IsBot {
		t.Fatal("empty UA should be classified as bot")
	}
	if r.Classification != bot.ClassSuspicious {
		t.Fatalf("expected suspicious, got %s", r.Classification)
	}

	// Short UA
	r2 := d.Detect("short-ua")
	if !r2.IsBot {
		t.Fatal("short UA should be classified as bot")
	}
	if r2.Classification != bot.ClassSuspicious {
		t.Fatalf("expected suspicious for short UA, got %s", r2.Classification)
	}
}

func TestBotDetectLikelyBot(t *testing.T) {
	d := bot.NewDetector()
	r := d.Detect("Mozilla/5.0 (compatible; GenericCrawler/1.0)")
	if !r.IsBot {
		t.Fatal("generic crawler should be classified as bot")
	}
	if r.Classification != bot.ClassLikelyBot {
		t.Fatalf("expected likely_bot, got %s", r.Classification)
	}
}

func TestBotDetectVerifiedBots(t *testing.T) {
	d := bot.NewDetector()

	verified := []struct {
		name string
		ua   string
	}{
		{"YandexBot", "Mozilla/5.0 (compatible; YandexBot/3.0)"},
		{"DuckDuckBot", "DuckDuckBot/1.0"},
		{"Slackbot", "Slackbot-LinkExpanding 1.0"},
		{"Discordbot", "Mozilla/5.0 (compatible; Discordbot/2.0)"},
		{"UptimeRobot", "UptimeRobot/2.0"},
	}

	for _, tc := range verified {
		r := d.Detect(tc.ua)
		if !r.IsBot {
			t.Fatalf("%s should be bot", tc.name)
		}
		if r.Classification != bot.ClassVerifiedBot {
			t.Fatalf("%s: expected verified_bot, got %s", tc.name, r.Classification)
		}
	}
}

func TestBotScore(t *testing.T) {
	d := bot.NewDetector()

	human := d.Detect("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	if human.Score != 0 {
		t.Fatalf("human score should be 0, got %d", human.Score)
	}

	malicious := d.Detect("sqlmap/1.5")
	if malicious.Score < 90 {
		t.Fatalf("malicious score should be >= 90, got %d", malicious.Score)
	}

	verified := d.Detect("Googlebot/2.1")
	if verified.Score > 20 {
		t.Fatalf("verified bot score should be <= 20, got %d", verified.Score)
	}
}
