package tests

import (
	"testing"

	"axcerberus/internal/waf"
)

func TestExtractAttackType(t *testing.T) {
	tests := []struct {
		ruleID   int
		expected string
	}{
		{1001, "SQL Injection"},
		{1050, "SQL Injection"},
		{1099, "SQL Injection"},
		{1101, "Cross-Site Scripting"},
		{1199, "Cross-Site Scripting"},
		{1201, "Path Traversal"},
		{1301, "Remote File Inclusion"},
		{1401, "Command Injection"},
		{1501, "Log4Shell"},
		{1601, "HTTP Protocol Abuse"},
		{1701, "Scanner Detection"},
		{1801, "Sensitive File Access"},
		{1901, "Bot Detection"},
		{2001, "API Protection"},
		{2101, "WordPress Protection"},
		{2201, "PHP Protection"},
		{9999, "Unknown"},
		{0, "Unknown"},
		{500, "Unknown"},
	}

	for _, tc := range tests {
		got := waf.ExtractAttackType(tc.ruleID)
		if got != tc.expected {
			t.Errorf("ExtractAttackType(%d) = %q, want %q", tc.ruleID, got, tc.expected)
		}
	}
}

func TestExtractAttackTypeBoundaries(t *testing.T) {
	// Test exact boundaries
	if waf.ExtractAttackType(1000) != "Unknown" {
		t.Error("1000 should be Unknown")
	}
	if waf.ExtractAttackType(1001) != "SQL Injection" {
		t.Error("1001 should be SQL Injection")
	}
	if waf.ExtractAttackType(1100) != "Unknown" {
		t.Error("1100 should be Unknown")
	}
	if waf.ExtractAttackType(1101) != "Cross-Site Scripting" {
		t.Error("1101 should be Cross-Site Scripting")
	}
	if waf.ExtractAttackType(2299) != "PHP Protection" {
		t.Error("2299 should be PHP Protection")
	}
	if waf.ExtractAttackType(2300) != "Unknown" {
		t.Error("2300 should be Unknown")
	}
}
