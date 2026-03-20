package tests

import (
	"testing"

	"axcerberus/internal/alert"
)

func TestAlertDispatchDisabled(t *testing.T) {
	d := alert.New(false, "", 10, "low")
	// Should not panic
	d.Dispatch(alert.Alert{
		Type:     alert.EventWAFBlock,
		Severity: alert.SevCritical,
		Message:  "test",
	})
	recent := d.GetRecent(10)
	if len(recent) != 0 {
		t.Fatalf("disabled dispatcher should store no alerts, got %d", len(recent))
	}
}

func TestAlertDispatchEnabled(t *testing.T) {
	d := alert.New(true, "", 10, "low")
	d.Dispatch(alert.Alert{
		Type:     alert.EventWAFBlock,
		Severity: alert.SevHigh,
		Message:  "WAF blocked request",
	})

	recent := d.GetRecent(10)
	if len(recent) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(recent))
	}
	if recent[0].Type != alert.EventWAFBlock {
		t.Fatalf("expected waf_block type, got %s", recent[0].Type)
	}
}

func TestAlertSeverityFilter(t *testing.T) {
	d := alert.New(true, "", 10, "high") // min severity = high

	d.Dispatch(alert.Alert{
		Type:     alert.EventIPBlocked,
		Severity: alert.SevLow,
		Message:  "low severity",
	})
	d.Dispatch(alert.Alert{
		Type:     alert.EventIPBlocked,
		Severity: alert.SevMedium,
		Message:  "medium severity",
	})

	recent := d.GetRecent(10)
	if len(recent) != 0 {
		t.Fatalf("low/medium alerts should be filtered when min=high, got %d", len(recent))
	}

	d.Dispatch(alert.Alert{
		Type:     alert.EventDDoSDetected,
		Severity: alert.SevHigh,
		Message:  "high severity",
	})
	d.Dispatch(alert.Alert{
		Type:     alert.EventDDoSDetected,
		Severity: alert.SevCritical,
		Message:  "critical severity",
	})

	recent = d.GetRecent(10)
	if len(recent) != 2 {
		t.Fatalf("expected 2 high+ alerts, got %d", len(recent))
	}
}

func TestAlertThrottling(t *testing.T) {
	d := alert.New(true, "", 3, "low") // max 3 per hour per type

	for i := 0; i < 5; i++ {
		d.Dispatch(alert.Alert{
			Type:     alert.EventHoneypotHit,
			Severity: alert.SevMedium,
			Message:  "honeypot hit",
		})
	}

	recent := d.GetRecent(10)
	if len(recent) != 3 {
		t.Fatalf("expected 3 alerts (throttled), got %d", len(recent))
	}
}

func TestAlertThrottlingPerType(t *testing.T) {
	d := alert.New(true, "", 2, "low")

	// 2 WAF alerts (should all pass)
	for i := 0; i < 2; i++ {
		d.Dispatch(alert.Alert{Type: alert.EventWAFBlock, Severity: alert.SevHigh, Message: "waf"})
	}
	// 3rd WAF should be throttled
	d.Dispatch(alert.Alert{Type: alert.EventWAFBlock, Severity: alert.SevHigh, Message: "waf"})

	// But different type should still work
	d.Dispatch(alert.Alert{Type: alert.EventDDoSDetected, Severity: alert.SevHigh, Message: "ddos"})

	recent := d.GetRecent(10)
	if len(recent) != 3 { // 2 waf + 1 ddos
		t.Fatalf("expected 3 alerts, got %d", len(recent))
	}
}

func TestAlertGetRecentLimit(t *testing.T) {
	d := alert.New(true, "", 100, "low")

	for i := 0; i < 10; i++ {
		d.Dispatch(alert.Alert{
			Type:     alert.EventWAFBlock,
			Severity: alert.SevHigh,
			Message:  "test",
		})
	}

	recent := d.GetRecent(5)
	if len(recent) != 5 {
		t.Fatalf("expected 5 recent alerts, got %d", len(recent))
	}

	all := d.GetRecent(0)
	if len(all) != 10 {
		t.Fatalf("expected 10 total alerts, got %d", len(all))
	}
}

func TestAlertRingBuffer(t *testing.T) {
	d := alert.New(true, "", 1000, "low")

	// Dispatch more than maxRecent (200)
	for i := 0; i < 250; i++ {
		d.Dispatch(alert.Alert{
			Type:     alert.EventWAFBlock,
			Severity: alert.SevHigh,
			Message:  "test",
		})
	}

	recent := d.GetRecent(0)
	if len(recent) > 200 {
		t.Fatalf("ring buffer should cap at 200, got %d", len(recent))
	}
}

func TestAlertEventTypes(t *testing.T) {
	types := []alert.EventType{
		alert.EventWAFBlock,
		alert.EventIPBlocked,
		alert.EventDDoSDetected,
		alert.EventHoneypotHit,
		alert.EventCredentialAttack,
		alert.EventDLPDetection,
		alert.EventAutoRule,
	}

	d := alert.New(true, "", 100, "low")
	for _, et := range types {
		d.Dispatch(alert.Alert{Type: et, Severity: alert.SevHigh, Message: "test"})
	}

	recent := d.GetRecent(0)
	if len(recent) != len(types) {
		t.Fatalf("expected %d alerts, got %d", len(types), len(recent))
	}
}
