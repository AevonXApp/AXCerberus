// Package alert provides event alerting with throttling and webhook delivery.
package alert

import (
	"sync"
	"time"
)

// Severity levels for alerts.
type Severity string

const (
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// EventType categorizes alert events.
type EventType string

const (
	EventWAFBlock        EventType = "waf_block"
	EventIPBlocked       EventType = "ip_blocked"
	EventDDoSDetected    EventType = "ddos_detected"
	EventHoneypotHit     EventType = "honeypot_triggered"
	EventCredentialAttack EventType = "credential_attack"
	EventDLPDetection    EventType = "dlp_event"
	EventAutoRule        EventType = "auto_rule"
)

// Alert represents a security event notification.
type Alert struct {
	Type      EventType `json:"type"`
	Severity  Severity  `json:"severity"`
	Message   string    `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Dispatcher routes alerts to configured channels with throttling.
type Dispatcher struct {
	mu               sync.Mutex
	enabled          bool
	webhookURL       string
	maxPerHour       int
	minSeverity      Severity
	webhook          *WebhookSender

	// Throttle tracking: type → timestamps
	throttle map[EventType][]time.Time

	// Recent alerts ring buffer
	recent   []Alert
	maxRecent int
}

// New creates an alert dispatcher.
func New(enabled bool, webhookURL string, maxPerHour int, minSeverity string) *Dispatcher {
	d := &Dispatcher{
		enabled:     enabled,
		webhookURL:  webhookURL,
		maxPerHour:  maxPerHour,
		minSeverity: Severity(minSeverity),
		throttle:    make(map[EventType][]time.Time),
		maxRecent:   200,
	}
	if enabled && webhookURL != "" {
		d.webhook = NewWebhookSender(webhookURL)
	}
	return d
}

// Dispatch sends an alert if it passes severity and throttle checks.
func (d *Dispatcher) Dispatch(a Alert) {
	if !d.enabled {
		return
	}

	a.Timestamp = time.Now()

	// Check severity threshold
	if !d.meetsSeverity(a.Severity) {
		return
	}

	// Check throttle
	if !d.allowThrottled(a.Type) {
		return
	}

	// Store in recent
	d.mu.Lock()
	if len(d.recent) >= d.maxRecent {
		d.recent = d.recent[1:]
	}
	d.recent = append(d.recent, a)
	d.mu.Unlock()

	// Send via webhook (async)
	if d.webhook != nil {
		go d.webhook.Send(a)
	}
}

// GetRecent returns recent alerts.
func (d *Dispatcher) GetRecent(limit int) []Alert {
	d.mu.Lock()
	defer d.mu.Unlock()

	if limit <= 0 || limit > len(d.recent) {
		limit = len(d.recent)
	}
	start := len(d.recent) - limit
	result := make([]Alert, limit)
	copy(result, d.recent[start:])
	return result
}

func (d *Dispatcher) meetsSeverity(sev Severity) bool {
	order := map[Severity]int{
		SevLow: 0, SevMedium: 1, SevHigh: 2, SevCritical: 3,
	}
	return order[sev] >= order[d.minSeverity]
}

func (d *Dispatcher) allowThrottled(et EventType) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Hour)

	// Slide window
	times := d.throttle[et]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= d.maxPerHour {
		d.throttle[et] = valid
		return false
	}

	d.throttle[et] = append(valid, now)
	return true
}

// severityLevel returns the numeric level for sorting.
func severityLevel(s Severity) int {
	switch s {
	case SevLow:
		return 0
	case SevMedium:
		return 1
	case SevHigh:
		return 2
	case SevCritical:
		return 3
	default:
		return 0
	}
}
