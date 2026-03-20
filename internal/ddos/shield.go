// Package ddos provides Layer 7 DDoS detection and auto-mitigation.
package ddos

import (
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MitigationLevel represents the current DDoS defense posture.
type MitigationLevel int

const (
	LevelNone    MitigationLevel = 0
	LevelLow     MitigationLevel = 1 // JS challenge for new IPs
	LevelMedium  MitigationLevel = 2 // Block low-reputation IPs
	LevelHigh    MitigationLevel = 3 // Allowlist-only mode
)

// Status reports the current DDoS shield state.
type Status struct {
	Level       MitigationLevel `json:"level"`
	CurrentQPS  float64         `json:"current_qps"`
	BaselineQPS float64         `json:"baseline_qps"`
	UnderAttack bool            `json:"under_attack"`
	Since       *time.Time      `json:"attack_since,omitempty"`
}

// Shield implements L7 DDoS detection using EWMA baseline learning.
type Shield struct {
	mu            sync.RWMutex
	enabled       bool
	autoMitigate  bool
	spikeMulti    float64
	maxConnsPerIP int

	// EWMA baseline (requests per 5-second bucket)
	alpha    float64 // smoothing factor
	baseline float64 // EWMA smoothed baseline
	samples  int     // number of samples collected

	// Current state
	level       MitigationLevel
	underAttack bool
	attackSince *time.Time

	// Counters (reset every 5 seconds)
	currentCount atomic.Int64
	lastCount    int64

	// Per-IP connection tracking
	conns map[string]int

	stopCh chan struct{}
}

// New creates a DDoS shield.
func New(enabled, autoMitigate bool, spikeMultiplier float64, maxConnsPerIP int) *Shield {
	s := &Shield{
		enabled:       enabled,
		autoMitigate:  autoMitigate,
		spikeMulti:    spikeMultiplier,
		maxConnsPerIP: maxConnsPerIP,
		alpha:         0.1, // EWMA smoothing
		conns:         make(map[string]int),
		stopCh:        make(chan struct{}),
	}
	if enabled {
		go s.monitor()
	}
	return s
}

// Middleware returns an HTTP middleware that enforces DDoS protection.
func (s *Shield) Middleware(next http.Handler) http.Handler {
	if !s.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.currentCount.Add(1)

		ip := extractIP(r)

		// Connection limit per IP
		if s.maxConnsPerIP > 0 {
			s.mu.Lock()
			s.conns[ip]++
			count := s.conns[ip]
			s.mu.Unlock()

			if count > s.maxConnsPerIP {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				s.mu.Lock()
				s.conns[ip]--
				s.mu.Unlock()
				return
			}

			defer func() {
				s.mu.Lock()
				s.conns[ip]--
				if s.conns[ip] <= 0 {
					delete(s.conns, ip)
				}
				s.mu.Unlock()
			}()
		}

		// Check mitigation level
		level := s.GetLevel()
		if level >= LevelHigh {
			// In extreme mode, block most traffic
			http.Error(w, "Service Unavailable - DDoS Protection Active", http.StatusServiceUnavailable)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// monitor runs every 5 seconds to update baseline and detect spikes.
func (s *Shield) monitor() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			count := s.currentCount.Swap(0)
			qps := float64(count) / 5.0

			s.mu.Lock()
			s.lastCount = count

			// Update EWMA baseline
			if s.samples == 0 {
				s.baseline = qps
			} else {
				s.baseline = s.alpha*qps + (1-s.alpha)*s.baseline
			}
			s.samples++

			// Spike detection (need at least 12 samples = 1 minute of data)
			if s.samples > 12 && s.baseline > 0 {
				ratio := qps / s.baseline
				if ratio > s.spikeMulti && s.autoMitigate {
					if !s.underAttack {
						s.underAttack = true
						now := time.Now()
						s.attackSince = &now
					}
					// Escalate based on severity
					switch {
					case ratio > 10:
						s.level = LevelHigh
					case ratio > 5:
						s.level = LevelMedium
					default:
						s.level = LevelLow
					}
				} else if s.underAttack && ratio < 1.5 {
					// De-escalate
					s.underAttack = false
					s.attackSince = nil
					s.level = LevelNone
				}
			}
			s.mu.Unlock()

		case <-s.stopCh:
			return
		}
	}
}

// GetStatus returns the current DDoS shield status.
func (s *Shield) GetStatus() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	qps := float64(s.lastCount) / 5.0
	return Status{
		Level:       s.level,
		CurrentQPS:  math.Round(qps*100) / 100,
		BaselineQPS: math.Round(s.baseline*100) / 100,
		UnderAttack: s.underAttack,
		Since:       s.attackSince,
	}
}

// GetLevel returns the current mitigation level.
func (s *Shield) GetLevel() MitigationLevel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.level
}

// SetLevel manually overrides the mitigation level.
func (s *Shield) SetLevel(level MitigationLevel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.level = level
	if level > LevelNone {
		s.underAttack = true
		if s.attackSince == nil {
			now := time.Now()
			s.attackSince = &now
		}
	} else {
		s.underAttack = false
		s.attackSince = nil
	}
}

// ActiveConnections returns the number of IPs with active connections.
func (s *Shield) ActiveConnections() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]int, len(s.conns))
	for k, v := range s.conns {
		cp[k] = v
	}
	return cp
}

// Stop stops the monitor goroutine.
func (s *Shield) Stop() {
	close(s.stopCh)
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
