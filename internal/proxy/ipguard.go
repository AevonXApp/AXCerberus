package proxy

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// IPGuard limits concurrent requests per IP and manages allow/blocklists.
type IPGuard struct {
	mu        sync.Mutex
	maxConcur int
	blockSecs int
	escalate  bool // progressive blocking
	states    map[string]*ipState

	allowNets []*net.IPNet
	allowIPs  map[string]bool
	blockNets []*net.IPNet
	blockIPs  map[string]bool
}

type ipState struct {
	active       int
	blockedUntil time.Time
	permanent    bool
	offenses     int // for escalation

	TotalRequests int64  `json:"total_requests"`
	BlockedCount  int64  `json:"blocked_count"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
}

// BlockedIP represents a blocked IP entry.
type BlockedIP struct {
	IP         string `json:"ip"`
	Reason     string `json:"reason"`
	BlockedAt  string `json:"blocked_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Permanent  bool   `json:"permanent"`
	Violations int64  `json:"violations"`
}

// NewIPGuard creates a new IP guard.
func NewIPGuard(maxConcur, blockSecs int, escalate bool) *IPGuard {
	return &IPGuard{
		maxConcur: maxConcur,
		blockSecs: blockSecs,
		escalate:  escalate,
		states:    make(map[string]*ipState),
		allowIPs:  make(map[string]bool),
		blockIPs:  make(map[string]bool),
	}
}

// LoadAllowlist reads an allowlist file.
func (g *IPGuard) LoadAllowlist(path string) error {
	ips, nets, err := loadIPListFile(path)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.allowIPs = ips
	g.allowNets = nets
	return nil
}

// LoadBlocklist reads a blocklist file.
func (g *IPGuard) LoadBlocklist(path string) error {
	ips, nets, err := loadIPListFile(path)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blockIPs = ips
	g.blockNets = nets
	return nil
}

// Allow checks whether an IP may proceed.
func (g *IPGuard) Allow(ip string) (string, error, bool, time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()

	if g.isAllowlisted(ip) {
		st := g.getOrCreate(ip)
		st.TotalRequests++
		st.LastSeen = now.UTC().Format(time.RFC3339)
		st.active++
		return ip, nil, false, time.Time{}
	}

	if g.isBlocklisted(ip) {
		st := g.getOrCreate(ip)
		st.TotalRequests++
		st.BlockedCount++
		st.LastSeen = now.UTC().Format(time.RFC3339)
		return "", nil, true, time.Time{}
	}

	if g.maxConcur <= 0 {
		st := g.getOrCreate(ip)
		st.TotalRequests++
		st.LastSeen = now.UTC().Format(time.RFC3339)
		return ip, nil, false, time.Time{}
	}

	st := g.getOrCreate(ip)
	st.TotalRequests++
	st.LastSeen = now.UTC().Format(time.RFC3339)

	if st.permanent {
		st.BlockedCount++
		return "", nil, true, time.Time{}
	}

	if !st.blockedUntil.IsZero() && st.blockedUntil.After(now) {
		st.BlockedCount++
		return "", nil, true, st.blockedUntil
	}

	if !st.blockedUntil.IsZero() {
		st.blockedUntil = time.Time{}
	}

	st.active++
	if st.active > g.maxConcur {
		st.active--
		st.BlockedCount++
		st.offenses++

		duration := g.escalatedDuration(st.offenses)
		if duration < 0 {
			st.permanent = true
			return "", nil, true, time.Time{}
		}
		until := now.Add(time.Duration(duration) * time.Second)
		st.blockedUntil = until
		return "", nil, true, until
	}

	return ip, nil, false, time.Time{}
}

// escalatedDuration returns block duration based on offense count.
func (g *IPGuard) escalatedDuration(offenses int) int {
	if !g.escalate {
		if g.blockSecs < 0 {
			return -1
		}
		return g.blockSecs
	}
	switch {
	case offenses >= 4:
		return -1 // permanent
	case offenses >= 3:
		return 86400 // 24 hours
	case offenses >= 2:
		return 3600 // 1 hour
	default:
		return 300 // 5 minutes
	}
}

// Release decrements the active counter.
func (g *IPGuard) Release(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if st, ok := g.states[ip]; ok && st.active > 0 {
		st.active--
	}
}

// AddBlock manually blocks an IP.
func (g *IPGuard) AddBlock(ip string, durationSecs int, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.getOrCreate(ip)
	if durationSecs < 0 {
		st.permanent = true
	} else {
		st.blockedUntil = time.Now().Add(time.Duration(durationSecs) * time.Second)
	}
}

// RemoveBlock removes a block.
func (g *IPGuard) RemoveBlock(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if st, ok := g.states[ip]; ok {
		st.permanent = false
		st.blockedUntil = time.Time{}
		st.offenses = 0
	}
}

// GetBlockedIPs returns all blocked IPs.
func (g *IPGuard) GetBlockedIPs() []BlockedIP {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	var result []BlockedIP
	for ip, st := range g.states {
		if st.permanent {
			result = append(result, BlockedIP{IP: ip, Reason: "rate_limit", Permanent: true, Violations: st.BlockedCount})
		} else if !st.blockedUntil.IsZero() && st.blockedUntil.After(now) {
			result = append(result, BlockedIP{IP: ip, Reason: "rate_limit", ExpiresAt: st.blockedUntil.UTC().Format(time.RFC3339), Violations: st.BlockedCount})
		}
	}
	for ip := range g.blockIPs {
		result = append(result, BlockedIP{IP: ip, Reason: "manual_blocklist", Permanent: true})
	}
	return result
}

// GetAllowedIPs returns all allowlisted IPs.
func (g *IPGuard) GetAllowedIPs() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var result []string
	for ip := range g.allowIPs {
		result = append(result, ip)
	}
	return result
}

func (g *IPGuard) getOrCreate(ip string) *ipState {
	if st, ok := g.states[ip]; ok {
		return st
	}
	st := &ipState{FirstSeen: time.Now().UTC().Format(time.RFC3339), LastSeen: time.Now().UTC().Format(time.RFC3339)}
	g.states[ip] = st
	return st
}

func (g *IPGuard) isAllowlisted(ip string) bool {
	if g.allowIPs[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range g.allowNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func (g *IPGuard) isBlocklisted(ip string) bool {
	if g.blockIPs[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range g.blockNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func loadIPListFile(path string) (map[string]bool, []*net.IPNet, error) {
	ips := make(map[string]bool)
	var nets []*net.IPNet

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ips, nets, nil
		}
		return nil, nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			_, ipNet, err := net.ParseCIDR(line)
			if err == nil {
				nets = append(nets, ipNet)
				continue
			}
		}
		if net.ParseIP(line) != nil {
			ips[line] = true
		}
	}
	return ips, nets, scanner.Err()
}
