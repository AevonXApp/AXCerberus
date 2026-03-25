// Package stats — HTTP API server for real-time WAF statistics.
// Listens on 127.0.0.1 only. No external network exposure.
package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"axcerberus/internal/alert"
	"axcerberus/internal/credential"
	"axcerberus/internal/ddos"
	"axcerberus/internal/honeypot"
)

// APIServer serves the stats API on localhost.
type APIServer struct {
	engine   *Engine
	addr     string
	srv      *http.Server

	// Module references for extended endpoints
	honeypot   *honeypot.Engine
	ddos       *ddos.Shield
	credential *credential.Detector
	alerts     *alert.Dispatcher
}

// NewAPIServer creates a stats API server.
func NewAPIServer(engine *Engine, addr string) *APIServer {
	s := &APIServer{engine: engine, addr: addr}

	mux := http.NewServeMux()

	// Core stats
	mux.HandleFunc("/api/v1/stats/overview", s.handleOverview)
	mux.HandleFunc("/api/v1/stats/timeline", s.handleTimeline)
	mux.HandleFunc("/api/v1/stats/attack-types", s.handleAttackTypes)
	mux.HandleFunc("/api/v1/stats/countries", s.handleCountries)
	mux.HandleFunc("/api/v1/stats/top-attackers", s.handleTopAttackers)
	mux.HandleFunc("/api/v1/stats/top-uris", s.handleTopURIs)
	mux.HandleFunc("/api/v1/stats/domains", s.handleDomains)
	mux.HandleFunc("/api/v1/stats/qps", s.handleQPS)

	// New module endpoints
	mux.HandleFunc("/api/v1/ddos/status", s.handleDDoSStatus)
	mux.HandleFunc("/api/v1/credential/status", s.handleCredentialStatus)
	mux.HandleFunc("/api/v1/honeypot/hits", s.handleHoneypotHits)

	// Extended stats
	mux.HandleFunc("/api/v1/stats/response-times", s.handleResponseTimes)
	mux.HandleFunc("/api/v1/stats/status-codes", s.handleStatusCodes)
	mux.HandleFunc("/api/v1/stats/bot-details", s.handleBotDetails)
	mux.HandleFunc("/api/v1/alerts/recent", s.handleAlertsRecent)

	// Request logs
	mux.HandleFunc("/api/v1/logs/access", s.handleAccessLog)
	mux.HandleFunc("/api/v1/logs/blocks", s.handleBlockLog)

	// Health
	mux.HandleFunc("/healthz", s.handleHealth)

	s.srv = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	return s
}

// SetModules sets module references for extended API endpoints.
func (s *APIServer) SetModules(hp *honeypot.Engine, dd *ddos.Shield, cred *credential.Detector) {
	s.honeypot = hp
	s.ddos = dd
	s.credential = cred
}

// SetAlerts sets the alert dispatcher reference.
func (s *APIServer) SetAlerts(a *alert.Dispatcher) {
	s.alerts = a
}

// Serve starts the API server, blocking until ctx is cancelled.
func (s *APIServer) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.srv.Shutdown(shutCtx)
	}()
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("stats api: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

func (s *APIServer) handleOverview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.engine.GetOverview())
}

func (s *APIServer) handleTimeline(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"timeline": s.engine.GetTimeline()})
}

func (s *APIServer) handleAttackTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"attack_types": s.engine.GetAttackTypes()})
}

func (s *APIServer) handleCountries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"countries": s.engine.GetCountries()})
}

func (s *APIServer) handleTopAttackers(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	writeJSON(w, map[string]any{"attackers": s.engine.GetTopAttackers(limit)})
}

func (s *APIServer) handleTopURIs(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	writeJSON(w, map[string]any{"uris": s.engine.GetTopURIs(limit)})
}

func (s *APIServer) handleDomains(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"domains": s.engine.GetDomains()})
}

func (s *APIServer) handleQPS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"qps": s.engine.GetQPS()})
}

// ---------------------------------------------------------------------------
// Module handlers
// ---------------------------------------------------------------------------

func (s *APIServer) handleDDoSStatus(w http.ResponseWriter, r *http.Request) {
	if s.ddos == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, s.ddos.GetStatus())
}

func (s *APIServer) handleCredentialStatus(w http.ResponseWriter, r *http.Request) {
	if s.credential == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, s.credential.GetStats())
}

func (s *APIServer) handleHoneypotHits(w http.ResponseWriter, r *http.Request) {
	if s.honeypot == nil {
		writeJSON(w, map[string]any{"hits": []any{}})
		return
	}
	limit := queryInt(r, "limit", 50)
	writeJSON(w, map[string]any{"hits": s.honeypot.GetHits(limit)})
}

// ---------------------------------------------------------------------------
// Extended stats handlers
// ---------------------------------------------------------------------------

func (s *APIServer) handleResponseTimes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.engine.GetResponseTimePercentiles())
}

func (s *APIServer) handleStatusCodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"status_codes": s.engine.GetStatusCodes()})
}

func (s *APIServer) handleBotDetails(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.engine.GetBotDetails())
}

func (s *APIServer) handleAlertsRecent(w http.ResponseWriter, r *http.Request) {
	if s.alerts == nil {
		writeJSON(w, map[string]any{"alerts": []any{}, "count": 0})
		return
	}
	limit := queryInt(r, "limit", 50)
	alerts := s.alerts.GetRecent(limit)
	writeJSON(w, map[string]any{"alerts": alerts, "count": len(alerts)})
}

func (s *APIServer) handleAccessLog(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	writeJSON(w, map[string]any{"entries": s.engine.GetAccessLog(limit), "total": s.engine.accessLogLen})
}

func (s *APIServer) handleBlockLog(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	writeJSON(w, map[string]any{"entries": s.engine.GetBlockLog(limit), "total": s.engine.blockLogLen})
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(v)
}

func queryInt(r *http.Request, key string, fallback int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}
