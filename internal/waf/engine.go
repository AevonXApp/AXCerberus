// Package waf wraps the Coraza WAF engine.
package waf

import (
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"

	"axcerberus/internal/bot"
	"axcerberus/internal/config"
	"axcerberus/internal/geoip"
	"axcerberus/internal/logger"
	"axcerberus/internal/stats"

	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const maxBodyBytes = 10 * 1024 * 1024 // 10 MB

// Engine wraps a Coraza WAF instance.
type Engine struct {
	waf    coraza.WAF
	logs   *logger.Logs
	geoDB  *geoip.DB
	botDet *bot.Detector
	stats  *stats.Engine
}

// Build constructs a WAF engine and returns a Middleware.
func Build(cfg *config.Config, logs *logger.Logs, geoDB *geoip.DB,
	botDet *bot.Detector, statsEng *stats.Engine,
) (*Engine, error) {
	if !cfg.WAFEnabled {
		logs.Warning.Info("waf_disabled", "action", "passing_traffic_unfiltered")
		return nil, nil
	}

	wafInstance, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRequestBodyAccess().
			WithRequestBodyLimit(maxBodyBytes).
			WithRequestBodyInMemoryLimit(maxBodyBytes).
			WithResponseBodyAccess().
			WithResponseBodyLimit(maxBodyBytes).
			WithErrorCallback(errorCallback(logs, geoDB, statsEng)).
			WithDirectives(buildDirectives(cfg, logs)),
	)
	if err != nil {
		return nil, fmt.Errorf("waf: build engine: %w", err)
	}

	return &Engine{
		waf:    wafInstance,
		logs:   logs,
		geoDB:  geoDB,
		botDet: botDet,
		stats:  statsEng,
	}, nil
}

// Middleware returns an http.Handler middleware wrapping the WAF inspection.
func (e *Engine) Middleware(next http.Handler) http.Handler {
	if e == nil {
		return next
	}
	return newHandler(e.waf, next, e.logs, e.geoDB, e.botDet, e.stats)
}

func buildDirectives(cfg *config.Config, logs *logger.Logs) string {
	files, err := filepath.Glob(cfg.RulesFiles)
	if err != nil || len(files) == 0 {
		logs.Warning.Warn("waf_rules_not_found", "pattern", cfg.RulesFiles, "action", "detection_only_mode_active")
		return "SecRuleEngine DetectionOnly\n"
	}
	directives := "SecRuleEngine On\n"
	for _, f := range files {
		logs.Warning.Info("waf_rule_file_loaded", "path", f)
		directives += fmt.Sprintf("Include %s\n", f)
	}
	return directives
}

func errorCallback(logs *logger.Logs, geoDB *geoip.DB, statsEng *stats.Engine) func(types.MatchedRule) {
	return func(rule types.MatchedRule) {
		clientIP := rule.ClientIPAddress()
		attackType := ExtractAttackType(rule.Rule().ID())

		var countryCode, countryName string
		if geoDB != nil {
			geo := geoDB.Lookup(clientIP)
			countryCode = geo.CountryCode
			countryName = geo.CountryName
		}

		logs.LogSecurity("warn", "waf_rule_triggered",
			rule.Rule().ID(), rule.Rule().Severity().String(), rule.Message(),
			clientIP, rule.URI(), attackType,
			countryCode, countryName, "", "", 0, rule.Disruptive(),
		)

		if statsEng != nil && rule.Disruptive() {
			statsEng.RecordAttack(clientIP, countryName, countryCode, attackType, rule.URI())
		}
	}
}

// ExtractAttackType maps a rule ID to a human-readable attack category.
func ExtractAttackType(ruleID int) string {
	switch {
	case ruleID >= 1001 && ruleID <= 1099:
		return "SQL Injection"
	case ruleID >= 1101 && ruleID <= 1199:
		return "Cross-Site Scripting"
	case ruleID >= 1201 && ruleID <= 1299:
		return "Path Traversal"
	case ruleID >= 1301 && ruleID <= 1399:
		return "Remote File Inclusion"
	case ruleID >= 1401 && ruleID <= 1499:
		return "Command Injection"
	case ruleID >= 1501 && ruleID <= 1599:
		return "Log4Shell"
	case ruleID >= 1601 && ruleID <= 1699:
		return "HTTP Protocol Abuse"
	case ruleID >= 1701 && ruleID <= 1799:
		return "Scanner Detection"
	case ruleID >= 1801 && ruleID <= 1899:
		return "Sensitive File Access"
	case ruleID >= 1901 && ruleID <= 1999:
		return "Bot Detection"
	case ruleID >= 2001 && ruleID <= 2099:
		return "API Protection"
	case ruleID >= 2101 && ruleID <= 2199:
		return "WordPress Protection"
	case ruleID >= 2201 && ruleID <= 2299:
		return "PHP Protection"
	default:
		return "Unknown"
	}
}

var _ = (*slog.Logger)(nil) // keep slog import
