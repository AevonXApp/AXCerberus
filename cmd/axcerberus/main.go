// Cerberus — AevonX WAF Engine
//
// Usage:
//
//	axcerberus [-config PATH] [-version] [-check-config]
//	axcerberus exec <action> [args...]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"axcerberus/internal/alert"
	"axcerberus/internal/bot"
	"axcerberus/internal/cli"
	"axcerberus/internal/config"
	"axcerberus/internal/credential"
	"axcerberus/internal/ddos"
	"axcerberus/internal/dlp"
	"axcerberus/internal/geoip"
	"axcerberus/internal/honeypot"
	"axcerberus/internal/logger"
	"axcerberus/internal/proxy"
	"axcerberus/internal/ratelimit"
	"axcerberus/internal/stats"
)

var (
	Version = "dev"
	Commit  = "none"
	BuildAt = "unknown"
)

func main() {
	// CLI exec mode
	if len(os.Args) > 1 && os.Args[1] == "exec" {
		os.Exit(cli.RunExec(os.Args[2:]))
	}

	flags := parseFlags()

	if flags.version {
		fmt.Printf("axcerberus %s (commit %s, built %s)\n", Version, Commit, BuildAt)
		os.Exit(0)
	}

	cfg, err := config.Load(flags.configPath)
	if err != nil {
		log.Fatalf("fatal: load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("fatal: invalid config: %v", err)
	}

	if flags.checkConfig {
		fmt.Println("config OK")
		os.Exit(0)
	}

	logs, err := logger.New(cfg.AccessLogFile, cfg.ErrorLogFile, cfg.WarningLogFile, cfg.SecurityLogFile)
	if err != nil {
		log.Fatalf("fatal: open log files: %v", err)
	}

	// GeoIP
	var geoDB *geoip.DB
	if cfg.GeoIPDBPath != "" {
		geoDB, err = geoip.Open(cfg.GeoIPDBPath)
		if err != nil {
			logs.Warning.Warn("geoip_disabled", "reason", err.Error())
		} else {
			logs.Access.Info("geoip_loaded", "path", cfg.GeoIPDBPath)
		}
	}
	if geoDB != nil {
		defer geoDB.Close()
	}

	// Bot detector
	var botDet *bot.Detector
	if cfg.BotDetectionEnabled {
		botDet = bot.NewDetector()
		logs.Access.Info("bot_detection_enabled")
	}

	// Stats engine
	statsEng := stats.New()
	logs.Access.Info("stats_engine_started")

	// IP Guard
	ipGuard := proxy.NewIPGuard(cfg.IPMaxConcurrentReqs, cfg.IPBlockDurationSecs, cfg.AutoBlockEscalation)
	if cfg.IPAllowlistFile != "" {
		if err := ipGuard.LoadAllowlist(cfg.IPAllowlistFile); err != nil {
			logs.Warning.Warn("ip_allowlist_load_error", "error", err)
		}
	}
	if cfg.IPBlocklistFile != "" {
		if err := ipGuard.LoadBlocklist(cfg.IPBlocklistFile); err != nil {
			logs.Warning.Warn("ip_blocklist_load_error", "error", err)
		}
	}

	// Rate limiter
	var rateLimiter *ratelimit.Limiter
	if cfg.RateLimitEnabled {
		rateLimiter = ratelimit.New(cfg.GlobalRateLimit, cfg.LoginRateLimit, cfg.APIRateLimit,
			cfg.ThrottleMode, cfg.SplitLoginPaths())
		logs.Access.Info("rate_limiter_enabled")
	}

	// Honeypot
	var honeypotEng *honeypot.Engine
	if cfg.HoneypotEnabled {
		honeypotEng = honeypot.New(cfg.SplitHoneypotPaths(), cfg.HoneypotAutoBlock)
		honeypotEng.OnBlock = func(ip string) {
			ipGuard.AddBlock(ip, 3600, "honeypot")
			statsEng.RecordHoneypotHit()
			logs.Security.Warn("honeypot_block", "ip", ip)
		}
		logs.Access.Info("honeypot_enabled", "traps", cfg.HoneypotPaths)
	}

	// DDoS shield
	var ddosShield *ddos.Shield
	if cfg.DDoSEnabled {
		ddosShield = ddos.New(true, cfg.DDoSAutoMitigate, cfg.DDoSSpikeMultiplier, cfg.MaxConnsPerIP)
		logs.Access.Info("ddos_shield_enabled")
	}

	// Credential protection
	var credDet *credential.Detector
	if cfg.CredentialEnabled {
		credDet = credential.New(cfg.SplitLoginPaths(), cfg.MaxLoginAttemptsPerIP, cfg.MaxLoginAttemptsPerUser)
		credDet.OnBlock = func(ip, reason string) {
			ipGuard.AddBlock(ip, 3600, reason)
			statsEng.RecordCredentialAttack()
			logs.Security.Warn("credential_attack_blocked", "ip", ip, "reason", reason)
		}
		logs.Access.Info("credential_protection_enabled")
	}

	// Alert dispatcher
	alertDisp := alert.New(cfg.AlertsEnabled, cfg.AlertWebhookURL, cfg.AlertMaxPerHour, cfg.AlertSeverityThreshold)

	// DLP scanner
	var dlpScanner *dlp.Scanner
	if cfg.DLPEnabled {
		dlpScanner = dlp.NewScanner(cfg.DLPMode, cfg.DLPCreditCards, cfg.DLPAPIKeys, cfg.DLPStackTraces)
		dlpScanner.OnDetect = func(ev dlp.Event) {
			statsEng.RecordDLPEvent()
			alertDisp.Dispatch(alert.Alert{
				Type:     alert.EventDLPDetection,
				Severity: alert.SevHigh,
				Message:  "DLP detected " + string(ev.Type) + " in " + ev.URI,
			})
			logs.Security.Warn("dlp_detection", "type", string(ev.Type), "uri", ev.URI, "ip", ev.IP, "matches", ev.Matches)
		}
		logs.Access.Info("dlp_scanner_enabled", "mode", cfg.DLPMode)
	}

	// Build deps
	deps := &proxy.Deps{
		Config:     cfg,
		Logger:     logs,
		Stats:      statsEng,
		GeoIP:      geoDB,
		Bot:        botDet,
		IPGuard:    ipGuard,
		RateLimiter: rateLimiter,
		Honeypot:   honeypotEng,
		DDoS:       ddosShield,
		Credential: credDet,
		Alert:      alertDisp,
		DLP:        dlpScanner,
	}

	// Create server
	srv, err := proxy.New(deps)
	if err != nil {
		log.Fatalf("fatal: create server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Stats API server
	if cfg.StatsAPIEnabled && cfg.StatsAPIListen != "" {
		apiSrv := stats.NewAPIServer(statsEng, cfg.StatsAPIListen)
		apiSrv.SetModules(honeypotEng, ddosShield, credDet)
		apiSrv.SetAlerts(alertDisp)
		go func() {
			logs.Access.Info("stats_api_starting", "addr", cfg.StatsAPIListen)
			if err := apiSrv.Serve(ctx); err != nil {
				logs.Error.Error("stats_api_error", "error", err)
			}
		}()
	}

	// SIGHUP reload
	go watchReload(flags.configPath, srv, logs)

	if err := srv.Serve(ctx); err != nil {
		log.Fatalf("fatal: server exited: %v", err)
	}
}

func watchReload(configPath string, srv *proxy.Server, logs *logger.Logs) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		newCfg, err := config.Load(configPath)
		if err != nil {
			logs.Error.Error("reload_config_error", "error", err)
			continue
		}
		if err := newCfg.Validate(); err != nil {
			logs.Error.Error("reload_config_invalid", "error", err)
			continue
		}
		if err := srv.Reload(newCfg); err != nil {
			logs.Error.Error("reload_server_error", "error", err)
		}
	}
}

type flags struct {
	configPath  string
	version     bool
	checkConfig bool
}

func parseFlags() flags {
	var f flags
	flag.StringVar(&f.configPath, "config", config.DefaultPath, "path to config.avx file")
	flag.BoolVar(&f.version, "version", false, "print version and exit")
	flag.BoolVar(&f.checkConfig, "check-config", false, "validate config and exit")
	flag.Parse()
	return f
}
