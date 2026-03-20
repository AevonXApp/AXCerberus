// Package proxy implements the reverse-proxy layer.
package proxy

import (
	"axcerberus/internal/alert"
	"axcerberus/internal/bot"
	"axcerberus/internal/config"
	"axcerberus/internal/credential"
	"axcerberus/internal/ddos"
	"axcerberus/internal/geoip"
	"axcerberus/internal/honeypot"
	"axcerberus/internal/logger"
	"axcerberus/internal/ratelimit"
	"axcerberus/internal/stats"
)

// Deps aggregates all module dependencies injected into the proxy server.
type Deps struct {
	Config     *config.Config
	Logger     *logger.Logs
	Stats      *stats.Engine
	GeoIP      *geoip.DB
	Bot        *bot.Detector
	IPGuard    *IPGuard
	RateLimiter *ratelimit.Limiter
	Honeypot   *honeypot.Engine
	DDoS       *ddos.Shield
	Credential *credential.Detector
	Alert      *alert.Dispatcher
}
