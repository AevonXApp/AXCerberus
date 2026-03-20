// Package logger provides structured JSON logging for all WAF log channels.
package logger

import (
	"log/slog"
	"os"
)

// Logs holds the four dedicated log channels used by Cerberus.
type Logs struct {
	Access   *slog.Logger
	Error    *slog.Logger
	Warning  *slog.Logger
	Security *slog.Logger
}

// New opens the four log files and returns a Logs bundle.
func New(accessPath, errorPath, warningPath, securityPath string) (*Logs, error) {
	access, err := openLogger(accessPath, slog.LevelInfo)
	if err != nil {
		return nil, err
	}
	errLog, err := openLogger(errorPath, slog.LevelError)
	if err != nil {
		return nil, err
	}
	warning, err := openLogger(warningPath, slog.LevelWarn)
	if err != nil {
		return nil, err
	}
	security, err := openLogger(securityPath, slog.LevelWarn)
	if err != nil {
		return nil, err
	}
	return &Logs{
		Access:   access,
		Error:    errLog,
		Warning:  warning,
		Security: security,
	}, nil
}

// LogAccess writes a structured access log entry.
func (l *Logs) LogAccess(method, path string, status int, durationMs int64,
	remoteIP, host, userAgent, countryCode, countryName, requestID string,
	bytesIn, bytesOut int64, botClassification string,
) {
	l.Access.Info("request",
		"request_id", requestID,
		"method", method,
		"path", path,
		"status", status,
		"duration_ms", durationMs,
		"remote_ip", remoteIP,
		"host", host,
		"user_agent", userAgent,
		"country_code", countryCode,
		"country_name", countryName,
		"bytes_in", bytesIn,
		"bytes_out", bytesOut,
		"bot_class", botClassification,
	)
}

// LogSecurity writes a structured security event.
func (l *Logs) LogSecurity(level, event string,
	ruleID int, severity, message, clientIP, uri, attackType,
	countryCode, countryName, userAgent, requestID string,
	anomalyScore int, disruptive bool,
) {
	l.Security.Warn(event,
		"request_id", requestID,
		"rule_id", ruleID,
		"severity", severity,
		"message", message,
		"client_ip", clientIP,
		"uri", uri,
		"attack_type", attackType,
		"country_code", countryCode,
		"country_name", countryName,
		"user_agent", userAgent,
		"anomaly_score", anomalyScore,
		"disruptive", disruptive,
	)
}

func openLogger(path string, level slog.Level) (*slog.Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return slog.New(slog.NewJSONHandler(f, &slog.HandlerOptions{Level: level})), nil
}
