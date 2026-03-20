// Package cli implements the one-shot "exec" CLI mode for Cerberus.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	apiBase       = "http://127.0.0.1:9443"
	confDir       = "/etc/aevonx/plugins/axcerberus"
	logDir        = "/var/log/aevonx/plugins/axcerberus"
	blocklistFile = confDir + "/ip_blocklist.avx"
	allowlistFile = confDir + "/ip_allowlist.avx"
	configFile    = confDir + "/config.avx"
	serviceName   = "axcerberus"
	binaryPath    = "/usr/local/bin/axcerberus"
	httpTimeout   = 3 * time.Second
)

var actions = map[string]func(args []string) (any, error){
	// Stats
	"waf.stats.overview":        actionStatsOverview,
	"waf.stats.blocked_today":   actionStatsBlockedToday,
	"waf.stats.protection_rate": actionStatsProtectionRate,
	"waf.stats.qps":             actionStatsSimple("/api/v1/stats/qps"),
	"waf.stats.attack_timeline": actionStatsSimple("/api/v1/stats/timeline"),
	"waf.stats.attack_types":    actionStatsSimple("/api/v1/stats/attack-types"),
	"waf.stats.countries":       actionStatsSimple("/api/v1/stats/countries"),
	"waf.stats.top_attackers":   actionStatsSimple("/api/v1/stats/top-attackers"),
	"waf.stats.top_uris":        actionStatsSimple("/api/v1/stats/top-uris"),
	"waf.stats.domains":         actionStatsSimple("/api/v1/stats/domains"),

	// DDoS
	"waf.ddos.status": actionStatsSimple("/api/v1/ddos/status"),

	// Honeypot
	"waf.honeypot.hits": actionStatsSimple("/api/v1/honeypot/hits"),

	// Credential
	"waf.credential.status": actionStatsSimple("/api/v1/credential/status"),

	// Service
	"waf.service.status": actionServiceStatus,

	// Blocklist
	"waf.blocklist.list":   actionBlocklistList,
	"waf.blocklist.add":    actionBlocklistAdd,
	"waf.blocklist.remove": actionBlocklistRemove,

	// Allowlist
	"waf.allowlist.list":   actionAllowlistList,
	"waf.allowlist.add":    actionAllowlistAdd,
	"waf.allowlist.remove": actionAllowlistRemove,

	// Config
	"waf.config.show": actionConfigShow,
}

// RunExec dispatches a CLI exec invocation.
func RunExec(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `{"error":"no action specified"}`)
		return 1
	}
	action := args[0]
	fn, ok := actions[action]
	if !ok {
		fmt.Fprintf(os.Stderr, `{"error":"unknown action: %s"}`+"\n", action)
		return 1
	}
	result, err := fn(args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error":"%s"}`+"\n", err.Error())
		return 1
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))
	return 0
}

// ---------------------------------------------------------------------------
// Stats actions
// ---------------------------------------------------------------------------

func actionStatsOverview(_ []string) (any, error)        { return apiGet("/api/v1/stats/overview") }
func actionStatsBlockedToday(_ []string) (any, error)     { return apiGet("/api/v1/stats/overview") }
func actionStatsProtectionRate(_ []string) (any, error)   { return apiGet("/api/v1/stats/overview") }

func actionStatsSimple(endpoint string) func([]string) (any, error) {
	return func(_ []string) (any, error) { return apiGet(endpoint) }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

func actionServiceStatus(_ []string) (any, error) {
	out, err := exec.Command("systemctl", "is-active", serviceName).Output()
	status := strings.TrimSpace(string(out))
	if err != nil {
		status = "inactive"
	}
	return map[string]any{
		"service": serviceName,
		"status":  status,
		"binary":  binaryPath,
	}, nil
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

func actionBlocklistList(_ []string) (any, error) {
	return readIPFile(blocklistFile)
}

func actionBlocklistAdd(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: blocklist.add <ip>")
	}
	return appendIPFile(blocklistFile, args[0])
}

func actionBlocklistRemove(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: blocklist.remove <ip>")
	}
	return removeIPFile(blocklistFile, args[0])
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

func actionAllowlistList(_ []string) (any, error)   { return readIPFile(allowlistFile) }
func actionAllowlistAdd(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: allowlist.add <ip>")
	}
	return appendIPFile(allowlistFile, args[0])
}
func actionAllowlistRemove(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: allowlist.remove <ip>")
	}
	return removeIPFile(allowlistFile, args[0])
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

func actionConfigShow(_ []string) (any, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	var raw any
	json.Unmarshal(data, &raw)
	return raw, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func apiGet(path string) (any, error) {
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Get(apiBase + path)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result any
	json.Unmarshal(body, &result)
	return result, nil
}

func readIPFile(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{"ips": []string{}, "count": 0}, nil
		}
		return nil, err
	}
	var ips []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return map[string]any{"ips": ips, "count": len(ips)}, nil
}

func appendIPFile(path, ip string) (any, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\n", ip)
	reloadService()
	return map[string]any{"added": ip}, nil
}

func removeIPFile(path, ip string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	removed := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == ip {
			removed = true
			continue
		}
		if trimmed != "" {
			lines = append(lines, line)
		}
	}
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	reloadService()
	return map[string]any{"removed": removed, "ip": ip}, nil
}

func reloadService() {
	exec.Command("systemctl", "reload", serviceName).Run()
}

// Used by strconv import
var _ = strconv.Itoa
