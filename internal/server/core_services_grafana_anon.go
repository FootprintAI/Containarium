package server

import (
	"fmt"
	"log"
	"strings"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// grafanaIniPath is where the daemon writes Grafana's config inside the
// core-victoriametrics container.
const grafanaIniPath = "/etc/grafana/grafana.ini"

// renderGrafanaIni is the grafana.ini the daemon provisions. Anonymous
// access is off: the dashboard port is on the same bridge as every tenant
// (see docs/security/multi-tenant-isolation.md), so an anonymous Viewer
// role would let any tenant read platform dashboards with no credential at
// all (#2079). Dashboards are reached through Caddy with a login.
func renderGrafanaIni(postgresIP, dbUser, dbPassword string) string {
	return fmt.Sprintf(`[database]
type = postgres
host = %s:5432
name = grafana
user = %s
password = %s
ssl_mode = disable
max_open_conn = 5
max_idle_conn = 2
conn_max_lifetime = 14400

[security]
allow_embedding = true
admin_user = admin
admin_password = containarium

[auth.anonymous]
enabled = false

[users]
default_theme = light

[server]
http_port = 3000
root_url = %%(protocol)s://%%(domain)s/grafana/
serve_from_sub_path = true
`, postgresIP, dbUser, grafanaIniValue(dbPassword))
}

// grafanaAnonymousEnabled reports the value of [auth.anonymous] enabled in
// an ini text. ok is false when the section or key is absent — Grafana's
// own default is then "disabled", so absent is safe.
func grafanaAnonymousEnabled(ini string) (enabled, ok bool) {
	inSection := false
	for _, raw := range strings.Split(ini, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			inSection = strings.EqualFold(line, "[auth.anonymous]")
			continue
		}
		if !inSection {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "enabled") {
			continue
		}
		return strings.EqualFold(strings.TrimSpace(val), "true"), true
	}
	return false, false
}

// disableGrafanaAnonymous rewrites [auth.anonymous] enabled to false and
// reports whether anything changed. Only that one key is touched; a text
// with anonymous already off, or with no such section, is returned as is.
func disableGrafanaAnonymous(ini string) (string, bool) {
	if enabled, ok := grafanaAnonymousEnabled(ini); !ok || !enabled {
		return ini, false
	}
	lines := strings.Split(ini, "\n")
	inSection := false
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			inSection = strings.EqualFold(line, "[auth.anonymous]")
			continue
		}
		if !inSection {
			continue
		}
		key, _, found := strings.Cut(line, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "enabled") {
			lines[i] = "enabled = false"
			return strings.Join(lines, "\n"), true
		}
	}
	return ini, false
}

// backfillGrafanaAnonymous closes anonymous access on a Grafana the daemon
// provisioned before renderGrafanaIni turned it off. It is the same shape
// as backfillConfig — run on every start against an existing container,
// no-op once converged — and it reloads by restarting grafana-server,
// because Grafana does not re-read its ini on SIGHUP.
//
// Failures are logged, not fatal: a host whose Grafana is unreachable at
// startup still needs the rest of core services up, and the next start
// tries again.
func (cs *CoreServices) backfillGrafanaAnonymous() {
	raw, err := cs.incusClient.ReadFile(CoreVictoriaMetricsContainer, grafanaIniPath)
	if err != nil {
		log.Printf("Warning: could not read %s on %s to check anonymous access: %v", grafanaIniPath, CoreVictoriaMetricsContainer, err)
		return
	}
	fixed, changed := disableGrafanaAnonymous(string(raw))
	if !changed {
		return
	}
	if err := cs.incusClient.WriteFile(CoreVictoriaMetricsContainer, grafanaIniPath, []byte(fixed), "0644"); err != nil {
		log.Printf("Warning: failed to disable Grafana anonymous access on %s: %v", CoreVictoriaMetricsContainer, err)
		return
	}
	if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, []string{"systemctl", "restart", "grafana-server"}); err != nil {
		log.Printf("Warning: grafana.ini updated but grafana-server restart failed on %s: %v (anonymous access stays on until it restarts)", CoreVictoriaMetricsContainer, err)
		return
	}
	log.Printf("Disabled Grafana anonymous access on %s (backfill, #2079)", CoreVictoriaMetricsContainer)
}

// hardenDetectedGrafana runs the Grafana backfill on a host where the
// metrics container was auto-detected at startup (#2103). That detection
// pre-sets the VictoriaMetrics URL, which makes the daemon skip
// EnsureVictoriaMetrics — and with it the backfill above — on every
// existing host, i.e. exactly the hosts an upgrade is supposed to fix.
//
// It reuses the CoreServices the caller already has, builds a minimal one
// otherwise, and returns whichever it used so later steps (the OTel
// collector) can share it. Nil backend → nothing to do, nil back.
func hardenDetectedGrafana(cs *CoreServices, be incus.Backend) *CoreServices {
	if be == nil {
		return cs
	}
	if cs == nil {
		cs = NewCoreServices(be, CoreServicesConfig{})
	}
	cs.backfillGrafanaAnonymous()
	cs.backfillGrafanaDBPassword()
	return cs
}
