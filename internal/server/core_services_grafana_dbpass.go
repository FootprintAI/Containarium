package server

import (
	"context"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// grafanaDBName is the database Grafana stores its state in. EnsureVictoriaMetrics
// creates it, owned by the core Postgres role.
const grafanaDBName = "grafana"

// pgPingArgs is what a Postgres connection test needs. Kept as a struct so the
// test seam on CoreServices has one stable, typed shape.
type pgPingArgs struct {
	Host     string // host:port, as Grafana's ini carries it
	User     string
	Password string
	Database string
}

// pgxPing is the production connection test: it opens one real connection with
// the given credentials and pings it. Credentials go through url.UserPassword,
// so a password with reserved characters is escaped, not interpreted.
func pgxPing(ctx context.Context, a pgPingArgs) error {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(a.User, a.Password),
		Host:   a.Host,
		Path:   "/" + a.Database,
	}
	q := u.Query()
	q.Set("sslmode", "disable")
	q.Set("connect_timeout", "5")
	u.RawQuery = q.Encode()

	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()
	return conn.Ping(ctx)
}

// grafanaIniValue renders a value for grafana.ini. Grafana reads an unquoted
// `#` or `;` as the start of a comment, so a password containing either (or a
// quote, or leading/trailing space) is wrapped in triple quotes, which Grafana
// reads literally.
func grafanaIniValue(v string) string {
	if strings.ContainsAny(v, "#;\"`") || v != strings.TrimSpace(v) {
		return `"""` + v + `"""`
	}
	return v
}

// grafanaIniUnquote undoes grafanaIniValue for a value read from an ini line.
func grafanaIniUnquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 6 && strings.HasPrefix(v, `"""`) && strings.HasSuffix(v, `"""`) {
		return v[3 : len(v)-3]
	}
	return v
}

// grafanaDBSettings reads host, user and password from the [database] section
// of a grafana.ini. ok is false when that section has no password key: a
// `password` key in any other section (smtp, ldap) is not the database one.
func grafanaDBSettings(ini string) (host, user, password string, ok bool) {
	inSection := false
	for _, raw := range strings.Split(ini, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			inSection = strings.EqualFold(line, "[database]")
			continue
		}
		if !inSection {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "host":
			host = strings.TrimSpace(val)
		case "user":
			user = strings.TrimSpace(val)
		case "password":
			password = grafanaIniUnquote(val)
			ok = true
		}
	}
	return host, user, password, ok
}

// withGrafanaDBPassword sets the [database] password and reports whether
// anything changed. Only that one key is touched: another section's `password`
// key, and every other line, is returned as it was. An ini with no [database]
// password, or one already holding the value, is returned unchanged.
func withGrafanaDBPassword(ini, password string) (string, bool) {
	if _, _, current, ok := grafanaDBSettings(ini); !ok || current == password {
		return ini, false
	}
	lines := strings.Split(ini, "\n")
	inSection := false
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			inSection = strings.EqualFold(line, "[database]")
			continue
		}
		if !inSection {
			continue
		}
		key, _, found := strings.Cut(line, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "password") {
			lines[i] = "password = " + grafanaIniValue(password)
			return strings.Join(lines, "\n"), true
		}
	}
	return ini, false
}

// backfillGrafanaDBPassword brings Grafana's database password in line with the
// password the daemon resolves for itself (#2091). Until the template was fixed
// it always wrote the compiled-in default, so a host whose Postgres role has
// been rotated left Grafana holding a password that no longer works.
//
// It runs on every start against an existing container and is a no-op once the
// two agree. The write is guarded: it only happens when the daemon's password
// actually connects to Grafana's database. On a host rotated by hand, where
// Grafana already holds the working password and the daemon's environment
// still resolves to something else, the test fails and Grafana is left alone —
// overwriting it would take Grafana's database offline.
//
// Failures are logged, not fatal, like the other Grafana backfills: core
// services must come up regardless, and the next start tries again.
func (cs *CoreServices) backfillGrafanaDBPassword() {
	raw, err := cs.incusClient.ReadFile(CoreVictoriaMetricsContainer, grafanaIniPath)
	if err != nil {
		log.Printf("Warning: could not read %s on %s to check Grafana's database password: %v", grafanaIniPath, CoreVictoriaMetricsContainer, err)
		return
	}
	ini := string(raw)
	host, user, current, ok := grafanaDBSettings(ini)
	if !ok || host == "" || user == "" {
		return
	}
	want := cs.config.PostgresPassword
	if want == "" || current == want {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cs.pgPing(ctx, pgPingArgs{Host: host, User: user, Password: want, Database: grafanaDBName}); err != nil {
		log.Printf("Note: Grafana's database password differs from the daemon's, but the daemon's does not connect to the %q database (%v); leaving grafana.ini as it is", grafanaDBName, err)
		return
	}

	fixed, changed := withGrafanaDBPassword(ini, want)
	if !changed {
		return
	}
	if err := cs.incusClient.WriteFile(CoreVictoriaMetricsContainer, grafanaIniPath, []byte(fixed), "0644"); err != nil {
		log.Printf("Warning: failed to update Grafana's database password on %s: %v", CoreVictoriaMetricsContainer, err)
		return
	}
	if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, []string{"systemctl", "restart", "grafana-server"}); err != nil {
		log.Printf("Warning: grafana.ini updated but grafana-server restart failed on %s: %v (Grafana keeps the old database password until it restarts)", CoreVictoriaMetricsContainer, err)
		return
	}
	log.Printf("Updated Grafana's database password on %s to the daemon's effective one (#2091)", CoreVictoriaMetricsContainer)
}
