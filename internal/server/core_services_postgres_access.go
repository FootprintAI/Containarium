package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	pgConfPath = "/etc/postgresql/16/main/postgresql.conf"
	pgHbaPath  = "/etc/postgresql/16/main/pg_hba.conf"

	// hbaMarker tags every pg_hba.conf line this code writes, so the fallback
	// can find and remove exactly those lines and nothing an operator added.
	hbaMarker = "# containarium-core"

	// hbaGrafanaDB is the database Grafana's login is limited to.
	hbaGrafanaDB = "grafana"
)

var (
	// postgresProbeAttempts and postgresProbeRetryDelay bound how long a fresh
	// Postgres gets to accept the daemon's first login after a restart.
	postgresProbeAttempts   = 5
	postgresProbeRetryDelay = 2 * time.Second
	postgresRoleName        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	localAddrFor            = defaultLocalAddrFor // overridden in tests
)

// defaultLocalAddrFor returns the source address the kernel would use to reach
// remote. A UDP "connection" sends nothing; it only makes the kernel pick a
// route, which is exactly the address Postgres will see the daemon connect from
// (the bridge address). Reading it beats assuming the gateway is ".1".
func defaultLocalAddrFor(remote string) (string, error) {
	c, err := net.Dial("udp4", net.JoinHostPort(remote, strconv.Itoa(DefaultPostgresPort)))
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	addr, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return "", fmt.Errorf("no local address towards %s", remote)
	}
	return addr.IP.String(), nil
}

// postgresHBALines returns the pg_hba.conf lines that let exactly the core
// clients in: the daemon, for the databases its role owns, and the metrics
// container's Grafana for its own database. Each is one address (/32) and uses
// scram-sha-256. grafanaIP may be empty, in which case only the daemon line is
// returned.
//
// Every value ends up inside a shell command, so each is validated first:
// addresses must parse as IPv4 and the role name must be a plain identifier.
func postgresHBALines(user, daemonIP, grafanaIP string) ([]string, error) {
	if !postgresRoleName.MatchString(user) {
		return nil, fmt.Errorf("postgres role %q is not a plain identifier", user)
	}
	d, err := ipv4(daemonIP)
	if err != nil {
		return nil, fmt.Errorf("daemon address: %w", err)
	}
	lines := []string{hbaLine("all", user, d)}
	if grafanaIP != "" {
		g, err := ipv4(grafanaIP)
		if err != nil {
			return nil, fmt.Errorf("metrics container address: %w", err)
		}
		lines = append(lines, hbaLine(hbaGrafanaDB, user, g))
	}
	return lines, nil
}

func ipv4(s string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("%q is not an IPv4 address", s)
	}
	return ip.To4().String(), nil
}

func hbaLine(db, user, ip string) string {
	return fmt.Sprintf("host    %-15s %-15s %-18s scram-sha-256   %s", db, user, ip+"/32", hbaMarker)
}

// postgresHBABroadLine is the original subnet-wide rule, kept only as the
// fallback when the scoped rules cannot be applied or the daemon cannot log in.
func postgresHBABroadLine(cidr string) string {
	return fmt.Sprintf("host    all             all             %s            md5", cidr)
}

// grafanaClientIP is the address Grafana will connect from: the metrics
// container's actual address if it already exists, otherwise the address it is
// pinned to when it is created. Empty when neither is known.
func (cs *CoreServices) grafanaClientIP() string {
	if info, err := cs.incusClient.GetContainer(CoreVictoriaMetricsContainer); err == nil && info != nil && info.IPAddress != "" {
		return info.IPAddress
	}
	ip, err := coreStaticIP(cs.config.NetworkCIDR, CoreVictoriaMetricsContainer)
	if err != nil {
		return ""
	}
	return ip
}

// configurePostgresAccess is the access half of a first install: it turns on
// connection logging and writes pg_hba.conf so that only the core clients, not
// every box on the bridge, can try to log in.
//
// Tenants share the bridge with the core containers, and the previous rule
// admitted the whole subnet, so any tenant could reach a login prompt for the
// platform database. This narrows it to the daemon and Grafana.
//
// A wrong rule would lock the daemon out of its own database, and pg_isready
// (which waitForPostgres runs) cannot see that, so after applying the scoped
// rules it logs in as the daemon would. If that fails, the scoped lines are
// removed and the subnet rule is written instead: the install keeps working
// exactly as it did before, and the ERROR says what to look at.
func (cs *CoreServices) configurePostgresAccess(ctx context.Context) error {
	if err := cs.incusClient.Exec(CorePostgresContainer, []string{
		"bash", "-c", fmt.Sprintf("grep -q '^log_connections' %s || echo 'log_connections = on' >> %s", pgConfPath, pgConfPath),
	}); err != nil {
		return fmt.Errorf("failed to update postgresql.conf: %w", err)
	}

	daemonIP, err := localAddrFor(cs.postgresIP)
	if err != nil {
		log.Printf("Warning: not limiting pg_hba.conf to the core clients: cannot tell which address the daemon connects from (%v); using the subnet-wide rule", err)
		return cs.applyBroadHBA(ctx, false)
	}
	lines, err := postgresHBALines(cs.config.PostgresUser, daemonIP, cs.grafanaClientIP())
	if err != nil {
		log.Printf("Warning: not limiting pg_hba.conf to the core clients: %v; using the subnet-wide rule", err)
		return cs.applyBroadHBA(ctx, false)
	}

	for _, l := range lines {
		if err := cs.incusClient.Exec(CorePostgresContainer, []string{
			"bash", "-c", fmt.Sprintf("echo '%s' >> %s", l, pgHbaPath),
		}); err != nil {
			return fmt.Errorf("failed to update pg_hba.conf: %w", err)
		}
	}
	if err := cs.restartPostgresAndWait(ctx); err != nil {
		return err
	}

	if err := cs.probeDaemonLogin(ctx); err != nil {
		log.Printf("ERROR: the daemon cannot log in to PostgreSQL with the pg_hba.conf rules limited to %s (%v); "+
			"falling back to the subnet-wide rule. Check which address the daemon connects from.", daemonIP, err)
		return cs.applyBroadHBA(ctx, true)
	}
	log.Printf("PostgreSQL access limited to the daemon (%s) and the metrics container (%q); connection logging on", daemonIP, cs.grafanaClientIP())
	return nil
}

// applyBroadHBA writes the original subnet-wide rule. removeScoped first deletes
// the lines this code added: pg_hba.conf is first-match, so a scoped line that
// still matches the daemon would keep rejecting it in front of the fallback.
func (cs *CoreServices) applyBroadHBA(ctx context.Context, removeScoped bool) error {
	if removeScoped {
		if err := cs.incusClient.Exec(CorePostgresContainer, []string{
			"bash", "-c", fmt.Sprintf("sed -i '/%s$/d' %s", hbaMarker, pgHbaPath),
		}); err != nil {
			return fmt.Errorf("failed to remove the scoped pg_hba.conf rules: %w", err)
		}
	}
	if err := cs.incusClient.Exec(CorePostgresContainer, []string{
		"bash", "-c", fmt.Sprintf("echo '%s' >> %s", postgresHBABroadLine(cs.config.NetworkCIDR), pgHbaPath),
	}); err != nil {
		return fmt.Errorf("failed to update pg_hba.conf: %w", err)
	}
	return cs.restartPostgresAndWait(ctx)
}

func (cs *CoreServices) restartPostgresAndWait(ctx context.Context) error {
	if err := cs.incusClient.Exec(CorePostgresContainer, []string{"systemctl", "restart", "postgresql"}); err != nil {
		return fmt.Errorf("failed to restart postgresql: %w", err)
	}
	return cs.waitForPostgres(ctx)
}

// probeDaemonLogin logs in the way the daemon will, retrying briefly because a
// just-restarted Postgres can refuse connections for a moment.
func (cs *CoreServices) probeDaemonLogin(ctx context.Context) error {
	probe := cs.pgLoginProbe
	if probe == nil {
		probe = cs.postgresLogin
	}
	var err error
	for i := 0; i < postgresProbeAttempts; i++ {
		if err = probe(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(postgresProbeRetryDelay):
		}
	}
	return err
}

// postgresLogin opens one real connection over the network with the daemon's
// credentials and pings it.
func (cs *CoreServices) postgresLogin(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cs.config.PostgresUser, cs.config.PostgresPassword),
		Host:     net.JoinHostPort(cs.postgresIP, strconv.Itoa(DefaultPostgresPort)),
		Path:     "/" + cs.config.PostgresDB,
		RawQuery: "sslmode=disable&connect_timeout=5",
	}
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()
	return conn.Ping(ctx)
}
