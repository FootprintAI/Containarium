package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

func TestPostgresHBALines(t *testing.T) {
	t.Run("daemon and grafana only, each a /32, scram, tagged", func(t *testing.T) {
		got, err := postgresHBALines("containarium", "10.100.0.1", "10.100.0.239")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d lines, want 2: %v", len(got), got)
		}
		want := []struct{ db, ip string }{{"all", "10.100.0.1/32"}, {"grafana", "10.100.0.239/32"}}
		for i, w := range want {
			f := strings.Fields(got[i])
			// host <db> <user> <addr> <method> # tag
			if len(f) < 5 || f[0] != "host" || f[1] != w.db || f[2] != "containarium" || f[3] != w.ip || f[4] != "scram-sha-256" {
				t.Errorf("line %d = %q, want host %s containarium %s scram-sha-256", i, got[i], w.db, w.ip)
			}
			if !strings.HasSuffix(got[i], hbaMarker) {
				t.Errorf("line %d is not tagged %q, so the fallback could not find it: %q", i, hbaMarker, got[i])
			}
		}
	})
	t.Run("no grafana address → the daemon line only", func(t *testing.T) {
		got, err := postgresHBALines("containarium", "10.100.0.1", "")
		if err != nil || len(got) != 1 {
			t.Fatalf("lines=%v err=%v; want exactly the daemon line", got, err)
		}
	})
	t.Run("a subnet-wide rule is never produced", func(t *testing.T) {
		got, _ := postgresHBALines("containarium", "10.100.0.1", "10.100.0.239")
		for _, l := range got {
			if strings.Contains(l, "/24") || strings.Contains(l, "/16") || strings.Contains(l, "0.0.0.0") {
				t.Errorf("line allows more than one address: %q", l)
			}
		}
	})
	t.Run("values that reach a shell are validated", func(t *testing.T) {
		for _, tc := range []struct{ name, user, daemon, grafana string }{
			{"empty daemon address", "containarium", "", "10.100.0.239"},
			{"daemon not an IP", "containarium", "10.100.0.1; rm -rf /", ""},
			{"daemon is IPv6", "containarium", "fe80::1", ""},
			{"grafana not an IP", "containarium", "10.100.0.1", "x' >> /etc/passwd #"},
			{"user with a quote", "o'brien", "10.100.0.1", ""},
			{"user with a space", "two words", "10.100.0.1", ""},
			{"empty user", "", "10.100.0.1", ""},
		} {
			if got, err := postgresHBALines(tc.user, tc.daemon, tc.grafana); err == nil {
				t.Errorf("%s: expected an error, got lines %v", tc.name, got)
			}
		}
	})
}

// accessBox records every command run in the Postgres container and serves a
// scripted metrics container.
type accessBox struct {
	*incustest.MockBackend
	execs []string
}

func newAccessBox(vm *incus.ContainerInfo) *accessBox {
	b := &accessBox{MockBackend: incustest.NewMockBackend()}
	if vm != nil {
		b.Containers[CoreVictoriaMetricsContainer] = vm
	}
	b.ExecFunc = func(_ string, cmd []string) error {
		b.execs = append(b.execs, strings.Join(cmd, " "))
		return nil
	}
	return b
}

func (b *accessBox) ran(substr string) int {
	n := 0
	for _, e := range b.execs {
		if strings.Contains(e, substr) {
			n++
		}
	}
	return n
}

func (b *accessBox) restarts() int { return b.ran("systemctl restart postgresql") }

func newAccessServices(t *testing.T, b *accessBox, daemonIP string, daemonErr error, probe func(context.Context) error) *CoreServices {
	t.Helper()
	oldAddr, oldDelay := localAddrFor, postgresProbeRetryDelay
	localAddrFor = func(string) (string, error) { return daemonIP, daemonErr }
	postgresProbeRetryDelay = 0
	t.Cleanup(func() { localAddrFor, postgresProbeRetryDelay = oldAddr, oldDelay })

	cs := NewCoreServices(b, CoreServicesConfig{NetworkCIDR: "10.100.0.0/24", PostgresPassword: "pw"})
	cs.postgresIP = "10.100.0.242"
	cs.pgLoginProbe = probe
	return cs
}

func TestConfigurePostgresAccess(t *testing.T) {
	ok := func(context.Context) error { return nil }

	t.Run("scoped to the daemon and the running metrics container", func(t *testing.T) {
		b := newAccessBox(&incus.ContainerInfo{Name: CoreVictoriaMetricsContainer, IPAddress: "10.100.0.50", State: "Running"})
		cs := newAccessServices(t, b, "10.100.0.1", nil, ok)

		if err := cs.configurePostgresAccess(context.Background()); err != nil {
			t.Fatal(err)
		}
		if b.ran("10.100.0.1/32") != 1 || b.ran("10.100.0.50/32") != 1 {
			t.Fatalf("expected one rule each for the daemon and the metrics container (its actual address); execs:\n%s", strings.Join(b.execs, "\n"))
		}
		if b.ran("10.100.0.0/24") != 0 {
			t.Errorf("a subnet-wide rule was written:\n%s", strings.Join(b.execs, "\n"))
		}
		if b.ran("scram-sha-256") != 2 {
			t.Errorf("rules must use scram-sha-256:\n%s", strings.Join(b.execs, "\n"))
		}
		if b.ran("log_connections = on") != 1 {
			t.Errorf("connection logging was not turned on:\n%s", strings.Join(b.execs, "\n"))
		}
		if b.restarts() != 1 {
			t.Errorf("restarts = %d, want 1", b.restarts())
		}
	})

	t.Run("no metrics container yet → its pinned address", func(t *testing.T) {
		b := newAccessBox(nil)
		cs := newAccessServices(t, b, "10.100.0.1", nil, ok)

		if err := cs.configurePostgresAccess(context.Background()); err != nil {
			t.Fatal(err)
		}
		pinned, _ := coreStaticIP("10.100.0.0/24", CoreVictoriaMetricsContainer)
		if pinned == "" || b.ran(pinned+"/32") != 1 {
			t.Fatalf("expected a rule for the pinned address %q; execs:\n%s", pinned, strings.Join(b.execs, "\n"))
		}
	})

	t.Run("daemon cannot log in → falls back to the subnet rule and removes the scoped ones", func(t *testing.T) {
		b := newAccessBox(nil)
		cs := newAccessServices(t, b, "10.100.0.1", nil, func(context.Context) error { return errors.New("no pg_hba.conf entry") })

		if err := cs.configurePostgresAccess(context.Background()); err != nil {
			t.Fatalf("a failed lockout probe must not fail the install: %v", err)
		}
		if b.ran("10.100.0.0/24") != 1 {
			t.Fatalf("fallback rule missing:\n%s", strings.Join(b.execs, "\n"))
		}
		// The scoped lines must be removed, not left in front of the fallback:
		// pg_hba.conf is first-match, so a stale scoped line that still matches
		// the daemon would keep rejecting it.
		if b.ran("sed -i") < 1 || b.ran(hbaMarker) < 1 {
			t.Errorf("scoped rules were not removed before the fallback:\n%s", strings.Join(b.execs, "\n"))
		}
		if b.restarts() != 2 {
			t.Errorf("restarts = %d, want 2 (scoped, then fallback)", b.restarts())
		}
	})

	t.Run("daemon address cannot be determined → no scoped attempt", func(t *testing.T) {
		probeCalled := false
		b := newAccessBox(nil)
		cs := newAccessServices(t, b, "", errors.New("no route"), func(context.Context) error { probeCalled = true; return nil })

		if err := cs.configurePostgresAccess(context.Background()); err != nil {
			t.Fatal(err)
		}
		if b.ran("/32") != 0 {
			t.Errorf("scoped rules written without knowing the daemon's address:\n%s", strings.Join(b.execs, "\n"))
		}
		if b.ran("10.100.0.0/24") != 1 {
			t.Errorf("fallback rule missing:\n%s", strings.Join(b.execs, "\n"))
		}
		if probeCalled {
			t.Error("the login probe ran although nothing scoped was applied")
		}
	})

	t.Run("an unusable user name falls back instead of reaching a shell", func(t *testing.T) {
		b := newAccessBox(nil)
		cs := newAccessServices(t, b, "10.100.0.1", nil, ok)
		cs.config.PostgresUser = "o'brien"

		if err := cs.configurePostgresAccess(context.Background()); err != nil {
			t.Fatal(err)
		}
		if b.ran("o'brien") != 0 {
			t.Errorf("an unvalidated user name reached a command:\n%s", strings.Join(b.execs, "\n"))
		}
	})

	t.Run("a flaky first probe is retried before giving up", func(t *testing.T) {
		calls := 0
		b := newAccessBox(nil)
		cs := newAccessServices(t, b, "10.100.0.1", nil, func(context.Context) error {
			calls++
			if calls < 3 {
				return errors.New("connection refused")
			}
			return nil
		})

		if err := cs.configurePostgresAccess(context.Background()); err != nil {
			t.Fatal(err)
		}
		if b.ran("10.100.0.0/24") != 0 {
			t.Errorf("fell back although the third attempt succeeded:\n%s", strings.Join(b.execs, "\n"))
		}
	})
}

// The pg_hba rule for Grafana names an address before the metrics container
// exists, so creation must actually put the container on that address.
func TestPinCoreIP(t *testing.T) {
	cs := NewCoreServices(incustest.NewMockBackend(), CoreServicesConfig{NetworkCIDR: "10.100.0.0/24"})

	t.Run("a pinned container gets its address on the core bridge", func(t *testing.T) {
		cfg := incus.ContainerConfig{Name: CoreVictoriaMetricsContainer}
		cs.pinCoreIP(&cfg, CoreVictoriaMetricsContainer)

		if cfg.NIC == nil || cfg.NIC.IPv4Address != "10.100.0.239" || cfg.NIC.Network != coreBridgeName {
			t.Fatalf("NIC = %+v, want 10.100.0.239 on %s", cfg.NIC, coreBridgeName)
		}
		// The address the pg_hba rule names must be the one the container gets.
		if want := cs.grafanaClientIP(); want != cfg.NIC.IPv4Address {
			t.Errorf("grafanaClientIP() = %q but the container is pinned to %q", want, cfg.NIC.IPv4Address)
		}
	})
	t.Run("postgres is pinned too", func(t *testing.T) {
		cfg := incus.ContainerConfig{Name: CorePostgresContainer}
		cs.pinCoreIP(&cfg, CorePostgresContainer)
		if cfg.NIC == nil || cfg.NIC.IPv4Address != "10.100.0.240" {
			t.Fatalf("NIC = %+v", cfg.NIC)
		}
	})
	t.Run("an unpinned container stays on DHCP", func(t *testing.T) {
		cfg := incus.ContainerConfig{Name: CoreSecurityContainer}
		cs.pinCoreIP(&cfg, CoreSecurityContainer)
		if cfg.NIC != nil {
			t.Fatalf("NIC = %+v, want none", cfg.NIC)
		}
	})
	t.Run("an address that cannot be computed falls back to DHCP", func(t *testing.T) {
		small := NewCoreServices(incustest.NewMockBackend(), CoreServicesConfig{NetworkCIDR: "10.0.0.0/28"})
		cfg := incus.ContainerConfig{Name: CorePostgresContainer}
		small.pinCoreIP(&cfg, CorePostgresContainer)
		if cfg.NIC != nil {
			t.Fatalf("NIC = %+v, want none on a subnet too small for the offset", cfg.NIC)
		}
	})
}
