//go:build !windows

package cmd

import (
	"strings"
	"testing"
)

func TestRenderTunnelUnit_RequiredFlags(t *testing.T) {
	u := renderTunnelUnit(tunnelUnitParams{
		SentinelAddr: "sentinel.example.com:443",
		Token:        "tok-123",
		SpotID:       "node1",
		Ports:        "22,8080,443",
		Pool:         "prod",
	})
	for _, want := range []string{
		"--sentinel-addr sentinel.example.com:443",
		"--token tok-123",
		"--spot-id node1",
		"--ports 22,8080,443",
		"--pool prod",
		"WantedBy=multi-user.target",
		"Restart=always",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("tunnel unit missing %q\n---\n%s", want, u)
		}
	}
	// No public hostname requested → no public flags rendered.
	if strings.Contains(u, "--public-hostname") || strings.Contains(u, "--public-port") {
		t.Errorf("tunnel unit should not carry public-* flags when unset:\n%s", u)
	}
}

func TestRenderTunnelUnit_PublicPrimary(t *testing.T) {
	u := renderTunnelUnit(tunnelUnitParams{
		SentinelAddr:   "s:443",
		Token:          "t",
		SpotID:         "n",
		Ports:          "443",
		Pool:           "prod",
		PublicHostname: "node1.example.com",
		PublicPort:     443,
	})
	if !strings.Contains(u, "--public-hostname node1.example.com") {
		t.Errorf("missing --public-hostname:\n%s", u)
	}
	if !strings.Contains(u, "--public-port 443") {
		t.Errorf("missing --public-port:\n%s", u)
	}
}

func TestRenderPoolDropIn(t *testing.T) {
	// ExecStart must be cleared then re-set (systemd override semantics).
	argv := resolvePoolDaemonArgv(nil, false, "prod", "", nil)
	d := renderPoolDropIn(argv)
	if !strings.Contains(d, "ExecStart=\nExecStart=/usr/local/bin/containarium daemon") {
		t.Errorf("drop-in must clear+reset ExecStart:\n%s", d)
	}
	if !strings.Contains(d, "--pool prod") {
		t.Errorf("drop-in missing --pool:\n%s", d)
	}
	if strings.Contains(d, "--base-domain") {
		t.Errorf("drop-in should omit --base-domain when empty:\n%s", d)
	}
	d2 := renderPoolDropIn(resolvePoolDaemonArgv(nil, false, "prod", "boxes.example.com", nil))
	if !strings.Contains(d2, "--base-domain boxes.example.com") {
		t.Errorf("drop-in missing --base-domain when set:\n%s", d2)
	}
}

func TestResolvePoolDaemonArgv_FreshHostUsesMinimal(t *testing.T) {
	argv := resolvePoolDaemonArgv(nil, false, "prod", "", nil)
	got := strings.Join(argv, " ")
	want := "/usr/local/bin/containarium daemon --rest --jwt-secret-file /etc/containarium/jwt.secret --pool prod"
	if got != want {
		t.Errorf("fresh host argv = %q, want %q", got, want)
	}
}

func TestResolvePoolDaemonArgv_PreservesExistingFlags(t *testing.T) {
	// The #702 case: a host already running with extra flags must keep them.
	current := []string{
		"/usr/local/bin/containarium", "daemon", "--rest",
		"--jwt-secret-file", "/etc/containarium/jwt.secret",
		"--app-hosting", "--network-subnet", "10.0.5.0/24",
	}
	argv := resolvePoolDaemonArgv(current, true, "prod", "boxes.example.com", nil)
	got := strings.Join(argv, " ")
	for _, want := range []string{"--app-hosting", "--network-subnet 10.0.5.0/24", "--pool prod", "--base-domain boxes.example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("preserved argv missing %q\n got: %s", want, got)
		}
	}
}

func TestResolvePoolDaemonArgv_ReRunDoesNotDuplicateManagedFlags(t *testing.T) {
	// Re-running join (pool.conf already in effect) must re-set, not duplicate,
	// the managed flags — and must pick up a changed --base-domain / --pool.
	current := []string{
		"/usr/local/bin/containarium", "daemon", "--rest",
		"--jwt-secret-file", "/etc/containarium/jwt.secret",
		"--app-hosting", "--pool", "old", "--base-domain", "old.example.com",
	}
	argv := resolvePoolDaemonArgv(current, true, "new", "new.example.com", nil)
	got := strings.Join(argv, " ")
	if strings.Count(got, "--pool ") != 1 || strings.Count(got, "--base-domain ") != 1 {
		t.Errorf("managed flags must appear exactly once: %s", got)
	}
	if !strings.Contains(got, "--pool new") || !strings.Contains(got, "--base-domain new.example.com") {
		t.Errorf("managed flags must update to new values: %s", got)
	}
	if strings.Contains(got, "old") {
		t.Errorf("stale managed values must be stripped: %s", got)
	}
	if !strings.Contains(got, "--app-hosting") {
		t.Errorf("non-managed flag must survive: %s", got)
	}
}

func TestResolvePoolDaemonArgv_DaemonFlagOverride(t *testing.T) {
	argv := resolvePoolDaemonArgv(nil, false, "prod", "", []string{"--app-hosting", "--network-subnet=10.1.0.0/24"})
	got := strings.Join(argv, " ")
	if !strings.Contains(got, "--app-hosting") || !strings.Contains(got, "--network-subnet=10.1.0.0/24") {
		t.Errorf("operator --daemon-flag values must be appended: %s", got)
	}
}

func TestStripValuedFlag(t *testing.T) {
	cases := []struct {
		in   []string
		flag string
		want string
	}{
		{[]string{"daemon", "--pool", "prod", "--rest"}, "--pool", "daemon --rest"},
		{[]string{"daemon", "--pool=prod", "--rest"}, "--pool", "daemon --rest"},
		{[]string{"daemon", "--rest"}, "--pool", "daemon --rest"},
		{[]string{"daemon", "--base-domain", "x", "--base-domain", "y"}, "--base-domain", "daemon"},
	}
	for _, c := range cases {
		if got := strings.Join(stripValuedFlag(c.in, c.flag), " "); got != c.want {
			t.Errorf("stripValuedFlag(%v, %q) = %q, want %q", c.in, c.flag, got, c.want)
		}
	}
}

func TestParseExecStartArgv(t *testing.T) {
	out := "{ path=/usr/local/bin/containarium ; argv[]=/usr/local/bin/containarium daemon --rest --jwt-secret-file /etc/containarium/jwt.secret --app-hosting ; ignore_errors=no ; start_time=[n/a] }"
	argv, ok := parseExecStartArgv(out)
	if !ok {
		t.Fatalf("expected to parse argv from %q", out)
	}
	got := strings.Join(argv, " ")
	want := "/usr/local/bin/containarium daemon --rest --jwt-secret-file /etc/containarium/jwt.secret --app-hosting"
	if got != want {
		t.Errorf("parsed argv = %q, want %q", got, want)
	}
	// Empty / unrecognized values yield (nil, false).
	for _, bad := range []string{"", "{ path=/x ; argv[]= ; ignore_errors=no }", "{ argv[]=/usr/bin/other thing ; }"} {
		if _, ok := parseExecStartArgv(bad); ok {
			t.Errorf("parseExecStartArgv(%q) should be false", bad)
		}
	}
}
