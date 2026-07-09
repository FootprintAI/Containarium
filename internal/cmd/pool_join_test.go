//go:build !windows

package cmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
)

// testCmd returns a *cobra.Command with a real context — a bare
// &cobra.Command{} has a nil Context() (unlike OutOrStdout/ErrOrStderr,
// which do fall back), which panics deep inside net/context on first use.
func testCmd() *cobra.Command {
	c := &cobra.Command{}
	c.SetContext(context.Background())
	return c
}

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

// TestCloudEnrollAfterPoolJoin_RedeemsSameToken locks in the containarium-cloud#799
// fix: `pool join --cloud-control-plane` chains the SAME join token into
// EnrollHost, with oss_backend_id derived as "tunnel-"+spotID (matching the
// sentinel's own OnTunnelConnect prefixing) — not left for the operator to
// separately discover and pass by hand.
func TestCloudEnrollAfterPoolJoin_RedeemsSameToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // isolate cloud.Save's ~/.containarium/cloud.yaml write

	var got cloudv1.EnrollHostRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/actuation/enroll" {
			t.Errorf("path = %s, want /v1/actuation/enroll", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = protojson.Unmarshal(raw, &got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hostId":"host-abc"}`))
	}))
	defer srv.Close()

	cmd := testCmd()
	err := cloudEnrollAfterPoolJoin(cmd, srv.URL, "host-abc.secret", "tunnel-lab-node1", false)
	if err != nil {
		t.Fatalf("cloudEnrollAfterPoolJoin: %v", err)
	}
	if got.GetJoinToken() != "host-abc.secret" {
		t.Errorf("server saw join_token = %q, want the same token pool join used", got.GetJoinToken())
	}
	if got.GetOssBackendId() != "tunnel-lab-node1" {
		t.Errorf("server saw oss_backend_id = %q, want tunnel-lab-node1", got.GetOssBackendId())
	}
}

// TestCloudEnrollAfterPoolJoin_SurfacesServerError ensures a failed enroll
// (e.g. expired/redeemed token) is returned as an error, not swallowed —
// runPoolJoin's caller is what decides to downgrade it to a warning.
func TestCloudEnrollAfterPoolJoin_SurfacesServerError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":9,"message":"join token expired"}`))
	}))
	defer srv.Close()

	cmd := testCmd()
	if err := cloudEnrollAfterPoolJoin(cmd, srv.URL, "host-abc.secret", "tunnel-lab-node1", false); err == nil {
		t.Fatal("expected an error from an expired join token, got nil")
	}
}

// TestPoolJoinFlags_CloudControlPlaneIsOptOut confirms the cloud-enroll
// chaining flags exist and default to off — a plain OSS pool join with no
// --cloud-control-plane must not attempt any cloud call.
func TestPoolJoinFlags_CloudControlPlaneIsOptOut(t *testing.T) {
	if poolJoinCmd.Flags().Lookup("cloud-control-plane") == nil {
		t.Fatal("expected a --cloud-control-plane flag on pool join")
	}
	if poolJoinCmd.Flags().Lookup("cloud-insecure") == nil {
		t.Fatal("expected a --cloud-insecure flag on pool join")
	}
	if poolJoinCloudControlPlane != "" {
		t.Errorf("--cloud-control-plane default = %q, want empty (opt-in)", poolJoinCloudControlPlane)
	}
}
