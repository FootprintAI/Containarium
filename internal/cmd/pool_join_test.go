//go:build !windows && !containarium_client

package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
)

func TestRenderTunnelUnit_RequiredFlags(t *testing.T) {
	u := renderTunnelUnit(tunnelUnitParams{
		SentinelAddr: "sentinel.example.com:443",
		SpotID:       "node1",
		Ports:        "22,8080,443",
		Pool:         "prod",
	})
	for _, want := range []string{
		"--sentinel-addr sentinel.example.com:443",
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

// TestRenderTunnelUnit_TokenNeverInExecStart is the regression guard for
// #935: the tunnel-handshake token is a bearer-equivalent credential (the
// sentinel's TokenPolicy grants standing tunnel access to whoever presents
// it) and must never appear in the world-readable (0644) unit's ExecStart
// line — it's supplied via EnvironmentFile= instead (see
// tunnelTokenSecretFile), which `containarium tunnel` already reads as
// $CONTAINARIUM_TUNNEL_TOKEN.
func TestRenderTunnelUnit_TokenNeverInExecStart(t *testing.T) {
	u := renderTunnelUnit(tunnelUnitParams{
		SentinelAddr: "sentinel.example.com:443",
		SpotID:       "node1",
		Ports:        "22,8080,443",
		Pool:         "prod",
	})
	if strings.Contains(u, "--token") {
		t.Errorf("tunnel unit must not embed --token in ExecStart:\n%s", u)
	}
	if !strings.Contains(u, "EnvironmentFile="+tunnelTokenSecretFile) {
		t.Errorf("tunnel unit missing EnvironmentFile=%s:\n%s", tunnelTokenSecretFile, u)
	}
}

func TestRenderTunnelUnit_PublicPrimary(t *testing.T) {
	u := renderTunnelUnit(tunnelUnitParams{
		SentinelAddr:   "s:443",
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
	d := renderPoolDropIn(argv, "")
	if !strings.Contains(d, "ExecStart=\nExecStart=/usr/local/bin/containariumd daemon") {
		t.Errorf("drop-in must clear+reset ExecStart:\n%s", d)
	}
	if !strings.Contains(d, "--pool prod") {
		t.Errorf("drop-in missing --pool:\n%s", d)
	}
	if strings.Contains(d, "--base-domain") {
		t.Errorf("drop-in should omit --base-domain when empty:\n%s", d)
	}
	if strings.Contains(d, "EnvironmentFile") {
		t.Errorf("drop-in should omit EnvironmentFile when no auth secret file given:\n%s", d)
	}
	d2 := renderPoolDropIn(resolvePoolDaemonArgv(nil, false, "prod", "boxes.example.com", nil), "")
	if !strings.Contains(d2, "--base-domain boxes.example.com") {
		t.Errorf("drop-in missing --base-domain when set:\n%s", d2)
	}
}

// TestRenderPoolDropIn_SentinelAuthSecret pins #687's fix: the drop-in must
// reference the auth-secret file via EnvironmentFile=, never embed the
// secret value inline (the drop-in itself stays 0644/world-readable).
func TestRenderPoolDropIn_SentinelAuthSecret(t *testing.T) {
	argv := resolvePoolDaemonArgv(nil, false, "prod", "", nil)
	d := renderPoolDropIn(argv, "/etc/containarium/sentinel-auth.env")
	if !strings.Contains(d, "EnvironmentFile=/etc/containarium/sentinel-auth.env") {
		t.Errorf("drop-in missing EnvironmentFile directive:\n%s", d)
	}
	if strings.Contains(d, "CONTAINARIUM_SENTINEL_AUTH_SECRET") {
		t.Errorf("drop-in must never embed the secret value inline:\n%s", d)
	}
}

// #959: pool join always warned --sentinel-auth-secret wasn't set for THIS
// invocation, even when the host already has it durably provisioned via an
// existing EnvironmentFile= drop-in (the documented, expected way — you
// provision it once, not on every join). These tests cover the detection
// helper directly.

func writeSecretFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestSentinelAuthSecretFileHasValue(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"real secret", "CONTAINARIUM_SENTINEL_AUTH_SECRET=abcdefghijklmnopqrstuvwxyz012345\n", true},
		{"empty value", "CONTAINARIUM_SENTINEL_AUTH_SECRET=\n", false},
		{"whitespace-only value", "CONTAINARIUM_SENTINEL_AUTH_SECRET=   \n", false},
		{"key absent entirely", "SOME_OTHER_VAR=x\n", false},
		{"value on a later line, with a comment above", "# managed by pool join\nCONTAINARIUM_SENTINEL_AUTH_SECRET=abcdefghijklmnopqrstuvwxyz012345\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSecretFile(t, dir, tt.name+".env", tt.content)
			if got := sentinelAuthSecretFileHasValue(path); got != tt.want {
				t.Errorf("sentinelAuthSecretFileHasValue(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}

	t.Run("file does not exist", func(t *testing.T) {
		if sentinelAuthSecretFileHasValue(filepath.Join(dir, "does-not-exist.env")) {
			t.Error("want false for a missing file")
		}
	})
}

func TestFindExistingSentinelAuthSecretFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.env")
	empty := writeSecretFile(t, dir, "empty.env", "CONTAINARIUM_SENTINEL_AUTH_SECRET=\n")
	real := writeSecretFile(t, dir, "real.env", "CONTAINARIUM_SENTINEL_AUTH_SECRET=abcdefghijklmnopqrstuvwxyz012345\n")

	t.Run("finds the first usable candidate", func(t *testing.T) {
		got := findExistingSentinelAuthSecretFile([]string{missing, empty, real})
		if got != real {
			t.Errorf("got %q, want %q", got, real)
		}
	})

	t.Run("none usable returns empty", func(t *testing.T) {
		got := findExistingSentinelAuthSecretFile([]string{missing, empty})
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("no candidates returns empty", func(t *testing.T) {
		if got := findExistingSentinelAuthSecretFile(nil); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

func TestResolvePoolDaemonArgv_FreshHostUsesMinimal(t *testing.T) {
	argv := resolvePoolDaemonArgv(nil, false, "prod", "", nil)
	got := strings.Join(argv, " ")
	want := "/usr/local/bin/containariumd daemon --rest --jwt-secret-file /etc/containarium/jwt.secret --pool prod"
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

// TestParseExecStartArgv_RecognizesContainariumd is #1780's fix: a host
// mid-rollout may already be running the post-flip unit
// (/usr/local/bin/containariumd) when `pool join` re-runs, and #702's
// flag-preservation must still recognize it as the daemon command rather
// than falling back to the minimal baseline and silently dropping flags.
func TestParseExecStartArgv_RecognizesContainariumd(t *testing.T) {
	out := "{ path=/usr/local/bin/containariumd ; argv[]=/usr/local/bin/containariumd daemon --rest --jwt-secret-file /etc/containarium/jwt.secret --app-hosting ; ignore_errors=no }"
	argv, ok := parseExecStartArgv(out)
	if !ok {
		t.Fatalf("expected to parse argv from %q", out)
	}
	got := strings.Join(argv, " ")
	want := "/usr/local/bin/containariumd daemon --rest --jwt-secret-file /etc/containarium/jwt.secret --app-hosting"
	if got != want {
		t.Errorf("parsed argv = %q, want %q", got, want)
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

// TestPoolJoinFlags_TokenFileExists confirms the --token-file flag is
// registered (#1961) alongside the pre-existing --token, so a provisioner
// has a way to supply the join token that never lands on argv.
func TestPoolJoinFlags_TokenFileExists(t *testing.T) {
	if poolJoinCmd.Flags().Lookup("token-file") == nil {
		t.Fatal("expected a --token-file flag on pool join")
	}
	if poolJoinCmd.Flags().Lookup("token") == nil {
		t.Fatal("expected the --token flag to still exist on pool join (backward compatibility)")
	}
}

// TestResolvePoolJoinToken covers #1961's intake precedence for the join
// token: --token-file (read + trimmed, mirroring `cloud enroll`'s own
// semantics) beats $CONTAINARIUM_TUNNEL_TOKEN, which beats the legacy
// --token flag on argv. An empty/missing --token-file is always an error,
// even when a lower-precedence source would otherwise supply a token —
// a provisioner that got the path wrong should see that immediately, not
// silently fall through to a stale env var or flag.
func TestResolvePoolJoinToken(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeSecretFile(t, dir, "token.env", "file-token\n")
	whitespaceOnlyFile := writeSecretFile(t, dir, "empty.env", "   \n")
	missingFile := filepath.Join(dir, "does-not-exist.env")

	tests := []struct {
		name      string
		tokenFlag string
		tokenFile string
		env       string
		want      string
		wantErr   bool
	}{
		{
			name:      "token-file wins over both the env var and --token",
			tokenFlag: "flag-token",
			tokenFile: tokenFile,
			env:       "env-token",
			want:      "file-token",
		},
		{
			name:      "token-file trims surrounding whitespace/newline",
			tokenFile: tokenFile,
			want:      "file-token",
		},
		{
			name:      "empty (whitespace-only) token-file errors",
			tokenFile: whitespaceOnlyFile,
			wantErr:   true,
		},
		{
			name:      "missing token-file errors",
			tokenFile: missingFile,
			wantErr:   true,
		},
		{
			name:      "env var used when --token-file is absent",
			tokenFlag: "flag-token",
			env:       "env-token",
			want:      "env-token",
		},
		{
			name:      "--token used as the last resort",
			tokenFlag: "flag-token",
			want:      "flag-token",
		},
		{
			name:    "nothing provided errors",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CONTAINARIUM_TUNNEL_TOKEN", tt.env)
			got, err := resolvePoolJoinToken(tt.tokenFlag, tt.tokenFile)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolvePoolJoinToken(%q, %q) = %q, nil; want an error", tt.tokenFlag, tt.tokenFile, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePoolJoinToken(%q, %q): unexpected error: %v", tt.tokenFlag, tt.tokenFile, err)
			}
			if got != tt.want {
				t.Errorf("resolvePoolJoinToken(%q, %q) = %q, want %q", tt.tokenFlag, tt.tokenFile, got, tt.want)
			}
		})
	}
}
