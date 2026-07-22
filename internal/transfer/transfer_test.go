package transfer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolve_UnresolvedSentinelIsTyped locks in that a missing sentinel
// (no field, no $CONTAINARIUM_SENTINEL_HOST) surfaces as ErrSentinelUnresolved
// so callers can errors.Is it and attach surface-specific guidance, and that
// the message points at the container's ssh_host rather than only the env var.
func TestResolve_UnresolvedSentinelIsTyped(t *testing.T) {
	t.Setenv("CONTAINARIUM_SENTINEL_HOST", "")
	opt := &Options{
		Username:  "alice",
		KeyPath:   writeKey(t),
		LocalPath: t.TempDir(),
	}
	err := opt.resolve()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSentinelUnresolved), "must be matchable with errors.Is")
	assert.Contains(t, err.Error(), "ssh_host", "message should point the caller at ssh_host")
}

// keyFile is a minimal test helper: writes a file at path so the
// readability check in Options.resolve() passes.
func writeKey(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "key-*")
	require.NoError(t, err)
	_, _ = f.WriteString("not a real ssh key — just satisfying the readability check\n")
	require.NoError(t, f.Close())
	return f.Name()
}

func TestResolve_TildePrefixExpands(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// "~" alone → /home/alice
		{"~", "/home/alice"},
		// "~/work" → /home/alice/work — the agent-feedback case
		{"~/work", "/home/alice/work"},
		// "~/nested/path" → /home/alice/nested/path
		{"~/nested/path", "/home/alice/nested/path"},
		// Absolute path stays absolute
		{"/srv/app", "/srv/app"},
		// "/home/alice/work" stays as-is
		{"/home/alice/work", "/home/alice/work"},
		// Tilde in the middle is NOT expanded — only a leading "~" or "~/".
		{"/srv/~/app", "/srv/~/app"},
	}
	keyPath := writeKey(t)
	cwd, _ := os.Getwd()
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			opt := &Options{
				Username:     "alice",
				SentinelHost: "host.example.com",
				KeyPath:      keyPath,
				LocalPath:    cwd,
				RemotePath:   c.in,
			}
			require.NoError(t, opt.resolve())
			assert.Equal(t, c.want, opt.RemotePath)
		})
	}
}

func TestResolve_DefaultRemotePathIsAbsolute(t *testing.T) {
	keyPath := writeKey(t)
	cwd, _ := os.Getwd()
	opt := &Options{
		Username:     "alice",
		SentinelHost: "host.example.com",
		KeyPath:      keyPath,
		LocalPath:    cwd,
	}
	require.NoError(t, opt.resolve())
	assert.Equal(t, "/home/alice/work", opt.RemotePath, "default must already be absolute")
}

func TestDefaultSyncExcludes_BlocksEnvFiles(t *testing.T) {
	// The agent-feedback case: sync silently clobbered the container's
	// .env with the laptop's .env. Defaults must catch the common
	// env-file shapes.
	for _, p := range []string{".env", ".env.local", ".env.production", ".envrc"} {
		assert.True(t, matchesAny(p, DefaultSyncExcludes),
			"DefaultSyncExcludes must filter %q", p)
	}
	// Don't over-block: a file containing "env" in its name should be fine.
	for _, p := range []string{"environment.go", "envoy/config.yaml", "test_env_helper.go"} {
		assert.False(t, matchesAny(p, DefaultSyncExcludes),
			"DefaultSyncExcludes should not filter %q", p)
	}
}

// TestSshBaseArgs_HostKeyCheckingIsAcceptNew locks in the fix for the
// security-sweep finding (issue #1060): host key checking must use
// accept-new against the default known_hosts, matching the pattern
// connectcore.BuildSSHArgs and sshexec.go's tofuHostKeyCallback already
// use elsewhere in this codebase — never StrictHostKeyChecking=no, and
// never a UserKnownHostsFile=/dev/null that would make accept-new a no-op.
func TestSshBaseArgs_HostKeyCheckingIsAcceptNew(t *testing.T) {
	opt := &Options{KeyPath: "/k/id"}
	joined := strings.Join(opt.sshBaseArgs(), " ")
	assert.Contains(t, joined, "StrictHostKeyChecking=accept-new")
	assert.NotContains(t, joined, "StrictHostKeyChecking=no")
	assert.NotContains(t, joined, "UserKnownHostsFile=/dev/null")
}

// keep these vars used so go vet doesn't complain
var _ = filepath.Separator
