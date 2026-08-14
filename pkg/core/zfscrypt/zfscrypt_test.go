package zfscrypt

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/zfskey"
)

// fakeRunner records every zfs invocation and replays canned responses.
//
// It proves the orchestration, not ZFS's own semantics — see the package
// doc and #1200. Where a test depends on how real ZFS behaves, that
// assumption is named in the test so it can be checked against a pool.
type fakeRunner struct {
	calls  [][]string
	stdins [][]byte

	// responses, keyed by the zfs subcommand (calls[0]).
	stdout map[string]string
	stderr map[string]string
	errs   map[string]error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		stdout: map[string]string{},
		stderr: map[string]string{},
		errs:   map[string]error{},
	}
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, args ...string) (string, string, error) {
	f.calls = append(f.calls, args)
	// Copy: the caller may reuse or zero its buffer.
	cp := make([]byte, len(stdin))
	copy(cp, stdin)
	f.stdins = append(f.stdins, cp)

	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	return f.stdout[sub], f.stderr[sub], f.errs[sub]
}

func (f *fakeRunner) lastCall() []string {
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

// ran reports whether any invocation's joined args contain the substring.
func (f *fakeRunner) ran(substr string) bool {
	return strings.Contains(f.allArgs(), substr)
}

func (f *fakeRunner) allArgs() string {
	var b strings.Builder
	for _, c := range f.calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteString("\n")
	}
	return b.String()
}

func testKey(t *testing.T, fill byte) zfskey.Key {
	t.Helper()
	k, err := zfskey.NewKey(bytes.Repeat([]byte{fill}, zfskey.KeyLen))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

// AC (#1199): key material is piped to zfs via stdin — never on argv,
// never in a temp file.
//
// argv is world-readable through /proc/<pid>/cmdline for the life of the
// process, so a key there is a key disclosed to every local user. This
// is the single most important property in the package.
func TestKeyMaterialNeverReachesArgv(t *testing.T) {
	key := testKey(t, 0xAB)
	raw := string(key.Bytes())

	for _, tc := range []struct {
		name string
		call func(*Manager) error
	}{
		{"create", func(m *Manager) error {
			return m.CreateEncrypted(context.Background(), "pool/containers/alice", key)
		}},
		{"load", func(m *Manager) error {
			return m.LoadKey(context.Background(), "pool/containers/alice", key)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunner()
			f.stdout["get"] = "unavailable" // so LoadKey proceeds
			m := NewManager(f)

			if err := tc.call(m); err != nil {
				t.Fatalf("call: %v", err)
			}

			args := f.allArgs()
			if strings.Contains(args, raw) {
				t.Error("key material appeared on argv — readable via /proc/<pid>/cmdline")
			}
			// Also catch it hidden inside a keylocation value.
			for _, c := range f.calls {
				for _, a := range c {
					if strings.Contains(a, raw) {
						t.Errorf("key material embedded in argument %q", a)
					}
				}
			}

			// It must have gone somewhere: stdin.
			var sawKeyOnStdin bool
			for _, in := range f.stdins {
				if bytes.Equal(in, key.Bytes()) {
					sawKeyOnStdin = true
				}
			}
			if !sawKeyOnStdin {
				t.Error("key was never written to stdin — it has to reach zfs somehow")
			}
			if !strings.Contains(args, "file:///dev/stdin") {
				t.Error("zfs was not pointed at stdin for the key")
			}
		})
	}
}

// The create command must actually request encryption. A dataset created
// without these properties is plaintext, and every later check would
// still pass.
func TestCreateEncryptedRequestsNativeEncryption(t *testing.T) {
	f := newFakeRunner()
	m := NewManager(f)

	if err := m.CreateEncrypted(context.Background(), "pool/containers/alice", testKey(t, 1)); err != nil {
		t.Fatalf("CreateEncrypted: %v", err)
	}

	args := strings.Join(f.lastCall(), " ")
	for _, want := range []string{"create", "encryption=on", "keyformat=raw", "pool/containers/alice"} {
		if !strings.Contains(args, want) {
			t.Errorf("create is missing %q: %s", want, args)
		}
	}
}

// An empty key must never produce a dataset — that would be an
// unencrypted container the caller believes is encrypted.
func TestCreateAndLoadRejectAnEmptyKey(t *testing.T) {
	f := newFakeRunner()
	m := NewManager(f)

	if err := m.CreateEncrypted(context.Background(), "pool/c/alice", zfskey.Key{}); err == nil {
		t.Error("CreateEncrypted accepted an empty key")
	}
	if err := m.LoadKey(context.Background(), "pool/c/alice", zfskey.Key{}); err == nil {
		t.Error("LoadKey accepted an empty key")
	}
	if len(f.calls) != 0 {
		t.Errorf("refusal must happen before any zfs runs, got %v", f.calls)
	}
}

// Dataset names are validated before they become command arguments. A
// leading dash would be parsed as a flag, and a bare name is the pool
// root — destroying or re-keying that is never what the caller meant.
func TestDatasetNameValidation(t *testing.T) {
	for _, name := range []string{"", "-o", "pool", "pool/with space", "pool/with\nnewline"} {
		t.Run("name="+name, func(t *testing.T) {
			f := newFakeRunner()
			m := NewManager(f)
			if err := m.CreateEncrypted(context.Background(), name, testKey(t, 1)); err == nil {
				t.Errorf("accepted dataset name %q", name)
			}
			if len(f.calls) != 0 {
				t.Error("a rejected name must not reach zfs")
			}
		})
	}
}

// LoadKey is idempotent: a daemon restart re-runs the pre-start hook
// against a container whose key is already resident, and that must
// succeed rather than error.
func TestLoadKeyIsANoOpWhenAlreadyLoaded(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "available"
	m := NewManager(f)

	if err := m.LoadKey(context.Background(), "pool/c/alice", testKey(t, 1)); err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if strings.Contains(f.allArgs(), "load-key") {
		t.Error("load-key ran despite the key already being available")
	}
}

// AC (#1201): unloading must tolerate "still in use" — a tenant's other
// container is legitimately still running under the same encryptionroot.
func TestUnloadKeyReportsInUseDistinctly(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "available"
	f.errs["unload-key"] = errors.New("exit status 1")
	f.stderr["unload-key"] = "cannot unload key for 'pool/c/alice': dataset is busy"
	m := NewManager(f)

	err := m.UnloadKey(context.Background(), "pool/c/alice")
	if !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("err = %v, want ErrKeyInUse — a co-tenant still running is not a failure", err)
	}
}

// A genuine unload failure is not swallowed as "in use".
func TestUnloadKeySurfacesRealFailures(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "available"
	f.errs["unload-key"] = errors.New("exit status 1")
	f.stderr["unload-key"] = "cannot open 'pool/c/alice': permission denied"
	m := NewManager(f)

	err := m.UnloadKey(context.Background(), "pool/c/alice")
	if err == nil || errors.Is(err, ErrKeyInUse) {
		t.Fatalf("err = %v, want a real error", err)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("zfs's own message should survive, got %q", err)
	}
}

// Unloading an already-ciphertext dataset is a no-op, so the post-stop
// hook can run unconditionally.
func TestUnloadKeyIsANoOpWhenAlreadyUnavailable(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "unavailable"
	m := NewManager(f)

	if err := m.UnloadKey(context.Background(), "pool/c/alice"); err != nil {
		t.Fatalf("UnloadKey: %v", err)
	}
	if strings.Contains(f.allArgs(), "unload-key") {
		t.Error("unload-key ran against an already-unavailable key")
	}
}

func TestKeyStatusParsing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		out     string
		want    KeyStatus
		wantErr bool
	}{
		{"available", "available\n", KeyAvailable, false},
		{"unavailable", "unavailable\n", KeyUnavailable, false},
		{"unencrypted dataset", "-\n", "", true},
		{"empty", "", "", true},
		{"unrecognised", "sideways\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunner()
			f.stdout["get"] = tc.out
			m := NewManager(f)

			got, err := m.KeyStatus(context.Background(), "pool/c/alice")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error for keystatus %q", tc.out)
				}
				return
			}
			if err != nil {
				t.Fatalf("KeyStatus: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Two tenants must never land on the same encryptionroot — that is the
// isolation claim. This test pins the accessor; the daemon-side dataset
// naming that makes it true is #1199's wiring.
func TestEncryptionRoot(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "pool/containers/alice\n"
	m := NewManager(f)

	root, err := m.EncryptionRoot(context.Background(), "pool/containers/alice/sub")
	if err != nil {
		t.Fatalf("EncryptionRoot: %v", err)
	}
	if root != "pool/containers/alice" {
		t.Errorf("root = %q", root)
	}

	f2 := newFakeRunner()
	f2.stdout["get"] = "-\n"
	if _, err := NewManager(f2).EncryptionRoot(context.Background(), "pool/c/bob"); err == nil {
		t.Error("an unencrypted dataset must not report an encryptionroot")
	}
}

// Exists distinguishes "absent" from "the command failed", so the
// create path can tell a missing dataset from a broken pool.
func TestExists(t *testing.T) {
	f := newFakeRunner()
	f.errs["list"] = errors.New("exit status 1")
	f.stderr["list"] = "cannot open 'pool/c/alice': dataset does not exist"
	m := NewManager(f)

	got, err := m.Exists(context.Background(), "pool/c/alice")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if got {
		t.Error("reported an absent dataset as present")
	}

	f2 := newFakeRunner()
	f2.errs["list"] = errors.New("exit status 1")
	f2.stderr["list"] = "cannot open pool: I/O error"
	if _, err := NewManager(f2).Exists(context.Background(), "pool/c/alice"); err == nil {
		t.Error("a broken pool must be an error, not 'absent'")
	}
}

// EnsureParent exists because a tenant encryptionroot is created at
// <root>/<tenant>, and `zfs create` does not make intermediate datasets.
// The daemon derives that root from its storage pool, so on a fresh host the
// intermediate does not exist and every encrypted create failed with "parent
// does not exist" — caught by the incus lane in #1341, not by any unit test.
func TestEnsureParent(t *testing.T) {
	t.Run("creates the chain when the parent is absent", func(t *testing.T) {
		r := newFakeRunner()
		r.errs["list"] = errors.New("exit status 1")
		r.stderr["list"] = "cannot open 'tank/tenants': dataset does not exist"
		m := NewManager(r)

		if err := m.EnsureParent(context.Background(), "tank/tenants/alice"); err != nil {
			t.Fatalf("EnsureParent: %v", err)
		}
		if !r.ran("create -p tank/tenants") {
			t.Errorf("the parent chain was not created; calls=%v", r.calls)
		}
	})

	t.Run("an existing parent is left alone", func(t *testing.T) {
		r := newFakeRunner()
		m := NewManager(r)

		if err := m.EnsureParent(context.Background(), "tank/tenants/alice"); err != nil {
			t.Fatalf("EnsureParent: %v", err)
		}
		if r.ran("create") {
			t.Errorf("an existing parent was re-created; calls=%v", r.calls)
		}
	})

	// A pool root always exists — creating it is neither possible nor
	// meaningful, and `zfs create tank` would fail.
	t.Run("a bare pool parent is a no-op", func(t *testing.T) {
		r := newFakeRunner()
		m := NewManager(r)

		if err := m.EnsureParent(context.Background(), "tank/alice"); err != nil {
			t.Fatalf("EnsureParent: %v", err)
		}
		if len(r.calls) != 0 {
			t.Errorf("zfs was invoked for a pool root; calls=%v", r.calls)
		}
	})
}
