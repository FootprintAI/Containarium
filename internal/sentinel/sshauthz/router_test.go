package sshauthz

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

// routerFixture writes a config.yaml in the shape keysync's
// renderSSHPiperConfig generates: alice trusts the CA and her own key, bob
// trusts only his own key and has no trusted_user_ca_keys line.
type routerFixture struct {
	dir, config    string
	alice, bob, ca ssh.Signer
	upstreamKey    []byte
}

func newRouterFixture(t *testing.T, extra string) routerFixture {
	t.Helper()
	f := routerFixture{dir: t.TempDir(), alice: testKey(t), bob: testKey(t), ca: testKey(t), upstreamKey: []byte("upstream-private-key")}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(f.dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	aliceKeys := write("users/alice/authorized_keys", ssh.MarshalAuthorizedKey(f.alice.PublicKey()))
	bobKeys := write("users/bob/authorized_keys", ssh.MarshalAuthorizedKey(f.bob.PublicKey()))
	caKeys := write("trusted_user_ca_keys", ssh.MarshalAuthorizedKey(f.ca.PublicKey()))
	upstream := write("upstream_key", f.upstreamKey)
	f.config = write("config.yaml", fmt.Appendf(nil, `version: "1.0"
pipes:
  - from:
      - username: "alice"
        authorized_keys:
          - %s
        trusted_user_ca_keys:
          - %s%s
    to:
      host: 192.0.2.10:2222
      username: "alice"
      ignore_hostkey: true
      private_key: %s
  - from:
      - username: "bob"
        authorized_keys:
          - %s
    to:
      host: 192.0.2.11:22
      username: "bob"
      ignore_hostkey: true
      private_key: %s
`, aliceKeys, caKeys, extra, upstream, bobKeys, upstream))
	return f
}

func routerCert(t *testing.T, key ssh.PublicKey, signer ssh.Signer, principal string, validBefore uint64) []byte {
	t.Helper()
	cert := &ssh.Certificate{Key: key, CertType: ssh.UserCert, ValidPrincipals: []string{principal}, ValidBefore: validBefore}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return cert.Marshal()
}

// The router must return what sshpiper's yaml plugin returns for the same
// config.yaml: the pipe's upstream when the key or certificate verifies, and
// an error (no upstream) otherwise.
func TestRouterMirrorsYAMLPlugin(t *testing.T) {
	f := newRouterFixture(t, "")
	stranger, untrusted := testKey(t), testKey(t)
	const expired = 1 // ValidBefore one second after the epoch
	for _, tt := range []struct {
		name, login string
		wire        []byte
		uri         string // "" expects a refusal
	}{
		{name: "authorized key", login: "alice", wire: f.alice.PublicKey().Marshal(), uri: "tcp://192.0.2.10:2222"},
		{name: "second pipe", login: "bob", wire: f.bob.PublicKey().Marshal(), uri: "tcp://192.0.2.11:22"},
		{name: "unknown key", login: "alice", wire: stranger.PublicKey().Marshal()},
		{name: "another login's key", login: "alice", wire: f.bob.PublicKey().Marshal()},
		{name: "no pipe for login", login: "mallory", wire: f.alice.PublicKey().Marshal()},
		{name: "certificate from trusted CA", login: "alice", wire: routerCert(t, stranger.PublicKey(), f.ca, "alice", ssh.CertTimeInfinity), uri: "tcp://192.0.2.10:2222"},
		{name: "certificate from untrusted CA", login: "alice", wire: routerCert(t, stranger.PublicKey(), untrusted, "alice", ssh.CertTimeInfinity)},
		{name: "certificate for another principal", login: "alice", wire: routerCert(t, stranger.PublicKey(), f.ca, "bob", ssh.CertTimeInfinity)},
		{name: "expired certificate", login: "alice", wire: routerCert(t, stranger.PublicKey(), f.ca, "alice", expired)},
		{name: "certificate on a pipe without CA trust", login: "bob", wire: routerCert(t, stranger.PublicKey(), f.ca, "bob", ssh.CertTimeInfinity)},
		{name: "CA key offered as a plain key", login: "alice", wire: f.ca.PublicKey().Marshal()},
		{name: "malformed key", login: "alice", wire: []byte("bad")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			up, err := NewRouter(f.config).Route(&libplugin.ConnMeta{UserName: tt.login, FromAddr: "203.0.113.1:1234", UniqId: "conn-1"}, tt.wire)
			if tt.uri == "" {
				if err == nil || up != nil {
					t.Fatalf("want refusal, got upstream %v err %v", up, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want upstream, got %v", err)
			}
			if up.GetOrGenerateUri() != tt.uri || up.UserName != tt.login || len(up.KnownHostsData) != 0 {
				t.Fatalf("upstream = %+v", up)
			}
			if pk := up.GetPrivateKey(); pk == nil || !bytes.Equal(pk.PrivateKey, f.upstreamKey) || len(pk.CaPublicKey) != 0 {
				t.Fatalf("upstream auth = %+v", up.Auth)
			}
		})
	}
}

// The router models only what keysync generates. A config it cannot read the
// way the yaml plugin would (a field outside that subset, an open file mode
// the yaml plugin rejects, or a missing file) refuses instead of guessing.
func TestRouterFailsClosedOnConfigItCannotMirror(t *testing.T) {
	for _, tt := range []struct {
		name  string
		extra string
		setup func(t *testing.T, f routerFixture)
	}{
		{name: "regex matching", extra: "\n        username_regex_match: true"},
		{name: "inline key data", extra: "\n        authorized_keys_data:\n          - Zm9v"},
		{name: "group-readable config", setup: func(t *testing.T, f routerFixture) {
			if err := os.Chmod(f.config, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing config", setup: func(t *testing.T, f routerFixture) {
			if err := os.Remove(f.config); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newRouterFixture(t, tt.extra)
			if tt.setup != nil {
				tt.setup(t, f)
			}
			up, err := NewRouter(f.config).Route(&libplugin.ConnMeta{UserName: "alice"}, f.alice.PublicKey().Marshal())
			if err == nil || up != nil {
				t.Fatalf("want refusal, got upstream %v err %v", up, err)
			}
		})
	}
}
