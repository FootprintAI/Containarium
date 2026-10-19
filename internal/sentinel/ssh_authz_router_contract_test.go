package sentinel

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

// Contract: the enforce-mode router reads the config.yaml renderSSHPiperConfig
// actually writes. The router refuses fields outside the subset it models, so
// a renderer change it cannot read fails here, not as refused logins.
func TestSSHAuthzRouterReadsRenderedConfig(t *testing.T) {
	newKey := func() ssh.Signer {
		t.Helper()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return signer
	}
	alice, bob, ca := newKey(), newKey(), newKey()

	// Render with the production paths, then move them under a temp dir:
	// the test cannot write /etc/sshpiper.
	dir := t.TempDir()
	rendered := string(renderSSHPiperConfig([]userRoute{
		{username: "alice", backendIP: "192.0.2.10", sshPort: 2222},
		{username: "bob", backendIP: "192.0.2.11"},
	}, sshpiperTrustedUserCAKeys))
	if !strings.Contains(rendered, sshpiperConfigDir+"/") {
		t.Fatalf("rendered config has no %s paths:\n%s", sshpiperConfigDir, rendered)
	}
	rendered = strings.ReplaceAll(rendered, sshpiperConfigDir+"/", dir+"/")
	write := func(path string, data []byte) {
		t.Helper()
		path = strings.Replace(path, sshpiperConfigDir, dir, 1)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(sshpiperUsersDir, "alice", "authorized_keys"), ssh.MarshalAuthorizedKey(alice.PublicKey()))
	write(filepath.Join(sshpiperUsersDir, "bob", "authorized_keys"), ssh.MarshalAuthorizedKey(bob.PublicKey()))
	write(sshpiperTrustedUserCAKeys, ssh.MarshalAuthorizedKey(ca.PublicKey()))
	write(sshpiperUpstreamKey, []byte("upstream-private-key"))
	write(sshpiperConfigFile, []byte(rendered))

	cert := &ssh.Certificate{Key: newKey().PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	router := sshauthz.NewRouter(strings.Replace(sshpiperConfigFile, sshpiperConfigDir, dir, 1))
	for _, tt := range []struct {
		name, login, uri string // uri "" expects a refusal
		wire             []byte
	}{
		{name: "authorized key, advertised port", login: "alice", wire: alice.PublicKey().Marshal(), uri: "tcp://192.0.2.10:2222"},
		{name: "authorized key, legacy port", login: "bob", wire: bob.PublicKey().Marshal(), uri: "tcp://192.0.2.11:22"},
		{name: "certificate from trusted CA", login: "alice", wire: cert.Marshal(), uri: "tcp://192.0.2.10:2222"},
		{name: "another login's key", login: "bob", wire: alice.PublicKey().Marshal()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			up, err := router.Route(&libplugin.ConnMeta{UserName: tt.login}, tt.wire)
			if tt.uri == "" {
				if err == nil || up != nil {
					t.Fatalf("want refusal, got upstream %v err %v", up, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("router refused the rendered config: %v\n%s", err, rendered)
			}
			if pk := up.GetPrivateKey(); up.GetOrGenerateUri() != tt.uri || up.UserName != tt.login || pk == nil || string(pk.PrivateKey) != "upstream-private-key" {
				t.Fatalf("upstream = %+v", up)
			}
		})
	}
}
