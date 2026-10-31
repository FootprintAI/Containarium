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
	"golang.org/x/crypto/ssh/knownhosts"
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

	cert := &ssh.Certificate{Key: newKey().PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}

	// Both renderer branches: production renders without a CA path until a
	// CA bundle is installed (sshpiperCAKeysPath), and with it afterwards.
	for _, variant := range []struct {
		name, caPath string
	}{
		{name: "with CA trust", caPath: sshpiperTrustedUserCAKeys},
		{name: "without CA trust"},
	} {
		t.Run(variant.name, func(t *testing.T) {
			// Render with the production paths, then move them under a temp
			// dir: the test cannot write /etc/sshpiper.
			dir := t.TempDir()
			rendered := string(renderSSHPiperConfig([]userRoute{
				{username: "alice", backendIP: "192.0.2.10", sshPort: 2222},
				{username: "bob", backendIP: "127.0.0.1"},
			}, variant.caPath))
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
			pins := []byte(knownhosts.Line([]string{"192.0.2.10:2222"}, newKey().PublicKey()) + "\n" + knownhosts.Line([]string{"127.0.0.1:20022"}, newKey().PublicKey()) + "\n")
			write(sshpiperKnownHosts, pins)
			write(sshpiperConfigFile, []byte(rendered))

			certURI := "" // without CA trust the certificate must be refused
			if variant.caPath != "" {
				certURI = "tcp://192.0.2.10:2222"
			}
			router := sshauthz.NewRouter(strings.Replace(sshpiperConfigFile, sshpiperConfigDir, dir, 1))
			for _, tt := range []struct {
				name, login, uri string // uri "" expects a refusal
				wire             []byte
			}{
				{name: "authorized key, advertised port", login: "alice", wire: alice.PublicKey().Marshal(), uri: "tcp://192.0.2.10:2222"},
				{name: "authorized key, tunnel-loopback port", login: "bob", wire: bob.PublicKey().Marshal(), uri: "tcp://127.0.0.1:20022"},
				{name: "certificate from the CA", login: "alice", wire: cert.Marshal(), uri: certURI},
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
					if string(up.KnownHostsData) != string(pins) {
						t.Fatal("generated route lost backend host pins")
					}
				})
			}
		})
	}
}
