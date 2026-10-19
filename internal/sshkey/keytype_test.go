package sshkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/ssh"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// authorizedLine renders an ssh.PublicKey as an authorized_keys line.
func authorizedLine(t *testing.T, pub interface{}) string {
	t.Helper()
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(pk))
}

// skLine builds a FIDO2 security-key public key line by hand: x/crypto
// parses both sk- types but has no constructor for them.
func skLine(t *testing.T, keyType string, body interface{}) string {
	t.Helper()
	wire := ssh.Marshal(body)
	return keyType + " " + base64.StdEncoding.EncodeToString(wire) + " user@security-key"
}

func TestParseType(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey := func(c elliptic.Curve) *ecdsa.PublicKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &k.PublicKey
	}
	p256 := ecKey(elliptic.P256())

	skEd := skLine(t, ssh.KeyAlgoSKED25519, struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{ssh.KeyAlgoSKED25519, edPub, "ssh:"})
	skEc := skLine(t, ssh.KeyAlgoSKECDSA256, struct {
		Name        string
		ID          string
		Key         []byte
		Application string
	}{ssh.KeyAlgoSKECDSA256, "nistp256", elliptic.Marshal(elliptic.P256(), p256.X, p256.Y), "ssh:"}) //nolint:staticcheck // wire encoding of the point, as OpenSSH writes it

	tests := []struct {
		name string
		pub  string
		want pb.SSHKeyType
	}{
		{"ed25519", authorizedLine(t, edPub), pb.SSHKeyType_SSH_KEY_TYPE_ED25519},
		{"rsa", authorizedLine(t, &rsaKey.PublicKey), pb.SSHKeyType_SSH_KEY_TYPE_RSA},
		{"ecdsa nistp256", authorizedLine(t, p256), pb.SSHKeyType_SSH_KEY_TYPE_ECDSA},
		{"ecdsa nistp384", authorizedLine(t, ecKey(elliptic.P384())), pb.SSHKeyType_SSH_KEY_TYPE_ECDSA},
		{"ecdsa nistp521", authorizedLine(t, ecKey(elliptic.P521())), pb.SSHKeyType_SSH_KEY_TYPE_ECDSA},
		{"sk-ssh-ed25519", skEd, pb.SSHKeyType_SSH_KEY_TYPE_SK_ED25519},
		{"sk-ecdsa-sha2-nistp256", skEc, pb.SSHKeyType_SSH_KEY_TYPE_SK_ECDSA},
		{"options prefix", `no-pty,command="echo hi" ` + authorizedLine(t, edPub), pb.SSHKeyType_SSH_KEY_TYPE_ED25519},
		{"empty", "", pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED},
		{"garbage", "not a key at all", pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED},
		{"known prefix, bad body", "ssh-ed25519 AAAA-not-base64", pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED},
		{"unknown type", "ssh-dss AAAAB3NzaC1kc3M= old@box", pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseType(tc.pub); got != tc.want {
				t.Fatalf("ParseType(%q) = %v, want %v", tc.pub, got, tc.want)
			}
		})
	}
}
