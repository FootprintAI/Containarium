//go:build k8s

package k8s

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The box runs dropbear with BOTH an ed25519 and an RSA host key: dropbear
// crashes (rsa.c NULL assert) if a client offers rsa-sha2 and it has no RSA
// key, and sshpiper's Go client does offer rsa-sha2 and negotiates it. So both
// keys must be stable and pinned, or the gateway's known_hosts check fails on
// whichever key sshpiper picks. Verified live.

// generateEd25519HostKey makes an ed25519 host key: OpenSSH-PEM private (the
// box entrypoint feeds it to dropbearconvert) + authorized-key public.
func generateEd25519HostKey() (privPEM []byte, pubAuthorized string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	return marshalHostKey(priv, pub)
}

// generateRSAHostKey makes a 3072-bit RSA host key in the same forms.
func generateRSAHostKey() (privPEM []byte, pubAuthorized string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, "", err
	}
	return marshalHostKey(priv, priv.Public())
}

func marshalHostKey(priv crypto.PrivateKey, pub crypto.PublicKey) (privPEM []byte, pubAuthorized string, err error) {
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(block), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
}

// knownHostsData builds sshpiper's spec.to.known_hosts_data: a base64-encoded
// known_hosts file with one line per pinned host key. The host is the upstream
// "host:port"; known_hosts brackets a non-22 port as "[host]:port".
//
//	[box-0.boxes.tenant-a.svc.cluster.local]:2222 ssh-ed25519 AAAA...
//	[box-0.boxes.tenant-a.svc.cluster.local]:2222 ssh-rsa AAAA...
func knownHostsData(hostPort string, pubs ...string) string {
	host, port, found := strings.Cut(hostPort, ":")
	pattern := host
	if found {
		pattern = fmt.Sprintf("[%s]:%s", host, port)
	}
	var b strings.Builder
	for _, p := range pubs {
		if p == "" {
			continue
		}
		fmt.Fprintf(&b, "%s %s\n", pattern, p)
	}
	return base64.StdEncoding.EncodeToString([]byte(b.String()))
}
