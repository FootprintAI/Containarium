package sshkey

import (
	"strings"

	"golang.org/x/crypto/ssh"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ParseType classifies an OpenSSH public key (an authorized_keys line,
// options prefix allowed) as the SSH authorization contract's key type.
// The key must parse: a line that only looks like a known type, an
// unsupported algorithm (ssh-dss, certificates), or garbage is
// SSH_KEY_TYPE_UNSPECIFIED. The two FIDO2 types are the OpenSSH
// vendor-suffixed names sk-ssh-ed25519@openssh.com and
// sk-ecdsa-sha2-nistp256@openssh.com (#2517).
func ParseType(pub string) pb.SSHKeyType {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(pub)))
	if err != nil {
		return pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED
	}
	switch pk.Type() {
	case ssh.KeyAlgoED25519:
		return pb.SSHKeyType_SSH_KEY_TYPE_ED25519
	case ssh.KeyAlgoRSA:
		return pb.SSHKeyType_SSH_KEY_TYPE_RSA
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return pb.SSHKeyType_SSH_KEY_TYPE_ECDSA
	case ssh.KeyAlgoSKED25519:
		return pb.SSHKeyType_SSH_KEY_TYPE_SK_ED25519
	case ssh.KeyAlgoSKECDSA256:
		return pb.SSHKeyType_SSH_KEY_TYPE_SK_ECDSA
	default:
		return pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED
	}
}
