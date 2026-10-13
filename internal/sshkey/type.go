package sshkey

import (
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
)

// ParseType identifies the registered OpenSSH public-key algorithm.
func ParseType(publicKey string) pb.SSHKeyType {
	fields := strings.Fields(publicKey)
	if len(fields) < 2 {
		return pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED
	}
	switch fields[0] {
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
	}
	return pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED
}
