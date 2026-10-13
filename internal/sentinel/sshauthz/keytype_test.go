package sshauthz

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
)

func TestCredentialKeyTypeMapping(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want pb.SSHKeyType
	}{
		{ssh.KeyAlgoED25519, pb.SSHKeyType_SSH_KEY_TYPE_ED25519},
		{ssh.KeyAlgoRSA, pb.SSHKeyType_SSH_KEY_TYPE_RSA},
		{ssh.KeyAlgoECDSA256, pb.SSHKeyType_SSH_KEY_TYPE_ECDSA},
		{ssh.KeyAlgoECDSA384, pb.SSHKeyType_SSH_KEY_TYPE_ECDSA},
		{ssh.KeyAlgoECDSA521, pb.SSHKeyType_SSH_KEY_TYPE_ECDSA},
		{ssh.KeyAlgoSKED25519, pb.SSHKeyType_SSH_KEY_TYPE_SK_ED25519},
		{ssh.KeyAlgoSKECDSA256, pb.SSHKeyType_SSH_KEY_TYPE_SK_ECDSA},
		{"unsupported", pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED},
	} {
		t.Run(tc.key, func(t *testing.T) {
			if got := keyType(tc.key); got != tc.want {
				t.Fatalf("%v want %v", got, tc.want)
			}
		})
	}
}
