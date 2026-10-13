package sshkey

import (
	"encoding/base64"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
)

func TestParseType(t *testing.T) {
	// Algorithm recognition is separate from full key validation: fake bytes
	// allow every prefix (including hardware keys) to be covered without devices.
	for _, tc := range []struct {
		prefix string
		want   pb.SSHKeyType
	}{
		{ssh.KeyAlgoED25519, pb.SSHKeyType_SSH_KEY_TYPE_ED25519},
		{ssh.KeyAlgoRSA, pb.SSHKeyType_SSH_KEY_TYPE_RSA},
		{ssh.KeyAlgoECDSA256, pb.SSHKeyType_SSH_KEY_TYPE_ECDSA},
		{ssh.KeyAlgoECDSA384, pb.SSHKeyType_SSH_KEY_TYPE_ECDSA},
		{ssh.KeyAlgoECDSA521, pb.SSHKeyType_SSH_KEY_TYPE_ECDSA},
		{ssh.KeyAlgoSKED25519, pb.SSHKeyType_SSH_KEY_TYPE_SK_ED25519},
		{ssh.KeyAlgoSKECDSA256, pb.SSHKeyType_SSH_KEY_TYPE_SK_ECDSA},
		{"garbage", pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED},
		{"", pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			key := strings.TrimSpace(tc.prefix + " " + base64.StdEncoding.EncodeToString([]byte("fixture")))
			if got := ParseType(key); got != tc.want {
				t.Fatalf("type=%v, want %v", got, tc.want)
			}
		})
	}
}
