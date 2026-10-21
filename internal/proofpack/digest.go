package proofpack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/proto"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// LogDigest is the SHA-256 (lowercase hex) of b. It is the digest every
// pack part carries.
func LogDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// PackDigest is the SHA-256 (lowercase hex) of the pack's deterministic
// proto encoding: the digest of the whole manifest, parts included.
func PackDigest(pack *pb.ProofPack) (string, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(pack)
	if err != nil {
		return "", err
	}
	return LogDigest(b), nil
}

// CheckPartDigests recomputes each step's log digest and returns an error
// naming the first step whose stored log does not match it.
func CheckPartDigests(pack *pb.ProofPack) error {
	for i, s := range pack.GetSteps() {
		if got := LogDigest(s.GetLog()); got != s.GetLogSha256() {
			return fmt.Errorf("proofpack: step %d (%q): log digest %s does not match recorded %s", i, s.GetName(), got, s.GetLogSha256())
		}
	}
	return nil
}
