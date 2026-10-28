package guardrailpolicy

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Signer rotation and revocation as read-edit-write over SetGuardrailPolicy
// (#2729). Each builder returns the full replacement request for the stored
// policy with expected_revision set to the revision it read, so a concurrent
// Set makes the write ABORTED instead of being overwritten.

var errNoPolicy = errors.New("no guardrail policy is configured on the server; set one first with 'guardrail policy set'")

func baseRequest(cur *pb.GetGuardrailPolicyResponse) (*pb.SetGuardrailPolicyRequest, error) {
	if !cur.GetConfigured() || cur.GetPolicy() == nil {
		return nil, errNoPolicy
	}
	p := Clone(cur.GetPolicy())
	rev := p.GetRevision()
	return &pb.SetGuardrailPolicyRequest{
		Policy:           p.GetPolicy(),
		TrustedSigners:   p.GetTrustedSigners(),
		RevokedSigners:   p.GetRevokedSigners(),
		ExpectedRevision: &rev,
	}, nil
}

// RotateRequest trusts pub next to the signers already trusted. The old key
// stays so attestations it signed keep verifying; retire it with RevokeRequest.
func RotateRequest(cur *pb.GetGuardrailPolicyResponse, pub ed25519.PublicKey, label string) (*pb.SetGuardrailPolicyRequest, error) {
	req, err := baseRequest(cur)
	if err != nil {
		return nil, err
	}
	id := guardrail.KeyID(pub)
	for _, r := range req.GetRevokedSigners() {
		if r.GetKeyId() == id {
			return nil, fmt.Errorf("key %s is revoked; revocation is permanent, generate a new key", id)
		}
	}
	for _, s := range req.GetTrustedSigners() {
		if s.GetKeyId() == id {
			return nil, fmt.Errorf("key %s is already trusted", id)
		}
	}
	req.TrustedSigners = append(req.TrustedSigners, &pb.GuardrailTrustedSigner{KeyId: id, PublicKey: pub, Label: label})
	return req, nil
}

// RevokeRequest permanently revokes keyID with a reason and drops it from the
// trusted signers (the server refuses a key that is both). revoked_at is
// assigned by the server.
func RevokeRequest(cur *pb.GetGuardrailPolicyResponse, keyID, reason string) (*pb.SetGuardrailPolicyRequest, error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, fmt.Errorf("key id %q must be the SHA-256 of the public key, 64 lowercase hex characters", keyID)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, errors.New("--reason is required: every refused verify names it")
	}
	req, err := baseRequest(cur)
	if err != nil {
		return nil, err
	}
	for _, r := range req.GetRevokedSigners() {
		if r.GetKeyId() == keyID {
			return nil, fmt.Errorf("key %s is already revoked: %s", keyID, r.GetReason())
		}
	}
	kept := req.TrustedSigners[:0]
	for _, s := range req.GetTrustedSigners() {
		if s.GetKeyId() != keyID {
			kept = append(kept, s)
		}
	}
	req.TrustedSigners = kept
	req.RevokedSigners = append(req.RevokedSigners, &pb.GuardrailRevokedKey{KeyId: keyID, Reason: reason})
	return req, nil
}

// BundleOf is the trust an offline verifier needs, copied out of the policy.
func BundleOf(p *pb.ServerGuardrailPolicy) *pb.GuardrailTrustBundle {
	b := &pb.GuardrailTrustBundle{}
	for _, s := range p.GetTrustedSigners() {
		b.Signers = append(b.Signers, proto.Clone(s).(*pb.GuardrailTrustedSigner))
	}
	for _, r := range p.GetRevokedSigners() {
		b.Revoked = append(b.Revoked, proto.Clone(r).(*pb.GuardrailRevokedKey))
	}
	return b
}
