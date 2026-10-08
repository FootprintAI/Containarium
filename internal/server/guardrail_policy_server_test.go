package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func gpAdminCtx() context.Context {
	return auth.ContextWithTestSubject(context.Background(), "ops", auth.RoleAdmin)
}

func gpUserCtx() context.Context {
	return auth.ContextWithTestSubject(context.Background(), "data-owner", "user")
}

func gpSigner(seed byte) *pb.GuardrailTrustedSigner {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	pub := ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
	return &pb.GuardrailTrustedSigner{KeyId: guardrail.KeyID(pub), PublicKey: pub, Label: "release key"}
}

func gpRequest(maxResidual int32, signers ...*pb.GuardrailTrustedSigner) *pb.SetGuardrailPolicyRequest {
	return &pb.SetGuardrailPolicyRequest{
		Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
			{Kind: pb.GuardrailKind_GUARDRAIL_KIND_PII, Action: pb.GuardrailAction_GUARDRAIL_ACTION_REDACT, MaxResidual: maxResidual},
			{Kind: pb.GuardrailKind_GUARDRAIL_KIND_SECRET, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK},
		}},
		TrustedSigners: signers,
	}
}

func newGPServer() (*GuardrailPolicyServer, *fakeAuditLogger) {
	s := NewGuardrailPolicyServer(guardrailpolicy.NewMemoryStore())
	a := &fakeAuditLogger{}
	s.audit = a
	return s, a
}

// TestSetPolicy_AdminOnly: Set is admin-only (Q6); a non-admin is
// PERMISSION_DENIED, no subject is UNAUTHENTICATED, and neither changes the
// stored policy.
func TestSetPolicy_AdminOnly(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"admin", gpAdminCtx(), codes.OK},
		{"non-admin", gpUserCtx(), codes.PermissionDenied},
		{"unauthenticated", context.Background(), codes.Unauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newGPServer()
			_, err := s.SetGuardrailPolicy(tc.ctx, gpRequest(0, gpSigner(1)))
			if got := status.Code(err); got != tc.want {
				t.Fatalf("SetGuardrailPolicy as %s = %v (%v), want %v", tc.name, got, err, tc.want)
			}
			get, err := s.GetGuardrailPolicy(gpAdminCtx(), &pb.GetGuardrailPolicyRequest{})
			if err != nil {
				t.Fatalf("GetGuardrailPolicy: %v", err)
			}
			if wantConfigured := tc.want == codes.OK; get.GetConfigured() != wantConfigured {
				t.Fatalf("configured after a %s Set = %v, want %v", tc.name, get.GetConfigured(), wantConfigured)
			}
		})
	}
}

// TestGetPolicy_AnyAuthenticatedCaller: a data owner (no admin role) can read
// the policy; an unauthenticated caller cannot; "never set" is configured=false,
// not an error.
func TestGetPolicy_AnyAuthenticatedCaller(t *testing.T) {
	s, _ := newGPServer()
	got, err := s.GetGuardrailPolicy(gpUserCtx(), &pb.GetGuardrailPolicyRequest{})
	if err != nil || got.GetConfigured() || got.GetPolicyHash() != "" {
		t.Fatalf("Get before any Set = (%v, %v), want configured=false and no hash", got, err)
	}
	if _, err := s.SetGuardrailPolicy(gpAdminCtx(), gpRequest(1, gpSigner(1))); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err = s.GetGuardrailPolicy(gpUserCtx(), &pb.GetGuardrailPolicyRequest{})
	if err != nil || !got.GetConfigured() {
		t.Fatalf("Get as a non-admin = (%v, %v), want the configured policy", got, err)
	}
	wantHash, _ := guardrail.PolicyHash(gpRequest(1).GetPolicy())
	if got.GetPolicyHash() != wantHash {
		t.Fatalf("policy_hash = %q, want the attestation hash of the rules %q", got.GetPolicyHash(), wantHash)
	}
	if !proto.Equal(got.GetPolicy().GetPolicy(), gpRequest(1).GetPolicy()) || got.GetPolicy().GetUpdatedBy() != "ops" {
		t.Fatalf("stored = %v, want the rules set by ops", got.GetPolicy())
	}
	if _, err := s.GetGuardrailPolicy(context.Background(), &pb.GetGuardrailPolicyRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Get unauthenticated = %v, want Unauthenticated", err)
	}
}

type failingPolicyStore struct{ guardrailpolicy.Store }

func (failingPolicyStore) Get(context.Context) (*pb.ServerGuardrailPolicy, error) {
	return nil, errors.New("connection refused")
}

// TestGetPolicy_ReadErrorIsNotNotConfigured: a store read error is an RPC
// error, never configured=false, so no client can read an outage as "no
// policy".
func TestGetPolicy_ReadErrorIsNotNotConfigured(t *testing.T) {
	s := NewGuardrailPolicyServer(failingPolicyStore{guardrailpolicy.NewMemoryStore()})
	got, err := s.GetGuardrailPolicy(gpUserCtx(), &pb.GetGuardrailPolicyRequest{})
	if err == nil {
		t.Fatalf("Get with a failing store = %v, want an error", got)
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

// TestSetPolicy_Validation: every invalid policy is INVALID_ARGUMENT and the
// stored revision is unchanged.
func TestSetPolicy_Validation(t *testing.T) {
	good := gpSigner(1)
	badSigner := &pb.GuardrailTrustedSigner{KeyId: gpSigner(2).GetKeyId(), PublicKey: good.GetPublicKey()}
	rule := func(k pb.GuardrailKind, a pb.GuardrailAction, max int32) *pb.GuardrailRule {
		return &pb.GuardrailRule{Kind: k, Action: a, MaxResidual: max}
	}
	const (
		pii    = pb.GuardrailKind_GUARDRAIL_KIND_PII
		redact = pb.GuardrailAction_GUARDRAIL_ACTION_REDACT
	)
	cases := []struct {
		name string
		req  *pb.SetGuardrailPolicyRequest
	}{
		{"missing policy", &pb.SetGuardrailPolicyRequest{}},
		{"unspecified kind", &pb.SetGuardrailPolicyRequest{Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pb.GuardrailKind_GUARDRAIL_KIND_UNSPECIFIED, redact, 0)}}}},
		{"unspecified action", &pb.SetGuardrailPolicyRequest{Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pii, pb.GuardrailAction_GUARDRAIL_ACTION_UNSPECIFIED, 0)}}}},
		{"duplicate kind", &pb.SetGuardrailPolicyRequest{Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pii, redact, 0), rule(pii, redact, 1)}}}},
		{"negative residual", &pb.SetGuardrailPolicyRequest{Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{rule(pii, redact, -1)}}}},
		{"signer key_id does not match its key", gpRequest(0, good, badSigner)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, audit := newGPServer()
			if _, err := s.SetGuardrailPolicy(gpAdminCtx(), gpRequest(0, good)); err != nil {
				t.Fatalf("seed Set: %v", err)
			}
			_, err := s.SetGuardrailPolicy(gpAdminCtx(), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Set(%s) = %v, want InvalidArgument", tc.name, err)
			}
			got, err := s.GetGuardrailPolicy(gpAdminCtx(), &pb.GetGuardrailPolicyRequest{})
			if err != nil || got.GetPolicy().GetRevision() != 1 || !proto.Equal(got.GetPolicy().GetPolicy(), gpRequest(0).GetPolicy()) {
				t.Fatalf("after a refused Set the store = (%v, %v), want revision 1 and the seed policy", got, err)
			}
			if n := len(audit.byAction(guardrailPolicySetAction)); n != 1 {
				t.Fatalf("audit entries = %d, want 1 (the seed only; a refused Set is not a change)", n)
			}
		})
	}
}

// TestSetPolicy_RevisionMonotonic: each Set returns revision n and the hash of
// exactly the rules it stored.
func TestSetPolicy_RevisionMonotonic(t *testing.T) {
	s, _ := newGPServer()
	for want := int64(1); want <= 3; want++ {
		req := gpRequest(int32(want), gpSigner(1))
		resp, err := s.SetGuardrailPolicy(gpAdminCtx(), req)
		if err != nil {
			t.Fatalf("Set #%d: %v", want, err)
		}
		if resp.GetPolicy().GetRevision() != want {
			t.Fatalf("revision = %d, want %d", resp.GetPolicy().GetRevision(), want)
		}
		wantHash, _ := guardrail.PolicyHash(req.GetPolicy())
		if resp.GetPolicyHash() != wantHash {
			t.Fatalf("Set #%d policy_hash = %q, want %q", want, resp.GetPolicyHash(), wantHash)
		}
	}
}

// TestSetPolicy_AuditEntry: one guardrail.policy.set entry per Set, carrying
// old and new revision and hash, attributed to the caller, and no key bytes in
// any encoding.
func TestSetPolicy_AuditEntry(t *testing.T) {
	s, audit := newGPServer()
	signer := gpSigner(7)
	first, err := s.SetGuardrailPolicy(gpAdminCtx(), gpRequest(0, signer))
	if err != nil {
		t.Fatalf("Set #1: %v", err)
	}
	second, err := s.SetGuardrailPolicy(gpAdminCtx(), gpRequest(4, signer))
	if err != nil {
		t.Fatalf("Set #2: %v", err)
	}
	entries := audit.byAction(guardrailPolicySetAction)
	if len(entries) != 2 {
		t.Fatalf("audit entries = %d, want 2", len(entries))
	}
	e := entries[1]
	if e.Username != "ops" || e.ResourceType != "guardrail_policy" {
		t.Fatalf("entry = user %q type %q, want ops / guardrail_policy", e.Username, e.ResourceType)
	}
	var d guardrailPolicyAuditDetail
	if err := json.Unmarshal([]byte(e.Detail), &d); err != nil {
		t.Fatalf("detail is not the typed JSON: %v (%s)", err, e.Detail)
	}
	want := guardrailPolicyAuditDetail{
		PreviousRevision:    1,
		PreviousPolicyHash:  first.GetPolicyHash(),
		Revision:            2,
		PolicyHash:          second.GetPolicyHash(),
		TrustedSignerKeyIDs: []string{signer.GetKeyId()},
	}
	if d.PreviousRevision != want.PreviousRevision || d.PreviousPolicyHash != want.PreviousPolicyHash ||
		d.Revision != want.Revision || d.PolicyHash != want.PolicyHash ||
		len(d.TrustedSignerKeyIDs) != 1 || d.TrustedSignerKeyIDs[0] != signer.GetKeyId() {
		t.Fatalf("detail = %+v, want %+v", d, want)
	}
	var firstDetail guardrailPolicyAuditDetail
	_ = json.Unmarshal([]byte(entries[0].Detail), &firstDetail)
	if firstDetail.PreviousRevision != 0 || firstDetail.PreviousPolicyHash != "" {
		t.Fatalf("first Set's detail = %+v, want no previous revision or hash", firstDetail)
	}
	key := signer.GetPublicKey()
	for _, enc := range []string{string(key), hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key), base64.URLEncoding.EncodeToString(key)} {
		for _, field := range []string{e.Detail, e.ResourceID, e.Username, e.Action} {
			if strings.Contains(field, enc) {
				t.Fatalf("audit entry carries the public key bytes (%q)", field)
			}
		}
	}
}
