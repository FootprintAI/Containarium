package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// guardrailPolicySetAction is the audit action every successful Set writes.
const guardrailPolicySetAction = "guardrail.policy.set"

// guardrailPolicyAuditDetail is the Detail of a guardrail.policy.set entry:
// revisions, hashes and signer key ids. Never key bytes.
type guardrailPolicyAuditDetail struct {
	PreviousRevision    int64    `json:"previous_revision"`
	PreviousPolicyHash  string   `json:"previous_policy_hash,omitempty"`
	Revision            int64    `json:"revision"`
	PolicyHash          string   `json:"policy_hash"`
	TrustedSignerKeyIDs []string `json:"trusted_signer_key_ids,omitempty"`
}

// GuardrailPolicyServer serves the cluster-wide guardrail policy (#2368;
// docs/architecture/guardrail-inbound-and-server-policy.md). Get is open to
// any authenticated caller; Set is admin-only, validated, and audited.
type GuardrailPolicyServer struct {
	pb.UnimplementedGuardrailPolicyServiceServer
	store guardrailpolicy.Store
	audit auditLogger
}

func NewGuardrailPolicyServer(store guardrailpolicy.Store) *GuardrailPolicyServer {
	return &GuardrailPolicyServer{store: store}
}

// SetStore swaps the backing store. Startup only (the in-memory store is
// upgraded to Postgres once the pool exists), before the server serves.
func (s *GuardrailPolicyServer) SetStore(store guardrailpolicy.Store) { s.store = store }

// Provider is the read side for the deploy gate and the model gateway. Call
// after any startup-time SetStore swap.
func (s *GuardrailPolicyServer) Provider() guardrailpolicy.PolicyProvider { return s.store }

// SetAuditStore wires the audit store once the Postgres pool exists. The nil
// check keeps a nil *audit.Store from becoming a non-nil interface.
func (s *GuardrailPolicyServer) SetAuditStore(store *audit.Store) {
	if store != nil {
		s.audit = store
	}
}

func (s *GuardrailPolicyServer) GetGuardrailPolicy(ctx context.Context, _ *pb.GetGuardrailPolicyRequest) (*pb.GetGuardrailPolicyResponse, error) {
	if _, _, ok := auth.SubjectFromGRPCContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}
	p, err := s.store.Get(ctx)
	if errors.Is(err, guardrailpolicy.ErrNotConfigured) {
		return &pb.GetGuardrailPolicyResponse{Configured: false}, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read guardrail policy: %v", err)
	}
	hash, err := guardrailpolicy.Hash(p)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash guardrail policy: %v", err)
	}
	return &pb.GetGuardrailPolicyResponse{Configured: true, Policy: p, PolicyHash: hash}, nil
}

func (s *GuardrailPolicyServer) SetGuardrailPolicy(ctx context.Context, req *pb.SetGuardrailPolicyRequest) (*pb.SetGuardrailPolicyResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if err := guardrailpolicy.Validate(req.GetPolicy(), req.GetTrustedSigners()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	subject, _, _ := auth.SubjectFromGRPCContext(ctx)
	res, err := s.store.Set(ctx, req.GetPolicy(), req.GetTrustedSigners(), subject)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store guardrail policy: %v", err)
	}
	hash, err := guardrailpolicy.Hash(res.Current)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash guardrail policy: %v", err)
	}
	s.auditSet(ctx, subject, res, hash)
	return &pb.SetGuardrailPolicyResponse{Policy: res.Current, PolicyHash: hash}, nil
}

// auditSet records the change. Best-effort, the repo's convention for
// control-plane writes (see auditTrackerConnectionWrite): the policy is
// already committed, so a failed audit write is logged, not returned.
func (s *GuardrailPolicyServer) auditSet(ctx context.Context, subject string, res *guardrailpolicy.SetResult, hash string) {
	if s.audit == nil {
		return
	}
	d := guardrailPolicyAuditDetail{Revision: res.Current.GetRevision(), PolicyHash: hash}
	if res.Previous != nil {
		d.PreviousRevision = res.Previous.GetRevision()
		if prevHash, err := guardrailpolicy.Hash(res.Previous); err == nil {
			d.PreviousPolicyHash = prevHash
		}
	}
	for _, sg := range res.Current.GetTrustedSigners() {
		d.TrustedSignerKeyIDs = append(d.TrustedSignerKeyIDs, sg.GetKeyId())
	}
	payload, err := json.Marshal(d)
	if err != nil {
		log.Printf("[guardrail-policy] marshal audit detail: %v", err)
		return
	}
	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Username:     subject,
		Action:       guardrailPolicySetAction,
		ResourceType: "guardrail_policy",
		ResourceID:   "cluster",
		Detail:       string(payload),
	}); err != nil {
		log.Printf("[guardrail-policy] audit %s revision %d: %v", guardrailPolicySetAction, d.Revision, err)
	}
}
