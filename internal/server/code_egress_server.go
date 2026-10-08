package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/codeegress"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// codeEgressClusterDefaultResourceID names the cluster default in audit
// entries, where an empty resource id would read as "unknown".
const codeEgressClusterDefaultResourceID = "_cluster_default"

// CodingToolEgressPolicyServer serves the admin-approved egress allowlist for
// the coding tool (#2378, docs/architecture/coding-cli-egress-allowlist.md).
// Set and Delete are admin-only; Get is for an admin, or the tenant itself
// holding code-egress:read. Store only: nothing here programs the kernel.
type CodingToolEgressPolicyServer struct {
	pb.UnimplementedCodingToolEgressPolicyServiceServer
	store    CodingToolEgressPolicyStore
	audit    auditLogger
	implicit codeegress.Implicit
}

func NewCodingToolEgressPolicyServer(store CodingToolEgressPolicyStore) *CodingToolEgressPolicyServer {
	return &CodingToolEgressPolicyServer{store: store}
}

// SetStore swaps the backing store. Startup only, before serving.
func (s *CodingToolEgressPolicyServer) SetStore(store CodingToolEgressPolicyStore) { s.store = store }

// SetAuditStore wires the audit log once it exists. A nil *audit.Store is
// kept as "no audit" rather than a non-nil interface holding nil.
func (s *CodingToolEgressPolicyServer) SetAuditStore(a auditLogger) {
	if st, ok := a.(*audit.Store); ok && st == nil {
		s.audit = nil
		return
	}
	s.audit = a
}

// SetImplicit records what the daemon knows about the always-allowed
// destinations shown in the effective policy.
func (s *CodingToolEgressPolicyServer) SetImplicit(imp codeegress.Implicit) { s.implicit = imp }

func (s *CodingToolEgressPolicyServer) SetCodingToolEgressPolicy(ctx context.Context, req *pb.SetCodingToolEgressPolicyRequest) (*pb.SetCodingToolEgressPolicyResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	norm, err := codeegress.Normalize(req.GetPolicy())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	subject, _, _ := auth.SubjectFromGRPCContext(ctx)
	stored, prev, err := s.store.Set(ctx, norm, subject)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store coding-tool egress policy: %v", err)
	}
	s.auditChange(ctx, "code_egress_policy.set", subject, stored.GetTenant(), codeEgressAuditDetail{
		PreviousRevision: prev,
		Revision:         stored.GetRevision(),
		Mode:             stored.GetMode().String(),
		CIDRCount:        len(stored.GetEgressCidrs()),
		DomainCount:      len(stored.GetEgressDomains()),
	})
	return &pb.SetCodingToolEgressPolicyResponse{Policy: stored}, nil
}

func (s *CodingToolEgressPolicyServer) GetCodingToolEgressPolicy(ctx context.Context, req *pb.GetCodingToolEgressPolicyRequest) (*pb.GetCodingToolEgressPolicyResponse, error) {
	// An admin reads anything; otherwise the caller must hold code-egress:read
	// explicitly AND be the tenant asked about. The cluster default on its
	// own is admin-only (a tenant sees it through its effective policy).
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeCodeEgressRead); err != nil {
		return nil, err
	}
	tenant := strings.TrimSpace(req.GetTenant())
	if tenant == "" {
		if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
			return nil, err
		}
	} else if err := auth.AuthorizeTenant(ctx, tenant); err != nil {
		return nil, err
	}
	own, err := s.lookup(ctx, tenant)
	if err != nil {
		return nil, err
	}
	def := own
	if tenant != "" {
		if def, err = s.lookup(ctx, ""); err != nil {
			return nil, err
		}
	}
	tenantPolicy := own
	if tenant == "" {
		tenantPolicy = nil
	}
	return &pb.GetCodingToolEgressPolicyResponse{
		Policy:    own,
		Effective: codeegress.Effective(tenant, tenantPolicy, def, s.implicit),
	}, nil
}

func (s *CodingToolEgressPolicyServer) DeleteCodingToolEgressPolicy(ctx context.Context, req *pb.DeleteCodingToolEgressPolicyRequest) (*pb.DeleteCodingToolEgressPolicyResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	tenant := strings.TrimSpace(req.GetTenant())
	removed, err := s.store.Delete(ctx, tenant)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "delete coding-tool egress policy: %v", err)
	}
	if removed != 0 {
		subject, _, _ := auth.SubjectFromGRPCContext(ctx)
		s.auditChange(ctx, "code_egress_policy.delete", subject, tenant, codeEgressAuditDetail{PreviousRevision: removed})
	}
	return &pb.DeleteCodingToolEgressPolicyResponse{}, nil
}

func (s *CodingToolEgressPolicyServer) lookup(ctx context.Context, tenant string) (*pb.CodingToolEgressPolicy, error) {
	p, err := s.store.Get(ctx, tenant)
	if errors.Is(err, ErrCodingToolEgressPolicyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get coding-tool egress policy: %v", err)
	}
	return p, nil
}

// codeEgressAuditDetail is the audit payload: revisions and counts only,
// never the destinations.
type codeEgressAuditDetail struct {
	PreviousRevision int64  `json:"previous_revision"`
	Revision         int64  `json:"revision"`
	Mode             string `json:"mode"`
	CIDRCount        int    `json:"cidr_count"`
	DomainCount      int    `json:"domain_count"`
}

// auditChange is best-effort: an audit failure never fails the change.
func (s *CodingToolEgressPolicyServer) auditChange(ctx context.Context, action, subject, tenant string, d codeEgressAuditDetail) {
	if s.audit == nil {
		return
	}
	payload, err := json.Marshal(d)
	if err != nil {
		log.Printf("[code-egress] marshal audit detail for %s: %v", action, err)
		return
	}
	id := tenant
	if id == "" {
		id = codeEgressClusterDefaultResourceID
	}
	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Username:     subject,
		Action:       action,
		ResourceType: "coding_tool_egress_policy",
		ResourceID:   id,
		Detail:       string(payload),
	}); err != nil {
		log.Printf("[code-egress] audit %s %s: %v", action, id, err)
	}
}
