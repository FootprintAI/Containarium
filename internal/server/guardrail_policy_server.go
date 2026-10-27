package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/guardrailpolicy"
	"github.com/footprintai/containarium/internal/guardrailrate"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// guardrailPolicySetAction is the audit action every successful Set writes.
const guardrailPolicySetAction = "guardrail.policy.set"

// guardrailBaselineSetAction is the audit action every successful baseline
// mode switch writes (#2738).
const guardrailBaselineSetAction = "guardrail.baseline.set"

// guardrailBaselineAuditDetail is the Detail of a guardrail.baseline.set
// entry: the mode and revision replaced and stored (enum names).
type guardrailBaselineAuditDetail struct {
	PreviousMode     string `json:"previous_mode"`
	PreviousRevision int64  `json:"previous_revision"`
	Mode             string `json:"mode"`
	Revision         int64  `json:"revision"`
}

// guardrailPolicyAuditDetail is the Detail of a guardrail.policy.set entry:
// revisions, hashes and signer key ids. Never key bytes.
type guardrailPolicyAuditDetail struct {
	PreviousRevision    int64    `json:"previous_revision"`
	PreviousPolicyHash  string   `json:"previous_policy_hash,omitempty"`
	Revision            int64    `json:"revision"`
	PolicyHash          string   `json:"policy_hash"`
	TrustedSignerKeyIDs []string `json:"trusted_signer_key_ids,omitempty"`
	RevokedSignerKeyIDs []string `json:"revoked_signer_key_ids,omitempty"`
}

// GuardrailPolicyServer serves the cluster-wide guardrail policy (#2368;
// docs/architecture/guardrail-inbound-and-server-policy.md). Get is open to
// any authenticated caller; Set is admin-only, validated, and audited.
type GuardrailPolicyServer struct {
	pb.UnimplementedGuardrailPolicyServiceServer
	// store is swapped while the server is serving when the recovery retry
	// installs the Postgres store (#2483), so every read goes through it.
	store *swappableGuardrailPolicyStore
	audit auditLogger
	// onChange runs after a policy is stored, so the model gateway's cached
	// read does not delay a new rule (#2454). Startup wiring only.
	onChange func()
	// setLimit and getLimit rate-limit Set and Get per subject (#2404;
	// nil = disabled). Admins are not exempt from setLimit.
	setLimit, getLimit *guardrailrate.Limiter
}

func NewGuardrailPolicyServer(store guardrailpolicy.Store) *GuardrailPolicyServer {
	s := &GuardrailPolicyServer{store: &swappableGuardrailPolicyStore{}}
	s.store.swap(store)
	return s
}

// swappableGuardrailPolicyStore is a guardrailpolicy.Store whose backing
// store can be replaced while readers hold it. Provider() hands it out, so
// the deploy gate and the model gateway follow a later install (#2483).
type swappableGuardrailPolicyStore struct {
	cur atomic.Pointer[guardrailPolicyStoreRef]
}

type guardrailPolicyStoreRef struct{ guardrailpolicy.Store }

func (w *swappableGuardrailPolicyStore) swap(st guardrailpolicy.Store) {
	w.cur.Store(&guardrailPolicyStoreRef{st})
}

func (w *swappableGuardrailPolicyStore) current() guardrailpolicy.Store { return w.cur.Load().Store }

func (w *swappableGuardrailPolicyStore) Get(ctx context.Context) (*pb.ServerGuardrailPolicy, error) {
	return w.current().Get(ctx)
}

func (w *swappableGuardrailPolicyStore) Set(ctx context.Context, req *pb.SetGuardrailPolicyRequest, updatedBy string) (*guardrailpolicy.SetResult, error) {
	return w.current().Set(ctx, req, updatedBy)
}

func (w *swappableGuardrailPolicyStore) GetBaselineMode(ctx context.Context) (*pb.GuardrailBaselineSetting, error) {
	return w.current().GetBaselineMode(ctx)
}

func (w *swappableGuardrailPolicyStore) SetBaselineMode(ctx context.Context, mode pb.GuardrailBaselineMode, updatedBy string, beforeCommit guardrailpolicy.BaselineBeforeCommit) (*guardrailpolicy.BaselineSetResult, error) {
	return w.current().SetBaselineMode(ctx, mode, updatedBy, beforeCommit)
}

// errGuardrailPolicyStoreUnavailable is what every read and write returns
// while Postgres is configured but its guardrail policy store is not
// installed. It is a real error, never guardrailpolicy.ErrNotConfigured.
var errGuardrailPolicyStoreUnavailable = errors.New("guardrail policy store unavailable: Postgres is configured but the Postgres guardrail policy store is not installed yet (the daemon retries until Postgres answers)")

// unavailableGuardrailPolicyStore fails closed. An empty in-memory fallback
// would answer "no policy" (a PolicyProvider consumer would then switch the
// inbound scan off) and accept admin Sets a restart silently loses. This is
// the same case NetworkPolicy guards with policyStoreDurable (#2359).
type unavailableGuardrailPolicyStore struct{}

func (unavailableGuardrailPolicyStore) Get(context.Context) (*pb.ServerGuardrailPolicy, error) {
	return nil, errGuardrailPolicyStoreUnavailable
}

func (unavailableGuardrailPolicyStore) Set(context.Context, *pb.SetGuardrailPolicyRequest, string) (*guardrailpolicy.SetResult, error) {
	return nil, errGuardrailPolicyStoreUnavailable
}

func (unavailableGuardrailPolicyStore) GetBaselineMode(context.Context) (*pb.GuardrailBaselineSetting, error) {
	return nil, errGuardrailPolicyStoreUnavailable
}

func (unavailableGuardrailPolicyStore) SetBaselineMode(context.Context, pb.GuardrailBaselineMode, string, guardrailpolicy.BaselineBeforeCommit) (*guardrailpolicy.BaselineSetResult, error) {
	return nil, errGuardrailPolicyStoreUnavailable
}

// guardrailPolicyStartupStore picks the store the server runs on, once the
// daemon knows whether Postgres is configured. pg is the Postgres store, or
// nil when it was not installed: the pool could not be reached, or the
// store's bootstrap failed.
//   - No Postgres configured: the in-memory store is the store. That is
//     logged, because a policy set now does not survive a restart.
//   - Postgres configured with pg installed: pg.
//   - Postgres configured without pg: fail closed (unavailableGuardrailPolicyStore).
func guardrailPolicyStartupStore(postgresConfigured bool, pg guardrailpolicy.Store) guardrailpolicy.Store {
	switch {
	case !postgresConfigured:
		log.Printf("Guardrail policy: no database configured; using the in-memory store (a policy set now is lost on restart)")
		return guardrailpolicy.NewMemoryStore()
	case pg != nil:
		return pg
	default:
		log.Printf("Warning: guardrail policy store UNAVAILABLE: Postgres is configured but its store was not installed; policy reads and writes fail until the retry reaches the database")
		return unavailableGuardrailPolicyStore{}
	}
}

// SetStore sets the backing store at startup, once the daemon knows whether
// Postgres is configured (see guardrailPolicyStartupStore). A later install
// goes through InstallDurableStore.
func (s *GuardrailPolicyServer) SetStore(store guardrailpolicy.Store) { s.store.swap(store) }

// Provider is the read side for the deploy gate and the model gateway. It
// reads whichever store is current, so a durable store installed later by
// the recovery retry (#2483) reaches them without re-wiring.
func (s *GuardrailPolicyServer) Provider() guardrailpolicy.PolicyProvider { return s.store }

// BaselineModeProvider is the model gateway's read side of the baseline mode
// (#2738); like Provider, it follows a later durable install.
func (s *GuardrailPolicyServer) BaselineModeProvider() guardrailpolicy.BaselineModeProvider {
	return s.store
}

// Durable reports whether the server is off the fail-closed stand-in: the
// Postgres store is installed, or no Postgres is configured and the
// in-memory store is the store.
func (s *GuardrailPolicyServer) Durable() bool {
	_, standIn := s.store.current().(unavailableGuardrailPolicyStore)
	return !standIn
}

// InstallDurableStore opens the Postgres store and swaps it in atomically.
// On failure the current store stays (the fail-closed stand-in keeps
// refusing). Safe while the server is serving.
func (s *GuardrailPolicyServer) InstallDurableStore(open func() (guardrailpolicy.Store, error)) error {
	st, err := open()
	if err != nil {
		return err
	}
	if st == nil {
		return errors.New("guardrail policy store opener returned no store")
	}
	s.store.swap(st)
	return nil
}

// SetOnChange registers a callback run after every successful Set (policy
// or baseline mode). Call
// before the server serves.
func (s *GuardrailPolicyServer) SetOnChange(fn func()) { s.onChange = fn }

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
	if err := checkGuardrailRate(ctx, s.getLimit); err != nil {
		return nil, err
	}
	p, err := s.store.Get(ctx)
	if errors.Is(err, guardrailpolicy.ErrNotConfigured) {
		return &pb.GetGuardrailPolicyResponse{Configured: false}, nil
	}
	if err != nil {
		// Get is open to any authenticated caller: keep the database detail
		// in the daemon log, not in the response.
		log.Printf("[guardrail-policy] read: %v", err)
		return nil, status.Error(codes.Internal, "read guardrail policy failed")
	}
	hash, err := guardrailpolicy.Hash(p)
	if err != nil {
		log.Printf("[guardrail-policy] hash: %v", err)
		return nil, status.Error(codes.Internal, "hash guardrail policy failed")
	}
	return &pb.GetGuardrailPolicyResponse{Configured: true, Policy: p, PolicyHash: hash}, nil
}

// GetGuardrailStatus reports what scans model responses (#2737): BASELINE,
// ADMIN or NONE, derived from the store the model gateway reads. Open to any
// authenticated caller and rate-limited with Get; a read error is an error.
func (s *GuardrailPolicyServer) GetGuardrailStatus(ctx context.Context, _ *pb.GetGuardrailStatusRequest) (*pb.GetGuardrailStatusResponse, error) {
	if _, _, ok := auth.SubjectFromGRPCContext(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject in request context")
	}
	if err := checkGuardrailRate(ctx, s.getLimit); err != nil {
		return nil, err
	}
	resp, err := guardrailpolicy.EffectiveStatus(s.store.Get(ctx))
	if err != nil {
		log.Printf("[guardrail-policy] status read: %v", err)
		return nil, status.Error(codes.Internal, "read guardrail policy failed")
	}
	if resp.Baseline, err = s.store.GetBaselineMode(ctx); err != nil {
		log.Printf("[guardrail-policy] status baseline mode read: %v", err)
		return nil, status.Error(codes.Internal, "read guardrail baseline mode failed")
	}
	return resp, nil
}

// errBaselineAuditFailed marks a switch refused because its audit entry
// could not be written.
var errBaselineAuditFailed = errors.New("audit write failed")

// SetGuardrailBaselineMode switches the baseline between LOG and BLOCK
// (#2738). Admin-only, rate-limited with Set, and audited. It never touches
// the policy, so it cannot turn the baseline off; under a configured policy
// the mode is stored and unused.
//
// Unlike the policy's best-effort audit, the audit entry is part of the
// change (decision A on #2727): it is written while the store holds the new
// setting uncommitted, and a failed write rolls the change back and fails
// the call. A commit that fails after a written entry leaves an entry whose
// revision the store never reached; the status shows the lower revision.
// With no audit store the switch succeeds without an entry; whether it
// should is an open question. That is the case when the daemon has no
// Postgres, when REST is disabled (the audit store is wired only on the REST
// path in dual_server.go), or when the audit store failed to start; it has
// no startup retry.
func (s *GuardrailPolicyServer) SetGuardrailBaselineMode(ctx context.Context, req *pb.SetGuardrailBaselineModeRequest) (*pb.SetGuardrailBaselineModeResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if err := checkGuardrailRate(ctx, s.setLimit); err != nil {
		return nil, err
	}
	if !guardrailpolicy.ValidBaselineMode(req.GetMode()) {
		return nil, status.Error(codes.InvalidArgument, guardrailpolicy.ErrInvalidBaselineMode.Error())
	}
	subject, _, _ := auth.SubjectFromGRPCContext(ctx)
	var beforeCommit guardrailpolicy.BaselineBeforeCommit
	if s.audit != nil {
		beforeCommit = func(res *guardrailpolicy.BaselineSetResult) error { return s.auditBaselineSet(ctx, subject, res) }
	}
	res, err := s.store.SetBaselineMode(ctx, req.GetMode(), subject, beforeCommit)
	if errors.Is(err, errBaselineAuditFailed) {
		log.Printf("[guardrail-policy] baseline mode switch refused: %v", err)
		return nil, status.Error(codes.Internal, "write the guardrail baseline audit entry failed; the baseline mode is unchanged")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store guardrail baseline mode: %v", err)
	}
	if s.onChange != nil {
		s.onChange()
	}
	return &pb.SetGuardrailBaselineModeResponse{Baseline: res.Current}, nil
}

// auditBaselineSet writes the switch's audit entry. Its error (wrapping
// errBaselineAuditFailed) aborts the switch.
func (s *GuardrailPolicyServer) auditBaselineSet(ctx context.Context, subject string, res *guardrailpolicy.BaselineSetResult) error {
	payload, err := json.Marshal(guardrailBaselineAuditDetail{
		PreviousMode: res.Previous.GetMode().String(), PreviousRevision: res.Previous.GetRevision(),
		Mode: res.Current.GetMode().String(), Revision: res.Current.GetRevision(),
	})
	if err != nil {
		return fmt.Errorf("%w: marshal detail: %v", errBaselineAuditFailed, err)
	}
	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Username:     subject,
		Action:       guardrailBaselineSetAction,
		ResourceType: "guardrail_baseline",
		ResourceID:   "cluster",
		Detail:       string(payload),
	}); err != nil {
		return fmt.Errorf("%w: %s revision %d: %v", errBaselineAuditFailed, guardrailBaselineSetAction, res.Current.GetRevision(), err)
	}
	return nil
}

func (s *GuardrailPolicyServer) SetGuardrailPolicy(ctx context.Context, req *pb.SetGuardrailPolicyRequest) (*pb.SetGuardrailPolicyResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if err := checkGuardrailRate(ctx, s.setLimit); err != nil {
		return nil, err
	}
	if err := guardrailpolicy.ValidateSetRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	subject, _, _ := auth.SubjectFromGRPCContext(ctx)
	res, err := s.store.Set(ctx, req, subject)
	switch {
	case errors.Is(err, guardrailpolicy.ErrRevisionConflict):
		return nil, status.Error(codes.Aborted, err.Error())
	case errors.Is(err, guardrailpolicy.ErrRevocationPermanent):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	case err != nil:
		return nil, status.Errorf(codes.Internal, "store guardrail policy: %v", err)
	}
	hash, err := guardrailpolicy.Hash(res.Current)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash guardrail policy: %v", err)
	}
	s.auditSet(ctx, subject, res, hash)
	if s.onChange != nil {
		s.onChange()
	}
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
	for _, r := range res.Current.GetRevokedSigners() {
		d.RevokedSignerKeyIDs = append(d.RevokedSignerKeyIDs, r.GetKeyId())
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
