package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/gatewayprovider"
	"github.com/footprintai/containarium/internal/modelgateway"
	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ModelGatewayService (#1726) — the admin + mint surface around the model
// gateway's HTTP data plane.
//
// Everything here is authz first. Two scopes that must not substitute for one
// another (gateway:admin registers a real upstream key; gateway:mint issues a
// scoped token), and one ownership rule: a caller may only mint for a box it
// owns. The rest of the file is plumbing around those two facts.

// Gateway-token lifetime. Per the design note, a `code run` token is a per-run
// lease: 24h by default, capped server-side at the same figure, so a leaked
// token is one box, one provider, optionally one model, for at most a day — and
// revocable by jti before then.
//
// The cap is the SERVER's. A caller may ask for less and get it; a caller asking
// for more is capped rather than rejected, and the response's expires_at (which
// equals the signed exp) is the only truth about when it dies.
const (
	DefaultGatewayTokenTTL = 24 * time.Hour
	MaxGatewayTokenTTL     = 24 * time.Hour
)

// ErrBoxNotFound is returned by a BoxAttributionLookup when no box exists for a
// tenant. It is deliberately the same outcome the server reports for a box that
// belongs to somebody else — see resolveBoxKeyOwner.
var ErrBoxNotFound = errors.New("server: no such box")

// GatewayKeyStore is the per-owner provider-key custody this service needs.
// Satisfied by *secrets.Store; an interface so the service can be tested without
// Postgres and so nothing here can reach the tenant-facing secret verbs by
// accident.
type GatewayKeyStore interface {
	SetGatewayProviderKey(ctx context.Context, keyOwner, provider, key string) error
	DeleteGatewayProviderKey(ctx context.Context, keyOwner, provider string) error
	GatewayProviderKeyStatus(ctx context.Context, keyOwner, provider string) (secrets.GatewayKeyStatus, error)
	KeyFor(ctx context.Context, keyOwner, provider string) (string, bool)
}

// BoxAttributionLookup answers the one question the mint path asks of the box
// store: does this tenant have a box, and is that box attributed to a cloud
// organization?
//
// Narrow on purpose. The mint path must not be able to read, mutate or enumerate
// boxes — it needs existence plus one label.
type BoxAttributionLookup interface {
	// BoxAttribution returns the box's cloud-org id, or "" when the box exists
	// but carries no attribution. Returns ErrBoxNotFound when there is no box.
	BoxAttribution(ctx context.Context, tenant string) (orgID string, err error)
}

// ModelGatewayServer implements pb.ModelGatewayServiceServer.
type ModelGatewayServer struct {
	pb.UnimplementedModelGatewayServiceServer

	keys  GatewayKeyStore
	boxes BoxAttributionLookup

	// gw is the running model gateway. Nil when this daemon does not serve one
	// (no provider key and no operator-registered upstream), in which case the
	// mint and list verbs refuse rather than hand back a token that could never
	// be used.
	gw *modelgateway.Gateway

	// secret signs gateway tokens — the daemon's jwt secret, the same trust root
	// the gateway verifies with. No new PKI.
	secret []byte
	// gatewayHost is the host a BOX reaches this daemon's gateway on (the bridge
	// gateway IP). Empty means the daemon cannot name a reachable base URL, and
	// minting refuses rather than return one that is wrong.
	gatewayHost string
	httpPort    int
}

// NewModelGatewayServer wires the service. gw/secret/gatewayHost may be zero on
// a daemon that does not serve the model gateway; the key verbs still work
// (a control plane can pre-register keys), the token verbs refuse.
func NewModelGatewayServer(keys GatewayKeyStore, boxes BoxAttributionLookup, gw *modelgateway.Gateway, secret []byte, gatewayHost string, httpPort int) *ModelGatewayServer {
	return &ModelGatewayServer{keys: keys, boxes: boxes, gw: gw, secret: secret, gatewayHost: gatewayHost, httpPort: httpPort}
}

// containerBoxAttribution adapts the daemon's box store to
// BoxAttributionLookup. It is the only place in this service that knows a box is
// an Incus container with labels.
type containerBoxAttribution struct{ cs *ContainerServer }

// NewContainerBoxAttribution returns the BoxAttributionLookup the daemon wires
// into ModelGatewayServer.
func NewContainerBoxAttribution(cs *ContainerServer) BoxAttributionLookup {
	return containerBoxAttribution{cs: cs}
}

// BoxAttribution implements BoxAttributionLookup over the box backend.
//
// The cloud-org id is read from the `cloud_org_id` attribution label — the one
// the control plane stamps (ContainerServer.SetContainerAttribution, and
// CreateContainer for boxes it provisions). See resolveBoxKeyOwner for why the
// pull-mode tenant label is deliberately not consulted.
func (a containerBoxAttribution) BoxAttribution(ctx context.Context, tenant string) (string, error) {
	if a.cs == nil {
		return "", ErrBoxNotFound
	}
	st, err := a.cs.boxes().Get(ctx, box.BoxRef{Tenant: tenant})
	if err != nil {
		// "not there" and "the lookup broke" are different answers: the first is
		// NotFound, the second must not masquerade as one or a caller chases the
		// wrong problem during an outage.
		if incus.IsNotFound(err) {
			return "", ErrBoxNotFound
		}
		return "", err
	}
	if st == nil {
		return "", ErrBoxNotFound
	}
	return st.Labels[cloudOrgIDLabel], nil
}

// SetGateway tells the service that this daemon serves the model gateway, and
// on which host/port a box reaches it. Called by the daemon once the gateway is
// built (which happens after the gRPC services are registered, hence a setter
// rather than a constructor argument — the same shape RecipeServer and
// AgentSkillServer use for their gateway provisioning).
func (s *ModelGatewayServer) SetGateway(gw *modelgateway.Gateway, secret []byte, gatewayHost string, httpPort int) {
	s.gw = gw
	s.secret = secret
	s.gatewayHost = gatewayHost
	s.httpPort = httpPort
}

// GatewayKeyStoreOf returns containerServer's secrets store as a
// GatewayKeyStore, or nil when the daemon has none.
//
// The explicit nil check is load-bearing: a nil *secrets.Store placed in an
// interface field yields a NON-nil interface holding a nil pointer, so the
// service's `s.keys == nil` guards would not fire and every call would
// dereference nil. A daemon without Postgres reaches here with a nil store, so
// this is the common path, not a corner case. (Same hazard dual_server.go
// documents for the gateway's revocation and key-resolver fields.)
func GatewayKeyStoreOf(cs *ContainerServer) GatewayKeyStore {
	if cs == nil || cs.secretsStore == nil {
		return nil
	}
	return cs.secretsStore
}

// validateKeyOwnerArg turns a malformed key_owner into InvalidArgument. The rule
// itself lives in modelgateway (one definition, shared by the mint path and the
// store) — this only maps it to a gRPC code.
func validateKeyOwnerArg(keyOwner string) error {
	if err := modelgateway.ValidateKeyOwner(keyOwner); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// SetTenantProviderKey stores or rotates one key owner's real upstream key.
func (s *ModelGatewayServer) SetTenantProviderKey(ctx context.Context, req *pb.SetTenantProviderKeyRequest) (*pb.SetTenantProviderKeyResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeGatewayAdmin); err != nil {
		return nil, err
	}
	if s.keys == nil {
		return nil, status.Error(codes.Unavailable, "this daemon holds no secrets store, so it cannot store per-owner provider keys")
	}
	if err := validateKeyOwnerArg(req.GetKeyOwner()); err != nil {
		return nil, err
	}
	provider, err := gatewayprovider.Name(req.GetProvider())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if strings.TrimSpace(req.GetApiKey()) == "" {
		return nil, status.Error(codes.InvalidArgument, "api_key is required")
	}
	if err := s.keys.SetGatewayProviderKey(ctx, req.GetKeyOwner(), provider, req.GetApiKey()); err != nil {
		return nil, status.Errorf(codes.Internal, "storing the provider key failed: %v", err)
	}
	// Read the status back rather than fingerprinting the request: the response
	// then describes what is STORED, not what the caller sent.
	st, err := s.keys.GatewayProviderKeyStatus(ctx, req.GetKeyOwner(), provider)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reading the stored key's status failed: %v", err)
	}
	resp := &pb.SetTenantProviderKeyResponse{
		KeyOwner:    req.GetKeyOwner(),
		Provider:    req.GetProvider(),
		Fingerprint: st.Fingerprint,
	}
	if !st.SetAt.IsZero() {
		resp.SetAt = timestamppb.New(st.SetAt)
	}
	return resp, nil
}

// DeleteTenantProviderKey removes one owner's key and revokes the tokens issued
// against it.
func (s *ModelGatewayServer) DeleteTenantProviderKey(ctx context.Context, req *pb.DeleteTenantProviderKeyRequest) (*pb.DeleteTenantProviderKeyResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeGatewayAdmin); err != nil {
		return nil, err
	}
	if s.keys == nil {
		return nil, status.Error(codes.Unavailable, "this daemon holds no secrets store, so it cannot store per-owner provider keys")
	}
	if err := validateKeyOwnerArg(req.GetKeyOwner()); err != nil {
		return nil, err
	}
	provider, err := gatewayprovider.Name(req.GetProvider())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.keys.DeleteGatewayProviderKey(ctx, req.GetKeyOwner(), provider); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "no %s key registered for %s", provider, req.GetKeyOwner())
		}
		return nil, status.Errorf(codes.Internal, "removing the provider key failed: %v", err)
	}
	// Removing the key is only half of "stop spending it": tokens already issued
	// for this owner would otherwise keep working until they expire. Best-effort
	// and reported honestly — tokens_revoked=false says the tokens outlive the
	// key, which an operator needs to know rather than assume away.
	revoked := false
	if s.gw != nil {
		if rerr := s.gw.RevokeByKeyOwner(ctx, req.GetKeyOwner(), "provider key deleted"); rerr == nil {
			revoked = true
		}
	}
	return &pb.DeleteTenantProviderKeyResponse{TokensRevoked: revoked}, nil
}

// GetTenantProviderKeyStatus reports the metadata of one owner's key. Never the
// key.
func (s *ModelGatewayServer) GetTenantProviderKeyStatus(ctx context.Context, req *pb.GetTenantProviderKeyStatusRequest) (*pb.GetTenantProviderKeyStatusResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeGatewayAdmin); err != nil {
		return nil, err
	}
	if s.keys == nil {
		return nil, status.Error(codes.Unavailable, "this daemon holds no secrets store, so it cannot store per-owner provider keys")
	}
	if err := validateKeyOwnerArg(req.GetKeyOwner()); err != nil {
		return nil, err
	}
	provider, err := gatewayprovider.Name(req.GetProvider())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	st, err := s.keys.GatewayProviderKeyStatus(ctx, req.GetKeyOwner(), provider)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reading the key's status failed: %v", err)
	}
	resp := &pb.GetTenantProviderKeyStatusResponse{
		KeyOwner:    req.GetKeyOwner(),
		Provider:    req.GetProvider(),
		Set:         st.Set,
		Fingerprint: st.Fingerprint,
	}
	if !st.SetAt.IsZero() {
		resp.SetAt = timestamppb.New(st.SetAt)
	}
	return resp, nil
}

// MintGatewayToken issues a scoped gateway token for a box the caller owns.
func (s *ModelGatewayServer) MintGatewayToken(ctx context.Context, req *pb.MintGatewayTokenRequest) (*pb.MintGatewayTokenResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeGatewayMint); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetBox()) == "" {
		return nil, status.Error(codes.InvalidArgument, "box is required")
	}
	provider, err := gatewayprovider.Name(req.GetProvider())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if s.gw == nil {
		return nil, status.Error(codes.FailedPrecondition, "this daemon does not serve the model gateway; no provider key and no registered upstream")
	}
	if !s.gw.HasProvider(provider) {
		return nil, status.Errorf(codes.FailedPrecondition, "this daemon does not serve the provider %q", provider)
	}
	if s.gatewayHost == "" || s.httpPort == 0 {
		return nil, status.Error(codes.FailedPrecondition, "this daemon cannot name a reachable model-gateway base URL")
	}

	tenant, keyOwner, err := s.resolveBoxKeyOwner(ctx, req.GetBox())
	if err != nil {
		return nil, err
	}
	if s.keys == nil {
		return nil, status.Error(codes.Unavailable, "this daemon holds no secrets store, so it cannot resolve per-owner provider keys")
	}
	// Refuse rather than let the gateway fall back to the daemon-global key at
	// call time (#1725's resolveKey case 3): a token issued now that is KNOWN to
	// bill the operator instead of the owner is a billing bug we can decline to
	// create. The fallback stays for tokens issued before the key was removed.
	if key, ok := s.keys.KeyFor(ctx, keyOwner, provider); !ok || key == "" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"no %s key registered for %s; register one before minting a token that would spend it", provider, keyOwner)
	}

	boxName := tenant + gatewayBoxNameSuffix
	baseURL := fmt.Sprintf("http://%s:%d/v1/model/%s", s.gatewayHost, s.httpPort, provider)

	// dry_run has validated everything a real mint validates and stops here. It
	// returns what a real mint WOULD return minus anything issued — no token, no
	// jti, no expiry, because nothing exists to expire.
	if req.GetDryRun() {
		return &pb.MintGatewayTokenResponse{BaseUrl: baseURL, KeyOwner: keyOwner}, nil
	}

	token, minted, err := modelgateway.MintTokenWithID(s.secret, modelgateway.GatewayClaims{
		Tenant:        boxName,
		RunID:         req.GetRunId(),
		Provider:      provider,
		KeyOwner:      keyOwner,
		AllowedModels: req.GetAllowedModels(),
	}, cappedGatewayTokenTTL(req))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "minting the gateway token failed: %v", err)
	}
	return &pb.MintGatewayTokenResponse{
		Token:     token,
		BaseUrl:   baseURL,
		KeyOwner:  keyOwner,
		ExpiresAt: timestamppb.New(minted.ExpiresAt),
		TokenId:   minted.JTI,
	}, nil
}

// ListGatewayModels reads the provider's model list on the resolved owner's key.
func (s *ModelGatewayServer) ListGatewayModels(ctx context.Context, req *pb.ListGatewayModelsRequest) (*pb.ListGatewayModelsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeGatewayMint); err != nil {
		return nil, err
	}
	provider, err := gatewayprovider.Name(req.GetProvider())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if s.gw == nil {
		return nil, status.Error(codes.FailedPrecondition, "this daemon does not serve the model gateway; no provider key and no registered upstream")
	}

	var keyOwner string
	if strings.TrimSpace(req.GetBox()) != "" {
		// Named box: the same ownership check and the same resolution the mint
		// path uses, so "which models may this box use" and "which key will this
		// box spend" cannot disagree.
		if _, keyOwner, err = s.resolveBoxKeyOwner(ctx, req.GetBox()); err != nil {
			return nil, err
		}
	} else {
		// No box named: the caller's own owner id. This is the
		// `containarium gateway models --provider …` shape, where the question
		// is "what can I see", not "what can that box see".
		subject, _, ok := auth.SubjectFromGRPCContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
		}
		keyOwner = modelgateway.UserKeyOwner(subject)
		if verr := modelgateway.ValidateKeyOwner(keyOwner); verr != nil {
			return nil, status.Errorf(codes.Internal, "the caller's own key owner is malformed: %v", verr)
		}
	}

	models, err := s.gw.ListModels(ctx, keyOwner, provider)
	if err != nil {
		return nil, gatewayModelListError(provider, keyOwner, err)
	}
	out := make([]*pb.GatewayModel, 0, len(models))
	for _, id := range models {
		out = append(out, &pb.GatewayModel{Id: id})
	}
	return &pb.ListGatewayModelsResponse{Models: out, KeyOwner: keyOwner}, nil
}

// gatewayModelListError maps a modelgateway model-list failure onto a gRPC code.
// The distinction that matters: a customer's key being wrong or missing is
// FailedPrecondition (the caller can fix it), not Internal (we page someone).
func gatewayModelListError(provider, keyOwner string, err error) error {
	switch {
	case errors.Is(err, modelgateway.ErrNoKey):
		return status.Errorf(codes.FailedPrecondition, "no %s key registered for %s", provider, keyOwner)
	case errors.Is(err, modelgateway.ErrUnknownProvider),
		errors.Is(err, modelgateway.ErrModelListUnsupported):
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	var upstream *modelgateway.UpstreamStatusError
	if errors.As(err, &upstream) {
		switch upstream.StatusCode {
		case 401, 403:
			return status.Errorf(codes.FailedPrecondition,
				"the %s key registered for %s was rejected upstream (%d)", provider, keyOwner, upstream.StatusCode)
		case 429:
			return status.Errorf(codes.ResourceExhausted, "%v", upstream)
		}
		return status.Errorf(codes.Unavailable, "%v", upstream)
	}
	return status.Errorf(codes.Unavailable, "listing %s models failed: %v", provider, err)
}

// gatewayBoxNameSuffix is the `<username>-container` convention box names follow.
const gatewayBoxNameSuffix = "-container"

// resolveBoxKeyOwner turns a caller-supplied box reference into (tenant,
// key_owner), enforcing ownership on the way.
//
// Cross-tenant and non-existent are DELIBERATELY the same answer — NotFound,
// with the same message. A box name is derivable from a username
// (`<username>-container`), so a PermissionDenied here would be a working oracle
// for "does tenant X have a box on this daemon"; collapsing the two closes it.
// Note this differs from SandboxServer.lookupOwnedSandbox, which returns
// PermissionDenied for cross-tenant on purpose — a sandbox id is a
// server-generated opaque id, so confirming one exists reveals nothing an
// attacker could have guessed. Same principle, opposite answer, because the
// identifier's guessability differs. (#1726)
//
// The org half deliberately reads ONLY the cloud_org_id attribution label. The
// pull-mode actuator writes an org id into incus.TenantLabelKey, but so does
// SandboxServer — with a USERNAME — and treating a username as an org id is
// exactly the namespace collision #1725's `user:`/`org:` prefixes exist to make
// impossible. An ambiguous label is not evidence of attribution.
func (s *ModelGatewayServer) resolveBoxKeyOwner(ctx context.Context, boxRef string) (tenant, keyOwner string, err error) {
	// notFound is one value so the cross-tenant and absent cases are
	// byte-identical, not merely the same code.
	notFound := status.Error(codes.NotFound, "no such box")

	tenant = strings.TrimSpace(boxRef)
	tenant = strings.TrimSuffix(tenant, gatewayBoxNameSuffix)
	if tenant == "" {
		return "", "", status.Error(codes.InvalidArgument, "box is required")
	}

	subject, roles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return "", "", status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	// Ownership BEFORE existence, so a cross-tenant probe never reaches the box
	// store at all — the check cannot be reordered past an early return because
	// there is nothing between the two.
	if !auth.HasRole(roles, auth.RoleAdmin) && tenant != subject {
		return "", "", notFound
	}
	if s.boxes == nil {
		return "", "", status.Error(codes.Unavailable, "this daemon cannot look boxes up")
	}
	orgID, err := s.boxes.BoxAttribution(ctx, tenant)
	if err != nil {
		if errors.Is(err, ErrBoxNotFound) {
			return "", "", notFound
		}
		return "", "", status.Errorf(codes.Internal, "looking the box up failed: %v", err)
	}

	if orgID = strings.TrimSpace(orgID); orgID != "" {
		keyOwner = modelgateway.OrgKeyOwner(orgID)
	} else {
		keyOwner = modelgateway.UserKeyOwner(tenant)
	}
	// A stamped-but-malformed attribution must not silently degrade to the
	// username's key: that would bill the wrong owner and is indistinguishable
	// from a crafted label.
	if verr := modelgateway.ValidateKeyOwner(keyOwner); verr != nil {
		return "", "", status.Errorf(codes.Internal, "box %q has an unusable key owner: %v", tenant, verr)
	}
	return tenant, keyOwner, nil
}

// cappedGatewayTokenTTL is the server's TTL decision: absent, zero or negative
// takes the default; anything above the cap is capped.
func cappedGatewayTokenTTL(req *pb.MintGatewayTokenRequest) time.Duration {
	ttl := DefaultGatewayTokenTTL
	if d := req.GetTtl(); d != nil {
		if asked := d.AsDuration(); asked > 0 {
			ttl = asked
		}
	}
	if ttl > MaxGatewayTokenTTL {
		ttl = MaxGatewayTokenTTL
	}
	return ttl
}
