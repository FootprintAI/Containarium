// Package sshcontrol shares guarded SSH setup admission across local plugins.
package sshcontrol

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshgate"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config supplies explicit policy, private durable state and authoritative routing.
type Config struct {
	Policy    *pb.SSHUpstreamPolicy
	StatePath string
	Resolve   func(endpoint string) (string, error)
	Now       func() time.Time
}

// Controller is the one process-shared owner for main and anonymous admission.
type Controller struct {
	pb.UnimplementedSentinelSSHUpstreamServiceServer
	mu              sync.Mutex
	cfg             Config
	gate            *sshgate.Gate
	generation      string
	readyAt         time.Time
	aliases         map[string]string
	versions        map[string]uint64
	connections     map[string]*connection
	anonymousRoutes map[string]string
	leases          map[string]reservation
	fault           error
	stateLock       *os.File
}

// New validates policy and restores conservative risk before exposing admission.
func New(cfg Config) (*Controller, error) {
	if cfg.Policy == nil || cfg.StatePath == "" {
		return nil, errors.New("upstream policy and private state path are required")
	}
	cfg.Policy = proto.Clone(cfg.Policy).(*pb.SSHUpstreamPolicy)
	p := cfg.Policy
	for _, d := range []interface{ CheckValid() error }{p.InitialDelay, p.MaxDelay, p.Window, p.SetupTimeout} {
		if err := d.CheckValid(); err != nil {
			return nil, fmt.Errorf("invalid upstream duration: %w", err)
		}
	}
	if p.RiskPerAttempt == 0 || p.RiskPerAttempt > p.FailureBudget || p.MaxConnections == 0 || p.MaxConnections > 65536 || p.MaxBackends > 65536 || p.MaxPending > 65536 || p.FailureBudget > 65536 || p.EgressGroup == "" {
		return nil, errors.New("invalid bounded upstream policy")
	}
	for _, r := range p.Routes {
		if r.BackendId == "" || !validEndpoint(r.Endpoint) {
			return nil, errors.New("invalid authoritative upstream route")
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	g, err := sshgate.New(sshgate.Policy{InitialDelay: p.InitialDelay.AsDuration(), MaxDelay: p.MaxDelay.AsDuration(), Window: p.Window.AsDuration(), LeaseTimeout: p.SetupTimeout.AsDuration(), Budget: int(p.FailureBudget), MaxBackends: int(p.MaxBackends), MaxPending: int(p.MaxPending), Jitter: p.Jitter}, cfg.Now, rand.Float64)
	if err != nil {
		return nil, err
	}
	c := &Controller{cfg: cfg, gate: g, generation: crand.Text(), aliases: map[string]string{}, versions: map[string]uint64{}, connections: map[string]*connection{}, leases: map[string]reservation{}, anonymousRoutes: map[string]string{}}
	if err := privateDirectory(filepath.Dir(cfg.StatePath)); err != nil {
		return nil, err
	}
	c.stateLock, err = lockState(cfg.StatePath + ".lock")
	if err != nil {
		return nil, err
	}
	if err := c.restore(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// Close prevents further admission before releasing exclusive durable ownership.
func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fault = errors.New("upstream controller closed")
	if c.stateLock == nil {
		return nil
	}
	f := c.stateLock
	c.stateLock = nil
	return f.Close()
}

// Faulted reports a poisoned/closed owner without exposing private storage errors.
func (c *Controller) Faulted() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.fault != nil }

// connection holds transport-bound provenance for the current route only.
type connection struct {
	ref                                          *pb.SSHUpstreamConnection
	route, lease, anonymousEndpoint, anonymousID string
	authSkip, terminalSkip                       bool
	expires                                      time.Time
}

// reservation retains authority for exactly one admitted backend setup.
type reservation struct {
	lease                  sshgate.Lease
	owner, route, endpoint string
	proxy                  bool
}

// validEndpoint accepts a concrete network endpoint, never an arbitrary URI.
func validEndpoint(endpoint string) bool {
	if len(endpoint) > 512 {
		return false
	}
	host, port, err := net.SplitHostPort(endpoint)
	n, perr := strconv.Atoi(port)
	return err == nil && host != "" && perr == nil && n > 0 && n <= 65535
}

// connectionKey preserves listener separation even when transport UUIDs collide.
func connectionKey(ref *pb.SSHUpstreamConnection) string {
	return fmt.Sprintf("%d/%s", ref.GetListener(), ref.GetConnectionId())
}

// validConnection requires the full original transport address, not just its IP.
func validConnection(ref *pb.SSHUpstreamConnection) bool {
	return ref != nil && (ref.Listener == pb.SSHBanListener_SSH_BAN_LISTENER_MAIN || ref.Listener == pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS) && ref.ConnectionId != "" && len(ref.ConnectionId) <= 128 && len(ref.RemoteAddr) <= 256 && validEndpoint(ref.RemoteAddr)
}

// find rejects stale processes and substituted metadata before any state change.
func (c *Controller) find(ref *pb.SSHUpstreamConnection) (*connection, error) {
	if !validConnection(ref) || ref.ControllerGeneration != c.generation {
		return nil, status.Error(codes.FailedPrecondition, "unknown upstream controller generation")
	}
	s := c.connections[connectionKey(ref)]
	if s == nil || s.ref.RemoteAddr != ref.RemoteAddr || !c.cfg.Now().Before(s.expires) {
		return nil, status.Error(codes.NotFound, "unknown upstream transport")
	}
	return s, nil
}

// OpenSSHUpstreamConnection registers bounded, immutable transport metadata.
func (c *Controller) OpenSSHUpstreamConnection(_ context.Context, r *pb.OpenSSHUpstreamConnectionRequest) (*pb.OpenSSHUpstreamConnectionResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != nil {
		return nil, status.Error(codes.Unavailable, "upstream controller unavailable")
	}
	ref := r.GetConnection()
	if !validConnection(ref) {
		return nil, status.Error(codes.InvalidArgument, "invalid upstream transport")
	}
	c.reap()
	key := connectionKey(ref)
	if old := c.connections[key]; old != nil {
		if old.ref.RemoteAddr != ref.RemoteAddr {
			return nil, status.Error(codes.AlreadyExists, "transport identity substitution")
		}
	} else {
		if len(c.connections) >= int(c.cfg.Policy.MaxConnections) {
			return nil, status.Error(codes.ResourceExhausted, "upstream connection capacity")
		}
		source := transportSource(ref.RemoteAddr)
		used := 0
		for _, conn := range c.connections {
			if transportSource(conn.ref.RemoteAddr) == source {
				used++
			}
		}
		if used >= max(1, min(64, int(c.cfg.Policy.MaxConnections)/4)) {
			return nil, status.Error(codes.ResourceExhausted, "upstream per-source metadata capacity")
		}
		copy := proto.Clone(ref).(*pb.SSHUpstreamConnection)
		copy.ControllerGeneration = c.generation
		c.connections[key] = &connection{ref: copy, expires: c.cfg.Now().Add(5*time.Minute + c.cfg.Policy.SetupTimeout.AsDuration())}
	}
	return &pb.OpenSSHUpstreamConnectionResponse{ControllerGeneration: c.generation, ReadyAt: timestamppb.New(c.readyAt)}, nil
}

// transportSource normalizes mapped IPv4 so one address cannot borrow two caps.
func transportSource(remote string) string {
	host, _, _ := net.SplitHostPort(remote)
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	return host
}

// reap bounds abandoned metadata without refunding pending gate risk.
func (c *Controller) reap() {
	now := c.cfg.Now()
	for id, s := range c.connections {
		if !now.Before(s.expires) {
			delete(c.connections, id)
		}
	}
	for token, l := range c.leases {
		if !now.Before(l.lease.Deadline) {
			delete(c.leases, token)
		}
	}
	live := make(map[string]bool)
	for _, s := range c.connections {
		live[s.anonymousID] = true
	}
	for id := range c.anonymousRoutes {
		if !live[id] {
			delete(c.anonymousRoutes, id)
		}
	}
	// Risk-bearing inventory cannot be evicted by address churn or capacity.
	drained := make(map[string]bool)
	for id, version := range c.versions {
		if c.gate.Forget(sshgate.Key{Backend: id, Egress: c.cfg.Policy.EgressGroup}, version) {
			delete(c.versions, id)
			drained[id] = true
		}
	}
	for alias, canonical := range c.aliases {
		if drained[canonical] {
			delete(c.aliases, alias)
		}
	}
}

// BeginSSHUpstreamRoute clears prior exceptions before child authorization.
func (c *Controller) BeginSSHUpstreamRoute(_ context.Context, r *pb.BeginSSHUpstreamRouteRequest) (*pb.BeginSSHUpstreamRouteResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != nil {
		return nil, status.Error(codes.Unavailable, "upstream controller unavailable")
	}
	s, err := c.find(r.GetConnection())
	if err != nil {
		return nil, err
	}
	if l, ok := c.leases[s.lease]; ok {
		c.gate.Complete(l.lease, sshgate.SetupFailed)
		delete(c.leases, s.lease)
		if err := c.persist(); err != nil {
			return nil, err
		}
	}
	s.route, s.lease, s.authSkip, s.terminalSkip = crand.Text(), "", false, false
	return &pb.BeginSSHUpstreamRouteResponse{RouteToken: s.route}, nil
}

// resolve accepts operator inventory or an endpoint registered by signed Ensure.
func (c *Controller) resolve(s *connection, endpoint string) (string, error) {
	if !validEndpoint(endpoint) {
		return "", errors.New("invalid selected endpoint")
	}
	if c.cfg.Resolve != nil {
		if id, err := c.cfg.Resolve(endpoint); err == nil && id != "" {
			return id, nil
		}
	}
	for _, r := range c.cfg.Policy.Routes {
		if r.Endpoint == endpoint {
			return r.BackendId, nil
		}
	}
	if endpoint == s.anonymousEndpoint && s.anonymousID != "" && c.anonymousRoutes[s.anonymousID] == endpoint {
		// Box names authorize a live route; the physical endpoint owns jail
		// risk across DHCP lifetimes, without permanent box/address unions.
		return "endpoint/" + endpoint, nil
	}
	return "", errors.New("selected endpoint is absent from authoritative inventory")
}

// identify preserves one budget across endpoints and stable backend aliases.
func (c *Controller) identify(id, endpoint string) (sshgate.Key, uint64, error) {
	if id == "" || len(id) > 512 {
		return sshgate.Key{}, 0, errors.New("invalid canonical backend identity")
	}
	ia, ea := "id:"+id, "endpoint:"+endpoint
	canonical, existing := c.aliases[ia], c.aliases[ea]
	if canonical != "" && existing != "" && canonical != existing {
		return sshgate.Key{}, 0, errors.New("conflicting backend identities")
	}
	if canonical == "" {
		canonical = existing
	}
	if canonical == "" {
		canonical = id
	}
	needed := 0
	if c.aliases[ia] == "" {
		needed++
	}
	if c.aliases[ea] == "" {
		needed++
	}
	if len(c.aliases)+needed > int(c.cfg.Policy.MaxBackends)*16 {
		return sshgate.Key{}, 0, &sshgate.Denied{Reason: sshgate.Capacity}
	}
	version := c.versions[canonical]
	if version == 0 {
		version = 1
	}
	key := sshgate.Key{Backend: canonical, Egress: c.cfg.Policy.EgressGroup}
	if err := c.gate.Register(key, version); err != nil {
		return sshgate.Key{}, 0, err
	}
	c.aliases[ia], c.aliases[ea], c.versions[canonical] = canonical, canonical, version
	return key, version, nil
}

// AcquireSSHUpstream commits a reservation before allowing any backend socket.
func (c *Controller) AcquireSSHUpstream(_ context.Context, r *pb.AcquireSSHUpstreamRequest) (*pb.AcquireSSHUpstreamResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.find(r.GetConnection())
	if err != nil {
		return nil, err
	}
	if r.RouteToken == "" || r.RouteToken != s.route || r.AttemptId == "" || len(r.AttemptId) > 128 || s.lease != "" {
		return nil, status.Error(codes.InvalidArgument, "invalid or reused upstream route")
	}
	deny := func(reason pb.SSHUpstreamAdmissionReason, retry time.Time) (*pb.AcquireSSHUpstreamResponse, error) {
		s.authSkip, s.terminalSkip = true, true
		out := &pb.AcquireSSHUpstreamResponse{Reason: reason}
		if !retry.IsZero() {
			out.RetryAt = timestamppb.New(retry)
		}
		return out, nil
	}
	if c.fault != nil {
		return deny(pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_STATE_UNAVAILABLE, time.Time{})
	}
	if c.cfg.Now().Before(c.readyAt) {
		return deny(pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_WARMUP, c.readyAt)
	}
	id, err := c.resolve(s, r.Endpoint)
	if err != nil {
		return deny(pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_UNKNOWN_ROUTE, time.Time{})
	}
	key, version, err := c.identify(id, r.Endpoint)
	if err != nil {
		var denied *sshgate.Denied
		if errors.As(err, &denied) {
			return deny(admissionReason(denied.Reason), denied.RetryAt)
		}
		return deny(pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_IDENTITY_CONFLICT, time.Time{})
	}
	lease, err := c.gate.Acquire(key, version, int(c.cfg.Policy.RiskPerAttempt))
	if err != nil {
		var d *sshgate.Denied
		if errors.As(err, &d) {
			return deny(admissionReason(d.Reason), d.RetryAt)
		}
		return deny(pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_STATE_UNAVAILABLE, time.Time{})
	}
	token := crand.Text()
	c.leases[token] = reservation{lease: lease, owner: connectionKey(s.ref), route: s.route, proxy: r.ProxyCredential, endpoint: r.Endpoint}
	s.lease = token
	if err := c.persist(); err != nil {
		return deny(pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_STATE_UNAVAILABLE, time.Time{})
	}
	return &pb.AcquireSSHUpstreamResponse{Admitted: true, LeaseToken: token, Deadline: timestamppb.New(lease.Deadline)}, nil
}

// admissionReason preserves the gate's typed denial across the private contract.
func admissionReason(reason sshgate.Reason) pb.SSHUpstreamAdmissionReason {
	switch reason {
	case sshgate.UnknownBackend:
		return pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_UNKNOWN_ROUTE
	case sshgate.StaleRoute:
		return pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_STALE_ROUTE
	case sshgate.InvalidCost:
		return pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_INVALID_COST
	case sshgate.Cooldown:
		return pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_COOLDOWN
	case sshgate.ProbeBusy:
		return pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_PROBE_BUSY
	case sshgate.BudgetExhausted:
		return pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_BUDGET_EXHAUSTED
	case sshgate.Capacity:
		return pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_CAPACITY
	default:
		return pb.SSHUpstreamAdmissionReason_SSH_UPSTREAM_ADMISSION_REASON_STATE_UNAVAILABLE
	}
}

// CompleteSSHUpstream settles only the original route, lease and process.
func (c *Controller) CompleteSSHUpstream(_ context.Context, r *pb.CompleteSSHUpstreamRequest) (*pb.CompleteSSHUpstreamResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != nil {
		return nil, status.Error(codes.Unavailable, "upstream durable controller unavailable")
	}
	s, err := c.find(r.GetConnection())
	if err != nil {
		return nil, err
	}
	l, ok := c.leases[r.LeaseToken]
	if !ok || s.route != r.RouteToken || s.lease != r.LeaseToken || l.owner != connectionKey(s.ref) || l.route != r.RouteToken {
		return &pb.CompleteSSHUpstreamResponse{}, nil
	}
	outcome, skip := sshgate.SetupFailed, false
	stale := false
	switch r.Outcome {
	case pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SSH_READY:
		outcome = sshgate.SetupSucceeded
		id, err := c.resolve(s, l.endpoint)
		moved := s.anonymousID != "" && c.anonymousRoutes[s.anonymousID] != l.endpoint
		if err != nil || moved || c.aliases["id:"+id] != l.lease.Key.Backend || l.lease.Route != c.versions[l.lease.Key.Backend] {
			outcome, skip, stale = sshgate.ClientAuthRejected, true, true
		}
	case pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_TCP_REFUSED, pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_CONNECT_FAILED:
		outcome, skip = sshgate.DialRefused, true
	case pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_HOST_KEY_FAILED:
		skip = true
	case pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_PROXY_AUTH_REJECTED:
		if !l.proxy {
			return nil, status.Error(codes.InvalidArgument, "client credential cannot claim proxy rejection")
		}
		outcome, skip = sshgate.ProxyAuthRejected, true
	case pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_CLIENT_AUTH_REJECTED:
		outcome = sshgate.ClientAuthRejected
	case pb.SSHUpstreamOutcome_SSH_UPSTREAM_OUTCOME_SETUP_FAILED:
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown upstream outcome")
	}
	accepted := c.gate.Complete(l.lease, outcome)
	accepted = accepted && !stale
	delete(c.leases, r.LeaseToken)
	s.lease = ""
	if skip {
		s.authSkip, s.terminalSkip = true, true
	}
	if err := c.persist(); err != nil {
		return nil, status.Error(codes.Unavailable, "cannot commit upstream outcome")
	}
	if accepted && outcome == sshgate.SetupSucceeded {
		delete(c.connections, connectionKey(s.ref))
	}
	return &pb.CompleteSSHUpstreamResponse{Accepted: accepted}, nil
}

// ConsumeSSHUpstreamFailure consumes typed exceptions and otherwise counts.
func (c *Controller) ConsumeSSHUpstreamFailure(_ context.Context, r *pb.ConsumeSSHUpstreamFailureRequest) (*pb.ConsumeSSHUpstreamFailureResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != nil {
		return &pb.ConsumeSSHUpstreamFailureResponse{}, nil
	}
	if r.GetConnection().GetControllerGeneration() != c.generation {
		return &pb.ConsumeSSHUpstreamFailureResponse{}, nil
	}
	s, err := c.find(r.GetConnection())
	if err != nil {
		return nil, err
	}
	var count bool
	switch r.Kind {
	case pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_AUTH:
		count = !s.authSkip
		s.authSkip = false
	case pb.SSHUpstreamFailureKind_SSH_UPSTREAM_FAILURE_KIND_PIPE_CREATE:
		count = !s.terminalSkip
		if l, ok := c.leases[s.lease]; ok {
			c.gate.Complete(l.lease, sshgate.SetupFailed)
			delete(c.leases, s.lease)
			if err := c.persist(); err != nil {
				return nil, err
			}
		}
		delete(c.connections, connectionKey(s.ref))
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown source failure event")
	}
	return &pb.ConsumeSSHUpstreamFailureResponse{CountSourceFailure: count}, nil
}

// RegisterSSHAnonymousRoute binds the trusted Ensure result to its transport.
func (c *Controller) RegisterSSHAnonymousRoute(_ context.Context, r *pb.RegisterSSHAnonymousRouteRequest) (*pb.RegisterSSHAnonymousRouteResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != nil {
		return nil, status.Error(codes.Unavailable, "upstream controller unavailable")
	}
	c.reap()
	s, err := c.find(r.GetConnection())
	if err != nil {
		return nil, err
	}
	if s.ref.Listener != pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS || r.BoxName == "" || len(r.BoxName) > 256 || !validEndpoint(r.Endpoint) {
		return nil, status.Error(codes.InvalidArgument, "invalid anonymous Ensure route")
	}
	s.anonymousID, s.anonymousEndpoint = "anonymous/"+r.BoxName, r.Endpoint
	old := c.anonymousRoutes[s.anonymousID]
	if old == "" && len(c.anonymousRoutes) >= int(c.cfg.Policy.MaxBackends)*16 {
		s.authSkip, s.terminalSkip = true, true
		return nil, status.Error(codes.ResourceExhausted, "anonymous route capacity")
	}
	c.anonymousRoutes[s.anonymousID] = r.Endpoint
	id, err := c.resolve(s, r.Endpoint)
	if err != nil {
		return nil, err
	}
	_, _, err = c.identify(id, r.Endpoint)
	if err != nil {
		s.authSkip, s.terminalSkip = true, true
		return nil, status.Error(codes.FailedPrecondition, "conflicting anonymous route")
	}
	if err := c.persist(); err != nil {
		return nil, status.Error(codes.Unavailable, "cannot commit anonymous identity")
	}
	return &pb.RegisterSSHAnonymousRouteResponse{}, nil
}

// HintSSHUpstreamRecovery advances cooldown without releasing any risk.
func (c *Controller) HintSSHUpstreamRecovery(_ context.Context, r *pb.HintSSHUpstreamRecoveryRequest) (*pb.HintSSHUpstreamRecoveryResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != nil {
		return nil, status.Error(codes.Unavailable, "upstream controller unavailable")
	}
	id := c.aliases["id:"+r.BackendId]
	advanced := id != "" && c.gate.HintRecovery(sshgate.Key{Backend: id, Egress: c.cfg.Policy.EgressGroup}, c.versions[id])
	if advanced {
		if err := c.persist(); err != nil {
			return nil, err
		}
	}
	return &pb.HintSSHUpstreamRecoveryResponse{Advanced: advanced}, nil
}
