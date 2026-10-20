// Package sshban owns the sentinel SSH plugin's live source-IP failure budget.
package sshban

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config describes one listener's independent policy.
type Config struct {
	Listener    pb.SSHBanListener
	MaxFailures uint32
	Duration    time.Duration
	IgnoreCIDRs []string
	MaxEntries  uint32
	Now         func() time.Time
	// Emit is serialized with state changes and must not call back into Guard.
	Emit func(Event)
}

// Event is an operational event; it must never be written to plugin stdout.
type Event struct {
	Kind      string
	IP        string
	Failures  uint64
	ExpiresAt time.Time
	Reason    string
}

// entry tracks one fixed window; blockedLogged bounds repeated-reject logging.
type entry struct {
	failures      uint64
	expires       time.Time
	blockedLogged bool
}

// Guard owns one listener's enforcement state and its generated control API.
// The same mutex serializes plugin callbacks and operator mutations.
type Guard struct {
	pb.UnimplementedSentinelSSHBanServiceServer
	mu                     sync.Mutex
	callbackMu             sync.Mutex
	callbacksClosed        bool
	callbacksActive        int
	callbacksDone          chan struct{}
	cfg                    Config
	policy                 *pb.SSHBanPolicy
	prefixes               []netip.Prefix
	entries                map[netip.Addr]entry
	nextExpiry             time.Time
	lastCapacityLog        time.Time
	generation, sentinelID string
}

// New validates policy before exposing either enforcement or its control socket.
// Each instance has a new generation even when its effective policy is unchanged.
func New(c Config) (*Guard, error) {
	if (c.Listener != pb.SSHBanListener_SSH_BAN_LISTENER_MAIN && c.Listener != pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS) || c.MaxFailures == 0 || c.Duration <= 0 || c.MaxEntries == 0 {
		return nil, fmt.Errorf("listener, positive max-failures, duration and max-entries are required")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	g := &Guard{cfg: c, entries: make(map[netip.Addr]entry), generation: rand.Text()}
	g.sentinelID, _ = os.Hostname()
	for _, raw := range c.IgnoreCIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid exemption CIDR %q", raw)
		}
		g.prefixes = append(g.prefixes, p.Masked())
	}
	cidrs := make([]string, 0, len(g.prefixes))
	for _, p := range g.prefixes {
		cidrs = append(cidrs, p.String())
	}
	sort.Strings(cidrs)
	g.policy = &pb.SSHBanPolicy{MaxFailures: c.MaxFailures, Duration: durationpb.New(c.Duration), IgnoreCidrs: cidrs, MaxEntries: c.MaxEntries}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(g.policy)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(encoded)
	g.policy.Hash = hex.EncodeToString(hash[:])
	return g, nil
}

// parseIP rejects ranges/scopes and unifies native and mapped IPv4 identities.
func parseIP(raw string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, status.Error(codes.InvalidArgument, "one bare IPv4 or IPv6 address is required")
	}
	return ip.Unmap(), nil
}

// sourceIP accepts only the transport address supplied by sshpiperd.
func sourceIP(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid source address: %w", err)
	}
	return parseIP(host)
}

// exempt tests the immutable configured prefixes without granting SSH access.
func (g *Guard) exempt(ip netip.Addr) bool {
	for _, p := range g.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// emit records a transition while the caller holds the policy mutex.
func (g *Guard) emit(kind string, ip netip.Addr, e entry) {
	if g.cfg.Emit != nil {
		g.cfg.Emit(Event{Kind: kind, IP: ip.String(), Failures: e.failures, ExpiresAt: e.expires})
	}
}

// EventWindowFailures summarizes failures below the ban budget when a window
// ends, or its partial count on shutdown (#2419). A ban has its own "ban"
// event when reached, so a banned window does not also emit this.
const EventWindowFailures = "window_failures"

// Sweep runs the expiry pass on a timer. Windows otherwise only end when the
// next connection arrives, so on a quiet sentinel the last window's failures
// would sit unreported indefinitely.
func (g *Guard) Sweep() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.prune(g.cfg.Now())
}

// TrySweep skips a busy guard rather than holding up the audit recorder's
// periodic loop. The next tick or the final shutdown flush will prune it.
func (g *Guard) TrySweep() {
	if !g.mu.TryLock() {
		return
	}
	defer g.mu.Unlock()
	g.prune(g.cfg.Now())
}

// FlushFailureWindows reports partial failure counts when the plugin exits.
// Bans were already reported when their threshold was reached.
func (g *Guard) FlushFailureWindows() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.prune(g.cfg.Now())
	for ip, e := range g.entries {
		if e.failures > 0 && e.failures < uint64(g.cfg.MaxFailures) {
			g.emit(EventWindowFailures, ip, e)
		}
	}
}

// prune amortizes expiry sweeps by waiting for the earliest remaining deadline.
// Ban expiries and windows that ended with unbanned failures generate an
// operational transition.
func (g *Guard) prune(now time.Time) {
	if !g.nextExpiry.IsZero() && now.Before(g.nextExpiry) {
		return
	}
	g.nextExpiry = time.Time{}
	for ip, e := range g.entries {
		if !now.Before(e.expires) {
			switch {
			case e.failures >= uint64(g.cfg.MaxFailures):
				g.emit("expire", ip, e)
			case e.failures > 0:
				g.emit(EventWindowFailures, ip, e)
			}
			delete(g.entries, ip)
			continue
		}
		if g.nextExpiry.IsZero() || e.expires.Before(g.nextExpiry) {
			g.nextExpiry = e.expires
		}
	}
}

// Check initializes or checks a source window without consuming its budget.
// Rejections include the actual deadline; they never refresh it.
func (g *Guard) Check(remote string) error {
	ip, err := sourceIP(remote)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.exempt(ip) {
		return nil
	}
	now := g.cfg.Now()
	g.prune(now)
	e, found := g.entries[ip]
	if found {
		if e.failures >= uint64(g.cfg.MaxFailures) {
			if !e.blockedLogged {
				g.emit("blocked", ip, e)
				e.blockedLogged = true
				g.entries[ip] = e
			}
			return fmt.Errorf("source_ip_banned: source %s blocked until %s", ip, e.expires.UTC().Format(time.RFC3339Nano))
		}
		return nil
	}
	if uint64(len(g.entries)) >= uint64(g.cfg.MaxEntries) {
		if g.lastCapacityLog.IsZero() || now.Sub(g.lastCapacityLog) >= time.Minute {
			g.emit("policy_capacity", ip, entry{})
			g.lastCapacityLog = now
		}
		return fmt.Errorf("policy_capacity: cannot track additional source IPs")
	}
	e = entry{expires: now.Add(g.cfg.Duration)}
	g.entries[ip] = e
	if g.nextExpiry.IsZero() || e.expires.Before(g.nextExpiry) {
		g.nextExpiry = e.expires
	}
	return nil
}

// Fail preserves upstream callback accounting, including pipe-create failures.
// Incrementing a counter never changes its original expiry.
func (g *Guard) Fail(remote, kind string) {
	ip, err := sourceIP(remote)
	if err != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.exempt(ip) {
		return
	}
	g.prune(g.cfg.Now())
	e, found := g.entries[ip]
	if !found {
		return
	}
	wasBanned := e.failures >= uint64(g.cfg.MaxFailures)
	if e.failures < math.MaxUint64 {
		e.failures++
	}
	g.entries[ip] = e
	// Once banned, repeated callbacks cannot change the deadline and need not
	// flood the journal. The transition and live counter remain authoritative.
	if !wasBanned {
		g.emit(kind, ip, e)
		if e.failures >= uint64(g.cfg.MaxFailures) {
			g.emit("ban", ip, e)
		}
	}
}

// validate prevents a request to one listener from acting on another's state.
func (g *Guard) validate(listener pb.SSHBanListener) error {
	if listener != pb.SSHBanListener_SSH_BAN_LISTENER_MAIN && listener != pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS {
		return status.Error(codes.InvalidArgument, "listener is required")
	}
	if listener != g.cfg.Listener {
		return status.Error(codes.NotFound, "listener is not served by this plugin")
	}
	return nil
}

// snapshot builds an independent wire value while the policy mutex is held.
func (g *Guard) snapshot(ip netip.Addr) *pb.SSHBanStatus {
	r := &pb.SSHBanStatus{Ip: ip.String(), State: pb.SSHBanState_SSH_BAN_STATE_CLEAR}
	if g.exempt(ip) {
		r.State = pb.SSHBanState_SSH_BAN_STATE_EXEMPT
		return r
	}
	if e, ok := g.entries[ip]; ok {
		r.State = pb.SSHBanState_SSH_BAN_STATE_TRACKING
		r.Failures = e.failures
		r.ExpiresAt = timestamppb.New(e.expires)
		if e.failures >= uint64(g.cfg.MaxFailures) {
			r.State = pb.SSHBanState_SSH_BAN_STATE_BANNED
		}
	}
	return r
}

// GetSSHBan observes current state and effective policy in one locked snapshot.
func (g *Guard) GetSSHBan(_ context.Context, r *pb.GetSSHBanRequest) (*pb.GetSSHBanResponse, error) {
	if err := g.validate(r.GetListener()); err != nil {
		return nil, err
	}
	ip, err := parseIP(r.GetIp())
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.cfg.Now()
	g.prune(now)
	return &pb.GetSSHBanResponse{Status: g.snapshot(ip), Policy: proto.Clone(g.policy).(*pb.SSHBanPolicy), Generation: g.generation, SentinelId: g.sentinelID, Listener: g.cfg.Listener, ObservedAt: timestamppb.New(now)}, nil
}

// ListSSHBans returns a bounded, lexically ordered page of currently banned IPs.
// Pages observe live state rather than reserving a long-lived snapshot.
func (g *Guard) ListSSHBans(_ context.Context, r *pb.ListSSHBansRequest) (*pb.ListSSHBansResponse, error) {
	if err := g.validate(r.GetListener()); err != nil {
		return nil, err
	}
	if r.GetPageSize() > 1000 {
		return nil, status.Error(codes.InvalidArgument, "page size must be at most 1000")
	}
	token := r.GetPageToken()
	if token != "" {
		ip, err := parseIP(token)
		if err != nil {
			return nil, err
		}
		token = ip.String()
	}
	limit := r.GetPageSize()
	if limit == 0 {
		limit = 100
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.cfg.Now()
	g.prune(now)
	ips := make([]string, 0)
	for ip, e := range g.entries {
		if e.failures >= uint64(g.cfg.MaxFailures) && ip.String() > token {
			ips = append(ips, ip.String())
		}
	}
	sort.Strings(ips)
	out := &pb.ListSSHBansResponse{Policy: proto.Clone(g.policy).(*pb.SSHBanPolicy), Generation: g.generation, SentinelId: g.sentinelID, Listener: g.cfg.Listener, ObservedAt: timestamppb.New(now)}
	for i, raw := range ips {
		if uint64(i) >= uint64(limit) {
			out.NextPageToken = ips[i-1]
			break
		}
		ip, _ := netip.ParseAddr(raw)
		out.Bans = append(out.Bans, g.snapshot(ip))
	}
	return out, nil
}

// UnbanSSHSource atomically clears one counter/ban and records the operator's
// reason. Repeating the operation is safe and never touches other sources.
func (g *Guard) UnbanSSHSource(_ context.Context, r *pb.UnbanSSHSourceRequest) (*pb.UnbanSSHSourceResponse, error) {
	if err := g.validate(r.GetListener()); err != nil {
		return nil, err
	}
	ip, err := parseIP(r.GetIp())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.GetReason()) == "" || len(r.GetReason()) > 1024 {
		return nil, status.Error(codes.InvalidArgument, "operator reason must contain 1 to 1024 bytes")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.cfg.Now()
	g.prune(now)
	e, cleared := g.entries[ip]
	delete(g.entries, ip)
	if cleared {
		if g.cfg.Emit != nil {
			g.cfg.Emit(Event{Kind: "unban", IP: ip.String(), Failures: e.failures, ExpiresAt: e.expires, Reason: r.GetReason()})
		}
	}
	return &pb.UnbanSSHSourceResponse{Cleared: cleared, Generation: g.generation, SentinelId: g.sentinelID, Listener: g.cfg.Listener, ObservedAt: timestamppb.New(now)}, nil
}
