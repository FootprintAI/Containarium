package coreguard

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Mode is the guard's arming state. There is no audit mode: an Incus NIC
// ACL either drops or it doesn't. Evidence comes from the logged default
// action, and rollout safety from the two e2e scripts, not from a soft mode.
type Mode string

const (
	ModeOff     Mode = "off"
	ModeEnforce Mode = "enforce"
)

// ParseMode maps the CONTAINARIUM_CORE_GUARD value to a Mode. Anything that
// is not exactly "enforce" is off — the guard never arms by accident.
func ParseMode(s string) Mode {
	if s == string(ModeEnforce) {
		return ModeEnforce
	}
	return ModeOff
}

// ErrUnsupportedFirewall is returned when the host's Incus firewall driver
// cannot enforce bridge NIC ACLs (only nftables can). The reconciler
// refuses to attach anything rather than leave the operator believing they
// are guarded.
var ErrUnsupportedFirewall = errors.New("coreguard: incus firewall driver is not nftables; bridge NIC ACLs cannot be enforced")

// requiredFirewall is the only Incus firewall driver that renders NIC-level
// ACLs (doc/howto/network_acls.md, "Bridge limitations").
const requiredFirewall = "nftables"

// DefaultInterval is the steady-state reconcile cadence; bus events
// converge sooner.
const DefaultInterval = 60 * time.Second

// Config is the reconciler's static wiring.
type Config struct {
	Mode Mode
	// Bridge is the Incus network the core containers' NIC sits on
	// (e.g. incusbr0) — what EnsureNICDevice binds the instance-local
	// override to.
	Bridge string
	// BridgeCIDR is the bridge's ipv4.address as Incus reports it, gateway
	// form ("10.100.0.1/24"). Network form ("10.100.0.0/24") is accepted;
	// the gateway is then base+1, Incus's convention.
	BridgeCIDR string
	// NICDevice is the device name to guard on each core container
	// (default eth0).
	NICDevice string
	// Interval overrides DefaultInterval (tests).
	Interval time.Duration
}

// Entry is one core container's guard state as of the last pass.
type Entry struct {
	Container    string
	Role         incus.Role
	IP           string
	ACLName      string
	Attached     bool
	RulesApplied int
	LastError    string
}

// Status is the reconciler's last-pass snapshot, read by the status RPC.
type Status struct {
	Mode           Mode
	FirewallDriver string
	Entries        []Entry
	UnknownRoles   []incus.Role
	// StaleSince is set when the last pass could not read the host; the
	// ACLs from the previous good pass stay in force meanwhile.
	StaleSince time.Time
	LastError  string
	LastPass   time.Time
}

// Reconciler keeps the core containers' NIC ACLs equal to what Compute says
// they should be. It only ever writes on drift.
type Reconciler struct {
	be  incus.Backend
	cfg Config

	mu     sync.Mutex
	status Status
}

// NewReconciler wires a reconciler; nothing runs until ReconcileOnce or
// Run is called.
func NewReconciler(be incus.Backend, cfg Config) *Reconciler {
	if cfg.NICDevice == "" {
		cfg.NICDevice = "eth0"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeOff
	}
	return &Reconciler{be: be, cfg: cfg, status: Status{Mode: cfg.Mode}}
}

// Status returns a copy of the last-pass snapshot.
func (r *Reconciler) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.status
	st.Entries = append([]Entry(nil), r.status.Entries...)
	st.UnknownRoles = append([]incus.Role(nil), r.status.UnknownRoles...)
	return st
}

// Run reconciles at startup, on every bus event, and every Interval, until
// ctx is done. events is optional: a nil channel simply never fires.
func (r *Reconciler) Run(ctx context.Context, events <-chan struct{}) {
	if r.cfg.Mode != ModeEnforce {
		log.Printf("[coreguard] off (set CONTAINARIUM_CORE_GUARD=enforce to attach core-infra NIC ACLs)")
		return
	}
	if err := r.ReconcileOnce(ctx); err != nil {
		log.Printf("[coreguard] reconcile: %v", err)
	}
	tick := time.NewTicker(r.cfg.Interval)
	defer tick.Stop()
	log.Printf("[coreguard] started (bridge=%s, interval=%s, ENFORCE)", r.cfg.Bridge, r.cfg.Interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-events:
		}
		if err := r.ReconcileOnce(ctx); err != nil {
			log.Printf("[coreguard] reconcile: %v", err)
		}
	}
}

// ReconcileOnce performs one gather → compute → diff → write pass.
//
// Fail-safe shape: any error before the write phase returns with zero
// writes and the previous ACLs left in force. A write error on one
// container is recorded on its entry and the pass continues to the others;
// the pass then reports the first such error.
func (r *Reconciler) ReconcileOnce(ctx context.Context) error {
	if r.cfg.Mode != ModeEnforce {
		r.setStatus(func(s *Status) { s.Mode = r.cfg.Mode; s.LastPass = time.Now() })
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	bridge, gateway, err := parseBridge(r.cfg.BridgeCIDR)
	if err != nil {
		return r.fail(err)
	}

	info, err := r.be.GetServerInfo()
	if err != nil {
		return r.fail(fmt.Errorf("coreguard: server info: %w", err))
	}
	driver := info.Environment.Firewall
	if driver != requiredFirewall {
		r.setStatus(func(s *Status) { s.FirewallDriver = driver })
		return r.fail(fmt.Errorf("%w (driver=%q)", ErrUnsupportedFirewall, driver))
	}

	containers, err := r.be.ListContainers()
	if err != nil {
		r.setStatus(func(s *Status) { s.FirewallDriver = driver })
		return r.fail(fmt.Errorf("coreguard: list containers: %w", err))
	}

	// Gather: core roles → address, control planes → addresses, and a
	// status entry per core container (including the ones we cannot guard
	// yet, so the operator sees why).
	in := Inputs{BridgeCIDR: bridge, HostGateway: gateway, Core: map[incus.Role]netip.Addr{}}
	byRole := map[incus.Role]string{} // role → container name
	var entries []Entry
	for _, c := range containers {
		if !c.Role.IsCoreRole() {
			continue
		}
		addr, perr := netip.ParseAddr(c.IPAddress)
		if c.Role == incus.RoleControlPlane {
			if perr == nil {
				in.ControlPlane = append(in.ControlPlane, addr)
			}
			continue // a source, never a subject
		}
		e := Entry{Container: c.Name, Role: c.Role, IP: c.IPAddress, ACLName: ACLName(c.Role)}
		if perr != nil {
			e.LastError = "no IPv4 address yet; skipped this pass"
			entries = append(entries, e)
			continue
		}
		if prev, dup := byRole[c.Role]; dup {
			e.LastError = fmt.Sprintf("second container with role %s (already guarding %s); skipped", c.Role, prev)
			entries = append(entries, e)
			continue
		}
		in.Core[c.Role] = addr
		byRole[c.Role] = c.Name
		entries = append(entries, e)
	}

	pol, err := Compute(in)
	if err != nil {
		return r.fail(err)
	}

	// Write phase: per guarded container, ACL then NIC. An ACL that could
	// not be written is never attached — attaching a missing ACL name would
	// make Incus refuse the device update anyway, and attaching a stale one
	// would enforce yesterday's table.
	nicKeys := func(acl string) map[string]string {
		return map[string]string{
			"security.acls":                        acl,
			"security.acls.default.ingress.action": "drop",
			"security.acls.default.ingress.logged": "true",
			"security.acls.default.egress.action":  "allow",
		}
	}
	var firstErr error
	for i := range entries {
		e := &entries[i]
		if e.LastError != "" {
			continue
		}
		desired, ok := pol.ACLs[e.Role]
		if !ok {
			e.LastError = "no policy computed for role"
			continue
		}
		if err := r.ensureACL(desired); err != nil {
			e.LastError = err.Error()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := r.be.EnsureNICDevice(e.Container, incus.NICDevice{Name: r.cfg.NICDevice, Network: r.cfg.Bridge}); err != nil {
			e.LastError = fmt.Sprintf("nic device: %v", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := r.be.SetDeviceConfig(e.Container, r.cfg.NICDevice, nicKeys(desired.Name)); err != nil {
			e.LastError = fmt.Sprintf("nic acl keys: %v", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		e.Attached = true
		e.RulesApplied = len(desired.IngressRules)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Container < entries[j].Container })
	r.setStatus(func(s *Status) {
		s.Mode = r.cfg.Mode
		s.FirewallDriver = driver
		s.Entries = entries
		s.UnknownRoles = pol.UnknownRoles
		s.LastPass = time.Now()
		if firstErr != nil {
			s.LastError = firstErr.Error()
		} else {
			s.LastError = ""
			s.StaleSince = time.Time{}
		}
	})
	if firstErr != nil {
		return fmt.Errorf("coreguard: %w", firstErr)
	}
	return nil
}

// ensureACL creates the ACL when Incus doesn't have it and updates it only
// when its rules differ from desired.
func (r *Reconciler) ensureACL(desired incus.ACLConfig) error {
	existing, err := r.be.GetNetworkACL(desired.Name)
	if err != nil {
		// Treat any read failure as "absent": a create against an ACL that
		// does exist fails loudly and is retried next pass, which is
		// safer than assuming it matches.
		if cerr := r.be.CreateNetworkACL(desired); cerr != nil {
			return fmt.Errorf("create acl %s: %w", desired.Name, cerr)
		}
		return nil
	}
	if aclEqual(existing, desired) {
		return nil
	}
	if uerr := r.be.UpdateNetworkACL(desired.Name, desired); uerr != nil {
		return fmt.Errorf("update acl %s: %w", desired.Name, uerr)
	}
	return nil
}

// aclEqual compares what Incus holds with what Compute wants, on the
// fields the guard sets. Order-insensitive: Incus may return rules in its
// own order.
func aclEqual(have *api.NetworkACL, want incus.ACLConfig) bool {
	if have == nil || len(have.Egress) != len(want.EgressRules) || len(have.Ingress) != len(want.IngressRules) {
		return false
	}
	if have.Description != want.Description {
		return false
	}
	key := func(action, src, dst, proto, dport string) string {
		return action + "|" + src + "|" + dst + "|" + proto + "|" + dport
	}
	seen := map[string]int{}
	for _, rl := range have.Ingress {
		seen[key(rl.Action, rl.Source, rl.Destination, rl.Protocol, rl.DestinationPort)]++
	}
	for _, rl := range want.IngressRules {
		k := key(rl.Action, rl.Source, rl.Destination, rl.Protocol, rl.DestinationPort)
		if seen[k] == 0 {
			return false
		}
		seen[k]--
	}
	return true
}

func (r *Reconciler) fail(err error) error {
	r.setStatus(func(s *Status) {
		s.Mode = r.cfg.Mode
		s.LastError = err.Error()
		s.LastPass = time.Now()
		if s.StaleSince.IsZero() {
			s.StaleSince = time.Now()
		}
	})
	return err
}

func (r *Reconciler) setStatus(f func(*Status)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(&r.status)
}

// parseBridge turns Incus's ipv4.address ("10.100.0.1/24") into the bridge
// prefix and the host gateway. A network-form value ("10.100.0.0/24")
// yields base+1 as the gateway, which is what Incus assigns itself.
func parseBridge(s string) (netip.Prefix, netip.Addr, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("coreguard: bridge cidr %q: %w", s, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("coreguard: bridge cidr %q is not IPv4", s)
	}
	bridge := p.Masked()
	gw := p.Addr()
	if gw == bridge.Addr() {
		gw = gw.Next()
	}
	return bridge, gw, nil
}
