package tenantguard

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/nicguard"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// DefaultInterval is the steady-state reconcile cadence; bus events
// converge sooner.
const DefaultInterval = 60 * time.Second

// Config is the reconciler's static wiring.
type Config struct {
	Mode nicguard.Mode
	// Bridge is the Incus network tenant NICs sit on (e.g. incusbr0).
	Bridge string
	// BridgeCIDR is the bridge's ipv4.address as Incus reports it, gateway
	// form ("10.100.0.1/24"); network form is accepted.
	BridgeCIDR string
	// NICDevice is the device name to guard on each tenant container
	// (default eth0).
	NICDevice string
	// Interval overrides DefaultInterval (tests).
	Interval time.Duration
}

// Entry is one tenant container's guard state as of the last pass.
type Entry struct {
	Container string
	Tenant    string
	IP        string
	ACLName   string
	Attached  bool
	LastError string
}

// Status is the reconciler's last-pass snapshot.
type Status struct {
	Mode           nicguard.Mode
	FirewallDriver string
	Entries        []Entry
	// Unresolved lists containers that are neither core-role nor
	// attributable to a tenant; they are left unguarded and reported.
	Unresolved []string
	Tenants    int
	// Unsupported is set when this host cannot carry bridge NIC ACLs
	// (firewall driver or Incus too old): nothing is guarded, creates are
	// not refused, and LastError says why. Doctor treats it as red.
	Unsupported bool
	StaleSince  time.Time
	LastError   string
	LastPass    time.Time
}

// Reconciler keeps every tenant container's NIC ACL equal to what Compute
// says it should be. It only ever writes on drift.
type Reconciler struct {
	be  incus.Backend
	cfg Config

	mu     sync.Mutex
	status Status
	warned string // last unsupported reason logged

	// writeMu serialises every Incus write (ACL + NIC) across a reconcile
	// pass and Prepare. Without it the event-driven pass a create fires
	// and the ACL-at-birth hook for that same create race on one
	// instance, and Incus answers the loser with an ETag mismatch.
	writeMu sync.Mutex
}

// NewReconciler wires a reconciler; nothing runs until ReconcileOnce, Run
// or Prepare is called.
func NewReconciler(be incus.Backend, cfg Config) *Reconciler {
	if cfg.NICDevice == "" {
		cfg.NICDevice = "eth0"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Mode == "" {
		cfg.Mode = nicguard.ModeEnforce
	}
	return &Reconciler{be: be, cfg: cfg, status: Status{Mode: cfg.Mode}}
}

// Mode reports the arming state.
func (r *Reconciler) Mode() nicguard.Mode { return r.cfg.Mode }

// Status returns a copy of the last-pass snapshot.
func (r *Reconciler) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.status
	st.Entries = append([]Entry(nil), r.status.Entries...)
	st.Unresolved = append([]string(nil), r.status.Unresolved...)
	return st
}

// Run reconciles at startup, on every bus event, and every Interval, until
// ctx is done. events is optional: a nil channel simply never fires.
func (r *Reconciler) Run(ctx context.Context, events <-chan struct{}) {
	if r.cfg.Mode != nicguard.ModeEnforce {
		log.Printf("[tenantguard] off (CONTAINARIUM_TENANT_GUARD=off): tenant containers can reach each other on %s", r.cfg.Bridge)
		return
	}
	if err := r.ReconcileOnce(ctx); err != nil {
		log.Printf("[tenantguard] reconcile: %v", err)
	}
	tick := time.NewTicker(r.cfg.Interval)
	defer tick.Stop()
	log.Printf("[tenantguard] started (bridge=%s, interval=%s, ENFORCE)", r.cfg.Bridge, r.cfg.Interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-events:
		}
		if err := r.ReconcileOnce(ctx); err != nil {
			log.Printf("[tenantguard] reconcile: %v", err)
		}
	}
}

// Prepare guards a container that was just created and is not yet started
// (docs/architecture/tenant-network-guard.md, "ACL-at-birth"): the tenant's
// ACL is created if missing (with whatever siblings the host currently
// has; this box's own address is added by the next pass) and attached to
// the instance-local NIC. A no-op when the guard is off. Any failure is
// returned so the caller can refuse the create rather than start a box
// that co-tenants can reach.
func (r *Reconciler) Prepare(ctx context.Context, containerName, tenant string) error {
	if r.cfg.Mode != nicguard.ModeEnforce {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(tenant) == "" {
		return fmt.Errorf("tenantguard: %s has no resolvable tenant", containerName)
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	if _, err := nicguard.CheckSupport(r.be); err != nil {
		if nicguard.Unsupported(err) {
			// This host cannot carry bridge NIC ACLs at all (driver or
			// Incus too old). Refusing every create here would turn a
			// missing capability into an outage; the pass reports it and
			// doctor goes red instead. A capable host that fails to guard
			// one box still fails closed below.
			r.warnUnsupported(err)
			return nil
		}
		return fmt.Errorf("tenantguard: %w", err)
	}
	in, _, err := r.gather()
	if err != nil {
		return fmt.Errorf("tenantguard: %w", err)
	}
	// The box was just created and may not be listed yet, or be listed
	// without a tenant label the caller already knows: make sure it is in
	// the policy under its tenant so the ACL exists even for a tenant's
	// first box on the host.
	found := false
	for i := range in.Boxes {
		if in.Boxes[i].Name == containerName {
			in.Boxes[i].Tenant = tenant
			found = true
		}
	}
	if !found {
		in.Boxes = append(in.Boxes, Box{Name: containerName, Tenant: tenant})
	}
	pol, err := Compute(in)
	if err != nil {
		return fmt.Errorf("tenantguard: %w", err)
	}
	desired := pol.ACLs[tenant]
	if _, err := nicguard.EnsureACL(r.be, desired); err != nil {
		return fmt.Errorf("tenantguard: %w", err)
	}
	if err := r.attach(containerName, desired.Name); err != nil {
		return fmt.Errorf("tenantguard: %w", err)
	}
	return nil
}

// ReconcileOnce performs one gather → compute → diff → write pass.
//
// Fail-safe shape: any error before the write phase returns with zero
// writes and the previous ACLs left in force. A write error on one
// container is recorded on its entry and the pass continues to the others;
// the pass then reports the first such error.
func (r *Reconciler) ReconcileOnce(ctx context.Context) error {
	if r.cfg.Mode != nicguard.ModeEnforce {
		r.setStatus(func(s *Status) { s.Mode = r.cfg.Mode; s.LastPass = time.Now() })
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// One pass at a time, and never concurrently with Prepare: a pass that
	// gathered before a box existed must not prune the ACL Prepare just
	// created for it, and two writers must not race on one instance.
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	driver, err := nicguard.CheckSupport(r.be)
	if err != nil {
		r.setStatus(func(s *Status) { s.FirewallDriver = driver; s.Unsupported = nicguard.Unsupported(err) })
		if nicguard.Unsupported(err) {
			r.warnUnsupported(err)
		}
		return r.fail(fmt.Errorf("tenantguard: %w", err))
	}
	r.setStatus(func(s *Status) { s.Unsupported = false })

	in, unresolved, err := r.gather()
	if err != nil {
		r.setStatus(func(s *Status) { s.FirewallDriver = driver })
		return r.fail(fmt.Errorf("tenantguard: %w", err))
	}

	pol, err := Compute(in)
	if err != nil {
		return r.fail(err)
	}

	// Write phase: per tenant the ACL, then per box the NIC. An ACL that
	// could not be written is never attached.
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	aclOK := map[string]bool{}
	for tenant, desired := range pol.ACLs {
		if _, err := nicguard.EnsureACL(r.be, desired); err != nil {
			note(err)
			continue
		}
		aclOK[tenant] = true
	}

	entries := make([]Entry, 0, len(in.Boxes))
	for _, b := range in.Boxes {
		e := Entry{Container: b.Name, Tenant: b.Tenant, ACLName: ACLName(b.Tenant)}
		if b.IPv4.IsValid() {
			e.IP = b.IPv4.String()
		}
		if !aclOK[b.Tenant] {
			e.LastError = "tenant ACL not written this pass"
			entries = append(entries, e)
			continue
		}
		if err := r.attach(b.Name, e.ACLName); err != nil {
			e.LastError = err.Error()
			note(err)
			entries = append(entries, e)
			continue
		}
		e.Attached = true
		entries = append(entries, e)
	}

	// Garbage: ACLs for tenants that no longer have a box here.
	if err := r.pruneStale(pol); err != nil {
		note(err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Container < entries[j].Container })
	sort.Strings(unresolved)
	r.setStatus(func(s *Status) {
		s.Mode = r.cfg.Mode
		s.FirewallDriver = driver
		s.Entries = entries
		s.Unresolved = unresolved
		s.Tenants = len(pol.ACLs)
		s.LastPass = time.Now()
		if firstErr != nil {
			s.LastError = firstErr.Error()
		} else {
			s.LastError = ""
			s.StaleSince = time.Time{}
		}
	})
	if firstErr != nil {
		return fmt.Errorf("tenantguard: %w", firstErr)
	}
	return nil
}

// gather reads the host into Inputs. Core-role containers become
// initiators (when their role is one) and are never subjects; a container
// with no resolvable tenant is reported, not guessed.
func (r *Reconciler) gather() (Inputs, []string, error) {
	bridge, gateway, err := nicguard.ParseBridge(r.cfg.BridgeCIDR)
	if err != nil {
		return Inputs{}, nil, err
	}
	containers, err := r.be.ListContainers()
	if err != nil {
		return Inputs{}, nil, fmt.Errorf("list containers: %w", err)
	}
	in := Inputs{BridgeCIDR: bridge, HostGateway: gateway, Initiators: map[incus.Role][]netip.Addr{}}
	var unresolved []string
	for _, c := range containers {
		// ContainerInfo.IPAddress is the daemon's "primary" address and can
		// come from an interface that is not the bridge (a podman box
		// reports its cni/docker gateway first on some images). An address
		// outside the bridge, or the gateway's own, must not reach Compute:
		// it would fail validation and abort the whole pass — or, worse,
		// end up in an allow rule for the wrong thing. Such a box is
		// guarded (default drop) but contributes no sibling rule this pass.
		if c.Role.IsCoreRole() {
			if a, perr := netip.ParseAddr(c.IPAddress); perr == nil && (!a.Is4() || (bridge.Contains(a) && a != gateway)) {
				in.Initiators[c.Role] = append(in.Initiators[c.Role], a)
			}
			continue
		}
		tenant := incus.ResolveTenant(c.Tenant, c.Labels[incus.CloudOrgIDLabel], c.Name)
		if tenant == "" {
			unresolved = append(unresolved, c.Name)
			continue
		}
		b := Box{Name: c.Name, Tenant: tenant}
		if a, perr := netip.ParseAddr(c.IPAddress); perr == nil && a.Is4() && bridge.Contains(a) && a != gateway {
			b.IPv4 = a
		}
		in.Boxes = append(in.Boxes, b)
	}
	return in, unresolved, nil
}

// attach makes the NIC instance-local and sets the guard keys. Both calls
// are no-ops when converged. A transient Incus conflict (another writer
// changed the instance between our read and write, or the instance is
// mid-operation) is retried a few times; the writes are read-modify-write
// and idempotent, so a retry after a conflict is safe.
func (r *Reconciler) attach(container, acl string) error {
	return retryTransient(func() error {
		if err := r.be.EnsureNICDevice(container, incus.NICDevice{Name: r.cfg.NICDevice, Network: r.cfg.Bridge}); err != nil {
			return fmt.Errorf("nic device on %s: %w", container, err)
		}
		if err := r.be.SetDeviceConfig(container, r.cfg.NICDevice, tenantNICKeys(acl)); err != nil {
			return fmt.Errorf("nic acl keys on %s: %w", container, err)
		}
		return nil
	})
}

// tenantNICKeys are the guard keys plus Incus's anti-spoofing filters. The
// allow table admits by SOURCE ADDRESS, so without them a tenant could send
// with a sibling's, the gateway's or Caddy's address and be admitted;
// security.mac_filtering + security.ipv4_filtering pin a NIC to its own MAC
// and its DHCP/static IPv4 and drop spoofed ARP. (security.ipv6_filtering
// is left for the IPv6 sibling work: no allow rule names an IPv6 source
// yet, so there is nothing to spoof toward, and some kernels refuse it
// without br_netfilter.)
func tenantNICKeys(acl string) map[string]string {
	keys := nicguard.NICKeys(acl)
	keys["security.mac_filtering"] = "true"
	keys["security.ipv4_filtering"] = "true"
	return keys
}

// transientAttempts and transientBackoff bound the retry; a test lowers
// the backoff.
var (
	transientAttempts = 5
	transientBackoff  = 200 * time.Millisecond
)

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "ETag doesn't match") || strings.Contains(msg, "Instance is busy")
}

func retryTransient(f func() error) error {
	var err error
	for i := 0; i < transientAttempts; i++ {
		if err = f(); err == nil || !isTransient(err) {
			return err
		}
		time.Sleep(transientBackoff)
	}
	return fmt.Errorf("%w (gave up after %d attempts)", err, transientAttempts)
}

// pruneStale deletes containarium-tenant-* ACLs that no current tenant
// owns. Deletion of an ACL still attached somewhere fails in Incus and is
// reported; it is never forced.
func (r *Reconciler) pruneStale(pol Policy) error {
	acls, err := r.be.ListNetworkACLs()
	if err != nil {
		return fmt.Errorf("list acls: %w", err)
	}
	live := map[string]bool{}
	for _, a := range pol.ACLs {
		live[a.Name] = true
	}
	var firstErr error
	for _, a := range acls {
		if !strings.HasPrefix(a.Name, "containarium-tenant-") || live[a.Name] {
			continue
		}
		if err := r.be.DeleteNetworkACL(a.Name); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("delete stale acl %s: %w", a.Name, err)
		}
	}
	return firstErr
}

// warnUnsupported logs the capability gap once per reason, not every pass.
func (r *Reconciler) warnUnsupported(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.warned == err.Error() {
		return
	}
	r.warned = err.Error()
	log.Printf("[tenantguard] UNSUPPORTED on this host — tenants are NOT isolated from each other: %v (containarium doctor reports this; install Incus from the Zabbly repository with the nftables driver, or set CONTAINARIUM_TENANT_GUARD=off to acknowledge)", err)
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
