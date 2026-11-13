package server

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
)

// containerView is a reconcile-time snapshot of one managed container: its
// tenant, assigned tenant ID, IPv4 (if resolved), and host veth ifindex (if
// running + resolved). gather() builds these (Linux veth resolution);
// planReconcile() turns them + the compiled policies into BPF map entries.
type containerView struct {
	Name     string
	Tenant   string
	TenantID uint32
	// IP is the address the instance state reports — what the GUEST configured
	// on itself. It feeds ip_tenant (which tenant a destination belongs to) and
	// nothing the box's own packets are validated against.
	IP    [4]byte
	HasIP bool
	// HostIP is the box's address as the HOST knows it — the NIC device's
	// static ipv4.address or the bridge's DHCP lease — the only source the
	// program's source validation and inbound-flow seeding trust (#2618). Root
	// in the box cannot change it.
	HostIP    [4]byte
	HasHostIP bool
	Ifindex   int
	HasVeth   bool
	Running   bool
	// ValidateOnly marks an instance the daemon does not police (the control
	// plane, an instance with no tenant): it gets a veth entry that only stamps
	// its frames with the source-validation mark (#2618), no policy, no
	// ip_tenant row, no per-tenant status.
	ValidateOnly bool
}

// applyConnCap stamps the outbound connection-rate cap (#3709) onto every
// tenant veth's config in the plan. It is a separate pure step, not a
// planReconcile parameter, because the cap is a daemon-wide switch, not part of
// any tenant's policy. A validate-only veth (the control plane, an untenanted
// instance) is never capped: it is not policed at all. perSec 0 leaves the
// cap off everywhere. enforce is the effective decision: the caller has already
// folded in the daemon-wide arm, so a cap configured to enforce on a daemon
// that is not armed only counts.
func applyConnCap(plan *reconcilePlan, perSec uint16, enforce bool) {
	if perSec == 0 {
		return
	}
	mode := netbpf.ModeLogOnly
	if enforce {
		mode = netbpf.ModeEnforce
	}
	for ifindex, cfg := range plan.vethPolicy {
		if cfg.Flags&netbpf.PolicyFlagValidateOnly != 0 {
			continue
		}
		cfg.ConnCapPerSec = perSec
		cfg.ConnCapMode = mode
		plan.vethPolicy[ifindex] = cfg
	}
}

// reconcilePlan is the desired BPF map state for one reconcile pass — pure data
// so planReconcile is unit-testable without a kernel.
type reconcilePlan struct {
	ipTenant   map[[4]byte]uint32          // container IP -> tenant id
	ipBox      map[[4]byte]string          // container IP -> container name (same precedence as ipTenant; never written to the kernel)
	vethPolicy map[int]netbpf.PolicyConfig // running container veth ifindex -> policy config
	ifName     map[int]string              // ifindex -> container name (for bookkeeping)
	egress     []netbpf.EgressEntry        // per-tenant egress allow-list entries
	deny       []netbpf.DenyEntry          // per-tenant virtual-patch deny entries (#660)
	// compileFailed holds the tenants whose egress or deny rules failed to
	// compile this pass (#3518). Neither set is planned for them; holdLastGood
	// fills in what is installed so nothing of theirs is removed or replaced.
	compileFailed map[uint32]compileFailure
}

// compileFailure is one tenant whose policy rules did not compile (#3518).
type compileFailure struct {
	Tenant string
	Err    error
}

// planReconcile computes the desired BPF map state from the current container
// views and the compiled per-tenant policies. A container with no stored policy
// gets the Phase A default (log-only, no intra-tenant, empty egress) so its
// outbound is observed rather than silently unmanaged.
//
// enforceEnabled is the daemon-wide safety guard (Phase B): when false, a
// policy's ENFORCE mode is downgraded to LOG_ONLY before it reaches the kernel,
// so a stored `--mode enforce` policy is still observation-only until the
// operator explicitly arms enforcement. This prevents a misconfigured policy
// (e.g. one that forgot to allow DNS) from blackholing a container the moment
// it's set; operators soak in log_only, watch the would-deny logs, complete the
// allow-list, then arm enforce.
func planReconcile(views []containerView, policies map[string]netpolicy.CompiledPolicy, enforceEnabled bool) reconcilePlan {
	plan := reconcilePlan{
		ipTenant:   make(map[[4]byte]uint32),
		ipBox:      make(map[[4]byte]string),
		vethPolicy: make(map[int]netbpf.PolicyConfig),
		ifName:     make(map[int]string),

		compileFailed: make(map[uint32]compileFailure),
	}
	// egress entries are per tenant, not per container — emit each tenant's set
	// once, keyed by the tenant IDs we actually saw.
	egressDone := make(map[uint32]bool)

	// ip_tenant (#3690). A box's HOST-known address is attributed first. The
	// guest reports its own address, and root in the box can change it, so a
	// guest-reported address is only a fallback for a box the host has no
	// address for, and never overrides a host-known row. That stops a box
	// claiming another tenant's address while core services and stopped boxes
	// keep the tagging they had.
	for _, v := range views {
		if !v.ValidateOnly && v.HasHostIP {
			plan.ipTenant[v.HostIP] = v.TenantID
			plan.ipBox[v.HostIP] = v.Name
		}
	}
	for _, v := range views {
		if v.ValidateOnly || v.HasHostIP || !v.HasIP {
			continue
		}
		if _, taken := plan.ipTenant[v.IP]; !taken {
			plan.ipTenant[v.IP] = v.TenantID
			plan.ipBox[v.IP] = v.Name
		}
	}

	for _, v := range views {
		if v.ValidateOnly {
			// Not a tenant: no ip_tenant row, no policy. Its veth gets the
			// marking-only entry so the receiving side can tell its frames
			// from the host's (#2618); the address is the host-known one or 0.
			if v.Running && v.HasVeth {
				var ip [4]byte
				if v.HasHostIP {
					ip = v.HostIP
				}
				plan.vethPolicy[v.Ifindex] = netbpf.ValidateOnlyConfig(ip)
				plan.ifName[v.Ifindex] = v.Name
			}
			continue
		}
		policy, hasPolicy := policies[v.Tenant]

		if v.Running && v.HasVeth {
			var cfg netbpf.PolicyConfig
			if hasPolicy {
				cfg = netbpf.CompileConfig(v.TenantID, policy)
			} else {
				cfg = netbpf.PolicyConfig{TenantID: v.TenantID, Mode: netbpf.ModeLogOnly, EgressMode: netbpf.ModeLogOnly}
			}
			// Safety guard: enforcement only drops when armed daemon-wide. It
			// applies to both modes — the egress allow-list's own mode cannot
			// arm drops the guard has not armed.
			if !enforceEnabled {
				if cfg.Mode == netbpf.ModeEnforce {
					cfg.Mode = netbpf.ModeLogOnly
				}
				if cfg.EgressMode == netbpf.ModeEnforce {
					cfg.EgressMode = netbpf.ModeLogOnly
				}
			}
			// The box's own address (#2618): the program validates the box's
			// source against it and seeds inbound flows only from frames whose
			// source is the sending veth's address. HOST-known only (device
			// config or DHCP lease) — never v.IP, which the guest reports and
			// root in the box can change. Unknown stays zero, which the program
			// reads as "cannot validate this veth".
			if v.HasHostIP {
				cfg.BoxIP = v.HostIP
			}
			plan.vethPolicy[v.Ifindex] = cfg
			plan.ifName[v.Ifindex] = v.Name
		}

		if hasPolicy && !egressDone[v.TenantID] {
			egressDone[v.TenantID] = true
			// Virtual-patch deny entries (#660), once per tenant. Expired rules are
			// already filtered out of policy.DenyRules by the daemon (compiledPolicies)
			// before planning, so anything here is active.
			egress, errEgress := netbpf.CompileEgress(v.TenantID, policy)
			deny, errDeny := netbpf.CompileDeny(v.TenantID, policy)
			// Fail closed (#3518): one bad rule must not empty or shrink the
			// tenant's sets, so neither is planned; the caller holds the last
			// good ones and reports the failure.
			if err := errors.Join(errEgress, errDeny); err != nil {
				plan.compileFailed[v.TenantID] = compileFailure{Tenant: v.Tenant, Err: err}
				continue
			}
			plan.egress = append(plan.egress, egress...)
			plan.deny = append(plan.deny, deny...)
		}
	}
	return plan
}

// withDefaultPolicies returns policies plus, for every tenant seen in views
// that has no stored policy, the default posture from build (#2577 stage 1). A
// stored policy always wins; a nil build (default posture off) or a tenant the
// builder declines leaves the tenant on the bare log-only fallback in
// planReconcile. The input map is not modified.
func withDefaultPolicies(policies map[string]netpolicy.CompiledPolicy, views []containerView, build func(tenant string) (netpolicy.CompiledPolicy, bool)) map[string]netpolicy.CompiledPolicy {
	if build == nil {
		return policies
	}
	out := make(map[string]netpolicy.CompiledPolicy, len(policies))
	for k, v := range policies {
		out[k] = v
	}
	for _, v := range views {
		if v.Tenant == "" {
			continue
		}
		if _, ok := out[v.Tenant]; ok {
			continue
		}
		if c, ok := build(v.Tenant); ok {
			out[v.Tenant] = c
		}
	}
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }

// activeDenyRules returns the deny rules that have not expired as of now (#660).
// An expired virtual patch is excluded so it stops being installed into the
// kernel — the "Band-Aid auto-removes once the real fix lands" behavior.
func activeDenyRules(rules []netpolicy.DenyRule, now time.Time) []netpolicy.DenyRule {
	if len(rules) == 0 {
		return rules
	}
	out := make([]netpolicy.DenyRule, 0, len(rules))
	for _, r := range rules {
		if !r.Expired(now) {
			out = append(out, r)
		}
	}
	return out
}

// diffEgress computes the egress LPM entries to add and to delete so the kernel
// map converges to the desired set: add anything desired but not installed,
// delete anything installed but no longer desired. Deleting stale entries is
// what makes a removed allow-CIDR actually stop allowing — load-bearing once a
// tenant is in enforce mode. EgressEntry is comparable, so it keys the sets
// directly.
func diffEgress(installed map[netbpf.EgressEntry]bool, desired []netbpf.EgressEntry) (toAdd, toDel []netbpf.EgressEntry) {
	desiredSet := make(map[netbpf.EgressEntry]bool, len(desired))
	for _, e := range desired {
		desiredSet[e] = true
		if !installed[e] {
			toAdd = append(toAdd, e)
		}
	}
	for e := range installed {
		if !desiredSet[e] {
			toDel = append(toDel, e)
		}
	}
	return toAdd, toDel
}

// diffDeny computes the virtual-patch deny entries to upsert and the keys to
// delete so the kernel deny_cidr map converges to the desired set (#660). Unlike
// egress, a deny entry's kernel key (DenyKey: tenant+CIDR) is narrower than the
// full entry (which also carries port/proto in the map VALUE) — so a rule whose
// port changed keeps the same key and is an UPSERT, not a delete+add of two map
// slots. installed tracks the last-applied entry per key; an entry is upserted
// when its key is new OR its port/proto differs from what's installed, and a key
// is deleted only when no desired entry uses it. Deleting stale keys is what
// makes a removed/expired deny rule actually stop blocking.
func diffDeny(installed map[netbpf.DenyKey]netbpf.DenyEntry, desired []netbpf.DenyEntry) (toUpsert []netbpf.DenyEntry, toDel []netbpf.DenyKey) {
	desiredKeys := make(map[netbpf.DenyKey]bool, len(desired))
	for _, e := range desired {
		k := e.Key()
		desiredKeys[k] = true
		if cur, ok := installed[k]; !ok || cur != e {
			toUpsert = append(toUpsert, e)
		}
	}
	for k := range installed {
		if !desiredKeys[k] {
			toDel = append(toDel, k)
		}
	}
	return toUpsert, toDel
}

// denyApplier is the slice of the BPF loader the deny-rule reconcile needs.
// *netbpf.Loader satisfies it; an interface keeps applyDeny testable without a
// kernel.
type denyApplier interface {
	AddDeny(netbpf.DenyEntry) error
	DeleteDeny(netbpf.DenyKey) error
}

// egressApplier is the slice of the loader applyEgress writes through.
type egressApplier interface {
	AddEgress(netbpf.EgressEntry) error
	DeleteEgress(netbpf.EgressEntry) error
}

// applyEgress converges the kernel egress allow-list: add the entries in toAdd,
// delete those in toDel, updating installed in place. A failed op is logged and
// skipped WITHOUT touching installed, so the next pass retries it. It returns
// the tenants whose allow-list is not what their policy says after this pass
// (an add or a removal failed), so the status can say so instead of reporting
// the tenant as fully loaded (#2983).
func applyEgress(installed map[netbpf.EgressEntry]bool, toAdd, toDel []netbpf.EgressEntry, a egressApplier) map[uint32]bool {
	incomplete := make(map[uint32]bool)
	for _, ee := range toAdd {
		if err := a.AddEgress(ee); err != nil {
			log.Printf("[netpolicy] add egress: %v", err)
			incomplete[ee.TenantID] = true
			continue
		}
		installed[ee] = true
	}
	for _, ee := range toDel {
		if err := a.DeleteEgress(ee); err != nil {
			log.Printf("[netpolicy] delete egress: %v", err)
			incomplete[ee.TenantID] = true
			continue
		}
		delete(installed, ee)
	}
	return incomplete
}

// applyDeny converges the kernel deny_cidr map from installed to desired via the
// applier, updating installed in place (#660). Upserts apply BEFORE deletes;
// diffDeny guarantees the two sets never share a key, so an entry that was just
// upserted is never immediately deleted (a port-only change is one upsert of the
// same slot, not add+del). A failed op is logged and skipped WITHOUT touching
// installed, so the next reconcile retries it rather than recording a state the
// kernel doesn't actually hold.
func applyDeny(installed map[netbpf.DenyKey]netbpf.DenyEntry, desired []netbpf.DenyEntry, a denyApplier) {
	upsert, del := diffDeny(installed, desired)
	for _, de := range upsert {
		if err := a.AddDeny(de); err != nil {
			log.Printf("[netpolicy] add deny: %v", err)
			continue
		}
		installed[de.Key()] = de
	}
	for _, dk := range del {
		if err := a.DeleteDeny(dk); err != nil {
			log.Printf("[netpolicy] delete deny: %v", err)
			continue
		}
		delete(installed, dk)
	}
}

// diffIPTenant computes the ip_tenant entries to set and the keys to delete so
// the kernel map converges to the desired IP->tenant set (#923). An entry is
// (re)set when its IP is new OR its tenant differs from what's installed; a key
// is deleted when no desired entry uses that IP. Deleting stale keys is what
// makes a freed or excluded IP actually stop being treated as a same-tenant
// peer — without it the map is add-only and a stale tag survives until a daemon
// restart rebuilds the maps.
func diffIPTenant(installed, desired map[[4]byte]uint32) (toSet map[[4]byte]uint32, toDel [][4]byte) {
	toSet = make(map[[4]byte]uint32)
	for ip, tid := range desired {
		if cur, ok := installed[ip]; !ok || cur != tid {
			toSet[ip] = tid
		}
	}
	for ip := range installed {
		if _, ok := desired[ip]; !ok {
			toDel = append(toDel, ip)
		}
	}
	return toSet, toDel
}

// ipTenantApplier is the slice of the BPF loader the ip_tenant reconcile needs.
// *netbpf.Loader satisfies it; an interface keeps applyIPTenant testable without
// a kernel.
type ipTenantApplier interface {
	SetIPTenant(ip [4]byte, tenantID uint32) error
	DeleteIPTenant(ip [4]byte) error
}

// applyIPTenant converges the kernel ip_tenant map from installed to desired via
// the applier, updating installed in place (#923). Sets apply BEFORE deletes;
// diffIPTenant guarantees the two sets never share a key, so a just-set entry is
// never immediately deleted. A failed op is logged and skipped WITHOUT touching
// installed, so the next reconcile retries it rather than recording a state the
// kernel doesn't hold.
func applyIPTenant(installed, desired map[[4]byte]uint32, a ipTenantApplier) {
	set, del := diffIPTenant(installed, desired)
	for ip, tid := range set {
		if err := a.SetIPTenant(ip, tid); err != nil {
			log.Printf("[netpolicy] set ip_tenant: %v", err)
			continue
		}
		installed[ip] = tid
	}
	for _, ip := range del {
		if err := a.DeleteIPTenant(ip); err != nil {
			log.Printf("[netpolicy] delete ip_tenant: %v", err)
			continue
		}
		delete(installed, ip)
	}
}

// foldEgressModeForObject fits the plan to what the loaded object can apply
// (#2987). An object built before #2974 reads the egress_mode byte as padding
// and applies `mode` to the egress allow-list too, so for such an object every
// split veth config is rewritten to egress_mode = mode before it is written:
// the plan then says what the kernel will do, and the applied-state report
// built from it shows `mode`, never the requested egress mode. Returns the
// tenant ids whose split was folded, for the warning. A 0 egress byte already
// means "follow mode" and is left alone.
func foldEgressModeForObject(plan *reconcilePlan, supportsEgressMode bool) map[uint32]bool {
	ignored := make(map[uint32]bool)
	if supportsEgressMode {
		return ignored
	}
	for ifindex, cfg := range plan.vethPolicy {
		if cfg.EgressMode == 0 || cfg.EgressMode == cfg.Mode {
			continue
		}
		cfg.EgressMode = cfg.Mode
		plan.vethPolicy[ifindex] = cfg
		ignored[cfg.TenantID] = true
	}
	return ignored
}

// holdLastGood adds, for every tenant whose rules failed to compile this pass,
// the egress and deny entries already installed for it, so the converge step
// neither deletes them nor adds a partial set (#3518). A tenant with nothing
// installed yet keeps nothing: its policy has never compiled here.
func holdLastGood(plan *reconcilePlan, egressInstalled map[netbpf.EgressEntry]bool, denyInstalled map[netbpf.DenyKey]netbpf.DenyEntry) {
	if len(plan.compileFailed) == 0 {
		return
	}
	for e := range egressInstalled {
		if _, bad := plan.compileFailed[e.TenantID]; bad {
			plan.egress = append(plan.egress, e)
		}
	}
	for _, d := range denyInstalled {
		if _, bad := plan.compileFailed[d.TenantID]; bad {
			plan.deny = append(plan.deny, d)
		}
	}
}

// noteCompileFailures returns the log lines for compile failures that are new
// or changed since the last pass, and for tenants that recovered, updating seen
// in place, so a failure is logged once per change rather than every pass
// (#3518). The tenant is quoted (%q): it is operator-supplied text.
func noteCompileFailures(seen, failed map[uint32]compileFailure) []string {
	var lines []string
	for id, f := range failed {
		if prev, ok := seen[id]; ok && prev.Tenant == f.Tenant && prev.Err.Error() == f.Err.Error() {
			continue
		}
		seen[id] = f
		lines = append(lines, fmt.Sprintf("[netpolicy] tenant %q (id %d): policy rules failed to compile, keeping the last good egress and deny sets: %v", f.Tenant, id, f.Err))
	}
	for id, prev := range seen {
		if _, still := failed[id]; !still {
			delete(seen, id)
			lines = append(lines, fmt.Sprintf("[netpolicy] tenant %q (id %d): policy rules compile again", prev.Tenant, id))
		}
	}
	return lines
}
