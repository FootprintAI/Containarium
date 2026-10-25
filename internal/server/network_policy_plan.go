package server

import (
	"log"
	"strconv"
	"time"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// containerView is a reconcile-time snapshot of one managed container: its
// tenant, assigned tenant ID, IPv4 (if resolved), and host veth ifindex (if
// running + resolved). gather() builds these (Linux veth resolution);
// planReconcile() turns them + the compiled policies into BPF map entries.
type containerView struct {
	Name     string
	Tenant   string
	TenantID uint32
	IP       [4]byte
	HasIP    bool
	Ifindex  int
	HasVeth  bool
	Running  bool
}

// reconcilePlan is the desired BPF map state for one reconcile pass — pure data
// so planReconcile is unit-testable without a kernel.
type reconcilePlan struct {
	ipTenant   map[[4]byte]uint32          // container IP -> tenant id
	vethPolicy map[int]netbpf.PolicyConfig // running container veth ifindex -> policy config
	ifName     map[int]string              // ifindex -> container name (for bookkeeping)
	egress     []netbpf.EgressEntry        // per-tenant egress allow-list entries
	deny       []netbpf.DenyEntry          // per-tenant virtual-patch deny entries (#660)
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
		vethPolicy: make(map[int]netbpf.PolicyConfig),
		ifName:     make(map[int]string),
	}
	// egress entries are per tenant, not per container — emit each tenant's set
	// once, keyed by the tenant IDs we actually saw.
	egressDone := make(map[uint32]bool)

	for _, v := range views {
		if v.HasIP {
			plan.ipTenant[v.IP] = v.TenantID
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
			plan.vethPolicy[v.Ifindex] = cfg
			plan.ifName[v.Ifindex] = v.Name
		}

		if hasPolicy && !egressDone[v.TenantID] {
			if entries, err := netbpf.CompileEgress(v.TenantID, policy); err == nil {
				plan.egress = append(plan.egress, entries...)
			}
			// Virtual-patch deny entries (#660), once per tenant. Expired rules are
			// already filtered out of policy.DenyRules by the daemon (compiledPolicies)
			// before planning, so anything here is active.
			if entries, err := netbpf.CompileDeny(v.TenantID, policy); err == nil {
				plan.deny = append(plan.deny, entries...)
			}
			egressDone[v.TenantID] = true
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

// subEvents returns the subscriber's event channel, or a nil channel (which
// blocks forever in a select) when there is no subscriber.
func subEvents(sub *events.Subscriber) <-chan *pb.Event {
	if sub == nil {
		return nil
	}
	return sub.Events
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

// applyDeny converges the kernel deny_cidr map from installed to desired via the
// applier, updating installed in place (#660). Upserts apply BEFORE deletes;
// diffDeny guarantees the two sets never share a key, so an entry that was just
// upserted is never immediately deleted (a port-only change is one upsert of the
// same slot, not add+del). A failed op is logged and skipped WITHOUT touching
// installed, so the next reconcile retries it rather than recording a state the
// kernel doesn't actually hold.
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
