package server

import (
	"strconv"

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
}

// planReconcile computes the desired BPF map state from the current container
// views and the compiled per-tenant policies. A container with no stored policy
// gets the Phase A default (log-only, no intra-tenant, empty egress) so its
// outbound is observed rather than silently unmanaged.
func planReconcile(views []containerView, policies map[string]netpolicy.CompiledPolicy) reconcilePlan {
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
				cfg = netbpf.PolicyConfig{TenantID: v.TenantID, Mode: netbpf.ModeLogOnly}
			}
			plan.vethPolicy[v.Ifindex] = cfg
			plan.ifName[v.Ifindex] = v.Name
		}

		if hasPolicy && !egressDone[v.TenantID] {
			if entries, err := netbpf.CompileEgress(v.TenantID, policy); err == nil {
				plan.egress = append(plan.egress, entries...)
			}
			egressDone[v.TenantID] = true
		}
	}
	return plan
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
