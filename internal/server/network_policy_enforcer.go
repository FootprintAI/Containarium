package server

import (
	"context"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/perf"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// containerSuffix is the trailing tag every tenant container name carries; the
// tenant name is the part before it (mirrors container_server.go).
const containerSuffix = "-container"

// defaultNetPolicyReconcileInterval is how often the enforcer re-converges the BPF maps
// to the live container + policy state. The reconcile loop is the source of
// truth (robust against dropped bus events); the bus only triggers an early
// reconcile for latency.
const defaultNetPolicyReconcileInterval = 10 * time.Second

// containerInspector is the slice of the Incus client the enforcer needs.
type containerInspector interface {
	ListContainers() ([]incus.ContainerInfo, error)
	GetRawInstance(name string) (map[string]string, string, error)
}

// NetworkPolicyEnforcer owns the netbpf.Loader and keeps the kernel's
// per-tenant network-policy maps converged with the daemon's stored policies +
// live containers (#315 Phase A piece 6c). It is OFF by default — NewDualServer
// only constructs it when a BPF object path is configured — so an existing
// deployment is unaffected unless the operator opts in.
//
// Phase A is observation-only: the program never drops, it emits would-deny
// events that this enforcer's perf consumer turns into audit rows.
type NetworkPolicyEnforcer struct {
	objPath  string
	store    NetworkPolicyStore
	registry TenantRegistry
	insp     containerInspector
	audit    *audit.Store
	bus      *events.Bus
	interval time.Duration

	loader *netbpf.Loader

	mu       sync.Mutex
	attached map[int]string // ifindex -> container name currently attached
	idName   map[uint32]string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewNetworkPolicyEnforcer(objPath string, store NetworkPolicyStore, registry TenantRegistry, insp containerInspector, auditStore *audit.Store, bus *events.Bus) *NetworkPolicyEnforcer {
	return &NetworkPolicyEnforcer{
		objPath:  objPath,
		store:    store,
		registry: registry,
		insp:     insp,
		audit:    auditStore,
		bus:      bus,
		interval: defaultNetPolicyReconcileInterval,
		attached: make(map[int]string),
		idName:   make(map[uint32]string),
	}
}

// Start loads the BPF object, runs an initial reconcile, and launches the
// perf-ring consumer + the periodic reconcile loop (also woken by container bus
// events). Returns an error if the object fails to load (e.g. not on Linux);
// the caller logs and continues without enforcement.
func (e *NetworkPolicyEnforcer) Start(ctx context.Context) error {
	loader, err := netbpf.Load(e.objPath)
	if err != nil {
		return err
	}
	e.loader = loader
	e.ctx, e.cancel = context.WithCancel(ctx)

	if err := e.reconcile(e.ctx); err != nil {
		log.Printf("[netpolicy] initial reconcile: %v", err)
	}

	// Perf consumer: would-deny events -> audit rows.
	rd, err := perf.NewReader(loader.EventsMap(), 4096)
	if err != nil {
		log.Printf("[netpolicy] perf reader: %v (denied-flow audit disabled)", err)
	} else {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer rd.Close()
			go func() { <-e.ctx.Done(); rd.Close() }() // unblock Read on shutdown
			netbpf.ConsumeDenyEvents(e.ctx, rd, e, func(err error) {
				log.Printf("[netpolicy] perf: %v", err)
			})
		}()
	}

	// Reconcile loop + bus trigger.
	var sub *events.Subscriber
	if e.bus != nil {
		sub = e.bus.Subscribe(nil)
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		if sub != nil {
			defer e.bus.Unsubscribe(sub.ID)
		}
		tick := time.NewTicker(e.interval)
		defer tick.Stop()
		busCh := subEvents(sub) // nil channel (blocks forever) when no bus
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-tick.C:
				if err := e.reconcile(e.ctx); err != nil {
					log.Printf("[netpolicy] reconcile: %v", err)
				}
			case <-busCh:
				// Container changed — converge sooner. Errors are logged, not fatal.
				if err := e.reconcile(e.ctx); err != nil {
					log.Printf("[netpolicy] reconcile (event): %v", err)
				}
			}
		}
	}()

	log.Printf("[netpolicy] enforcer started (obj=%s, interval=%s, observation-only)", e.objPath, e.interval)
	return nil
}

// Stop cancels the loops and closes the loader (detaching every veth).
func (e *NetworkPolicyEnforcer) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	if e.loader != nil {
		if err := e.loader.Close(); err != nil {
			log.Printf("[netpolicy] loader close: %v", err)
		}
	}
}

// OnDenyEvent implements netbpf.DenyEventSink: write a would-deny flow to the
// audit log. Action network_policy.deny; the tenant name is resolved from the
// id->name map built during reconcile.
func (e *NetworkPolicyEnforcer) OnDenyEvent(ctx context.Context, ev netbpf.DenyEvent) {
	e.mu.Lock()
	tenant := e.idName[ev.TenantID]
	e.mu.Unlock()
	// Always log the would-deny flow — in log_only mode this line IS the
	// operator-visible signal that a flow would be blocked. The audit row below
	// is the durable record (when an audit store is configured).
	log.Printf("[netpolicy] would-deny: tenant=%q src=%s dst=%s proto=%d dport=%d (log_only)",
		tenant, ev.Src(), ev.Dst(), ev.Proto, ev.Dport)
	if e.audit == nil {
		return
	}
	detail := `{"src":"` + ev.Src().String() + `","dst":"` + ev.Dst().String() +
		`","proto":` + itoa(int(ev.Proto)) + `,"dport":` + itoa(int(ev.Dport)) + `}`
	entry := &audit.AuditEntry{
		Username:     "_system",
		Action:       "network_policy.deny",
		ResourceType: "network_policy",
		ResourceID:   tenant,
		Detail:       detail,
	}
	if err := e.audit.Log(ctx, entry); err != nil {
		log.Printf("[netpolicy] audit deny event: %v", err)
	}
}

// reconcile converges the BPF maps + veth attachments with the live container
// and policy state. It gathers the current containers (Linux veth resolution),
// builds a plan, applies it, and detaches veths no longer present.
func (e *NetworkPolicyEnforcer) reconcile(ctx context.Context) error {
	if e.loader == nil {
		return nil
	}
	views, idName, err := e.gather(ctx)
	if err != nil {
		return err
	}
	policies, err := e.compiledPolicies(ctx)
	if err != nil {
		return err
	}
	plan := planReconcile(views, policies)

	// ip_tenant: every managed container's IP -> its tenant id.
	for ip, tid := range plan.ipTenant {
		if err := e.loader.SetIPTenant(ip, tid); err != nil {
			log.Printf("[netpolicy] set ip_tenant: %v", err)
		}
	}
	// egress allow-list per tenant.
	for _, ee := range plan.egress {
		if err := e.loader.AddEgress(ee); err != nil {
			log.Printf("[netpolicy] add egress: %v", err)
		}
	}
	// Per-veth config + attach.
	e.mu.Lock()
	present := make(map[int]bool, len(plan.vethPolicy))
	for ifindex, cfg := range plan.vethPolicy {
		if err := e.loader.SetVethPolicy(ifindex, cfg); err != nil {
			log.Printf("[netpolicy] set veth_policy ifindex %d: %v", ifindex, err)
			continue
		}
		if err := e.loader.AttachVeth(ifindex); err != nil {
			log.Printf("[netpolicy] attach ifindex %d: %v", ifindex, err)
			continue
		}
		e.attached[ifindex] = plan.ifName[ifindex]
		present[ifindex] = true
	}
	// Detach veths that are gone (container stopped/deleted).
	for ifindex := range e.attached {
		if !present[ifindex] {
			if err := e.loader.DetachVeth(ifindex); err != nil {
				log.Printf("[netpolicy] detach ifindex %d: %v", ifindex, err)
			}
			delete(e.attached, ifindex)
		}
	}
	e.idName = idName
	e.mu.Unlock()
	return nil
}

// gather snapshots the running containers into reconcile views, resolving each
// one's host veth ifindex (Linux). It also returns the id->name map for the
// audit sink.
func (e *NetworkPolicyEnforcer) gather(_ context.Context) ([]containerView, map[uint32]string, error) {
	containers, err := e.insp.ListContainers()
	if err != nil {
		return nil, nil, err
	}
	views := make([]containerView, 0, len(containers))
	idName := make(map[uint32]string)
	for _, c := range containers {
		tenant := tenantOf(c.Name)
		if tenant == "" {
			continue
		}
		tid, err := e.registry.ID(e.ctx, tenant)
		if err != nil {
			log.Printf("[netpolicy] tenant id for %q: %v", tenant, err)
			continue
		}
		idName[tid] = tenant
		v := containerView{Name: c.Name, Tenant: tenant, TenantID: tid}
		if ip, err := netip.ParseAddr(c.IPAddress); err == nil && ip.Is4() {
			v.IP = ip.As4()
			v.HasIP = true
		}
		if strings.EqualFold(c.State, "running") {
			v.Running = true
			cfg, _, err := e.insp.GetRawInstance(c.Name)
			if err == nil {
				if veth := netbpf.HostVethFromConfig(cfg); veth != "" {
					if ifindex, err := netbpf.VethIndex(veth); err == nil {
						v.Ifindex = ifindex
						v.HasVeth = true
					}
				}
			}
		}
		views = append(views, v)
	}
	return views, idName, nil
}

// compiledPolicies loads + compiles every stored policy, keyed by tenant.
func (e *NetworkPolicyEnforcer) compiledPolicies(ctx context.Context) (map[string]netpolicy.CompiledPolicy, error) {
	stored, err := e.store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]netpolicy.CompiledPolicy, len(stored))
	for _, p := range stored {
		c, err := netpolicy.Compile(p)
		if err != nil {
			log.Printf("[netpolicy] compile policy for %q: %v", p.GetTenant(), err)
			continue
		}
		out[c.Tenant] = c
	}
	return out, nil
}

// tenantOf extracts the tenant name from a container name, or "" if it doesn't
// follow the <tenant>-container convention.
func tenantOf(containerName string) string {
	if !strings.HasSuffix(containerName, containerSuffix) {
		return ""
	}
	return strings.TrimSuffix(containerName, containerSuffix)
}
