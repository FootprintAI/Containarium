package server

import (
	"context"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/internal/traffic"
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

// defaultFlowPollInterval is how often the enforcer reads the BPF per-flow
// accounting map (#627) and feeds it to the traffic collector. Shorter than the
// reconcile interval isn't useful (the counters are cumulative); a few seconds
// keeps the traffic view fresh without churning the map iterator.
const defaultFlowPollInterval = 15 * time.Second

// defaultFlowIdleTimeout is how long a flow may go without a packet before the
// poll loop treats it as closed: persists its final counters to history (#632)
// and deletes it from the BPF map. The BPF program never deletes a flow on
// FIN/RST, and the 65536-entry LRU map only evicts under pressure — so without
// this sweep a quiesced flow on a lightly-loaded backend never reaches history
// (the gap on-backend validation surfaced). Two minutes is long enough that a
// briefly-idle but still-live connection isn't split, short enough that an ended
// flow lands in history promptly.
const defaultFlowIdleTimeout = 2 * time.Minute

// FlowSink receives per-flow accounting records sourced from the eBPF program
// (#627). *traffic.Collector implements it; kept an interface so the enforcer is
// testable without the collector.
type FlowSink interface {
	IngestEBPFFlows(flows []traffic.EBPFFlow)
	// PersistEBPFFlows writes a batch of closed/idle flows straight to history,
	// independent of IngestEBPFFlows' disappearance diff — the idle reaper (#632).
	PersistEBPFFlows(flows []traffic.EBPFFlow)
}

// defaultDomainRefreshInterval is how often egress_domains are re-resolved to
// IPs (Phase C). A fixed interval rather than per-record DNS TTL — TTL-aware
// refresh (raw DNS) is a future enhancement; for now a short fixed cadence keeps
// the allow-list reasonably fresh without a DNS library.
const defaultDomainRefreshInterval = 60 * time.Second

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
	objPath        string // BPF object source: a path, or a keyword ("embedded"/"1") → netbpf.Resolve
	store          NetworkPolicyStore
	registry       TenantRegistry
	insp           containerInspector
	audit          *audit.Store
	bus            *events.Bus
	interval       time.Duration
	enforceEnabled bool // daemon-wide guard: ENFORCE policies only drop when true

	resolver      *DomainResolver // Phase C: egress_domains -> IPs
	domainRefresh time.Duration

	flowSink        FlowSink      // #627: traffic-view flow accounting (nil = disabled)
	flowPoll        time.Duration // how often to read the BPF flows map
	flowIdleTimeout time.Duration // #632: idle age past which a flow is reaped to history

	loader *netbpf.Loader

	mu              sync.Mutex
	attached        map[int]string              // ifindex -> container name currently attached
	idName          map[uint32]string           // tenant id -> name (for audit/log)
	enforced        map[uint32]bool             // tenant ids whose effective mode is ENFORCE (deny == dropped)
	egressInstalled map[netbpf.EgressEntry]bool // egress LPM entries currently in the map

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewNetworkPolicyEnforcer(objPath string, store NetworkPolicyStore, registry TenantRegistry, insp containerInspector, auditStore *audit.Store, bus *events.Bus, enforceEnabled bool) *NetworkPolicyEnforcer {
	return &NetworkPolicyEnforcer{
		objPath:         objPath,
		store:           store,
		registry:        registry,
		insp:            insp,
		audit:           auditStore,
		bus:             bus,
		interval:        defaultNetPolicyReconcileInterval,
		enforceEnabled:  enforceEnabled,
		resolver:        NewDomainResolver(nil),
		domainRefresh:   defaultDomainRefreshInterval,
		flowPoll:        defaultFlowPollInterval,
		flowIdleTimeout: defaultFlowIdleTimeout,
		attached:        make(map[int]string),
		idName:          make(map[uint32]string),
		enforced:        make(map[uint32]bool),
		egressInstalled: make(map[netbpf.EgressEntry]bool),
	}
}

// SetFlowSink wires the traffic collector so the enforcer can feed it per-flow
// accounting read from the BPF flows map (#627). Must be called before Start.
// Nil leaves flow accounting off.
func (e *NetworkPolicyEnforcer) SetFlowSink(s FlowSink) { e.flowSink = s }

// Start loads the BPF object, runs an initial reconcile, and launches the
// perf-ring consumer + the periodic reconcile loop (also woken by container bus
// events). Returns an error if the object fails to load (e.g. not on Linux);
// the caller logs and continues without enforcement.
func (e *NetworkPolicyEnforcer) Start(ctx context.Context) error {
	// objPath is the env value: a filesystem path, or a keyword ("embedded"/"1")
	// selecting the object compiled into the binary (#627 follow-up). Resolve
	// picks the right loader.
	loader, err := netbpf.Resolve(e.objPath)
	if err != nil {
		return err
	}
	e.loader = loader
	e.ctx, e.cancel = context.WithCancel(ctx)

	// Resolve egress_domains once before the first reconcile so the initial
	// allow-list already includes domain IPs.
	e.refreshDomains()

	if err := e.reconcile(e.ctx); err != nil {
		log.Printf("[netpolicy] initial reconcile: %v", err)
	}

	// Domain refresh loop (Phase C): re-resolve egress_domains on a cadence. The
	// next reconcile folds the refreshed IPs into the egress map (and diffEgress
	// prunes IPs a domain no longer resolves to).
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(e.domainRefresh)
		defer t.Stop()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-t.C:
				e.refreshDomains()
			}
		}
	}()

	// Perf consumer: would-deny events -> audit rows.
	rd, err := perf.NewReader(loader.EventsMap(), 4096)
	if err != nil {
		log.Printf("[netpolicy] perf reader: %v (denied-flow audit disabled)", err)
	} else {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer func() { _ = rd.Close() }()
			go func() { <-e.ctx.Done(); _ = rd.Close() }() // unblock Read on shutdown
			netbpf.ConsumeDenyEvents(e.ctx, rd, e, func(err error) {
				log.Printf("[netpolicy] perf: %v", err)
			})
		}()
	}

	// Flow-accounting poll (#627): read the BPF per-flow map on a cadence and
	// feed it to the traffic collector so the traffic view shows real src/dst IP
	// + byte counts sourced from eBPF. Only runs when a sink is wired AND the
	// loaded object carries the flows map (an older object still enforces; the
	// poll just stays off until the operator rebuilds it).
	switch {
	case e.flowSink == nil:
		// no sink configured — flow accounting disabled
	case !loader.HasFlowAccounting():
		log.Printf("[netpolicy] traffic-flow accounting unavailable: loaded BPF object lacks the 'flows' map (rebuild netpolicy.bpf.o to enable #627)")
	default:
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			t := time.NewTicker(e.flowPoll)
			defer t.Stop()
			e.pollFlows() // prime the view immediately rather than after one tick
			for {
				select {
				case <-e.ctx.Done():
					return
				case <-t.C:
					e.pollFlows()
				}
			}
		}()
		log.Printf("[netpolicy] traffic-flow accounting enabled (poll=%s)", e.flowPoll)
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

	mode := "observation-only (log_only)"
	if e.enforceEnabled {
		mode = "ENFORCE ARMED — enforce-mode policies WILL DROP packets"
	}
	log.Printf("[netpolicy] enforcer started (obj=%s, interval=%s, %s)", e.objPath, e.interval, mode)
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
	dropped := e.enforced[ev.TenantID]
	e.mu.Unlock()
	// Always log the denied flow. The program emits the event whether or not it
	// drops, so the action depends on the tenant's effective mode: a DROP under
	// enforce, an observation under log_only. This line is the operator's signal.
	action := "log_only (not dropped)"
	if dropped {
		action = "DROPPED (enforce)"
	}
	log.Printf("[netpolicy] deny: tenant=%q src=%s dst=%s proto=%d dport=%d %s",
		tenant, ev.Src(), ev.Dst(), ev.Proto, ev.Dport, action)
	if e.audit == nil {
		return
	}
	detail := `{"src":"` + ev.Src().String() + `","dst":"` + ev.Dst().String() +
		`","proto":` + itoa(int(ev.Proto)) + `,"dport":` + itoa(int(ev.Dport)) +
		`,"dropped":` + boolStr(dropped) + `}`
	action2 := "network_policy.deny_logged"
	if dropped {
		action2 = "network_policy.deny_dropped"
	}
	entry := &audit.AuditEntry{
		Username:     "_system",
		Action:       action2,
		ResourceType: "network_policy",
		ResourceID:   tenant,
		Detail:       detail,
	}
	if err := e.audit.Log(ctx, entry); err != nil {
		log.Printf("[netpolicy] audit deny event: %v", err)
	}
}

// pollFlows reads the BPF per-flow accounting map (#627), attributes each flow
// to a container via the veth ifindex (exact — the map key carries it), and
// hands the batch to the traffic collector. Flows on a veth that is no longer
// attached are skipped (the container is gone; its flows age out of the LRU map).
func (e *NetworkPolicyEnforcer) pollFlows() {
	if e.loader == nil || e.flowSink == nil {
		return
	}
	records, err := e.loader.Flows()
	if err != nil {
		log.Printf("[netpolicy] read flows: %v", err)
		return
	}
	// Snapshot the ifindex -> container attribution under the lock.
	e.mu.Lock()
	attached := make(map[int]string, len(e.attached))
	for idx, name := range e.attached {
		attached[idx] = name
	}
	e.mu.Unlock()

	now := time.Now()
	active, idle := splitIdleFlows(records, monotonicNowNs(), e.flowIdleTimeout)

	// Live view = currently-active flows only (an idle flow being reaped this
	// poll shouldn't show as a live connection).
	e.flowSink.IngestEBPFFlows(flowsToEBPF(active, attached, now))

	// Idle reaper (#632): a flow whose last packet is older than the idle
	// timeout has effectively closed. Persist its final counters to history,
	// then delete it from the BPF map so it doesn't linger until the LRU map
	// fills — the gap on-backend validation found, where a quiesced flow on a
	// far-from-full 65536-entry map never disappeared, so closedFlows never
	// fired and history stayed empty.
	if len(idle) > 0 {
		e.flowSink.PersistEBPFFlows(flowsToEBPF(idle, attached, now))
		for _, r := range idle {
			if err := e.loader.DeleteFlow(r); err != nil {
				log.Printf("[netpolicy] reap idle flow: %v", err)
			}
		}
	}
}

// splitIdleFlows partitions BPF flow records into still-active and idle by the
// monotonic last-packet stamp. A flow whose last packet is older than idleFor
// (relative to nowNs — the current CLOCK_MONOTONIC reading, the same clock
// bpf_ktime_get_ns stamps records with) is treated as closed and returned in
// idle for persist+forget (#632). Pure: no clock or loader access, so it is
// unit-testable. A zero/garbage nowNs (clock read failed) yields no idle flows —
// the sweep simply no-ops that poll rather than reaping live flows.
func splitIdleFlows(records []netbpf.FlowRecord, nowNs uint64, idleFor time.Duration) (active, idle []netbpf.FlowRecord) {
	cutoff := uint64(idleFor.Nanoseconds())
	for _, r := range records {
		if nowNs > r.LastNs && nowNs-r.LastNs > cutoff {
			idle = append(idle, r)
		} else {
			active = append(active, r)
		}
	}
	return active, idle
}

// monotonicNowNs returns CLOCK_MONOTONIC in nanoseconds — the same clock
// bpf_ktime_get_ns() stamps flow records with, so the two are directly
// comparable for idle detection. Returns 0 if the clock read fails (the caller
// then reaps nothing that poll).
func monotonicNowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// flowsToEBPF attributes each BPF flow record to its container via the veth
// ifindex and renders it as a traffic.EBPFFlow. Records on an unmanaged veth are
// dropped. Pure (no loader/clock access) so it is unit-testable. Absolute
// first/last timestamps aren't recoverable from the monotonic ktime stamps, so
// First is derived as now-duration to preserve the flow's age.
func flowsToEBPF(records []netbpf.FlowRecord, attached map[int]string, now time.Time) []traffic.EBPFFlow {
	out := make([]traffic.EBPFFlow, 0, len(records))
	for _, r := range records {
		name := attached[int(r.Ifindex)]
		if name == "" {
			continue // veth not (or no longer) managed
		}
		// The accounting hook sees the container's egress, so the flow's source
		// IP is the container's own IP.
		src := r.Src().String()
		var dur time.Duration
		if r.LastNs >= r.FirstNs {
			// both are bpf_ktime_get_ns (ns); safecast guards the u64->i64 (Duration) cast
			dur = time.Duration(safecast.I64FromU64(r.LastNs - r.FirstNs))
		}
		out = append(out, traffic.EBPFFlow{
			ContainerName: name,
			ContainerIP:   src,
			Protocol:      protoName(r.Proto),
			SrcIP:         src,
			SrcPort:       r.Sport,
			DstIP:         r.Dst().String(),
			DstPort:       r.Dport,
			Bytes:         safecast.I64FromU64(r.Bytes),
			Packets:       safecast.I64FromU64(r.Packets),
			RxBytes:       safecast.I64FromU64(r.RxBytes),   // reply direction (#631)
			RxPackets:     safecast.I64FromU64(r.RxPackets), // 0 if object predates #631
			First:         now.Add(-dur),                    // absolute first/last unknown; preserve duration
			Last:          now,
		})
	}
	return out
}

// protoName renders an IP protocol number as the lowercase string the traffic
// collector's protoStringToEnum expects.
func protoName(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return ""
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
	plan := planReconcile(views, policies, e.enforceEnabled)

	// ip_tenant: every managed container's IP -> its tenant id.
	for ip, tid := range plan.ipTenant {
		if err := e.loader.SetIPTenant(ip, tid); err != nil {
			log.Printf("[netpolicy] set ip_tenant: %v", err)
		}
	}
	// egress allow-list: converge the map (add new, delete stale). Deleting
	// removed CIDRs is what makes a tightened policy actually take effect in
	// enforce mode.
	toAdd, toDel := diffEgress(e.egressInstalled, plan.egress)
	for _, ee := range toAdd {
		if err := e.loader.AddEgress(ee); err != nil {
			log.Printf("[netpolicy] add egress: %v", err)
			continue
		}
		e.egressInstalled[ee] = true
	}
	for _, ee := range toDel {
		if err := e.loader.DeleteEgress(ee); err != nil {
			log.Printf("[netpolicy] delete egress: %v", err)
			continue
		}
		delete(e.egressInstalled, ee)
	}
	// Per-veth config + attach. Track which tenants end up in effective-enforce
	// mode, so OnDenyEvent can label a denied flow as dropped vs observed.
	enforced := make(map[uint32]bool)
	e.mu.Lock()
	present := make(map[int]bool, len(plan.vethPolicy))
	for ifindex, cfg := range plan.vethPolicy {
		if cfg.Mode == netbpf.ModeEnforce {
			enforced[cfg.TenantID] = true
		}
		if err := e.loader.SetVethPolicy(ifindex, cfg); err != nil {
			log.Printf("[netpolicy] set veth_policy ifindex %d: %v", ifindex, err)
			continue
		}
		if err := e.loader.AttachVeth(ifindex); err != nil {
			log.Printf("[netpolicy] attach ifindex %d: %v", ifindex, err)
			continue
		}
		// Reply-direction accounting (#631): attach the egress program too. No-ops
		// on an object that predates it. Non-fatal — ingress accounting + policy
		// still work without it.
		if err := e.loader.AttachVethEgress(ifindex); err != nil {
			log.Printf("[netpolicy] attach egress ifindex %d: %v", ifindex, err)
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
	e.enforced = enforced
	e.mu.Unlock()
	return nil
}

// boolStr renders a bool as a JSON literal for the audit detail.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
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
		tenant := resolveTenant(c.Tenant, c.Name)
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
		// Phase C: fold each egress_domain's currently-resolved IPs into the
		// allow-list as /32 CIDRs. planReconcile/CompileEgress then treat them as
		// ordinary egress entries; diffEgress prunes IPs a domain stopped
		// resolving to on the next pass.
		for _, dom := range c.EgressDomains {
			for _, ip := range e.resolver.IPs(dom) {
				c.EgressCIDRs = append(c.EgressCIDRs, netip.PrefixFrom(ip, 32))
			}
		}
		out[c.Tenant] = c
	}
	return out, nil
}

// refreshDomains re-resolves every egress_domain across all stored policies into
// the resolver cache. Best-effort: store/lookup errors are logged, not fatal.
func (e *NetworkPolicyEnforcer) refreshDomains() {
	stored, err := e.store.List(e.ctx)
	if err != nil {
		log.Printf("[netpolicy] domain refresh: list policies: %v", err)
		return
	}
	var domains []string
	for _, p := range stored {
		domains = append(domains, p.GetEgressDomains()...)
	}
	if len(domains) == 0 {
		return
	}
	cctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	e.resolver.Refresh(cctx, domains)
}

// resolveTenant determines a container's owning tenant. An explicit tenant
// label (user.containarium.tenant) wins — it decouples tenant identity from the
// container name, which is what lets cloud-assigned containers (named
// cld-<uuid>, not <tenant>-container) be policed too (#315 "Cloud extension").
// Falls back to the <tenant>-container naming convention; "" if neither yields
// a tenant (the container is then left unmanaged).
func resolveTenant(tenantLabel, containerName string) string {
	if t := strings.TrimSpace(tenantLabel); t != "" {
		return t
	}
	return tenantOf(containerName)
}

// tenantOf extracts the tenant name from a container name, or "" if it doesn't
// follow the <tenant>-container convention.
func tenantOf(containerName string) string {
	if !strings.HasSuffix(containerName, containerSuffix) {
		return ""
	}
	return strings.TrimSuffix(containerName, containerSuffix)
}
