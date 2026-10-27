package server

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/audit"
	appconfig "github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/internal/traffic"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// containerSuffix is the trailing tag every tenant container name carries; the
// tenant name is the part before it (mirrors container_server.go).
const containerSuffix = "-container"

// defaultNetPolicyReconcileInterval is how often the enforcer re-converges the BPF maps
// to the live container + policy state. The reconcile loop is the source of
// truth (robust against dropped bus events); the bus only triggers an early
// reconcile for latency. Each cycle does one Incus ListContainers plus a cheap
// per-container netlink lookup; the expensive per-container Incus inspect is
// cached and only re-runs when a container starts/restarts (#654).
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

// containerInspector is the slice of the Incus client the enforcer needs.
type containerInspector interface {
	ListContainers() ([]incus.ContainerInfo, error)
	GetRawInstance(name string) (map[string]string, string, error)
	// GetRawInstanceDevices is the instance's expanded device map, the
	// host-side source of its NIC's network and static address (#2618).
	GetRawInstanceDevices(name string) (map[string]map[string]string, error)
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

	// eventDebounce is the trailing debounce on the container-event path
	// (#3050); the timer path (interval) is not debounced.
	eventDebounce time.Duration
	// meter counts reconcile passes (#3050). pass is the reconcile a pass runs;
	// nil means e.reconcile (a test substitutes a fake).
	meter *reconcileMeter
	pass  func(context.Context) error

	// gateway is the bridge gateway, the box's DNS resolver. A policy with an
	// egress preset (#2440) implicitly allows it; the zero value means the
	// daemon could not name it and the preset adds nothing.
	gateway netip.Addr

	// defaultExtras is the operator's addition to the default egress allow-list;
	// defaultOn is whether a tenant with no stored policy gets that list
	// (#2577 stage 1). Set before Start.
	defaultOn      bool
	defaultExtras  netpolicy.DefaultEgressExtras
	defaultDomains []string // normalized built-ins + extras: what the resolver caches and the policy looks up

	resolver *DomainResolver // Phase C: egress_domains -> IPs (refresh cadence: min(TTL, 60s), #2379)

	flowSink        FlowSink      // #627: traffic-view flow accounting (nil = disabled)
	flowPoll        time.Duration // how often to read the BPF flows map
	flowIdleTimeout time.Duration // #632: idle age past which a flow is reaped to history

	// flowHook and denyHook feed the threat-detection engine (#1640): the
	// same per-poll flow batch and per-event deny stream this enforcer
	// already collects, fanned out to a second consumer. nil = sentry
	// disabled. Same one-callback pattern as Scanner.SetScanResultHook /
	// auto_quarantine.go — the one existing detect→act template.
	flowHook func(flows []netbpf.FlowRecord)
	denyHook func(ev netbpf.DenyEvent)

	loader *netbpf.Loader

	// execWatcher is the exec-telemetry userspace half (#2637). It rides this
	// enforcer's lifecycle and 10 s reconcile (the container list with init
	// pids is already gathered here) but loads its own BPF object, so its
	// failure never touches flow enforcement. nil = sentry off.
	execWatcher *ExecWatcher
	// lastContainers is the raw ListContainers result of the latest gather,
	// handed to the exec watcher's reconcile. Only touched from reconcile.
	lastContainers []incus.ContainerInfo

	// vethCache maps a running container name -> its host veth name and primary
	// NIC facts, so a steady reconcile resolves the ifindex with a cheap local
	// netlink lookup (VethIndex) instead of an Incus inspect (GetRawInstance +
	// GetRawInstanceDevices) every cycle (#654). Only touched from gather, which
	// runs serially inside reconcile (the reconcile loop is single-goroutine), so
	// it needs no lock.
	vethCache map[string]vethInfo

	// leaseDir is where the bridge DHCP lease files live (#2618); derived from
	// the Incus data dir (SetIncusDataDir), tests point it at a fixture.
	leaseDir string
	// addrWarned holds the running containers already warned that the host
	// knows no address for them (#2618 S5); cleared when known or stopped.
	addrWarned map[string]bool
	// extraUplinks are operator-named uplink interfaces
	// (CONTAINARIUM_NETWORK_POLICY_UPLINKS) added to the default-route ones.
	extraUplinks []string
	// trustedInstalled is what the kernel trusted_iif map holds (ifindex set).
	trustedInstalled map[int]bool
	// reseedLast is the inbound_reseed counter at the previous pass.
	reseedLast uint64

	// egressModeWarned holds the tenant ids already warned that the loaded
	// object ignores their egress_mode (#2987), so the warning is not repeated
	// every pass. Only touched from reconcile.
	egressModeWarned map[uint32]bool

	// egressNames maps a tenant id to its name for every tenant seen this pass
	// or still holding allow-list entries, so a failed write is attributed to
	// its tenant even when the tenant has no box left (#3051). Only touched from
	// reconcile.
	egressNames map[uint32]string

	sigEnabled bool                        // #661: populate + scan Tier 2 signatures (operator opt-in)
	sigStore   NetworkPolicySignatureStore // #661 PR-B: operator signatures (nil = built-ins only)
	sigNames   map[uint16]string           // signature id -> name, for audit labelling (built at populate)
	sigLoaded  string                      // last applied signature set fingerprint (skip redundant map writes)

	mu                sync.Mutex
	attached          map[int]string                      // ifindex -> container name currently attached
	idName            map[uint32]string                   // tenant id -> name (for audit/log)
	enforced          map[uint32]bool                     // tenant ids whose effective mode is ENFORCE (deny == dropped)
	egressInstalled   map[netbpf.EgressEntry]bool         // egress LPM entries currently in the map
	denyInstalled     map[netbpf.DenyKey]netbpf.DenyEntry // virtual-patch deny entries currently in the map (#660)
	ipTenantInstalled map[[4]byte]uint32                  // ip_tenant entries currently in the map (#923: converge deletes)
	running           bool                                // the BPF program is loaded (Start succeeded, Stop not yet called)
	applied           map[string]tenantApplied            // per-tenant state the last reconcile pass loaded; nil until a pass completes
	appliedAt         time.Time                           // when the pass that produced applied ended

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewNetworkPolicyEnforcer(objPath string, store NetworkPolicyStore, registry TenantRegistry, insp containerInspector, auditStore *audit.Store, bus *events.Bus, enforceEnabled bool) *NetworkPolicyEnforcer {
	return &NetworkPolicyEnforcer{
		objPath:           objPath,
		store:             store,
		registry:          registry,
		insp:              insp,
		audit:             auditStore,
		bus:               bus,
		interval:          defaultNetPolicyReconcileInterval,
		eventDebounce:     defaultContainerEventDebounce,
		meter:             globalReconcileMeter(),
		enforceEnabled:    enforceEnabled,
		resolver:          NewDomainResolver(nil),
		flowPoll:          defaultFlowPollInterval,
		flowIdleTimeout:   defaultFlowIdleTimeout,
		vethCache:         make(map[string]vethInfo),
		leaseDir:          defaultIncusLeaseDir,
		addrWarned:        make(map[string]bool),
		extraUplinks:      splitCSV(os.Getenv("CONTAINARIUM_NETWORK_POLICY_UPLINKS")),
		trustedInstalled:  make(map[int]bool),
		egressNames:       make(map[uint32]string),
		attached:          make(map[int]string),
		idName:            make(map[uint32]string),
		enforced:          make(map[uint32]bool),
		egressInstalled:   make(map[netbpf.EgressEntry]bool),
		denyInstalled:     make(map[netbpf.DenyKey]netbpf.DenyEntry),
		ipTenantInstalled: make(map[[4]byte]uint32),
	}
}

// SetDefaultEgress turns the default egress posture on for tenants with no
// stored policy (#2577 stage 1): the built-in allow-list plus extras, always in
// log_only. extras that do not validate are refused so a typo cannot quietly
// narrow the list; the caller decides what to run with instead. Must be called
// before Start.
func (e *NetworkPolicyEnforcer) SetDefaultEgress(extras netpolicy.DefaultEgressExtras) error {
	c, err := netpolicy.DefaultPolicy("probe", extras)
	if err != nil {
		return err
	}
	e.defaultOn, e.defaultExtras, e.defaultDomains = true, extras, c.EgressDomains
	return nil
}

// defaultEgressState is how the default egress posture came up at startup.
type defaultEgressState int

const (
	defaultEgressOff          defaultEgressState = iota // CONTAINARIUM_NETWORK_DEFAULT_EGRESS=off
	defaultEgressFull                                   // built-in list plus the operator's extras
	defaultEgressBuiltinsOnly                           // extras refused; built-in list only
)

// configureDefaultEgress applies the CONTAINARIUM_NETWORK_DEFAULT_EGRESS*
// settings to the enforcer and logs the outcome. Extras that do not validate
// are refused with the reason and the built-in list runs alone, so one typo
// cannot disable the posture or narrow it silently.
func configureDefaultEgress(e *NetworkPolicyEnforcer, mode, domains, cidrs string) defaultEgressState {
	on, extras := netpolicy.ParseDefaultEgress(mode, domains, cidrs)
	if !on {
		log.Printf("NetworkPolicy: default egress posture is off (%s=off); tenants with no stored policy run an empty allow-list in log_only", appconfig.EnvDefaultEgress)
		return defaultEgressOff
	}
	if err := e.SetDefaultEgress(extras); err != nil {
		log.Printf("NetworkPolicy: ignoring %s/%s (%v); using the built-in default allow-list only", appconfig.EnvDefaultEgressDomains, appconfig.EnvDefaultEgressCIDRs, err)
		if err := e.SetDefaultEgress(netpolicy.DefaultEgressExtras{}); err != nil {
			// Unreachable while the built-ins are valid; say so rather than
			// claim a list that is not applied.
			log.Printf("NetworkPolicy: the built-in default egress allow-list did not load (%v); the default posture is off", err)
			return defaultEgressOff
		}
		log.Printf("NetworkPolicy: built-in default egress allow-list (log_only, no extras) applies to tenants with no stored policy")
		return defaultEgressBuiltinsOnly
	}
	log.Printf("NetworkPolicy: default egress allow-list (log_only) applies to tenants with no stored policy")
	return defaultEgressFull
}

// defaultPolicyFor builds the default policy for a tenant, resolved the same
// way as a stored one. The second result is false when the posture is off.
func (e *NetworkPolicyEnforcer) defaultPolicyFor(tenant string) (netpolicy.CompiledPolicy, bool) {
	if !e.defaultOn {
		return netpolicy.CompiledPolicy{}, false
	}
	c, err := netpolicy.DefaultPolicy(tenant, e.defaultExtras)
	if err != nil {
		log.Printf("[netpolicy] default policy for %q: %v", tenant, err)
		return netpolicy.CompiledPolicy{}, false
	}
	return e.expandPolicy(c, false), true
}

// SetImplicitGateway tells the enforcer the bridge gateway address, the
// DNS resolver every box uses, so a policy with an egress preset (#2440) can
// allow it without the operator listing it. Must be called before Start.
func (e *NetworkPolicyEnforcer) SetImplicitGateway(a netip.Addr) { e.gateway = a }

// SetFlowSink wires the traffic collector so the enforcer can feed it per-flow
// accounting read from the BPF flows map (#627). Must be called before Start.
// Nil leaves flow accounting off.
func (e *NetworkPolicyEnforcer) SetFlowSink(s FlowSink) { e.flowSink = s }

// SetFlowHook wires the threat-detection engine's flow consumer (#1640).
// Called synchronously at the end of every flow-accounting poll (15s
// cadence) with that poll's active flow batch — the same records
// flowsToEBPF turns into traffic-view rows. Must be called before Start.
// Nil (default) leaves detection off.
func (e *NetworkPolicyEnforcer) SetFlowHook(fn func(flows []netbpf.FlowRecord)) { e.flowHook = fn }

// SetExecWatcher wires the exec-telemetry watcher (#2637): Start loads its
// object after this enforcer's, every reconcile hands it the container list,
// Stop stops it. Must be called before Start.
func (e *NetworkPolicyEnforcer) SetExecWatcher(w *ExecWatcher) { e.execWatcher = w }

// SetDenyHook wires the threat-detection engine's deny-event consumer
// (#1640). Called synchronously from OnDenyEvent, alongside the existing
// audit-log write. Must be called before Start. Nil (default) leaves
// detection off.
func (e *NetworkPolicyEnforcer) SetDenyHook(fn func(ev netbpf.DenyEvent)) { e.denyHook = fn }

// TenantForIP resolves a container IP to its owning tenant id via the
// ip_tenant cache this enforcer already maintains (refreshed every 10s
// reconcile — see reconcile/applyIPTenant). Exposed for
// threatdetect.RuleContext so rules can attribute a flow endpoint without
// talking to Incus or the DB themselves. ok is false for an IP this backend
// doesn't recognize.
func (e *NetworkPolicyEnforcer) TenantForIP(ip netip.Addr) (tenantID string, ok bool) {
	if !ip.Is4() {
		return "", false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	id, found := e.ipTenantInstalled[ip.As4()]
	if !found {
		return "", false
	}
	name, found := e.idName[id]
	if !found {
		return "", false
	}
	return name, true
}

// SetSignaturesEnabled opts into Tier 2 (#661) cleartext exploit-signature
// scanning on the inbound (container-receive) path: the curated built-in set is
// loaded into the BPF signature map and the per-packet scan is switched on. Must
// be called before Start. Off by default — scanning costs a per-packet bpf_loop,
// so it only runs when the operator opts in; drops still require enforce mode.
func (e *NetworkPolicyEnforcer) SetSignaturesEnabled(on bool) { e.sigEnabled = on }

// SetSignatureStore wires the operator-signature store (#661 PR-B) so the
// enforcer merges operator signatures with the built-ins. Must be called before
// Start. Nil leaves built-ins only.
func (e *NetworkPolicyEnforcer) SetSignatureStore(s NetworkPolicySignatureStore) { e.sigStore = s }

// armSignatures arms the scan gate (sig_config) and loads the initial signature
// set. Called once at Start. No-op unless opted in; logs (not fatal) when the
// loaded object predates Tier 2.
func (e *NetworkPolicyEnforcer) armSignatures() {
	if !e.sigEnabled || e.loader == nil {
		return
	}
	if !e.loader.HasSignatures() {
		log.Printf("[netpolicy] Tier 2 signatures enabled but the loaded BPF object lacks the 'signatures' map (rebuild netpolicy.bpf.o to enable #661)")
		return
	}
	n := e.refreshSignatureSlots()
	if err := e.loader.SetScanEnabled(true); err != nil {
		log.Printf("[netpolicy] enable signature scan: %v", err)
		return
	}
	log.Printf("[netpolicy] Tier 2 cleartext signature scanning ENABLED (%d signatures: built-in + operator, inbound)", n)
}

// effectiveSignatures merges the curated built-ins with the operator set (#661
// PR-B), built-ins first, capped to the BPF slot budget. A disabled operator
// signature is skipped. Returns the slice + a fingerprint so refresh can skip a
// redundant map rewrite when nothing changed.
func (e *NetworkPolicyEnforcer) effectiveSignatures() ([]netpolicy.Signature, string) {
	sigs := netpolicy.BuiltinSignatures()
	if e.sigStore != nil {
		ops, err := e.sigStore.List(e.ctx)
		if err != nil {
			log.Printf("[netpolicy] list operator signatures: %v", err)
		} else {
			for _, op := range ops {
				if !op.GetEnabled() {
					continue
				}
				if len(sigs) >= netbpf.SigMaxCount {
					log.Printf("[netpolicy] signature slot budget (%d) full; operator signature %q not loaded", netbpf.SigMaxCount, op.GetName())
					break
				}
				sigs = append(sigs, netpolicy.Signature{
					ID:      safecast.U16FromUint(op.GetId()),
					Name:    op.GetName(),
					Pattern: []byte(op.GetPattern()),
				})
			}
		}
	}
	// Fingerprint = ids+names+patterns in order (cheap; the set is tiny).
	var fp strings.Builder
	for _, s := range sigs {
		fmt.Fprintf(&fp, "%d:%s:%x;", s.ID, s.Name, s.Pattern)
	}
	return sigs, fp.String()
}

// refreshSignatureSlots writes the effective signature set into the BPF map
// (filling unused slots so a removed signature is cleared) and updates the
// id->name audit map. A no-op when the set is unchanged since the last write.
// Returns the active signature count. Safe to call every reconcile.
func (e *NetworkPolicyEnforcer) refreshSignatureSlots() int {
	if !e.sigEnabled || e.loader == nil || !e.loader.HasSignatures() {
		return 0
	}
	sigs, fp := e.effectiveSignatures()
	e.mu.Lock()
	unchanged := fp == e.sigLoaded
	e.mu.Unlock()
	if unchanged {
		return len(sigs)
	}
	names := make(map[uint16]string, len(sigs))
	for slot := 0; slot < netbpf.SigMaxCount; slot++ {
		var entry netbpf.SignatureEntry
		if slot < len(sigs) {
			entry = toSigEntry(sigs[slot])
			names[sigs[slot].ID] = sigs[slot].Name
		}
		if err := e.loader.SetSignature(safecast.U32(slot), entry); err != nil {
			log.Printf("[netpolicy] set signature slot %d: %v", slot, err)
		}
	}
	e.mu.Lock()
	e.sigNames = names
	e.sigLoaded = fp
	e.mu.Unlock()
	return len(sigs)
}

// toSigEntry converts a curated Signature into the BPF map entry, truncating an
// over-long pattern to SigMaxLen (the built-ins all fit; this is belt-and-suspenders).
func toSigEntry(s netpolicy.Signature) netbpf.SignatureEntry {
	var e netbpf.SignatureEntry
	e.ID = s.ID
	e.Enabled = true
	n := len(s.Pattern)
	if n > netbpf.SigMaxLen {
		n = netbpf.SigMaxLen
	}
	e.Len = safecast.U8(n)
	copy(e.Pattern[:], s.Pattern[:n])
	return e
}

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
	if !loader.SupportsEgressMode() {
		log.Printf("[netpolicy] loaded BPF object predates egress_mode (#2974): a tenant's egress_mode is applied and reported as its mode; rebuild netpolicy.bpf.o to apply it")
	}
	if !loader.SupportsInboundReplies() {
		log.Printf("[netpolicy] WARNING: loaded BPF object predates inbound-reply handling (#2618): a box with an enforce policy cannot answer connections opened toward it, and no source validation runs; rebuild netpolicy.bpf.o (or use the embedded object) before arming enforce for a tenant whose boxes serve inbound traffic")
	}
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.mu.Lock()
	e.running = true
	e.mu.Unlock()

	// Exec telemetry (#2637): the second object. Resolved from the same
	// operator value; a failure (no BTF, verifier reject, object not built) is
	// the watcher's own `unavailable (<reason>)` status and nothing else —
	// the flow program above is already loaded and keeps running.
	if e.execWatcher != nil {
		if err := e.execWatcher.Start(e.ctx, e.objPath); err != nil {
			log.Printf("[netpolicy] exec telemetry unavailable: %v (flow rules unaffected; see `containarium security sentry status`)", err)
		} else {
			log.Printf("[netpolicy] exec telemetry started (tracepoint sched/sched_process_exec)")
		}
	}

	// Tier 2 (#661): load the built-in exploit signatures + arm the scan gate once
	// (the set is static; no per-reconcile churn). No-op unless opted in.
	e.armSignatures()

	// Resolve stored policies' egress_domains once before the first reconcile
	// so the initial allow-list already includes domain IPs. The default
	// allow-list's names (#2577) are left to the refresh loop: resolving ~15
	// names here would hold up daemon startup on a host with slow or no DNS,
	// and the default is log-only, so a few seconds of would-deny rows for
	// them cost nothing.
	e.refreshDomainsForStartup()

	e.runPass(reconcileTriggerInitial)

	// Domain refresh loop (Phase C): wake when the earliest name is due —
	// min(record TTL, 60s) per name (#2379) — and re-resolve the due ones. The
	// next reconcile folds the refreshed IPs into the egress map (and diffEgress
	// prunes IPs a domain no longer resolves to).
	e.wg.Add(1)
	go e.domainRefreshLoop()

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

	// Reconcile loop + bus trigger: the 10 s timer, plus a debounced kick on
	// container topology events (#3050).
	kick := containerTopologyKick(e.ctx, e.bus, e.eventDebounce)
	e.wg.Add(1)
	go e.reconcileLoop(kick)

	mode := "observation-only (log_only)"
	if e.enforceEnabled {
		mode = "ENFORCE ARMED — enforce-mode policies WILL DROP packets"
	}
	log.Printf("[netpolicy] enforcer started (obj=%s, interval=%s, %s)", e.objPath, e.interval, mode)
	return nil
}

// Stop cancels the loops and closes the loader (detaching every veth).
func (e *NetworkPolicyEnforcer) Stop() {
	e.mu.Lock()
	e.running = false
	// A later Start reports "not reconciled" until its own first pass.
	e.applied = nil
	e.appliedAt = time.Time{}
	e.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	if e.execWatcher != nil {
		e.execWatcher.Stop()
	}
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
	// #1640: hand every deny event to the threat-detection engine, same as
	// the audit write below — nil hook is the default (sentry disabled).
	e.mu.Lock()
	tenant := e.idName[ev.TenantID]
	e.mu.Unlock()
	dropped := e.denyEventDropped(ev)
	// The hook learns whether the packet was really dropped (#2612): the BPF
	// program emits the event for a log_only would-deny exactly as for a drop.
	if e.denyHook != nil {
		hookEv := ev
		hookEv.LogOnly = !dropped
		e.denyHook(hookEv)
	}
	// Always log the denied flow. The program emits the event whether or not it
	// drops, so the action depends on the verdict it applied: a DROP under
	// enforce, an observation under log_only. This line is the operator's signal.
	action := "log_only (not dropped)"
	if dropped {
		action = "DROPPED (enforce)"
	}
	var sigName string
	if ev.Reason == netbpf.DenyReasonSignature {
		e.mu.Lock()
		sigName = e.sigNames[ev.SigID]
		e.mu.Unlock()
		log.Printf("[netpolicy] signature: tenant=%q src=%s dst=%s dport=%d sig=%d(%s) %s",
			tenant, ev.Src(), ev.Dst(), ev.Dport, ev.SigID, sigName, action)
	} else {
		kind := "deny"
		switch ev.Reason {
		case netbpf.DenyReasonVirtualPatch:
			kind = "virtual-patch"
		case netbpf.DenyReasonSpoofedSource:
			kind = "spoofed-source" // the box sent from an address that is not its own (#2618)
		}
		log.Printf("[netpolicy] %s: tenant=%q src=%s dst=%s proto=%d dport=%d %s",
			kind, tenant, ev.Src(), ev.Dst(), ev.Proto, ev.Dport, action)
	}
	if e.audit == nil {
		return
	}
	if err := e.audit.Log(ctx, denyAuditEntry(ev, tenant, sigName, dropped)); err != nil {
		log.Printf("[netpolicy] audit deny event: %v", err)
	}
}

// denyEventDropped reports whether the program dropped the packet behind ev.
// The program reports the verdict it applied (#2970): with a separate
// egress_mode an allow-list miss follows egress_mode while every other check
// follows mode, so the tenant-wide mode can be wrong in either direction. The
// tenant-wide mode (e.enforced) is only the fallback for an event from an
// object that predates the verdict byte.
func (e *NetworkPolicyEnforcer) denyEventDropped(ev netbpf.DenyEvent) bool {
	e.mu.Lock()
	enforced := e.enforced[ev.TenantID]
	e.mu.Unlock()
	return ev.Dropped(enforced)
}

// denyAuditEntry builds the audit row for one deny event. Each deny reason gets
// its own audit action so an operator can tell a blocked vulnerable destination
// (#660), a blocked inbound exploit (#661) and a box sending from a forged
// address (#2618) apart from a routine allow-list miss; dropped is the verdict
// the program applied (see denyEventDropped).
func denyAuditEntry(ev netbpf.DenyEvent, tenant, sigName string, dropped bool) *audit.AuditEntry {
	vpatch := ev.Reason == netbpf.DenyReasonVirtualPatch
	signature := ev.Reason == netbpf.DenyReasonSignature
	spoofed := ev.Reason == netbpf.DenyReasonSpoofedSource
	detail := `{"src":"` + ev.Src().String() + `","dst":"` + ev.Dst().String() +
		`","proto":` + itoa(int(ev.Proto)) + `,"dport":` + itoa(int(ev.Dport)) +
		`,"dropped":` + boolStr(dropped) + `,"virtual_patch":` + boolStr(vpatch) +
		`,"spoofed_source":` + boolStr(spoofed) + `}`
	if signature {
		// A Tier 2 signature match (#661): record which signature, on the INBOUND
		// (container-receive) path, so the audit names the blocked exploit.
		detail = `{"src":"` + ev.Src().String() + `","dst":"` + ev.Dst().String() +
			`","dport":` + itoa(int(ev.Dport)) + `,"sig_id":` + itoa(int(ev.SigID)) +
			`,"sig_name":"` + sigName + `","dropped":` + boolStr(dropped) + `}`
	}
	var action string
	switch {
	case signature:
		action = "network_policy.signature_match"
	case vpatch:
		action = "network_policy.virtual_patch"
	case spoofed:
		// The src is the forged address; the tenant names the box that sent it.
		action = "network_policy.spoofed_source"
	case dropped:
		action = "network_policy.deny_dropped"
	default:
		action = "network_policy.deny_logged"
	}
	return &audit.AuditEntry{
		Username:     "_system",
		Action:       action,
		ResourceType: "network_policy",
		ResourceID:   tenant,
		Detail:       detail,
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

	// #1640: hand this poll's active batch to the threat-detection engine,
	// synchronously — worst-case detection latency is one poll interval
	// (15s), well inside the engine's 60s budget. Runs in observation mode
	// (no ENFORCE requirement); nil hook is the default (sentry disabled).
	if e.flowHook != nil {
		e.flowHook(active)
	}

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
	cutoff := safecast.U64FromI64(idleFor.Nanoseconds())
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
	return safecast.U64FromI64(ts.Sec)*1_000_000_000 + safecast.U64FromI64(ts.Nsec)
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
	// Exec telemetry (#2637): converge watched_cgroups with the same container
	// list this pass gathered (no extra Incus call). Before the policy fetch:
	// it needs only the container list, so a policy-store (Postgres) outage
	// must not freeze the watched set.
	e.reconcileExec()
	policies, err := e.planPolicies(ctx, views)
	if err != nil {
		return err
	}
	plan := planReconcile(views, policies, e.enforceEnabled)
	// An older object ignores the egress_mode byte (#2987): fold it into mode
	// before writing, so what is written and reported is what the kernel does.
	e.warnEgressModeIgnored(foldEgressModeForObject(&plan, e.loader.SupportsEgressMode()), idName)

	// Tier 2 (#661 PR-B): pick up operator signature add/remove/toggle. A no-op
	// when the set is unchanged, so this is cheap every pass.
	e.refreshSignatureSlots()

	// Uplinks (#2618 B5): the host interfaces whose unmarked frames may seed an
	// inbound flow. Converged every pass so a changed default route follows.
	e.applyTrustedUplinks()
	e.logInboundReseeds()
	// ip_tenant: every managed container's IP -> its tenant id. Converge the map
	// (set desired, delete stale) like egress/deny below — an add-only pass would
	// leak a tag once a container's IP is freed or an entity is excluded from
	// tagging (e.g. the control plane), letting the program keep treating a
	// since-freed or re-purposed IP as a same-tenant peer until a daemon restart
	// rebuilt the maps (#923).
	applyIPTenant(e.ipTenantInstalled, plan.ipTenant, e.loader)
	// egress allow-list: converge the map (add new, delete stale). Deleting
	// removed CIDRs is what makes a tightened policy actually take effect in
	// enforce mode.
	egressIncomplete, egressNames := e.applyEgressPass(plan, idName, e.loader)
	// Virtual-patch deny rules (#660): converge the deny_cidr map the same way —
	// upsert desired entries, delete keys no longer desired (a removed/expired
	// rule must actually stop blocking). Only when the loaded object carries the
	// map; an older object simply can't be virtual-patched until rebuilt.
	if e.loader.HasDenyRules() {
		applyDeny(e.denyInstalled, plan.deny, e.loader)
	} else if len(plan.deny) > 0 {
		log.Printf("[netpolicy] %d virtual-patch deny rule(s) configured but loaded BPF object lacks the 'deny_cidr' map (rebuild netpolicy.bpf.o to enable #660)", len(plan.deny))
	}
	// Per-veth config + attach. Track which tenants end up in effective-enforce
	// mode. OnDenyEvent labels a denied flow from the verdict the program
	// reports (#2970); this map is only its fallback for an event from an
	// object that predates that verdict byte.
	enforced := make(map[uint32]bool)
	e.mu.Lock()
	present := make(map[int]bool, len(plan.vethPolicy))
	loaded := make(map[int]bool, len(plan.vethPolicy)) // config written AND program attached
	for ifindex, cfg := range plan.vethPolicy {
		validateOnly := cfg.Flags&netbpf.PolicyFlagValidateOnly != 0
		if cfg.Mode == netbpf.ModeEnforce && !validateOnly {
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
		// Reply-direction accounting (#631) and inbound-flow tracking (#2618):
		// attach the egress program too. No-ops on an object that predates it.
		// Non-fatal — ingress accounting + policy still work without it. A
		// validate-only veth is not policed, so it gets the sender hook alone.
		if !validateOnly {
			if err := e.loader.AttachVethEgress(ifindex); err != nil {
				log.Printf("[netpolicy] attach egress ifindex %d: %v", ifindex, err)
			}
		}
		e.attached[ifindex] = plan.ifName[ifindex]
		present[ifindex] = true
		loaded[ifindex] = true
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
	// What GetNetworkPolicyStatus reports: built from the plan this pass
	// actually wrote, never from the stored request.
	e.recordApplied(appliedFromPass(views, plan, loaded, policies, egressIncomplete, egressNames), time.Now())
	return nil
}

// applyEgressPass converges the egress allow-list map with the plan via a. It
// returns the tenant ids whose allow-list is incomplete after this pass and a
// name for each of them (#3051).
func (e *NetworkPolicyEnforcer) applyEgressPass(plan reconcilePlan, idName map[uint32]string, a egressApplier) (map[uint32]bool, map[uint32]string) {
	toAdd, toDel := diffEgress(e.egressInstalled, plan.egress)
	incomplete := applyEgress(e.egressInstalled, toAdd, toDel, a)
	// idName holds only tenants with a box this pass. A failed removal can belong
	// to a tenant with no box left, so remember the name of every tenant that
	// still has entries installed, and forget it once they are all gone.
	for id, name := range idName {
		e.egressNames[id] = name
	}
	held := make(map[uint32]bool, len(e.egressNames))
	for ee := range e.egressInstalled {
		held[ee.TenantID] = true
	}
	for id := range e.egressNames {
		if _, seen := idName[id]; !seen && !held[id] && !incomplete[id] {
			delete(e.egressNames, id)
		}
	}
	return incomplete, e.egressNames
}

// recordApplied stores one reconcile pass's per-tenant applied state.
func (e *NetworkPolicyEnforcer) recordApplied(a map[string]tenantApplied, at time.Time) {
	if a == nil {
		a = map[string]tenantApplied{}
	}
	e.mu.Lock()
	e.applied = a
	e.appliedAt = at
	e.mu.Unlock()
}

// AppliedState implements appliedStateSource: what the last completed
// reconcile pass loaded for tenant. Before Start (or after Stop) it reports not
// running; before the first completed pass it reports not reconciled, so the
// caller says unknown rather than guessing.
func (e *NetworkPolicyEnforcer) AppliedState(tenant string) appliedSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	snap := appliedSnapshot{Running: e.running, Reconciled: e.applied != nil, ReconciledAt: e.appliedAt, Interval: e.interval}
	if !snap.Running {
		return appliedSnapshot{}
	}
	snap.Tenant, snap.Found = e.applied[tenant]
	return snap
}

// boolStr renders a bool as a JSON literal for the audit detail.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// reconcileExec converges the exec watcher with the latest gathered
// container list; a no-op without a watcher.
func (e *NetworkPolicyEnforcer) reconcileExec() {
	if e.execWatcher != nil {
		e.execWatcher.Reconcile(e.lastContainers)
	}
}

// gather snapshots the running containers into reconcile views, resolving each
// one's host veth ifindex (Linux). It also returns the id->name map for the
// audit sink.
func (e *NetworkPolicyEnforcer) gather(_ context.Context) ([]containerView, map[uint32]string, error) {
	containers, err := e.insp.ListContainers()
	if err != nil {
		return nil, nil, err
	}
	e.lastContainers = containers
	views := make([]containerView, 0, len(containers))
	idName := make(map[uint32]string)
	running := make(map[string]bool, len(containers))
	leases := newLeaseReader(e.leaseDir, time.Now())
	for _, c := range containers {
		v := containerView{Name: c.Name}
		// The control plane is platform infrastructure, not a tenant (#780).
		// Keeping it out of tenant tagging means (1) its IP never enters
		// ip_tenant, so a tenant reaching its auth-gated API hits the
		// external/egress branch instead of the cross-tenant drop (reachable
		// under the default egress); and (2) its own veth is never policed, so
		// it can actuate every box. Other core services (postgres, caddy, …) are
		// deliberately NOT excluded here — they stay tenant-tagged and thus
		// isolated from tenants. Since #2618 it (and any instance with no
		// tenant) still gets a VALIDATE-ONLY veth entry: its frames are stamped
		// with the source-validation mark and nothing else, so that a frame
		// without the mark can only be the host's own or routed in from outside.
		tenant := resolveTenant(c.Tenant, c.Labels[cloudOrgIDLabel], c.Name)
		// The guest-reported address: ip_tenant tagging for tenants, and the
		// cross-check a DHCP lease must agree with before it is trusted (S4).
		if ip, err := netip.ParseAddr(c.IPAddress); err == nil && ip.Is4() {
			v.IP = ip.As4()
			v.HasIP = true
		}
		if c.Role == incus.RoleControlPlane || tenant == "" {
			v.ValidateOnly = true
		} else {
			tid, err := e.registry.ID(e.ctx, tenant)
			if err != nil {
				log.Printf("[netpolicy] tenant id for %q: %v", tenant, err)
				continue
			}
			idName[tid] = tenant
			v.Tenant, v.TenantID = tenant, tid
		}
		if strings.EqualFold(c.State, "running") {
			v.Running = true
			running[c.Name] = true
			if ifindex, nic, ok := e.resolveVeth(c.Name); ok {
				v.Ifindex = ifindex
				v.HasVeth = true
				// The address the program validates the box against comes from
				// the host (device config or DHCP lease), never from c.IPAddress,
				// which the guest reports about itself (#2618).
				v.HostIP, v.HasHostIP = hostIPv4For(nic, leases, v.IP, v.HasIP)
				if !v.HasHostIP {
					if !e.addrWarned[c.Name] {
						e.addrWarned[c.Name] = true
						log.Printf("[netpolicy] no host-known address for %q (no static ipv4.address, and no DHCP lease agreeing with the guest's %s): it cannot answer inbound connections under enforce and its frames never seed a flow", c.Name, c.IPAddress)
					}
				} else {
					delete(e.addrWarned, c.Name)
				}
			}
		}
		views = append(views, v)
	}
	for name := range e.addrWarned {
		if !running[name] {
			delete(e.addrWarned, name)
		}
	}
	// Evict cache entries for containers that are gone or no longer running, so the
	// map stays bounded and a container that restarts re-inspects for its new veth.
	for name := range e.vethCache {
		if !running[name] {
			delete(e.vethCache, name)
		}
	}
	return views, idName, nil
}

// resolveVeth maps a running container to its host veth ifindex (#654). It caches
// the container's veth *name* so the steady-state path is a cheap local netlink
// lookup (VethIndex) rather than an Incus inspect (GetRawInstance) every cycle.
// The expensive inspect runs only on a cache miss or when the cached veth has
// disappeared from the host — which is exactly when a container has just started
// or restarted (a restart yields a new veth, so the stale lookup fails and we
// re-inspect, self-healing without depending on perfect bus-event delivery).
//
// The same inspect also reads the primary NIC's host-side facts (#2618): the
// network it is on, its hardware address and any static ipv4.address, cached
// alongside the veth name since they change only across a restart too.
func (e *NetworkPolicyEnforcer) resolveVeth(name string) (int, hostNIC, bool) {
	if info := e.vethCache[name]; info.veth != "" {
		if ifindex, err := netbpf.VethIndex(info.veth); err == nil {
			return ifindex, info.nic, true
		}
		delete(e.vethCache, name) // veth gone (restart) — fall through to re-inspect
	}
	cfg, _, err := e.insp.GetRawInstance(name)
	if err != nil {
		return 0, hostNIC{}, false
	}
	veth := netbpf.HostVethFromConfig(cfg)
	if veth == "" {
		return 0, hostNIC{}, false
	}
	ifindex, err := netbpf.VethIndex(veth)
	if err != nil {
		return 0, hostNIC{}, false
	}
	// Device facts are best-effort: without them the box has no host-known
	// address, which the program treats as "cannot validate" (fail closed).
	var nic hostNIC
	if devices, err := e.insp.GetRawInstanceDevices(name); err == nil {
		nic = hostNICFor(cfg, devices)
	} else {
		log.Printf("[netpolicy] devices for %q: %v (box address unknown; it cannot answer inbound under enforce)", name, err)
	}
	e.vethCache[name] = vethInfo{veth: veth, nic: nic}
	return ifindex, nic, true
}

// vethInfo is one vethCache entry: the host veth name and the primary NIC's
// host-side facts, both fixed for a container's lifetime until it restarts.
type vethInfo struct {
	veth string
	nic  hostNIC
}

// planPolicies is the policy set a reconcile pass plans from: every stored
// policy, plus the default posture (#2577) for each tenant seen in views that
// has none. A store error fails the pass before any default is applied. A
// stored policy that no longer compiles is skipped by compiledPolicies, so its
// tenant runs the default like a tenant with none (both are log-only).
func (e *NetworkPolicyEnforcer) planPolicies(ctx context.Context, views []containerView) (map[string]netpolicy.CompiledPolicy, error) {
	policies, err := e.compiledPolicies(ctx)
	if err != nil {
		return nil, err
	}
	for _, view := range views {
		if _, exists := policies[view.Tenant]; exists {
			continue
		}
		legacy, account := incus.LegacyAccountPolicyKey(view.Tenant)
		if !account {
			continue
		}
		if inherited, exists := policies[legacy]; exists {
			inherited.Tenant = view.Tenant
			inherited.AllowFromTenants = nil
			policies[view.Tenant] = inherited
		}
	}
	if e.defaultOn {
		policies = withDefaultPolicies(policies, views, e.defaultPolicyFor)
	}
	return policies, nil
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
		c = e.expandPolicy(c, true)
		// Virtual-patch deny rules (#660): drop any whose expiry has passed so an
		// expired patch self-removes from the kernel on the next reconcile. Done
		// here (not in the pure netpolicy/plan layer) so those stay time-free.
		c.DenyRules = activeDenyRules(c.DenyRules, time.Now())
		out[c.Tenant] = c
	}
	// An ingress-only account row created by PatchTenantAccess must not turn
	// a legacy ENFORCE egress policy into the default log-only policy.
	for _, p := range stored {
		legacy, account := incus.LegacyAccountPolicyKey(p.GetTenant())
		if !account {
			continue
		}
		remainder := proto.Clone(p).(*pb.NetworkPolicy)
		remainder.Tenant, remainder.AllowFromTenants = "", nil
		if !proto.Equal(remainder, &pb.NetworkPolicy{}) {
			continue
		}
		if inherited, exists := out[legacy]; exists {
			inherited.Tenant = p.Tenant
			inherited.AllowFromTenants = nil
			out[p.Tenant] = inherited
		}
	}
	return out, nil
}

// expandPolicy folds what only the running daemon knows into a compiled
// policy: the currently-resolved addresses of its egress_domains and what an
// egress preset allows implicitly. warn reports a preset the unknown gateway
// cannot honour; the default posture passes false because that is a
// host-level condition logged once at startup, not once per tenant per pass.
func (e *NetworkPolicyEnforcer) expandPolicy(c netpolicy.CompiledPolicy, warn bool) netpolicy.CompiledPolicy {
	// Phase C: fold each egress_domain's currently-resolved IPs into the
	// allow-list as /32 CIDRs. planReconcile/CompileEgress then treat them as
	// ordinary egress entries; diffEgress prunes IPs a domain stopped
	// resolving to on the next pass.
	for _, dom := range c.EgressDomains {
		for _, ip := range e.resolver.IPs(dom) {
			c.EgressCIDRs = append(c.EgressCIDRs, netip.PrefixFrom(ip, 32))
		}
	}
	// Egress preset (#2440): fold in what the preset allows implicitly (the
	// box's DNS resolver). Not stored on the policy, so `get` still shows
	// what the operator wrote.
	if imp := netpolicy.ImplicitEgress(c, e.gateway); len(imp) > 0 {
		c.EgressCIDRs = append(c.EgressCIDRs, imp...)
	} else if warn && c.EgressPreset != pb.EgressPreset_EGRESS_PRESET_UNSPECIFIED {
		log.Printf("[netpolicy] tenant %q has an egress preset but the bridge gateway is unknown; the resolver is NOT implicitly allowed", c.Tenant)
	}
	return c
}

// domainRefreshLoop (Phase C, #2379) wakes when the earliest cached name is due
// and re-resolves; it runs until e.ctx is cancelled. The caller does wg.Add(1).
func (e *NetworkPolicyEnforcer) domainRefreshLoop() {
	defer e.wg.Done()
	// Start left the default allow-list's names unresolved (see Start); do it
	// now, off the startup path, rather than after the first timer wait. The
	// next reconcile folds the addresses into the egress map.
	if e.defaultOn {
		e.refreshDomains(true)
	}
	t := time.NewTimer(e.resolver.NextRefreshDelay())
	defer t.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-t.C:
			e.refreshDomains(true)
			t.Reset(e.resolver.NextRefreshDelay())
		}
	}
}

// refreshDomainsForStartup is the synchronous pre-reconcile refresh Start runs:
// stored policies' domains only, never the default allow-list's names (#2997).
// It is a named method so a test can pin that contract without a loaded BPF
// object, which Start itself needs.
func (e *NetworkPolicyEnforcer) refreshDomainsForStartup() {
	e.refreshDomains(false)
}

// refreshDomains re-resolves every egress_domain across all stored policies into
// the resolver cache. Best-effort: store/lookup errors are logged, not fatal.
//
// includeDefault adds the default allow-list's names (#2577) when that posture
// is on. refreshDomainsForStartup passes false so they are not resolved on the
// startup path.
func (e *NetworkPolicyEnforcer) refreshDomains(includeDefault bool) {
	stored, err := e.store.List(e.ctx)
	if err != nil {
		log.Printf("[netpolicy] domain refresh: list policies: %v", err)
		// Keep the cached addresses and retry on each name's interval, so a
		// store outage is not polled at the 1s floor.
		e.resolver.Postpone()
		return
	}
	var domains []string
	for _, p := range stored {
		domains = append(domains, p.GetEgressDomains()...)
	}
	if includeDefault && e.defaultOn {
		// The default allow-list's names are resolved too (#2577).
		domains = append(domains, e.defaultDomains...)
	}
	// No early return on an empty list: Refresh with no domains prunes the
	// cache, so a removed last domain cannot leave a stale past-due entry that
	// would floor NextRefreshDelay and wake this loop every second.
	cctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	e.resolver.Refresh(cctx, domains)
}

// cloudOrgIDLabel is the generic attribution label (incus.LabelPrefix +
// this key) the cloud control plane stamps on every container it creates via
// the OSS-primary driver (push-mode actuation, prd/cloud/oss-primary-driver.md)
// — cloud_org_id / cloud_container_id / managed_by. Distinct from
// incus.TenantLabelKey (user.containarium.tenant), which only the pull-based
// cloud-actuation client (cloudContainerActuator, #354) stamps. Both label a
// container with the same data (its owning org UUID); resolveTenant checks
// both so the network-policy enforcer works under either actuation mode.
const cloudOrgIDLabel = "cloud_org_id"

// resolveTenant determines a container's owning tenant. An explicit tenant
// label (user.containarium.tenant) wins — it decouples tenant identity from the
// container name, which is what lets cloud-assigned containers (named
// cld-<uuid>, not <tenant>-container) be policed too (#315 "Cloud extension").
// Falls back to the cloud_org_id attribution label (see cloudOrgIDLabel), then
// the <tenant>-container naming convention; "" if none yield a tenant (the
// container is then left unmanaged).
func resolveTenant(tenantLabel, cloudOrgID, containerName string) string {
	return incus.ResolveTenant(tenantLabel, cloudOrgID, containerName)
}

// tenantOf extracts the tenant name from a container name, or "" if it doesn't
// follow the <tenant>-container convention.
func tenantOf(containerName string) string {
	if !strings.HasSuffix(containerName, containerSuffix) {
		return ""
	}
	return strings.TrimSuffix(containerName, containerSuffix)
}

// warnEgressModeIgnored logs, once per tenant, that the loaded BPF object cannot
// apply the tenant's separate egress mode and enforces `mode` instead (#2987).
// ignored is this pass's set from foldEgressModeForObject; a tenant that drops
// out of it is forgotten, so a later split is warned about again. Only called
// from reconcile, which runs on one goroutine.
func (e *NetworkPolicyEnforcer) warnEgressModeIgnored(ignored map[uint32]bool, idName map[uint32]string) {
	for id := range e.egressModeWarned {
		if !ignored[id] {
			delete(e.egressModeWarned, id)
		}
	}
	for id := range ignored {
		if e.egressModeWarned[id] {
			continue
		}
		if e.egressModeWarned == nil {
			e.egressModeWarned = make(map[uint32]bool)
		}
		e.egressModeWarned[id] = true
		log.Printf("[netpolicy] WARNING: tenant %q sets egress_mode different from mode, but the loaded BPF object predates egress_mode (#2974) and applies mode to the egress allow-list; enforcing and reporting mode. Rebuild netpolicy.bpf.o (or use the embedded object) to apply egress_mode", idName[id])
	}
}

// SetIncusDataDir points the DHCP-lease lookup (#2618) at the Incus data dir the
// daemon actually talks to (the directory holding its unix socket), instead of
// the compiled-in default.
func (e *NetworkPolicyEnforcer) SetIncusDataDir(dir string) {
	if dir != "" {
		e.leaseDir = leaseDirFor(dir)
	}
}

// applyTrustedUplinks converges the kernel trusted_iif map with the host's
// current uplinks: the default-route interfaces plus any the operator named in
// CONTAINARIUM_NETWORK_POLICY_UPLINKS. A failed op is logged and skipped without
// touching the installed set, so the next pass retries it.
func (e *NetworkPolicyEnforcer) applyTrustedUplinks() {
	desired := uplinkIfindexes(e.extraUplinks)
	for idx := range desired {
		if e.trustedInstalled[idx] {
			continue
		}
		if err := e.loader.SetTrustedIface(idx); err != nil {
			log.Printf("[netpolicy] set trusted_iif: %v", err)
			continue
		}
		e.trustedInstalled[idx] = true
	}
	for idx := range e.trustedInstalled {
		if desired[idx] {
			continue
		}
		if err := e.loader.DeleteTrustedIface(idx); err != nil {
			log.Printf("[netpolicy] delete trusted_iif: %v", err)
			continue
		}
		delete(e.trustedInstalled, idx)
	}
}

// logInboundReseeds logs the growth of the inbound_reseed counter since the last
// pass (#2618 S5): TCP inbound entries re-created mid-stream, the sign that the
// shared inbound_flows LRU evicted live flows (or they idled out).
func (e *NetworkPolicyEnforcer) logInboundReseeds() {
	n, err := e.loader.InboundReseeds()
	if err != nil {
		log.Printf("[netpolicy] read inbound_reseed: %v", err)
		return
	}
	if n > e.reseedLast {
		log.Printf("[netpolicy] inbound flows re-seeded mid-stream: +%d this pass (total %d) — LRU pressure or idle expiry on connections into enforced boxes", n-e.reseedLast, n)
	}
	e.reseedLast = n
}

// splitCSV splits a comma-separated list, trimming blanks.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
