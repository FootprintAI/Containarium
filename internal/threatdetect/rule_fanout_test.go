package threatdetect

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const fanoutBoxIP = "10.0.3.2"

// fanoutFlows returns n flows from src to distinct public addresses on port.
func fanoutFlows(src string, n int, port uint16, proto uint8) []netbpf.FlowRecord {
	out := make([]netbpf.FlowRecord, 0, n)
	for i := 0; i < n; i++ {
		f := flow(src, fmt.Sprintf("93.184.%d.%d", i/250, 1+i%250))
		f.Dport = port
		f.Proto = proto
		out = append(out, f)
	}
	return out
}

type fanoutHarness struct {
	t   *testing.T
	r   *OutboundFanoutRule
	now time.Time
}

func newFanoutHarness(t *testing.T, th OutboundFanoutThresholds) *fanoutHarness {
	return &fanoutHarness{t: t, r: NewOutboundFanoutRule(th), now: time.Unix(1_700_000_000, 0)}
}

func (h *fanoutHarness) ctx(tenants map[string]string) RuleContext {
	return RuleContext{TenantForIP: fakeTenants(tenants), Now: func() time.Time { return h.now }}
}

func (h *fanoutHarness) feed(flows []netbpf.FlowRecord) {
	h.r.OnFlows(h.ctx(map[string]string{fanoutBoxIP: "alice"}), flows)
}

func (h *fanoutHarness) sweep() []RawFinding { return h.r.Sweep(h.ctx(nil), h.now) }

func TestOutboundFanoutRule_ID(t *testing.T) {
	if got := NewOutboundFanoutRule(OutboundFanoutThresholds{}).ID(); got != pb.ThreatRuleId_THREAT_RULE_ID_OUTBOUND_FANOUT {
		t.Fatalf("ID = %v", got)
	}
}

// The shape of the observed incident: one container, many distinct public
// addresses on port 3128.
func TestOutboundFanoutRule_ProxyFanoutFires(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	h.feed(fanoutFlows(fanoutBoxIP, 20, 3128, 6))
	got := h.sweep()
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Subject != "proxy-fanout" || f.TenantID != "alice" || f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM {
		t.Fatalf("finding = %+v", f)
	}
	if len(f.Evidence.Flows) != EvidenceCap || f.Evidence.Flows[0].SrcIP != fanoutBoxIP || f.Evidence.Flows[0].DstPort != 3128 {
		t.Fatalf("evidence = %+v", f.Evidence.Flows)
	}
}

func TestOutboundFanoutRule_BelowThresholdQuiet(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	h.feed(fanoutFlows(fanoutBoxIP, 14, 3128, 6)) // default is 15
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

// Many addresses on 443 is what a CDN-backed download looks like: never counts.
func TestOutboundFanoutRule_WebDNSNTPIgnored(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	for _, p := range []struct {
		port  uint16
		proto uint8
	}{{443, 6}, {80, 6}, {53, 17}, {123, 17}} {
		h.feed(fanoutFlows(fanoutBoxIP, 500, p.port, p.proto))
	}
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
	if n := h.r.trackedSources(); n != 0 {
		t.Fatalf("tracked sources = %d, want 0 (nothing qualified)", n)
	}
}

func TestOutboundFanoutRule_InternalDestinationsIgnored(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	var flows []netbpf.FlowRecord
	for i := 0; i < 50; i++ {
		for _, base := range []string{"10.1.%d.9", "192.168.%d.9", "172.16.%d.9", "127.0.%d.9", "169.254.%d.9", "224.0.%d.9"} {
			f := flow(fanoutBoxIP, fmt.Sprintf(base, i))
			f.Dport = 3128
			flows = append(flows, f)
		}
	}
	h.feed(flows)
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

func TestOutboundFanoutRule_ICMPIgnored(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	h.feed(fanoutFlows(fanoutBoxIP, 300, 0, 1))
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

func TestOutboundFanoutRule_WideFanoutFires(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	h.feed(fanoutFlows(fanoutBoxIP, 250, 22, 6))
	got := h.sweep()
	if len(got) != 1 || got[0].Subject != "wide-fanout" {
		t.Fatalf("findings = %+v, want one wide-fanout", got)
	}
	if len(got[0].Evidence.Flows) != EvidenceCap {
		t.Fatalf("evidence = %d flows, want capped at %d", len(got[0].Evidence.Flows), EvidenceCap)
	}
}

// A proxy-port flow counts toward proxy-fanout only, so one burst never
// raises both findings.
func TestOutboundFanoutRule_ProxyPortsDoNotCountAsWide(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{ProxyDistinct: 1000})
	h.feed(fanoutFlows(fanoutBoxIP, 300, 3128, 6))
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

func TestOutboundFanoutRule_UnknownSourceIgnored(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	h.r.OnFlows(h.ctx(nil), fanoutFlows("10.0.3.99", 40, 3128, 6))
	if n := h.r.trackedSources(); n != 0 {
		t.Fatalf("tracked sources = %d, want 0 for an unattributable IP", n)
	}
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

// Addresses age out of the window: a burst that stops is forgotten and the
// source is dropped, so state stays bounded and a quiet box emits nothing.
func TestOutboundFanoutRule_WindowExpiry(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{Window: 5 * time.Minute})
	h.feed(fanoutFlows(fanoutBoxIP, 20, 3128, 6))
	if got := h.sweep(); len(got) != 1 {
		t.Fatalf("findings = %d, want 1 while inside the window", len(got))
	}
	h.now = h.now.Add(6 * time.Minute)
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none after the window", got)
	}
	if n := h.r.trackedSources(); n != 0 {
		t.Fatalf("tracked sources = %d, want 0 after expiry", n)
	}
}

// The window is a sliding one: addresses seen across several polls add up.
func TestOutboundFanoutRule_AccumulatesAcrossPolls(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	all := fanoutFlows(fanoutBoxIP, 20, 3128, 6)
	h.feed(all[:8])
	h.now = h.now.Add(time.Minute)
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none at 8 addresses", got)
	}
	h.feed(all[8:])
	h.now = h.now.Add(time.Minute)
	if got := h.sweep(); len(got) != 1 {
		t.Fatalf("findings = %d, want 1 once 20 addresses fall in the window", len(got))
	}
}

// Re-seeing one address refreshes it rather than counting twice.
func TestOutboundFanoutRule_DistinctAddressesOnly(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	one := fanoutFlows(fanoutBoxIP, 1, 3128, 6)
	for i := 0; i < 100; i++ {
		h.feed(one)
	}
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none for one repeated address", got)
	}
}

func TestOutboundFanoutRule_PerSourceBound(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{ProxyDistinct: 1 << 30})
	h.feed(fanoutFlows(fanoutBoxIP, fanoutMaxAddrsPerSource+500, 3128, 6))
	h.r.mu.Lock()
	n := len(h.r.sources[netip.MustParseAddr(fanoutBoxIP)].proxy)
	h.r.mu.Unlock()
	if n != fanoutMaxAddrsPerSource {
		t.Fatalf("tracked addresses = %d, want capped at %d", n, fanoutMaxAddrsPerSource)
	}
}

func TestOutboundFanoutThresholds_Defaults(t *testing.T) {
	got := OutboundFanoutThresholds{ProxyDistinct: 3}.withDefaults()
	d := DefaultOutboundFanoutThresholds()
	if got.ProxyDistinct != 3 || got.Window != d.Window || got.WideDistinct != d.WideDistinct {
		t.Fatalf("withDefaults = %+v", got)
	}
}

// A box that serves public clients: every reply targets the client's
// ephemeral port. 300 distinct clients must not read as a scanner.
func TestOutboundFanoutRule_ServerRepliesToClientsIgnored(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	h.feed(fanoutFlows(fanoutBoxIP, 300, 51000, 6))
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none for replies to client ephemeral ports", got)
	}
	if n := h.r.trackedSources(); n != 0 {
		t.Fatalf("tracked sources = %d, want 0", n)
	}
}

func TestOutboundFanoutRule_ReservedRangesIgnored(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	var flows []netbpf.FlowRecord
	for i := 0; i < 50; i++ {
		for _, base := range []string{"100.64.%d.9", "100.127.%d.9", "198.18.%d.9", "198.19.%d.9", "240.0.%d.9", "192.0.2.%d", "198.51.100.%d", "203.0.113.%d", "0.1.%d.9"} {
			f := flow(fanoutBoxIP, fmt.Sprintf(base, i))
			f.Dport = 3128
			flows = append(flows, f)
		}
	}
	h.feed(flows)
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none for reserved ranges", got)
	}
}

// The thresholds are inclusive: one below is quiet, exactly at it fires.
func TestOutboundFanoutRule_ThresholdIsInclusive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		port  uint16
		below int
		at    int
	}{{"proxy", 3128, 14, 15}, {"wide", 22, 199, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFanoutHarness(t, OutboundFanoutThresholds{})
			h.feed(fanoutFlows(fanoutBoxIP, tc.below, tc.port, 6))
			if got := h.sweep(); len(got) != 0 {
				t.Fatalf("%d addresses: findings = %+v, want none", tc.below, got)
			}
			h2 := newFanoutHarness(t, OutboundFanoutThresholds{})
			h2.feed(fanoutFlows(fanoutBoxIP, tc.at, tc.port, 6))
			if got := h2.sweep(); len(got) != 1 {
				t.Fatalf("%d addresses: findings = %d, want 1", tc.at, len(got))
			}
		})
	}
}

func TestOutboundFanoutRule_UDPCounts(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	h.feed(fanoutFlows(fanoutBoxIP, 20, 3128, 17))
	if got := h.sweep(); len(got) != 1 {
		t.Fatalf("findings = %d, want 1 for UDP", len(got))
	}
}

// A burst that has ended is reported once, not on every sweep while its
// addresses linger in the window.
func TestOutboundFanoutRule_FinishedBurstDoesNotRefire(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	h.feed(fanoutFlows(fanoutBoxIP, 20, 3128, 6))
	if got := h.sweep(); len(got) != 1 {
		t.Fatalf("first sweep findings = %d, want 1", len(got))
	}
	h.now = h.now.Add(30 * time.Second)
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("second sweep findings = %+v, want none: nothing new arrived", got)
	}
	// Fresh activity (flows advanced) fires again.
	more := fanoutFlows(fanoutBoxIP, 20, 3128, 6)
	for i := range more {
		more[i].LastNs = 5
	}
	h.feed(more)
	if got := h.sweep(); len(got) != 1 {
		t.Fatalf("after fresh flows findings = %d, want 1", len(got))
	}
}

// Re-reporting an unchanged flow must not extend the window: pollFlows
// repeats idle flows for two minutes, and counting those would stretch the
// window by that long.
func TestOutboundFanoutRule_UnchangedFlowDoesNotRefreshWindow(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{Window: 5 * time.Minute})
	flows := fanoutFlows(fanoutBoxIP, 20, 3128, 6)
	for i := range flows {
		flows[i].LastNs = 1000
	}
	h.feed(flows)
	for i := 0; i < 4; i++ { // re-reported by later polls, same last packet
		h.now = h.now.Add(time.Minute)
		h.feed(flows)
	}
	h.now = h.now.Add(90 * time.Second) // 5.5 minutes after the real last packet
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none: the last real packet is older than the window", got)
	}
}

func TestOutboundFanoutRule_TwoSourcesTwoTenants(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	tenants := map[string]string{"10.0.3.2": "alice", "10.0.3.3": "bob"}
	h.r.OnFlows(h.ctx(tenants), append(fanoutFlows("10.0.3.2", 20, 3128, 6), fanoutFlows("10.0.3.3", 20, 3128, 6)...))
	got := h.sweep()
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (one per source)", len(got))
	}
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.TenantID] = true
		for _, e := range f.Evidence.Flows {
			if (f.TenantID == "alice") != (e.SrcIP == "10.0.3.2") {
				t.Fatalf("evidence from the wrong source in %s's finding: %+v", f.TenantID, e)
			}
		}
	}
	if !seen["alice"] || !seen["bob"] {
		t.Fatalf("tenants = %v", seen)
	}
}

// An address reassigned to another tenant's box starts from zero.
func TestOutboundFanoutRule_TenantChangeResetsHistory(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	flows := fanoutFlows(fanoutBoxIP, 20, 3128, 6)
	h.r.OnFlows(h.ctx(map[string]string{fanoutBoxIP: "alice"}), flows[:10])
	h.r.OnFlows(h.ctx(map[string]string{fanoutBoxIP: "bob"}), flows[10:])
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none: 10 addresses each side of a reassignment", got)
	}
}

func TestOutboundFanoutRule_SourceCap(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	tenants := map[string]string{}
	var flows []netbpf.FlowRecord
	for i := 0; i < fanoutMaxSources+50; i++ {
		ip := fmt.Sprintf("10.%d.%d.2", 1+i/250, i%250)
		tenants[ip] = "t"
		f := flow(ip, "93.184.0.1")
		f.Dport = 22
		flows = append(flows, f)
	}
	h.r.OnFlows(h.ctx(tenants), flows)
	if n := h.r.trackedSources(); n != fanoutMaxSources {
		t.Fatalf("tracked sources = %d, want capped at %d", n, fanoutMaxSources)
	}
}

func TestOutboundFanoutThresholds_ClampedToCap(t *testing.T) {
	got := OutboundFanoutThresholds{ProxyDistinct: 1 << 20, WideDistinct: 1 << 20}.withDefaults()
	if got.ProxyDistinct != fanoutMaxAddrsPerSource || got.WideDistinct != fanoutMaxAddrsPerSource {
		t.Fatalf("withDefaults = %+v, want clamped to %d", got, fanoutMaxAddrsPerSource)
	}
}

// Evidence names how many distinct addresses qualified and favours the
// newest, so a stored sample is neither the same lowest addresses forever
// nor silent about the scale.
func TestOutboundFanoutRule_EvidenceNewestFirstWithCount(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	old := fanoutFlows(fanoutBoxIP, 20, 3128, 6)
	h.feed(old)
	h.now = h.now.Add(time.Minute)
	fresh := flow(fanoutBoxIP, "93.184.200.200")
	fresh.Dport = 3128
	h.feed([]netbpf.FlowRecord{fresh})
	got := h.sweep()
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	ev := got[0].Evidence.Flows
	if ev[0].DstIP != "93.184.200.200" {
		t.Fatalf("first evidence flow = %s, want the newest address", ev[0].DstIP)
	}
	if ev[0].Matched != "proxy-fanout: 21 distinct addresses in window" {
		t.Fatalf("matched = %q", ev[0].Matched)
	}
}

func (h *fanoutHarness) feedBoxes(tenants, boxes map[string]string, flows []netbpf.FlowRecord) {
	ctx := h.ctx(tenants)
	ctx.ContainerForIP = func(ip netip.Addr) (string, bool) { b, ok := boxes[ip.String()]; return b, ok }
	h.r.OnFlows(ctx, flows)
}

// A tenant is an org and can own several boxes: two boxes fanning out are two
// findings, each naming its own box and carrying only its own evidence.
func TestOutboundFanoutRule_NamesTheBox(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	tenants := map[string]string{"10.0.3.2": "org", "10.0.3.3": "org"}
	boxes := map[string]string{"10.0.3.2": "box-x", "10.0.3.3": "box-y"}
	h.feedBoxes(tenants, boxes, append(fanoutFlows("10.0.3.2", 20, 3128, 6), fanoutFlows("10.0.3.3", 20, 3128, 6)...))
	got := h.sweep()
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (one per box of the same tenant)", len(got))
	}
	subjects := map[string]string{}
	for _, f := range got {
		subjects[f.Container] = f.Subject
		for _, e := range f.Evidence.Flows {
			if (f.Container == "box-x") != (e.SrcIP == "10.0.3.2") {
				t.Fatalf("evidence from the wrong box in %s's finding: %+v", f.Container, e)
			}
		}
	}
	if subjects["box-x"] != "proxy-fanout:box-x" || subjects["box-y"] != "proxy-fanout:box-y" {
		t.Fatalf("subjects = %v, want distinct per-box subjects", subjects)
	}
}

// With no box resolver (or an unknown IP) the rule keeps tenant-level
// attribution and the plain subject.
func TestOutboundFanoutRule_NoBoxFallsBackToTenant(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	h.feed(fanoutFlows(fanoutBoxIP, 20, 3128, 6))
	got := h.sweep()
	if len(got) != 1 || got[0].Container != "" || got[0].Subject != "proxy-fanout" {
		t.Fatalf("findings = %+v, want one tenant-level finding", got)
	}
}

// An address that moves to another box does not carry the old box's history.
func TestOutboundFanoutRule_BoxChangeResetsHistory(t *testing.T) {
	h := newFanoutHarness(t, OutboundFanoutThresholds{})
	tenants := map[string]string{fanoutBoxIP: "org"}
	flows := fanoutFlows(fanoutBoxIP, 20, 3128, 6)
	h.feedBoxes(tenants, map[string]string{fanoutBoxIP: "box-old"}, flows[:10])
	h.feedBoxes(tenants, map[string]string{fanoutBoxIP: "box-new"}, flows[10:])
	if got := h.sweep(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none: 10 addresses on each side of the move", got)
	}
}
