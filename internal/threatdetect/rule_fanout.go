package threatdetect

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// OutboundFanoutThresholds tunes OutboundFanoutRule. The zero value is
// replaced by DefaultOutboundFanoutThresholds field by field.
type OutboundFanoutThresholds struct {
	// Window is how long an address counts toward a container's fan-out
	// after its last flow was seen.
	Window time.Duration
	// ProxyDistinct is the number of distinct external addresses on
	// open-proxy ports within Window that raises a "proxy-fanout" finding.
	ProxyDistinct int
	// WideDistinct is the number of distinct external addresses, on ports
	// other than web, DNS and NTP, that raises a "wide-fanout" finding.
	WideDistinct int
}

// DefaultOutboundFanoutThresholds are deliberately far above what a package
// install, a git clone or a CI job opens: ordinary clients talk to a handful
// of CDN addresses on 443, which the rule ignores, and almost never to a
// dozen different hosts on a proxy port.
func DefaultOutboundFanoutThresholds() OutboundFanoutThresholds {
	return OutboundFanoutThresholds{
		Window:        5 * time.Minute,
		ProxyDistinct: 15,
		WideDistinct:  200,
	}
}

func (t OutboundFanoutThresholds) withDefaults() OutboundFanoutThresholds {
	d := DefaultOutboundFanoutThresholds()
	if t.Window <= 0 {
		t.Window = d.Window
	}
	if t.ProxyDistinct <= 0 {
		t.ProxyDistinct = d.ProxyDistinct
	}
	if t.WideDistinct <= 0 {
		t.WideDistinct = d.WideDistinct
	}
	// A threshold above the per-source cap could never be met.
	t.ProxyDistinct = min(t.ProxyDistinct, fanoutMaxAddrsPerSource)
	t.WideDistinct = min(t.WideDistinct, fanoutMaxAddrsPerSource)
	return t
}

const (
	fanoutSubjectProxy = "proxy-fanout"
	fanoutSubjectWide  = "wide-fanout"

	// fanoutMaxAddrsPerSource bounds one container's tracked addresses per
	// class. A source already far past either threshold gains nothing from
	// more entries, so new addresses are dropped once full.
	fanoutMaxAddrsPerSource = 4096
	// fanoutMaxSources bounds how many containers are tracked at once.
	fanoutMaxSources = 1024
	// fanoutEphemeralPortMin is the bottom of the Linux ephemeral range. The
	// flow map also holds replies a box sends to clients that connected to
	// it, and those carry the client's ephemeral port as the destination
	// port. wide-fanout therefore counts only destination ports below this,
	// so a public-facing server is not read as a scanner. The cost: a tool
	// that targets only high ports is not seen by wide-fanout.
	fanoutEphemeralPortMin = 32768
)

// fanoutReserved are non-public ranges net/netip does not classify as
// private: they never count as an external destination.
var fanoutReserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT / overlay networks
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
}

// fanoutProxyPorts are the ports public open-proxy lists are published on.
// 8080 and 8000 are included on purpose: a build tool talks to one or two
// hosts there, a proxy-rotating tool to dozens.
var fanoutProxyPorts = map[uint16]bool{
	1080: true, 3128: true, 3129: true, 8000: true, 8080: true,
	8081: true, 8118: true, 8888: true, 9050: true,
}

// fanoutIgnoredPorts are ports where reaching many distinct addresses is
// normal (the web, DNS, NTP) and so never counts toward wide-fanout.
var fanoutIgnoredPorts = map[uint16]bool{53: true, 80: true, 123: true, 443: true}

// fanoutEntry is the newest flow seen to one external address.
type fanoutEntry struct {
	at      time.Time
	lastNs  uint64 // the flow's own last-packet stamp (monotonic); 0 when the record has none
	sport   uint16
	dport   uint16
	proto   uint8
	bytes   uint64
	packets uint64
}

// fanoutSource is one container's recent destinations, keyed by address.
type fanoutSource struct {
	tenantID  string
	container string // "" when the IP does not resolve to a box
	proxy     map[netip.Addr]fanoutEntry
	wide      map[netip.Addr]fanoutEntry
	// dirtyProxy/dirtyWide: an address was added or refreshed since the last
	// Sweep. A finished burst is not re-fired for as long as its addresses
	// linger in the window.
	dirtyProxy, dirtyWide bool
}

// OutboundFanoutRule implements Rule for THREAT_RULE_ID_OUTBOUND_FANOUT: a
// container that reaches many distinct external addresses inside a window,
// either on open-proxy ports (a DDoS or scraping tool rotating through a
// public proxy list) or across a wide spread of non-web ports (a scanner).
// It exists because no other rule sees this shape: the traffic is not
// cross-tenant, not CPU-heavy, and goes to destinations nobody listed.
//
// Signals accumulate on OnFlows and Sweep evaluates, so a finding is
// re-fired on every sweep while the condition holds and the finding store
// dedupes it into one open finding per (tenant, subject). The rule is
// record-only: it never acts on a container.
type OutboundFanoutRule struct {
	th OutboundFanoutThresholds

	// respond raises a finding that names its box to HIGH, which is what
	// makes the process responder eligible to act on it (see RespondsTo).
	// Off by default: the rule is record-only at MEDIUM.
	respond bool

	mu        sync.Mutex
	sources   map[netip.Addr]*fanoutSource
	capLogged bool
}

// NewOutboundFanoutRule builds the rule; zero threshold fields take defaults.
func NewOutboundFanoutRule(th OutboundFanoutThresholds) *OutboundFanoutRule {
	return &OutboundFanoutRule{th: th.withDefaults(), sources: make(map[netip.Addr]*fanoutSource)}
}

// RespondWithHighSeverity opts the rule into the response path: a finding that
// names its box is raised at HIGH so the process responder may act on it under
// the operator's process policy (whose default action is ALERT, i.e. nothing is
// throttled or frozen until the operator chooses one). A finding with no named
// box stays MEDIUM: the responder acts on a container, and the rule never
// guesses one. Returns the rule for chaining at construction.
func (r *OutboundFanoutRule) RespondWithHighSeverity(on bool) *OutboundFanoutRule {
	r.respond = on
	return r
}

func (r *OutboundFanoutRule) ID() pb.ThreatRuleId {
	return pb.ThreatRuleId_THREAT_RULE_ID_OUTBOUND_FANOUT
}

// OnDeny: fan-out is judged on allowed flows; denies add nothing.
func (r *OutboundFanoutRule) OnDeny(RuleContext, netbpf.DenyEvent) []RawFinding { return nil }

// isExternalUnicast reports whether ip is a public, routable unicast
// address. Private, loopback, link-local, multicast and unspecified
// destinations (other boxes, the bridge, the metadata service) never count.
func isExternalUnicast(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range fanoutReserved {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// OnFlows records each qualifying flow against its source container. A
// source IP that does not resolve to a tenant is ignored: it is not a box
// this rule can attribute, and ignoring it also bounds the state.
func (r *OutboundFanoutRule) OnFlows(ctx RuleContext, flows []netbpf.FlowRecord) []RawFinding {
	now := ctx.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range flows {
		if f.Proto != 6 && f.Proto != 17 { // TCP and UDP only: ICMP has no port
			continue
		}
		dst := f.Dst()
		if !isExternalUnicast(dst) {
			continue
		}
		isProxy := fanoutProxyPorts[f.Dport]
		if !isProxy && (fanoutIgnoredPorts[f.Dport] || f.Dport >= fanoutEphemeralPortMin) {
			continue
		}
		src := f.Src()
		tenantID, ok := ctx.TenantForIP(src)
		if !ok {
			continue
		}
		box := ""
		if ctx.ContainerForIP != nil {
			box, _ = ctx.ContainerForIP(src)
		}
		s := r.sources[src]
		if s != nil && (s.tenantID != tenantID || s.container != box) {
			// The address was reassigned to another box (or tenant): what was
			// counted against the old one must not carry over.
			delete(r.sources, src)
			s = nil
		}
		if s == nil {
			if len(r.sources) >= fanoutMaxSources {
				if !r.capLogged {
					r.capLogged = true
					log.Printf("[sentry] outbound-fanout: tracking %d containers (the cap); further containers are not tracked", fanoutMaxSources)
				}
				continue
			}
			s = &fanoutSource{
				tenantID:  tenantID,
				container: box,
				proxy:     make(map[netip.Addr]fanoutEntry),
				wide:      make(map[netip.Addr]fanoutEntry),
			}
			r.sources[src] = s
		}
		set := s.wide
		if isProxy {
			set = s.proxy
		}
		prev, known := set[dst]
		if !known && len(set) >= fanoutMaxAddrsPerSource {
			continue
		}
		// Refresh an address only when its flow advanced. pollFlows reports
		// every flow not idle for 2 minutes on each poll, so re-stamping on
		// every sighting would stretch the window by that idle time.
		if known && f.LastNs != 0 && f.LastNs <= prev.lastNs {
			continue
		}
		set[dst] = fanoutEntry{at: now, lastNs: f.LastNs, sport: f.Sport, dport: f.Dport, proto: f.Proto, bytes: f.Bytes, packets: f.Packets}
		if isProxy {
			s.dirtyProxy = true
		} else {
			s.dirtyWide = true
		}
	}
	return nil
}

// Sweep prunes addresses older than the window, forgets sources left empty,
// and raises a MEDIUM finding for each class at or over its threshold.
func (r *OutboundFanoutRule) Sweep(ctx RuleContext, now time.Time) []RawFinding {
	cutoff := now.Add(-r.th.Window)
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []RawFinding
	for src, s := range r.sources {
		prune := func(set map[netip.Addr]fanoutEntry) {
			for a, e := range set {
				if !e.at.After(cutoff) {
					delete(set, a)
				}
			}
		}
		prune(s.proxy)
		prune(s.wide)
		if len(s.proxy) == 0 && len(s.wide) == 0 {
			delete(r.sources, src)
			continue
		}
		if s.dirtyProxy && len(s.proxy) >= r.th.ProxyDistinct {
			out = append(out, r.fanoutFinding(src, s, fanoutSubjectProxy, s.proxy))
		}
		if s.dirtyWide && len(s.wide) >= r.th.WideDistinct {
			out = append(out, r.fanoutFinding(src, s, fanoutSubjectWide, s.wide))
		}
		s.dirtyProxy, s.dirtyWide = false, false
	}
	return out
}

// fanoutFinding builds one finding with a capped, deterministic sample of
// the qualifying flows (address order) as evidence.
func (r *OutboundFanoutRule) fanoutFinding(src netip.Addr, s *fanoutSource, subject string, set map[netip.Addr]fanoutEntry) RawFinding {
	addrs := make([]netip.Addr, 0, len(set))
	for a := range set {
		addrs = append(addrs, a)
	}
	// Newest first (address order breaks ties), so the stored sample moves
	// with the box instead of showing the same lowest addresses forever.
	sort.Slice(addrs, func(i, j int) bool {
		a, b := set[addrs[i]], set[addrs[j]]
		if !a.at.Equal(b.at) {
			return a.at.After(b.at)
		}
		return addrs[i].Less(addrs[j])
	})
	matched := fmt.Sprintf("%s: %d distinct addresses in window", subject, len(set))
	if len(addrs) > EvidenceCap {
		addrs = addrs[:EvidenceCap]
	}
	flows := make([]FlowEvidence, 0, len(addrs))
	for _, a := range addrs {
		e := set[a]
		flows = append(flows, FlowEvidence{
			SrcIP:    src.String(),
			DstIP:    a.String(),
			SrcPort:  uint32(e.sport),
			DstPort:  uint32(e.dport),
			Protocol: protoName(e.proto),
			Bytes:    int64(e.bytes),   // #nosec G115 -- one flow's counters
			Packets:  int64(e.packets), // #nosec G115 -- one flow's counters
			LastSeen: e.at,
			Matched:  matched,
		})
	}
	// The finding store dedupes on (rule, tenant, subject) and a tenant is an
	// org that can own several boxes, so the box is part of the subject:
	// two boxes fanning out are two findings, not one with lost attribution.
	if s.container != "" {
		subject += ":" + s.container
	}
	severity := pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM
	if r.respond && s.container != "" {
		severity = pb.ThreatSeverity_THREAT_SEVERITY_HIGH
	}
	return RawFinding{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_OUTBOUND_FANOUT,
		Severity:  severity,
		TenantID:  s.tenantID,
		Container: s.container,
		Subject:   subject,
		Evidence:  Evidence{Flows: flows},
	}
}

// trackedSources is for tests: how many containers hold state.
func (r *OutboundFanoutRule) trackedSources() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sources)
}
