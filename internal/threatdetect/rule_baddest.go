package threatdetect

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// embeddedBadDestYAML is the baseline known-bad-destination list (#1641):
// mining pools first, per the design doc. Versioned so an operator can tell
// which baseline a given daemon build shipped with; extend it without a
// rebuild via AddDestination / `containarium security bad-destinations add`.
//
//go:embed rule_baddest_list.yaml
var embeddedBadDestYAML []byte

// badDestConfigKey is the DaemonConfigStore key operator-added entries are
// persisted under, JSON-encoded — same initSchema/key-value idiom every
// other daemon-config-backed feature uses.
const badDestConfigKey = "threatdetect.bad_destinations.operator"

// BadDestinationEntry is one entry in the known-bad-destination list,
// mirroring pb.BadDestinationEntry as a plain Go type for the rule's
// internal bookkeeping.
type BadDestinationEntry struct {
	// CIDR is always stored normalized (netip.Prefix.Masked().String()) —
	// an exact IP is a /32.
	CIDR  string
	Label string
	// Source is "baseline" (embedded, versioned list) or "operator" (added
	// via AddDestination). Baseline entries cannot be removed.
	Source string
}

type badDestYAMLFile struct {
	Version int `yaml:"version"`
	Entries []struct {
		CIDR  string `yaml:"cidr"`
		Label string `yaml:"label"`
	} `yaml:"entries"`
}

func parseBaselineBadDestYAML(raw []byte) ([]BadDestinationEntry, error) {
	var f badDestYAMLFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("threatdetect: parse baseline bad-destination list: %w", err)
	}
	out := make([]BadDestinationEntry, 0, len(f.Entries))
	for _, e := range f.Entries {
		cidr, err := normalizeCIDR(e.CIDR)
		if err != nil {
			return nil, fmt.Errorf("threatdetect: baseline bad-destination list: %w", err)
		}
		out = append(out, BadDestinationEntry{CIDR: cidr, Label: e.Label, Source: "baseline"})
	}
	return out, nil
}

// normalizeCIDR accepts an exact IPv4 ("203.0.113.7") or a CIDR
// ("203.0.113.0/24") and returns the canonical masked CIDR string — an
// exact IP becomes a /32. FlowRecord/DenyEvent addresses are IPv4-only
// (see netbpf), so this rejects IPv6 input rather than silently never
// matching it.
func normalizeCIDR(s string) (string, error) {
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return "", fmt.Errorf("invalid IP or CIDR %q: %w", s, err)
		}
		if !addr.Is4() {
			return "", fmt.Errorf("invalid IP or CIDR %q: only IPv4 is supported", s)
		}
		return netip.PrefixFrom(addr, 32).String(), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", fmt.Errorf("invalid IP or CIDR %q: %w", s, err)
	}
	if !p.Addr().Is4() {
		return "", fmt.Errorf("invalid IP or CIDR %q: only IPv4 is supported", s)
	}
	return p.Masked().String(), nil
}

// badDestMatcher is an immutable snapshot of the merged baseline + operator
// list, rebuilt (not mutated) on every add/remove — a linear scan over a
// handful to a few hundred entries is simple and fast enough; the design
// doc's LPM-trie note is headroom for a much larger list than this MVP
// ships with.
type badDestMatcher struct {
	entries []badDestMatcherEntry
}

type badDestMatcherEntry struct {
	prefix netip.Prefix
	label  string
}

func newBadDestMatcher(all []BadDestinationEntry) (*badDestMatcher, error) {
	m := &badDestMatcher{entries: make([]badDestMatcherEntry, 0, len(all))}
	for _, e := range all {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			return nil, fmt.Errorf("threatdetect: bad-destination entry %q: %w", e.CIDR, err)
		}
		m.entries = append(m.entries, badDestMatcherEntry{prefix: p, label: e.Label})
	}
	return m, nil
}

func (m *badDestMatcher) Match(ip netip.Addr) (label string, ok bool) {
	for _, e := range m.entries {
		if e.prefix.Contains(ip) {
			return e.label, true
		}
	}
	return "", false
}

// BadDestinationRule implements Rule for THREAT_RULE_ID_BAD_DESTINATION
// (#1641): a flow whose destination matches the known-bad list (baseline +
// operator-added) raises a HIGH finding. Deny events and time windows are
// irrelevant to this rule — OnDeny and Sweep are no-ops.
type BadDestinationRule struct {
	mu       sync.RWMutex
	baseline []BadDestinationEntry
	operator []BadDestinationEntry
	matcher  *badDestMatcher
	store    *app.DaemonConfigStore // nil = operator additions are in-memory only for this process's lifetime
}

// NewBadDestinationRule loads the embedded baseline list and, if store is
// non-nil, the previously persisted operator-added entries. store may be
// nil — the rule still works, but AddDestination/RemoveDestination don't
// survive a daemon restart (same graceful-degradation spirit as
// MemFindingStore for a Postgres-less deployment).
func NewBadDestinationRule(ctx context.Context, store *app.DaemonConfigStore) (*BadDestinationRule, error) {
	baseline, err := parseBaselineBadDestYAML(embeddedBadDestYAML)
	if err != nil {
		return nil, err
	}
	r := &BadDestinationRule{baseline: baseline, store: store}
	operator, err := r.loadOperatorEntries(ctx)
	if err != nil {
		return nil, err
	}
	r.operator = operator
	if err := r.rebuildMatcherLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *BadDestinationRule) loadOperatorEntries(ctx context.Context) ([]BadDestinationEntry, error) {
	if r.store == nil {
		return nil, nil
	}
	val, err := r.store.Get(ctx, badDestConfigKey)
	if err != nil {
		if errors.Is(err, app.ErrDaemonConfigNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("threatdetect: load operator bad-destinations: %w", err)
	}
	var entries []BadDestinationEntry
	if err := json.Unmarshal([]byte(val), &entries); err != nil {
		return nil, fmt.Errorf("threatdetect: unmarshal operator bad-destinations: %w", err)
	}
	return entries, nil
}

func (r *BadDestinationRule) persistOperatorLocked(ctx context.Context) error {
	if r.store == nil {
		return nil
	}
	data, err := json.Marshal(r.operator)
	if err != nil {
		return fmt.Errorf("threatdetect: marshal operator bad-destinations: %w", err)
	}
	return r.store.Set(ctx, badDestConfigKey, string(data))
}

// rebuildMatcherLocked recomputes the merged matcher from baseline+operator.
// Caller must hold r.mu (write lock at construction/mutation time).
func (r *BadDestinationRule) rebuildMatcherLocked() error {
	all := make([]BadDestinationEntry, 0, len(r.baseline)+len(r.operator))
	all = append(all, r.baseline...)
	all = append(all, r.operator...)
	m, err := newBadDestMatcher(all)
	if err != nil {
		return err
	}
	r.matcher = m
	return nil
}

// ID identifies this rule for findings, status, and rule config.
func (r *BadDestinationRule) ID() pb.ThreatRuleId {
	return pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION
}

// OnFlows matches each flow's destination against the merged bad-destination
// list. A hit raises a HIGH finding: subject = destination IP (the dedupe
// scope — repeat flows to the same bad IP from the same tenant dedupe into
// one open finding, per the engine's upsert), tenant = the source IP's
// owning tenant (never guessed — empty when unresolved, design doc: "a rule
// must never guess at an unknown IP's tenant").
func (r *BadDestinationRule) OnFlows(ctx RuleContext, flows []netbpf.FlowRecord) []RawFinding {
	r.mu.RLock()
	m := r.matcher
	r.mu.RUnlock()

	var out []RawFinding
	for _, f := range flows {
		dst := f.Dst()
		// The matched entry's label isn't part of Finding today (no free
		// text field on RawFinding/Evidence for it); the destination IP in
		// Subject/DstIP is enough to identify which list entry fired.
		if _, hit := m.Match(dst); !hit {
			continue
		}
		tenantID, _ := ctx.TenantForIP(f.Src())
		out = append(out, RawFinding{
			Rule:     pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION,
			Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
			TenantID: tenantID,
			Subject:  dst.String(),
			Evidence: Evidence{Flows: []FlowEvidence{{
				SrcIP:    f.Src().String(),
				DstIP:    dst.String(),
				SrcPort:  uint32(f.Sport),
				DstPort:  uint32(f.Dport),
				Protocol: badDestProtoName(f.Proto),
				Bytes:    int64(f.Bytes),   // #nosec G115 -- one flow's counters, never near int64 max
				Packets:  int64(f.Packets), // #nosec G115 -- one flow's counters, never near int64 max
			}}},
		})
	}
	return out
}

// OnDeny is a no-op — this rule only evaluates flow destinations.
func (r *BadDestinationRule) OnDeny(RuleContext, netbpf.DenyEvent) []RawFinding { return nil }

// Sweep is a no-op — this rule has no time-window state.
func (r *BadDestinationRule) Sweep(RuleContext, time.Time) []RawFinding { return nil }

// ListDestinations returns the merged baseline + operator list.
func (r *BadDestinationRule) ListDestinations() []BadDestinationEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]BadDestinationEntry, 0, len(r.baseline)+len(r.operator))
	out = append(out, r.baseline...)
	out = append(out, r.operator...)
	return out
}

// AddDestination adds (or updates the label of) an operator-supplied entry
// and takes effect immediately — no daemon rebuild or restart required. cidr
// may be an exact IP or a CIDR.
func (r *BadDestinationRule) AddDestination(ctx context.Context, cidr, label string) (BadDestinationEntry, error) {
	normalized, err := normalizeCIDR(cidr)
	if err != nil {
		return BadDestinationEntry{}, err
	}
	entry := BadDestinationEntry{CIDR: normalized, Label: label, Source: "operator"}

	r.mu.Lock()
	defer r.mu.Unlock()
	replaced := false
	for i, e := range r.operator {
		if e.CIDR == normalized {
			r.operator[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		r.operator = append(r.operator, entry)
	}
	if err := r.persistOperatorLocked(ctx); err != nil {
		return BadDestinationEntry{}, err
	}
	if err := r.rebuildMatcherLocked(); err != nil {
		return BadDestinationEntry{}, err
	}
	return entry, nil
}

// RemoveDestination removes a previously operator-added entry. A baseline
// entry cannot be removed this way — it's shipped with the daemon.
func (r *BadDestinationRule) RemoveDestination(ctx context.Context, cidr string) error {
	normalized, err := normalizeCIDR(cidr)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.baseline {
		if e.CIDR == normalized {
			return fmt.Errorf("threatdetect: %q is a baseline entry and cannot be removed", normalized)
		}
	}
	idx := -1
	for i, e := range r.operator {
		if e.CIDR == normalized {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("threatdetect: %q not found among operator-added entries", normalized)
	}
	r.operator = append(r.operator[:idx], r.operator[idx+1:]...)
	if err := r.persistOperatorLocked(ctx); err != nil {
		return err
	}
	return r.rebuildMatcherLocked()
}

// badDestProtoName renders an IP protocol number as the lowercase string
// used elsewhere for evidence/audit rendering. Duplicated from
// internal/server's protoName (unexported there) rather than introducing a
// server->threatdetect->server import — threatdetect must stay free of a
// dependency on internal/server, which already imports internal/threatdetect.
func badDestProtoName(proto uint8) string {
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
