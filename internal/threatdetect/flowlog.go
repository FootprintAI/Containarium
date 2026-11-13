package threatdetect

import (
	"log"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
)

// FlowLog is a bounded, in-memory record of which box contacted which public
// destination, and when. It exists to attribute a provider egress alert to a
// box after the fact: a firewall deny names a VM and a destination, and without
// this the host has no per-flow history to say which of its boxes did it.
//
// Privacy posture: it keeps destination addresses, which the conntrack fan-out
// design (docs/EGRESS-FANOUT-DETECTION.md) deliberately does not. So it is
// opt-in, held in memory only (a restart empties it), limited to public
// destinations, kept for a bounded retention, and queried through a
// tenant-scoped, scope-checked RPC.
type FlowLog struct {
	retention  time.Duration
	maxEntries int
	startedAt  time.Time

	mu        sync.Mutex
	entries   map[flowLogKey]*FlowLogEntry
	lastPrune time.Time
	capLogged bool
}

const (
	// DefaultFlowLogMaxEntries bounds the log's memory: at roughly 150 bytes an
	// entry, 200k entries is about 30 MB.
	DefaultFlowLogMaxEntries = 200_000
	// MaxFlowLogRetention is the longest retention the log accepts.
	MaxFlowLogRetention = 72 * time.Hour

	flowLogPruneEvery = time.Minute
)

type flowLogKey struct {
	container string
	src, dst  netip.Addr
	dport     uint16
	proto     uint8
}

// FlowLogEntry is one box's recorded contact with one destination.
type FlowLogEntry struct {
	Container string // "" when only the tenant is known
	TenantID  string
	Src, Dst  netip.Addr
	Dport     uint16
	Proto     uint8
	FirstSeen time.Time
	LastSeen  time.Time
	// Bytes and Packets are the largest cumulative counters reported for any
	// single flow to this destination (several connections share one entry).
	Bytes, Packets uint64
}

// LikelyReply reports whether the entry may be the box answering a client:
// the destination port is in the ephemeral range.
func (e FlowLogEntry) LikelyReply() bool { return e.Dport >= fanoutEphemeralPortMin }

// NewFlowLog builds a log keeping entries for retention, clamped to
// (0, MaxFlowLogRetention]. A non-positive retention returns nil: a nil
// *FlowLog is "off", and every method on it is a no-op.
func NewFlowLog(retention time.Duration, now time.Time) *FlowLog {
	if retention <= 0 {
		return nil
	}
	retention = min(retention, MaxFlowLogRetention)
	return &FlowLog{
		retention:  retention,
		maxEntries: DefaultFlowLogMaxEntries,
		startedAt:  now,
		entries:    make(map[flowLogKey]*FlowLogEntry),
		lastPrune:  now,
	}
}

// Retention is how long an entry is kept after it was last seen.
func (l *FlowLog) Retention() time.Duration {
	if l == nil {
		return 0
	}
	return l.retention
}

// Record notes each public-destination flow against the box that opened it.
// tenantFor and boxFor resolve a source IP and may be nil; a flow whose source
// resolves to no tenant is not recorded (it is not a box this host manages).
// They are called before the log's lock is taken.
func (l *FlowLog) Record(now time.Time, flows []netbpf.FlowRecord, tenantFor, boxFor func(netip.Addr) (string, bool)) {
	if l == nil || len(flows) == 0 {
		return
	}
	type resolved struct {
		key    flowLogKey
		tenant string
		rec    netbpf.FlowRecord
	}
	batch := make([]resolved, 0, len(flows))
	for _, f := range flows {
		dst := f.Dst()
		if !isExternalUnicast(dst) {
			continue
		}
		src := f.Src()
		if tenantFor == nil {
			continue
		}
		tenant, ok := tenantFor(src)
		if !ok {
			continue
		}
		box := ""
		if boxFor != nil {
			box, _ = boxFor(src)
		}
		batch = append(batch, resolved{
			key:    flowLogKey{container: box, src: src, dst: dst, dport: f.Dport, proto: f.Proto},
			tenant: tenant,
			rec:    f,
		})
	}
	if len(batch) == 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range batch {
		e := l.entries[r.key]
		if e == nil {
			e = &FlowLogEntry{
				Container: r.key.container, TenantID: r.tenant,
				Src: r.key.src, Dst: r.key.dst, Dport: r.key.dport, Proto: r.key.proto,
				FirstSeen: now,
			}
			l.entries[r.key] = e
		}
		e.TenantID = r.tenant
		e.LastSeen = now
		e.Bytes = max(e.Bytes, r.rec.Bytes)
		e.Packets = max(e.Packets, r.rec.Packets)
	}
	l.pruneLocked(now)
}

// pruneLocked drops entries past retention (at most once a minute) and, if the
// log is over its size bound, the least recently seen ones.
func (l *FlowLog) pruneLocked(now time.Time) {
	if now.Sub(l.lastPrune) >= flowLogPruneEvery {
		l.lastPrune = now
		cutoff := now.Add(-l.retention)
		for k, e := range l.entries {
			if e.LastSeen.Before(cutoff) {
				delete(l.entries, k)
			}
		}
	}
	if len(l.entries) <= l.maxEntries {
		return
	}
	if !l.capLogged {
		l.capLogged = true
		log.Printf("[sentry] flow log is over its %d-entry bound; the least recently seen entries are dropped, so history is shorter than the configured retention", l.maxEntries)
	}
	type kv struct {
		k flowLogKey
		t time.Time
	}
	all := make([]kv, 0, len(l.entries))
	for k, e := range l.entries {
		all = append(all, kv{k, e.LastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	// Drop down to 90% so an entry-per-flow churn does not re-sort every poll.
	for _, x := range all[:len(l.entries)-l.maxEntries*9/10] {
		delete(l.entries, x.k)
	}
}

// FlowLogQuery selects entries. Dst is required; the rest are optional.
type FlowLogQuery struct {
	Dst      netip.Addr
	Dport    uint16 // 0 matches any port
	Since    time.Time
	Until    time.Time
	TenantID string
	Limit    int
}

// Query returns the entries matching q, most recently seen first, and the
// moment the log can answer from: the later of when recording started and
// (now - retention), so a caller can tell "nothing recorded" from "not covered".
func (l *FlowLog) Query(now time.Time, q FlowLogQuery) (entries []FlowLogEntry, coveredSince time.Time) {
	if l == nil {
		return nil, time.Time{}
	}
	coveredSince = l.startedAt
	if floor := now.Add(-l.retention); floor.After(coveredSince) {
		coveredSince = floor
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		switch {
		case e.Dst != q.Dst:
		case q.Dport != 0 && e.Dport != q.Dport:
		case q.TenantID != "" && e.TenantID != q.TenantID:
		case !q.Since.IsZero() && e.LastSeen.Before(q.Since):
		case !q.Until.IsZero() && e.FirstSeen.After(q.Until):
		default:
			entries = append(entries, *e)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].LastSeen.Equal(entries[j].LastSeen) {
			return entries[i].LastSeen.After(entries[j].LastSeen)
		}
		return entries[i].Container < entries[j].Container
	})
	if q.Limit > 0 && len(entries) > q.Limit {
		entries = entries[:q.Limit]
	}
	return entries, coveredSince
}

// Len is for tests and status: how many entries the log holds.
func (l *FlowLog) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
