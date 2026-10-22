package netpolicy

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"time"
)

// DenyRow is one network-policy deny audit row, the input to AggregateDenies.
// Time is the row's timestamp; Detail is the JSON the enforcer wrote.
type DenyRow struct {
	Time   time.Time
	Detail string
}

// denyDetail is the enforcer's deny audit detail (see the enforcer's
// handleDeny): a named struct, not a map, so a field rename there fails a
// test here instead of silently producing an empty plan.
type denyDetail struct {
	Src          string `json:"src"`
	Dst          string `json:"dst"`
	Proto        int    `json:"proto"`
	Dport        int    `json:"dport"`
	Dropped      bool   `json:"dropped"`
	VirtualPatch bool   `json:"virtual_patch"`
}

// Destination is one denied/dropped destination aggregated over a window.
type Destination struct {
	IP       netip.Addr
	Port     uint16
	Proto    string // "tcp", "udp", or the protocol number
	Count    uint32
	Dropped  bool
	LastSeen time.Time
}

type destKey struct {
	ip    netip.Addr
	port  uint16
	proto string
}

// AggregateDenies groups deny rows by (destination IP, port, protocol),
// busiest first. Rows that are virtual-patch denies (an operator's deliberate
// block, not an allow-list miss), unparseable, or whose destination is already
// allowed (allowed != nil and returns true) are skipped. The count is
// per-row, i.e. per denied flow event, not per packet.
func AggregateDenies(rows []DenyRow, allowed func(netip.Addr) bool) []Destination {
	agg := map[destKey]*Destination{}
	for _, r := range rows {
		var d denyDetail
		if json.Unmarshal([]byte(r.Detail), &d) != nil || d.VirtualPatch {
			continue
		}
		ip, err := netip.ParseAddr(d.Dst)
		if err != nil || !ip.Is4() {
			continue
		}
		if allowed != nil && allowed(ip) {
			continue
		}
		port := uint16(0)
		if d.Dport > 0 && d.Dport < 65536 {
			port = uint16(d.Dport) // #nosec G115 -- bounded by the check above
		}
		k := destKey{ip, port, protoLabel(d.Proto)}
		e := agg[k]
		if e == nil {
			e = &Destination{IP: ip, Port: port, Proto: k.proto}
			agg[k] = e
		}
		if e.Count < ^uint32(0) {
			e.Count++
		}
		e.Dropped = e.Dropped || d.Dropped
		if r.Time.After(e.LastSeen) {
			e.LastSeen = r.Time
		}
	}
	out := make([]Destination, 0, len(agg))
	for _, e := range agg {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if c := out[i].IP.Compare(out[j].IP); c != 0 {
			return c < 0
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func protoLabel(p int) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return strconv.Itoa(p)
	}
}

// Allows reports whether the policy's egress CIDRs, plus any implicit
// prefixes, cover ip. Domain entries are not consulted: their resolved
// addresses live in the enforcer, so a destination allowed only through
// egress_domains still shows up in a plan (the response says so).
func (c CompiledPolicy) Allows(ip netip.Addr, implicit []netip.Prefix) bool {
	for _, p := range c.EgressCIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	for _, p := range implicit {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
