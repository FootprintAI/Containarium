//go:build !windows

package cmd

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Sentinel selection for `pool join` (#699). A host joining a multi-region pool
// should dial its LOWEST-LATENCY sentinel, and latency can only be measured
// from the host. So the operator (or the control plane's "add compute" flow)
// passes the candidate sentinels and the host probes + self-selects.

const (
	defaultProbeAttempts = 3
	defaultProbeTimeout  = 2 * time.Second
)

// sentinelCandidate is one dialable sentinel, optionally labeled with a region.
type sentinelCandidate struct {
	Region string // "" when the operator passed a bare host:port
	Addr   string // host:port
}

// rttRow is a candidate's probe result — RTT on success, Err on failure.
type rttRow struct {
	Cand sentinelCandidate
	RTT  time.Duration
	Err  error
}

// parseSentinelCandidates parses repeated --sentinel values, each either
// "host:port" (unlabeled) or "region=host:port". Pure.
func parseSentinelCandidates(vals []string) ([]sentinelCandidate, error) {
	out := make([]sentinelCandidate, 0, len(vals))
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		var c sentinelCandidate
		// Split on the FIRST '=' so a region label is optional; host:port has no '='.
		if i := strings.Index(v, "="); i >= 0 {
			c.Region = strings.TrimSpace(v[:i])
			c.Addr = strings.TrimSpace(v[i+1:])
			if c.Region == "" {
				return nil, fmt.Errorf("invalid --sentinel %q: empty region before '='", v)
			}
		} else {
			c.Addr = v
		}
		if c.Addr == "" {
			return nil, fmt.Errorf("invalid --sentinel %q: empty host:port", v)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no sentinel candidates")
	}
	return out, nil
}

// pickLowestRTT returns the candidate with the lowest successful median RTT.
// Candidates that failed to probe are excluded; if none succeeded it returns an
// error listing what was tried (never silently picks nothing). Pure.
func pickLowestRTT(rows []rttRow) (sentinelCandidate, error) {
	best := -1
	for i, r := range rows {
		if r.Err != nil {
			continue
		}
		if best < 0 || r.RTT < rows[best].RTT {
			best = i
		}
	}
	if best < 0 {
		var tried []string
		for _, r := range rows {
			tried = append(tried, fmt.Sprintf("%s (%v)", r.Cand.Addr, r.Err))
		}
		return sentinelCandidate{}, fmt.Errorf("all sentinel candidates failed to probe: %s", strings.Join(tried, "; "))
	}
	return rows[best].Cand, nil
}

// probeRTT measures the median TCP-connect RTT to addr over `attempts` dials
// with a per-dial timeout. Returns an error only when every attempt failed.
func probeRTT(addr string, attempts int, timeout time.Duration) (time.Duration, error) {
	if attempts < 1 {
		attempts = 1
	}
	var samples []time.Duration
	var lastErr error
	for i := 0; i < attempts; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		samples = append(samples, time.Since(start))
		_ = conn.Close()
	}
	if len(samples) == 0 {
		return 0, lastErr
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], nil
}

// probeCandidates probes each candidate and returns a row per candidate (in
// input order). Impure (dials the network).
func probeCandidates(cands []sentinelCandidate, attempts int, timeout time.Duration) []rttRow {
	rows := make([]rttRow, 0, len(cands))
	for _, c := range cands {
		rtt, err := probeRTT(c.Addr, attempts, timeout)
		rows = append(rows, rttRow{Cand: c, RTT: rtt, Err: err})
	}
	return rows
}

// resolveSentinel picks the sentinel to dial from the parsed candidates:
//   - exactly one candidate → use it, skip probing (regardless of region).
//   - region == "auto" → probe all, pick lowest RTT (returns the probe table).
//   - region == "<name>" → pick the candidate with that label.
//   - region == "" with >1 candidate → ambiguous, error.
//
// probe is injected for testability (nil → the real network probe).
func resolveSentinel(cands []sentinelCandidate, region string, probe func([]sentinelCandidate) []rttRow) (sentinelCandidate, []rttRow, error) {
	switch {
	case len(cands) == 0:
		return sentinelCandidate{}, nil, fmt.Errorf("no sentinel candidates")
	case len(cands) == 1:
		return cands[0], nil, nil
	case region == "auto":
		if probe == nil {
			probe = func(cs []sentinelCandidate) []rttRow {
				return probeCandidates(cs, defaultProbeAttempts, defaultProbeTimeout)
			}
		}
		rows := probe(cands)
		chosen, err := pickLowestRTT(rows)
		return chosen, rows, err
	case region != "":
		for _, c := range cands {
			if c.Region == region {
				return c, nil, nil
			}
		}
		return sentinelCandidate{}, nil, fmt.Errorf("no --sentinel candidate labeled region %q", region)
	default:
		return sentinelCandidate{}, nil, fmt.Errorf("multiple --sentinel candidates given; pass --region auto to probe-and-select, or --region <name> to pick one")
	}
}

// formatRTTTable renders a human-readable region/RTT table for logging.
func formatRTTTable(rows []rttRow) string {
	var b strings.Builder
	for _, r := range rows {
		region := r.Cand.Region
		if region == "" {
			region = "-"
		}
		if r.Err != nil {
			fmt.Fprintf(&b, "  %-12s %-24s unreachable (%v)\n", region, r.Cand.Addr, r.Err)
			continue
		}
		fmt.Fprintf(&b, "  %-12s %-24s %v\n", region, r.Cand.Addr, r.RTT.Round(time.Millisecond))
	}
	return b.String()
}
