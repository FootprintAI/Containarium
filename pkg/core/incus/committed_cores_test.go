package incus

import (
	"math"
	"testing"
)

// TestCommittedCores pins the request-string → committed-cores mapping the
// #1029 capacity accounting sums over. It must agree with what CreateContainer
// actually wrote (post-#1034 hard quotas), read legacy percentage allowances,
// count CPU-set cardinality, and never blow up on junk (returns 0, since a
// single bad entry must not make a whole host un-schedulable).
func TestCommittedCores(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"  ", 0},
		{"1", 1},
		{"4", 4},
		{"8", 8},
		{"250m", 0.25},
		{"1500m", 1.5},
		{"0.25", 0.25},
		{"2.5", 2.5},
		{"400ms/100ms", 4}, // hard quota read straight back
		{"100ms/100ms", 1},
		{"800%", 8},  // legacy soft-share allowance
		{"200%", 2},  // legacy
		{"0-3", 4},   // CPU set / range cardinality
		{"0,2-4", 4}, // 0 + {2,3,4}
		{"0-7", 8},
		{"garbage", 0}, // unparseable → 0, not a panic
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := CommittedCores(c.in)
			if math.Abs(got-c.want) > 1e-9 {
				t.Fatalf("CommittedCores(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestCommittedCoresRoundTripsParseCPULimit is the property that keeps the
// accounting honest: whatever CreateContainer would set for a request, reading
// it back as committed cores must equal the request's own core count. If
// parseCPULimit changes how it encodes a request, this catches an accounting
// drift immediately.
func TestCommittedCoresRoundTripsParseCPULimit(t *testing.T) {
	reqs := map[string]float64{
		"1": 1, "4": 4, "8": 8,
		"250m": 0.25, "1500m": 1.5,
		"0.5": 0.5, "2.5": 2.5,
	}
	for req, cores := range reqs {
		cl, err := parseCPULimit(req)
		if err != nil {
			t.Fatalf("parseCPULimit(%q): %v", req, err)
		}
		// Reconstruct the request string the way ContainerInfo.CPU would carry it.
		read := formatCPULimitFromConfig(map[string]string{
			"limits.cpu":           cl.Count,
			"limits.cpu.allowance": cl.Allowance,
		})
		if got := CommittedCores(read); math.Abs(got-cores) > 1e-9 {
			t.Errorf("request %q → stored %q → CommittedCores %v, want %v", req, read, got, cores)
		}
	}
}
