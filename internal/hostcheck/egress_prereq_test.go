package hostcheck

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The coding-CLI egress program (#2370, design PR 3 = #2379) needs kernel >=
// 6.6, a unified cgroup v2 hierarchy and the cgroup_skb program type. Each
// missing prerequisite must fail with its own named reason, and anything the
// probe could not determine is a failure, never a pass.
func TestEgressPrereqChecks(t *testing.T) {
	supported := egressPrereqProbes{
		kernelRelease: func() (string, error) { return "6.8.0-generic", nil },
		cgroupV2:      func() (bool, error) { return true, nil },
		cgroupSKB:     func() error { return nil },
	}
	cases := map[string]struct {
		mutate     func(*egressPrereqProbes)
		failing    string // check name expected to fail ("" = all pass)
		wantReason EgressPrereqReason
	}{
		"supported host passes": {mutate: func(*egressPrereqProbes) {}},
		"kernel exactly 6.6 passes": {mutate: func(p *egressPrereqProbes) {
			p.kernelRelease = func() (string, error) { return "6.6.0", nil }
		}},
		"kernel 7.0 passes": {mutate: func(p *egressPrereqProbes) {
			p.kernelRelease = func() (string, error) { return "7.0.1-custom", nil }
		}},
		"kernel below 6.6": {
			mutate: func(p *egressPrereqProbes) {
				p.kernelRelease = func() (string, error) { return "6.5.13-generic", nil }
			},
			failing: egressCheckKernel, wantReason: ReasonKernelTooOld,
		},
		"kernel 5.15": {
			mutate: func(p *egressPrereqProbes) {
				p.kernelRelease = func() (string, error) { return "5.15.0-100-generic", nil }
			},
			failing: egressCheckKernel, wantReason: ReasonKernelTooOld,
		},
		"kernel release unparseable": {
			mutate: func(p *egressPrereqProbes) {
				p.kernelRelease = func() (string, error) { return "garbage", nil }
			},
			failing: egressCheckKernel, wantReason: ReasonKernelUnknown,
		},
		"uname fails": {
			mutate: func(p *egressPrereqProbes) {
				p.kernelRelease = func() (string, error) { return "", errors.New("uname: denied") }
			},
			failing: egressCheckKernel, wantReason: ReasonKernelUnknown,
		},
		"cgroup v1": {
			mutate: func(p *egressPrereqProbes) {
				p.cgroupV2 = func() (bool, error) { return false, nil }
			},
			failing: egressCheckCgroupV2, wantReason: ReasonCgroupNotV2,
		},
		"cgroup mount unreadable": {
			mutate: func(p *egressPrereqProbes) {
				p.cgroupV2 = func() (bool, error) { return false, errors.New("statfs: no such file") }
			},
			failing: egressCheckCgroupV2, wantReason: ReasonCgroupUnknown,
		},
		"no cgroup_skb": {
			mutate: func(p *egressPrereqProbes) {
				p.cgroupSKB = func() error { return fmt.Errorf("probe: %w", errCgroupSKBUnsupported) }
			},
			failing: egressCheckCgroupSKB, wantReason: ReasonNoCgroupSKB,
		},
		"cgroup_skb probe not permitted": {
			mutate: func(p *egressPrereqProbes) {
				p.cgroupSKB = func() error { return errors.New("operation not permitted") }
			},
			failing: egressCheckCgroupSKB, wantReason: ReasonCgroupSKBUnknown,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := supported
			tc.mutate(&p)
			checks := egressPrereqChecks(p)
			if len(checks) != 3 {
				t.Fatalf("got %d checks, want 3: %+v", len(checks), checks)
			}
			for _, c := range checks {
				if c.Required {
					t.Errorf("%s: egress prerequisites must not gate the daemon's required checks", c.Name)
				}
				if c.Name != tc.failing {
					if !c.OK {
						t.Errorf("%s: unexpected failure: %s", c.Name, c.Detail)
					}
					continue
				}
				if c.OK {
					t.Fatalf("%s: passed, want failure with reason %q", c.Name, tc.wantReason)
				}
				if !strings.HasPrefix(c.Detail, string(tc.wantReason)+":") {
					t.Fatalf("%s: detail %q does not name reason %q", c.Name, c.Detail, tc.wantReason)
				}
			}
		})
	}
}
