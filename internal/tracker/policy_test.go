package tracker

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestPolicy_Defaults pins the documented defaults (design:
// docs/architecture/issue-triggered-agents.md, "Chain guards"): a nil or
// zero-valued TrackerPolicy yields the same effective policy, and an
// explicitly set field is kept while the rest still default.
func TestPolicy_Defaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   *pb.TrackerPolicy
	}{
		{"nil", nil},
		{"zero value", &pb.TrackerPolicy{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := PolicyFromProto(tc.in)
			if !reflect.DeepEqual(p.LabelAllowList, DefaultLabelAllowList) {
				t.Errorf("LabelAllowList = %v, want defaults %v", p.LabelAllowList, DefaultLabelAllowList)
			}
			if p.AutoChain {
				t.Error("AutoChain = true, want false (human gate by default)")
			}
			if p.MaxDepth != DefaultMaxDepth {
				t.Errorf("MaxDepth = %d, want %d", p.MaxDepth, DefaultMaxDepth)
			}
			if p.MaxChildrenPerRun != DefaultMaxChildrenPerRun {
				t.Errorf("MaxChildrenPerRun = %d, want %d", p.MaxChildrenPerRun, DefaultMaxChildrenPerRun)
			}
			if p.RunTimeout != DefaultRunTimeout {
				t.Errorf("RunTimeout = %v, want %v", p.RunTimeout, DefaultRunTimeout)
			}
		})
	}

	t.Run("explicit fields kept, rest default", func(t *testing.T) {
		p := PolicyFromProto(&pb.TrackerPolicy{MaxDepth: 1, AutoChain: true, RunTimeoutSeconds: 90})
		if p.MaxDepth != 1 || !p.AutoChain || p.RunTimeout != 90*time.Second {
			t.Errorf("explicit fields not kept: %+v", p)
		}
		if p.MaxChildrenPerRun != DefaultMaxChildrenPerRun {
			t.Errorf("MaxChildrenPerRun = %d, want default %d", p.MaxChildrenPerRun, DefaultMaxChildrenPerRun)
		}
		if !reflect.DeepEqual(p.LabelAllowList, DefaultLabelAllowList) {
			t.Errorf("LabelAllowList = %v, want defaults", p.LabelAllowList)
		}
	})
}

// TestPolicy_LabelAllowList is the design's named table: exact, glob
// scope:*, rejected state label agent:done, rejected arbitrary
// deploy:prod, empty list = defaults — plus the reserved-state-label
// rule that no allow-list can lift for a run token.
func TestPolicy_LabelAllowList(t *testing.T) {
	tests := []struct {
		name     string
		allow    []string
		label    string
		runToken bool
		wantErr  error // nil = allowed
	}{
		{"exact gate label", nil, "agent:needs-approval", true, nil},
		{"glob scope:*", nil, "scope:architecture", true, nil},
		{"glob model:*", nil, "model:fable", true, nil},
		{"state label agent:done rejected for a run", nil, "agent:done", true, ErrStateLabelReserved},
		{"state label agent:queued rejected for a run", nil, "agent:queued", true, ErrStateLabelReserved},
		{"arbitrary deploy:prod rejected", nil, "deploy:prod", true, ErrLabelNotAllowed},
		{"empty list means defaults", []string{}, "scope:product", true, nil},
		{"custom list replaces defaults", []string{"triaged"}, "scope:product", true, ErrLabelNotAllowed},
		{"custom list allows its own entry", []string{"triaged"}, "triaged", true, nil},
		{"agent:* cannot lift the reserved rule for a run", []string{"agent:*"}, "agent:done", true, ErrStateLabelReserved},
		{"agent:* still allows the gate label for a run", []string{"agent:*"}, "agent:needs-approval", true, nil},
		{"operator with agent:* may write a state label", []string{"agent:*"}, "agent:done", false, nil},
		{"operator without agent:* may not", nil, "agent:done", false, ErrLabelNotAllowed},
		{"case-sensitive", nil, "Scope:product", true, ErrLabelNotAllowed},
		{"star spans slashes", []string{"area/*"}, "area/api/v2", true, nil},
		{"prefix without star is exact", []string{"scope:"}, "scope:product", true, ErrLabelNotAllowed},
		{"empty label rejected", nil, "", true, ErrLabelInvalid},

		// Review of #2034, blocking: GitLab's adapter comma-joins labels and
		// GitLab splits them back, so one "label" must never smuggle a second.
		{"comma smuggles a second label", nil, "scope:x,agent:done", true, ErrLabelInvalid},
		{"comma smuggles deploy:prod", nil, "scope:x,deploy:prod", true, ErrLabelInvalid},
		{"newline smuggles a second label", nil, "scope:x\nagent:done", true, ErrLabelInvalid},
		{"control character rejected", nil, "scope:x\tagent", true, ErrLabelInvalid},
		{"leading whitespace rejected", nil, " scope:x", true, ErrLabelInvalid},
		{"trailing whitespace rejected", nil, "agent:done ", true, ErrLabelInvalid},
		{"comma rejected even for an operator with *", []string{"*"}, "a,b", false, ErrLabelInvalid},
		{"inner space is a legal label", []string{"good first issue"}, "good first issue", true, nil},

		// Should-fix: reserved labels compare case-insensitively (GitHub
		// label names are), so a permissive allow-list can't be used to
		// write a differently-cased state label.
		{"Agent:Done reserved under *", []string{"*"}, "Agent:Done", true, ErrStateLabelReserved},
		{"AGENT:QUEUED reserved under *", []string{"*"}, "AGENT:QUEUED", true, ErrStateLabelReserved},
		{"agent:running reserved under *", []string{"*"}, "agent:running", true, ErrStateLabelReserved},

		// Nit: a glob star matches one or more characters, so a bare
		// prefix is not a scope.
		{"bare scope: rejected", nil, "scope:", true, ErrLabelNotAllowed},
		{"bare model: rejected", nil, "model:", true, ErrLabelNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PolicyFromProto(&pb.TrackerPolicy{LabelAllowList: tt.allow})
			err := p.CheckLabels([]string{tt.label}, tt.runToken)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("CheckLabels(%q) = %v, want allowed", tt.label, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CheckLabels(%q) = %v, want %v", tt.label, err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("%q", tt.label)) {
				t.Errorf("error %q should name the offending label %q", err, tt.label)
			}
		})
	}

	t.Run("names the first offending label of a batch", func(t *testing.T) {
		p := PolicyFromProto(nil)
		err := p.CheckLabels([]string{"scope:architecture", "deploy:prod", "agent:done"}, true)
		if !errors.Is(err, ErrLabelNotAllowed) || !strings.Contains(err.Error(), "deploy:prod") {
			t.Errorf("err = %v, want ErrLabelNotAllowed naming deploy:prod", err)
		}
	})
}

// TestPolicy_DepthAndFanout pins the boundary semantics: a child at
// depth == max_depth is still allowed, one past it is not; a run that
// has created max_children-1 children may create one more, one that has
// created max_children may not.
func TestPolicy_DepthAndFanout(t *testing.T) {
	p := PolicyFromProto(&pb.TrackerPolicy{MaxDepth: 3, MaxChildrenPerRun: 5})

	depthCases := []struct {
		depth int32
		want  bool
	}{{0, true}, {1, true}, {3, true}, {4, false}}
	for _, tc := range depthCases {
		if got := p.DepthAllowed(tc.depth); got != tc.want {
			t.Errorf("DepthAllowed(%d) = %v, want %v", tc.depth, got, tc.want)
		}
	}

	fanoutCases := []struct {
		existing int32
		want     bool
	}{{0, true}, {4, true}, {5, false}, {6, false}}
	for _, tc := range fanoutCases {
		if got := p.FanoutAllowed(tc.existing); got != tc.want {
			t.Errorf("FanoutAllowed(existing=%d) = %v, want %v", tc.existing, got, tc.want)
		}
	}
}

// TestMatchLabelGlob pins the glob semantics: '*' matches ONE or more
// characters (so "scope:*" does not admit a bare "scope:"), every other
// character matches itself.
func TestMatchLabelGlob(t *testing.T) {
	for _, tc := range []struct {
		pattern, label string
		want           bool
	}{
		{"scope:*", "scope:product", true},
		{"scope:*", "scope:", false},
		{"*", "", false},
		{"*", "x", true},
		{"a*b", "ab", false},
		{"a*b", "axb", true},
		{"a*b*c", "axbyc", true},
		{"a*b*c", "abc", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"*:done", "agent:done", true},
	} {
		if got := MatchLabelGlob(tc.pattern, tc.label); got != tc.want {
			t.Errorf("MatchLabelGlob(%q, %q) = %v, want %v", tc.pattern, tc.label, got, tc.want)
		}
	}
}

// TestValidateLabel is the provider-neutral wire-safety check both the
// daemon (CheckLabels) and the GitLab adapter apply.
func TestValidateLabel(t *testing.T) {
	for _, tc := range []struct {
		label string
		ok    bool
	}{
		{"scope:product", true},
		{"good first issue", true},
		{"", false},
		{"scope:x,agent:done", false},
		{"scope:x\nagent:done", false},
		{"scope:x\ragent:done", false},
		{"a\x00b", false},
		{" scope:x", false},
		{"scope:x ", false},
		// Re-review nits: invisible Unicode format characters (Cf) and a
		// length cap.
		{"scope:\u200bx", false},  // zero-width space
		{"scope:x\u200d", false},  // zero-width joiner
		{"scope:\u200cx", false},  // zero-width non-joiner
		{"\ufeffscope:x", false},  // BOM
		{"scope:\u202ex", false},  // right-to-left override
		{"scope:\u200fx", false},  // right-to-left mark
		{"scope:\u00e1rea", true}, // ordinary non-ASCII letters are fine
		{"scope:" + strings.Repeat("a", MaxLabelLength-6), true},
		{"scope:" + strings.Repeat("a", MaxLabelLength-5), false},
	} {
		err := ValidateLabel(tc.label)
		if tc.ok && err != nil {
			t.Errorf("ValidateLabel(%q) = %v, want nil", tc.label, err)
		}
		if !tc.ok && !errors.Is(err, ErrLabelInvalid) {
			t.Errorf("ValidateLabel(%q) = %v, want ErrLabelInvalid", tc.label, err)
		}
	}
}
