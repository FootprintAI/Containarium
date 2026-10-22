package server

import (
	"context"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func denyCidrs(rules []*pb.NetworkPolicyDenyRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.GetCidr())
	}
	return out
}

func TestApplyQuarantine(t *testing.T) {
	exp := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)

	// Empty → adds the quarantine rule with our note + expiry.
	got := applyQuarantine(nil, exp)
	if len(got) != 1 || got[0].GetCidr() != quarantineCIDR || got[0].GetNote() != quarantineNote {
		t.Fatalf("quarantine add wrong: %+v", got)
	}
	if got[0].GetExpiresAt() == "" {
		t.Error("quarantine rule should carry an expiry backstop")
	}

	// Re-apply with a later expiry → refreshes ours, no duplicate.
	exp2 := exp.Add(time.Hour)
	got2 := applyQuarantine(got, exp2)
	if len(got2) != 1 || got2[0].GetExpiresAt() != exp2.UTC().Format(time.RFC3339) {
		t.Fatalf("re-apply should refresh expiry without duplicating: %+v", got2)
	}

	// An operator's OWN 0.0.0.0/0 deny (different note) is left untouched.
	op := []*pb.NetworkPolicyDenyRule{{Cidr: "0.0.0.0/0", Note: "operator block"}}
	got3 := applyQuarantine(op, exp)
	if len(got3) != 1 || got3[0].GetNote() != "operator block" {
		t.Fatalf("operator's 0.0.0.0/0 deny must not be overwritten: %+v", got3)
	}

	// A pre-existing unrelated deny rule is preserved alongside the new quarantine.
	other := []*pb.NetworkPolicyDenyRule{{Cidr: "1.2.3.4/32", Note: "CVE-x"}}
	got4 := applyQuarantine(other, exp)
	if len(got4) != 2 {
		t.Fatalf("should keep the unrelated rule and add quarantine: %+v", denyCidrs(got4))
	}
}

// fakeMutator records the deny rules after each mutation, applying the mutator
// to its current state (like the real atomic store).
type fakeMutator struct {
	rules []*pb.NetworkPolicyDenyRule
	calls int
}

func (f *fakeMutator) MutateDenyRules(_ context.Context, _ string, fn func([]*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error)) (*pb.NetworkPolicy, error) {
	f.calls++
	out, err := fn(f.rules)
	if err != nil {
		return nil, err
	}
	f.rules = out
	return &pb.NetworkPolicy{DenyRules: out}, nil
}

func TestAutoQuarantine_OnScanResult(t *testing.T) {
	f := &fakeMutator{}
	q := &AutoQuarantine{store: f, ttl: time.Hour, now: func() time.Time { return time.Unix(0, 0).UTC() }}

	// infected → quarantine rule added.
	q.OnScanResult("alice-container", "alice", "infected")
	if len(f.rules) != 1 || f.rules[0].GetNote() != quarantineNote {
		t.Fatalf("infected should add quarantine: %+v", f.rules)
	}

	// re-infected → no duplicate (refresh).
	q.OnScanResult("alice-container", "alice", "infected")
	if len(f.rules) != 1 {
		t.Fatalf("re-infected should not duplicate: %+v", denyCidrs(f.rules))
	}

	// clean → NOT released (#2631): the verdict is produced inside the tenant's
	// own box, so a compromised box must not be able to lift its own quarantine.
	callsBefore := f.calls
	q.OnScanResult("alice-container", "alice", "clean")
	if len(f.rules) != 1 || f.rules[0].GetNote() != quarantineNote {
		t.Fatalf("clean must leave the quarantine in place: %+v", denyCidrs(f.rules))
	}
	if f.calls != callsBefore {
		t.Errorf("clean must not touch the store (calls %d→%d)", callsBefore, f.calls)
	}

	// unknown status / empty tenant → no store call.
	before := f.calls
	q.OnScanResult("x", "alice", "scanning")
	q.OnScanResult("x", "", "infected")
	if f.calls != before {
		t.Errorf("unknown status / empty tenant should not touch the store (calls %d→%d)", before, f.calls)
	}
}
