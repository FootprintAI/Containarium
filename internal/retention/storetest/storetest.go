// Package storetest is the behavioural contract every retention.Store must
// meet. The in-memory store runs it in the unit suite; the Postgres store
// runs it in the store-integration lane against a real database.
package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/internal/retention"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func window(c pb.RetentionClass, days int32) *pb.RetentionWindow {
	return &pb.RetentionWindow{Class: c, Days: days}
}

// days returns the policy's window per class.
func days(t *testing.T, p *pb.RetentionPolicy) map[pb.RetentionClass]*pb.RetentionWindow {
	t.Helper()
	out := map[pb.RetentionClass]*pb.RetentionWindow{}
	for _, w := range p.GetWindows() {
		out[w.GetClass()] = w
	}
	return out
}

// RunStoreContract runs the shared behaviour against stores built by newStore
// (each subtest gets a fresh, empty store).
func RunStoreContract(t *testing.T, newStore func(t *testing.T) retention.Store) {
	ctx := context.Background()

	t.Run("a fresh store reports the Q6 default for every class", func(t *testing.T) {
		p, err := newStore(t).GetPolicy(ctx)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		want := map[pb.RetentionClass]int32{
			pb.RetentionClass_RETENTION_CLASS_PROMPTS:             30,
			pb.RetentionClass_RETENTION_CLASS_RESPONSES:           30,
			pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS:        90,
			pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS: 90,
			pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES:    365,
		}
		if len(p.GetWindows()) != len(want) {
			t.Fatalf("windows = %v, want one per class (%d)", p.GetWindows(), len(want))
		}
		for i, w := range p.GetWindows() {
			if w.GetClass() != retention.Classes()[i] {
				t.Fatalf("window %d is %v, want %v (enum order)", i, w.GetClass(), retention.Classes()[i])
			}
			if w.GetDays() != want[w.GetClass()] || !w.GetIsDefault() {
				t.Errorf("%v = %d days (default %v), want the default %d", w.GetClass(), w.GetDays(), w.GetIsDefault(), want[w.GetClass()])
			}
		}
		if p.GetRevision() != 0 {
			t.Errorf("revision = %d, want 0 before any set", p.GetRevision())
		}
	})

	t.Run("set changes only the listed classes and round-trips", func(t *testing.T) {
		s := newStore(t)
		res, err := s.SetPolicy(ctx, []*pb.RetentionWindow{
			window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, 7),
			window(pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES, 400),
		}, "admin-a", nil)
		if err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}
		if res.Previous.GetRevision() != 0 || res.Current.GetRevision() != 1 {
			t.Fatalf("revisions = %d -> %d, want 0 -> 1", res.Previous.GetRevision(), res.Current.GetRevision())
		}
		got, err := s.GetPolicy(ctx)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		w := days(t, got)
		if d := w[pb.RetentionClass_RETENTION_CLASS_PROMPTS]; d.GetDays() != 7 || d.GetIsDefault() {
			t.Errorf("prompts = %v, want 7 days, set", d)
		}
		if d := w[pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES]; d.GetDays() != 400 || d.GetIsDefault() {
			t.Errorf("evidence bundles = %v, want 400 days, set", d)
		}
		if d := w[pb.RetentionClass_RETENTION_CLASS_RESPONSES]; d.GetDays() != 30 || !d.GetIsDefault() {
			t.Errorf("responses = %v, want the untouched default", d)
		}
		if got.GetRevision() != 1 || got.GetUpdatedBy() != "admin-a" || got.GetUpdatedAt() == nil {
			t.Errorf("bookkeeping = rev %d by %q at %v, want rev 1 by admin-a with a time", got.GetRevision(), got.GetUpdatedBy(), got.GetUpdatedAt())
		}
		if _, err := s.SetPolicy(ctx, []*pb.RetentionWindow{window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, 8)}, "admin-b", nil); err != nil {
			t.Fatalf("second SetPolicy: %v", err)
		}
		got, _ = s.GetPolicy(ctx)
		if got.GetRevision() != 2 || days(t, got)[pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES].GetDays() != 400 {
			t.Errorf("after a second set: %v, want revision 2 with evidence bundles still 400", got)
		}
	})

	t.Run("an invalid set is rejected and changes nothing", func(t *testing.T) {
		cases := map[string][]*pb.RetentionWindow{
			"empty":                nil,
			"zero days":            {window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, 0)},
			"negative days":        {window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, -1)},
			"one day over the cap": {window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, retention.MaxDays+1)},
			"max int32 days":       {window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, 1<<31-1)},
			"unspecified":          {window(pb.RetentionClass_RETENTION_CLASS_UNSPECIFIED, 30)},
			"unknown class":        {window(pb.RetentionClass(99), 30)},
			"repeated class": {
				window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, 10),
				window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, 20),
			},
			"one bad window among good ones": {
				window(pb.RetentionClass_RETENTION_CLASS_RESPONSES, 10),
				window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, 0),
			},
		}
		for name, ws := range cases {
			t.Run(name, func(t *testing.T) {
				s := newStore(t)
				if _, err := s.SetPolicy(ctx, ws, "admin-a", nil); !errors.Is(err, retention.ErrInvalid) {
					t.Fatalf("SetPolicy(%s) = %v, want ErrInvalid", name, err)
				}
				p, _ := s.GetPolicy(ctx)
				if p.GetRevision() != 0 || days(t, p)[pb.RetentionClass_RETENTION_CLASS_RESPONSES].GetDays() != 30 {
					t.Fatalf("policy after a rejected set = %v, want the untouched defaults", p)
				}
			})
		}
	})

	t.Run("the cap itself and one day are accepted", func(t *testing.T) {
		s := newStore(t)
		if retention.MaxDays != 36500 {
			t.Fatalf("MaxDays = %d, want 36500", retention.MaxDays)
		}
		if _, err := s.SetPolicy(ctx, []*pb.RetentionWindow{
			window(pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES, retention.MaxDays),
			window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, 1),
		}, "admin-a", nil); err != nil {
			t.Fatalf("SetPolicy at the bounds: %v", err)
		}
		p, _ := s.GetPolicy(ctx)
		if d := days(t, p)[pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES].GetDays(); d != retention.MaxDays {
			t.Fatalf("evidence bundles = %d, want %d", d, retention.MaxDays)
		}
	})

	t.Run("org ids are trimmed, so a padded id is the same org", func(t *testing.T) {
		s := newStore(t)
		h, err := s.SetHold(ctx, " org-a ", "case", "admin-a", nil)
		if err != nil || h.GetOrgId() != "org-a" {
			t.Fatalf("SetHold(\" org-a \") = (%v, %v), want the hold stored as org-a", h, err)
		}
		if _, err := s.SetHold(ctx, "org-a", "case", "admin-a", nil); !errors.Is(err, retention.ErrHoldExists) {
			t.Fatalf("SetHold(org-a) after the padded one = %v, want ErrHoldExists", err)
		}
		if r, err := s.ReleaseHold(ctx, "org-a\t", "admin-a", nil); err != nil || r.GetOrgId() != "org-a" {
			t.Fatalf("ReleaseHold(padded) = (%v, %v), want org-a released", r, err)
		}
	})

	t.Run("a failing beforeCommit discards the policy change", func(t *testing.T) {
		s := newStore(t)
		boom := errors.New("audit down")
		var seen *retention.PolicySetResult
		_, err := s.SetPolicy(ctx, []*pb.RetentionWindow{window(pb.RetentionClass_RETENTION_CLASS_PROMPTS, 7)}, "admin-a",
			func(r *retention.PolicySetResult) error { seen = r; return boom })
		if !errors.Is(err, boom) {
			t.Fatalf("SetPolicy = %v, want the hook's error", err)
		}
		if seen == nil || seen.Current.GetRevision() != 1 || days(t, seen.Current)[pb.RetentionClass_RETENTION_CLASS_PROMPTS].GetDays() != 7 {
			t.Fatalf("hook saw %v, want the pending revision 1 with prompts 7", seen)
		}
		p, _ := s.GetPolicy(ctx)
		if p.GetRevision() != 0 || days(t, p)[pb.RetentionClass_RETENTION_CLASS_PROMPTS].GetDays() != 30 {
			t.Fatalf("policy after a failed hook = %v, want unchanged", p)
		}
	})

	t.Run("hold, list and release round-trip per org", func(t *testing.T) {
		s := newStore(t)
		if hs, err := s.ListHolds(ctx); err != nil || len(hs) != 0 {
			t.Fatalf("ListHolds on a fresh store = (%v, %v), want none", hs, err)
		}
		for _, org := range []string{"org-b", "org-a"} {
			h, err := s.SetHold(ctx, org, "case 1", "admin-a", nil)
			if err != nil {
				t.Fatalf("SetHold(%s): %v", org, err)
			}
			if h.GetOrgId() != org || h.GetReason() != "case 1" || h.GetSetBy() != "admin-a" || h.GetSetAt() == nil {
				t.Fatalf("SetHold(%s) = %v", org, h)
			}
		}
		if _, err := s.SetHold(ctx, "org-a", "again", "admin-b", nil); !errors.Is(err, retention.ErrHoldExists) {
			t.Fatalf("second SetHold(org-a) = %v, want ErrHoldExists", err)
		}
		hs, err := s.ListHolds(ctx)
		if err != nil || len(hs) != 2 || hs[0].GetOrgId() != "org-a" || hs[1].GetOrgId() != "org-b" || hs[0].GetReason() != "case 1" {
			t.Fatalf("ListHolds = (%v, %v), want org-a then org-b, first reason kept", hs, err)
		}
		released, err := s.ReleaseHold(ctx, "org-a", "admin-b", nil)
		if err != nil || released.GetOrgId() != "org-a" || released.GetReason() != "case 1" {
			t.Fatalf("ReleaseHold(org-a) = (%v, %v), want the released hold", released, err)
		}
		if _, err := s.ReleaseHold(ctx, "org-a", "admin-b", nil); !errors.Is(err, retention.ErrHoldNotFound) {
			t.Fatalf("second ReleaseHold(org-a) = %v, want ErrHoldNotFound", err)
		}
		if hs, _ := s.ListHolds(ctx); len(hs) != 1 || hs[0].GetOrgId() != "org-b" {
			t.Fatalf("ListHolds after release = %v, want only org-b", hs)
		}
	})

	t.Run("an empty org or reason is rejected", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.SetHold(ctx, "", "case", "admin-a", nil); !errors.Is(err, retention.ErrInvalid) {
			t.Errorf("SetHold with no org = %v, want ErrInvalid", err)
		}
		if _, err := s.SetHold(ctx, "org-a", " ", "admin-a", nil); !errors.Is(err, retention.ErrInvalid) {
			t.Errorf("SetHold with no reason = %v, want ErrInvalid", err)
		}
		// A slash cannot travel in the REST path segment, so such a hold
		// could never be released over REST.
		if _, err := s.SetHold(ctx, "org/a", "case", "admin-a", nil); !errors.Is(err, retention.ErrInvalid) {
			t.Errorf("SetHold with a slash in the org = %v, want ErrInvalid", err)
		}
		if _, err := s.ReleaseHold(ctx, "", "admin-a", nil); !errors.Is(err, retention.ErrInvalid) {
			t.Errorf("ReleaseHold with no org = %v, want ErrInvalid", err)
		}
	})

	t.Run("a failing beforeCommit discards a hold and a release", func(t *testing.T) {
		s := newStore(t)
		boom := errors.New("audit down")
		fail := func(*pb.LegalHold) error { return boom }
		if _, err := s.SetHold(ctx, "org-a", "case", "admin-a", fail); !errors.Is(err, boom) {
			t.Fatalf("SetHold = %v, want the hook's error", err)
		}
		if hs, _ := s.ListHolds(ctx); len(hs) != 0 {
			t.Fatalf("holds after a failed hook = %v, want none", hs)
		}
		if _, err := s.SetHold(ctx, "org-a", "case", "admin-a", nil); err != nil {
			t.Fatalf("SetHold: %v", err)
		}
		if _, err := s.ReleaseHold(ctx, "org-a", "admin-a", fail); !errors.Is(err, boom) {
			t.Fatalf("ReleaseHold = %v, want the hook's error", err)
		}
		if hs, _ := s.ListHolds(ctx); len(hs) != 1 {
			t.Fatalf("holds after a failed release hook = %v, want the hold kept", hs)
		}
	})
}
