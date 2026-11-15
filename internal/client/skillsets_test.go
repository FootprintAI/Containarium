package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeApplier struct {
	calls int
	got   *pb.ApplyBoxSkillSetsRequest
	resp  *pb.ApplyBoxSkillSetsResponse
	err   error
}

func (f *fakeApplier) ApplyBoxSkillSets(req *pb.ApplyBoxSkillSetsRequest) (*pb.ApplyBoxSkillSetsResponse, error) {
	f.calls++
	f.got = req
	return f.resp, f.err
}

func refusalStatus(t *testing.T, reason pb.BoxSkillSetsRefusal, msg string) error {
	t.Helper()
	if reason == pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET {
		st, err := status.New(codes.InvalidArgument, msg).WithDetails(&errdetails.BadRequest{
			FieldViolations: []*errdetails.BadRequest_FieldViolation{{Field: "skill_sets", Reason: reason.String()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return st.Err()
	}
	st, err := status.New(codes.FailedPrecondition, msg).WithDetails(&errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{Type: reason.String(), Subject: "alice"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

func TestApplySkillSets_TypedRefusals(t *testing.T) {
	for _, reason := range []pb.BoxSkillSetsRefusal{
		pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS,
		pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_SET_PREDATES_MANIFEST,
		pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET,
	} {
		t.Run(reason.String(), func(t *testing.T) {
			f := &fakeApplier{err: refusalStatus(t, reason, "daemon says no")}
			_, err := ApplySkillSets(f, "alice", []string{"qa"}, "")
			var refused *SkillSetsRefusedError
			if !errors.As(err, &refused) {
				t.Fatalf("err = %v, want *SkillSetsRefusedError", err)
			}
			if refused.Reason != reason || refused.Message != "daemon says no" || refused.Box != "alice" {
				t.Errorf("refusal = %+v", refused)
			}
			want := "apply skill sets on alice: refused (" + strings.TrimPrefix(reason.String(), "BOX_SKILL_SETS_REFUSAL_") + "): daemon says no"
			if err.Error() != want {
				t.Errorf("message = %q, want %q", err.Error(), want)
			}
		})
	}
}

// A bad release tag is rejected before the client is called.
func TestApplySkillSets_BadReleaseSendsNothing(t *testing.T) {
	f := &fakeApplier{}
	if _, err := ApplySkillSets(f, "alice", []string{"qa"}, "v1;rm -rf /"); err == nil {
		t.Fatal("bad release accepted")
	}
	if f.calls != 0 {
		t.Errorf("client called %d times", f.calls)
	}
}

// An empty target stays an explicit empty list (remove everything).
func TestApplySkillSets_PassesTarget(t *testing.T) {
	f := &fakeApplier{resp: &pb.ApplyBoxSkillSetsResponse{}}
	if _, err := ApplySkillSets(f, "alice", []string{}, " v0.89.0 "); err != nil {
		t.Fatal(err)
	}
	if f.got.GetUsername() != "alice" || len(f.got.GetSkillSets()) != 0 || f.got.GetRelease() != "v0.89.0" {
		t.Errorf("request = %v", f.got)
	}
}

func TestApplySkillSets_UnimplementedKeepsItsCode(t *testing.T) {
	f := &fakeApplier{err: status.Error(codes.Unimplemented, "nope")}
	_, err := ApplySkillSets(f, "alice", nil, "")
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("err = %v", err)
	}
}

// Over REST the gateway puts the status details in the error body; the HTTP
// client keeps them so the reason survives that transport (#3511).
func TestHTTPApplyBoxSkillSets_RefusalReasonOverREST(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   pb.BoxSkillSetsRefusal
	}{
		{"precondition", http.StatusBadRequest,
			`{"code":9,"message":"box has a run in progress","details":[{"@type":"type.googleapis.com/google.rpc.PreconditionFailure","violations":[{"type":"BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS","subject":"alice"}]}]}`,
			pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS},
		{"bad request", http.StatusBadRequest,
			`{"code":3,"message":"unknown set nope","details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"skill_sets","reason":"BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET"}]}]}`,
			pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c, err := NewHTTPClient(srv.URL, "tok")
			if err != nil {
				t.Fatal(err)
			}
			_, err = ApplySkillSets(c, "alice", []string{"qa"}, "")
			var refused *SkillSetsRefusedError
			if !errors.As(err, &refused) || refused.Reason != tc.want {
				t.Fatalf("err = %v, want refusal %s", err, tc.want)
			}
		})
	}
}

// Without details the HTTP error stays the plain message, as before.
func TestHTTPApplyBoxSkillSets_PlainErrorUnchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":13,"message":"boom"}`))
	}))
	defer srv.Close()
	c, _ := NewHTTPClient(srv.URL, "tok")
	_, err := c.ApplyBoxSkillSets(&pb.ApplyBoxSkillSetsRequest{Username: "alice"})
	if err == nil || err.Error() != "boom" {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateBoxName(t *testing.T) {
	for _, ok := range []string{"alice", "a-b_c9"} {
		if err := ValidateBoxName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Alice", "a.b", "a b", "../x", strings.Repeat("a", 33)} {
		if err := ValidateBoxName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A skills version is passed to the daemon as asked, validated first, and a
// daemon that ignored it is not reported as having moved the box.
func TestApplySkillSetsWith_SkillsVersion(t *testing.T) {
	f := &fakeApplier{resp: &pb.ApplyBoxSkillSetsResponse{SkillSets: []string{"qa"}, Release: "v1", SkillsVersion: "2026.11.0"}}
	resp, err := ApplySkillSetsWith(f, SkillSetsApply{Box: "alice", Target: []string{"qa"}, SkillsVersion: " 2026.11.0 "})
	if err != nil {
		t.Fatal(err)
	}
	if f.got.GetSkillsVersion() != "2026.11.0" || resp.GetSkillsVersion() != "2026.11.0" {
		t.Errorf("sent %q, got back %q", f.got.GetSkillsVersion(), resp.GetSkillsVersion())
	}
	if out := RenderSkillSetsApply("alice", resp); !strings.Contains(out, "skills release 2026.11.0") {
		t.Errorf("output %q does not name the skills release", out)
	}

	for _, bad := range []string{"1;rm -rf /", "../1", "$(id)", "a b"} {
		g := &fakeApplier{resp: &pb.ApplyBoxSkillSetsResponse{}}
		if _, err := ApplySkillSetsWith(g, SkillSetsApply{Box: "alice", Target: []string{"qa"}, SkillsVersion: bad}); err == nil || g.calls != 0 {
			t.Errorf("%q: err = %v, calls = %d; want a refusal before any request", bad, err, g.calls)
		}
	}

	// A daemon from before skills_version drops the field and answers without one.
	old := &fakeApplier{resp: &pb.ApplyBoxSkillSetsResponse{SkillSets: []string{"qa"}, Release: "v1"}}
	_, err = ApplySkillSetsWith(old, SkillSetsApply{Box: "alice", Target: []string{"qa"}, SkillsVersion: "2026.11.0"})
	if err == nil || !strings.Contains(err.Error(), "predates per-box skills versions") {
		t.Errorf("err = %v, want the older-daemon refusal", err)
	}
	// With no version asked for, an answer without one is normal.
	if _, err := ApplySkillSetsWith(old, SkillSetsApply{Box: "alice", Target: []string{"qa"}}); err != nil {
		t.Errorf("no version asked: %v", err)
	}
	if out := RenderSkillSetsApply("alice", old.resp); strings.Contains(out, "skills release") {
		t.Errorf("output %q names a skills release the box is not on", out)
	}
}
