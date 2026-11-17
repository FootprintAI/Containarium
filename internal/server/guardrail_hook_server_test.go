package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/guardraildropin"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fakeGuardrailHookManager struct {
	set  []bool
	rows []guardraildropin.BoxCoverage
}

func (f *fakeGuardrailHookManager) SetEnabled(username string, enabled bool) (guardraildropin.BoxCoverage, error) {
	if username == "ghost" {
		return guardraildropin.BoxCoverage{}, guardraildropin.ErrBoxNotFound
	}
	if username == "broken" {
		return guardraildropin.BoxCoverage{}, errors.New("open /var/lib/secret/path: permission denied")
	}
	f.set = append(f.set, enabled)
	return guardraildropin.BoxCoverage{Username: username, Enabled: enabled}, nil
}

func (f *fakeGuardrailHookManager) Coverage(username string) (guardraildropin.BoxCoverage, error) {
	return guardraildropin.BoxCoverage{Username: username, Enabled: true, Result: guardraildropin.Result{
		Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED, Detail: "why", ClientVersion: "2.1.326", ClientInstalled: true}}, nil
}

func (f *fakeGuardrailHookManager) List() ([]guardraildropin.BoxCoverage, error) { return f.rows, nil }

func TestGuardrailHookServerAuthz(t *testing.T) {
	mgr := &fakeGuardrailHookManager{rows: []guardraildropin.BoxCoverage{{Username: "alice"}}}
	srv := NewGuardrailHookServer()
	srv.SetManager(mgr)

	tests := []struct {
		name string
		call func(context.Context) error
		ctx  context.Context
		want codes.Code
	}{
		{"set: a tenant cannot switch their own box", func(c context.Context) error {
			_, err := srv.SetGuardrailHook(c, &pb.SetGuardrailHookRequest{Username: "alice", Enabled: false})
			return err
		}, tenantCtx("alice"), codes.PermissionDenied},
		{"set: admin", func(c context.Context) error {
			_, err := srv.SetGuardrailHook(c, &pb.SetGuardrailHookRequest{Username: "alice", Enabled: true})
			return err
		}, adminCtx(), codes.OK},
		{"set: no username", func(c context.Context) error {
			_, err := srv.SetGuardrailHook(c, &pb.SetGuardrailHookRequest{})
			return err
		}, adminCtx(), codes.InvalidArgument},
		{"set: unknown box", func(c context.Context) error {
			_, err := srv.SetGuardrailHook(c, &pb.SetGuardrailHookRequest{Username: "ghost"})
			return err
		}, adminCtx(), codes.NotFound},
		{"get: own box", func(c context.Context) error {
			_, err := srv.GetGuardrailHookCoverage(c, &pb.GetGuardrailHookCoverageRequest{Username: "alice"})
			return err
		}, tenantCtx("alice"), codes.OK},
		{"get: another tenant's box", func(c context.Context) error {
			_, err := srv.GetGuardrailHookCoverage(c, &pb.GetGuardrailHookCoverageRequest{Username: "bob"})
			return err
		}, tenantCtx("alice"), codes.PermissionDenied},
		{"list: tenant", func(c context.Context) error {
			_, err := srv.ListGuardrailHookCoverage(c, &pb.ListGuardrailHookCoverageRequest{})
			return err
		}, tenantCtx("alice"), codes.PermissionDenied},
		{"list: unauthenticated", func(c context.Context) error {
			_, err := srv.ListGuardrailHookCoverage(c, &pb.ListGuardrailHookCoverageRequest{})
			return err
		}, context.Background(), codes.Unauthenticated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := status.Code(tc.call(tc.ctx)); got != tc.want {
				t.Fatalf("code = %v, want %v", got, tc.want)
			}
		})
	}
	if len(mgr.set) != 1 || !mgr.set[0] {
		t.Fatalf("manager saw sets %v, want exactly the admin's enable", mgr.set)
	}
}

func TestGuardrailHookServerMapsTheTypedResult(t *testing.T) {
	srv := NewGuardrailHookServer()
	srv.SetManager(&fakeGuardrailHookManager{})
	resp, err := srv.GetGuardrailHookCoverage(adminCtx(), &pb.GetGuardrailHookCoverageRequest{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	b := resp.GetBox()
	if b.GetUsername() != "alice" || !b.GetEnabled() || !b.GetClientInstalled() || b.GetDetail() != "why" || b.GetClientVersion() != "2.1.326" ||
		b.GetCoverage() != pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED {
		t.Fatalf("box = %v", b)
	}
	if b.GetCheckedAt() != nil {
		t.Errorf("a result that was never checked must leave checked_at unset, got %v", b.GetCheckedAt())
	}
}

// An internal error's text stays in the daemon's log.
func TestGuardrailHookServerDoesNotReturnInternalErrorText(t *testing.T) {
	srv := NewGuardrailHookServer()
	srv.SetManager(&fakeGuardrailHookManager{})
	_, err := srv.SetGuardrailHook(adminCtx(), &pb.SetGuardrailHookRequest{Username: "broken", Enabled: true})
	if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "/var/lib") {
		t.Fatalf("err = %v", err)
	}
}

// A daemon with no LXC runtime has no root path into a box.
func TestGuardrailHookServerWithoutManager(t *testing.T) {
	srv := NewGuardrailHookServer()
	_, err := srv.ListGuardrailHookCoverage(adminCtx(), &pb.ListGuardrailHookCoverageRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}
