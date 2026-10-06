package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/anonbox"
	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fakeAnonDoor struct {
	cfg    anonbox.DoorConfig
	err    error
	setErr error
}

func (f *fakeAnonDoor) DoorConfig() anonbox.DoorConfig           { return f.cfg }
func (f *fakeAnonDoor) SetDoorConfig(c anonbox.DoorConfig) error { f.cfg = c; return f.setErr }
func (f *fakeAnonDoor) DoorErr() error                           { return f.err }

func TestDoorConfig_GetAndSet(t *testing.T) {
	door := &fakeAnonDoor{cfg: anonbox.DefaultDoorConfig()}
	srv := anonSrv(nil, nil)
	srv.SetDoor(door)

	got, err := srv.GetAnonymousDoorConfig(testCtx(), &pb.GetAnonymousDoorConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Limits.MaxBoxes != 20 || got.Limits.PerFingerprintBurst != 2 || got.Limits.PerIpBurst != 6 || got.Limits.TtlSeconds != 4*3600 {
		t.Errorf("get = %+v / %+v", got, got.Limits)
	}

	set, err := srv.SetAnonymousDoorConfig(testCtx(), &pb.SetAnonymousDoorConfigRequest{Config: &pb.AnonymousDoorConfig{
		Enabled: false, DisabledMessage: "closed", BannedFingerprints: []string{"SHA256:x"},
		Limits: &pb.AnonymousBoxLimits{MaxBoxes: 999}, // read-only: ignored
	}})
	if err != nil {
		t.Fatal(err)
	}
	if set.Enabled || set.DisabledMessage != "closed" || len(set.BannedFingerprints) != 1 || set.Limits.MaxBoxes != 20 {
		t.Errorf("set echoed %+v / %+v", set, set.Limits)
	}
	if door.cfg.Enabled || door.cfg.DisabledMessage != "closed" || door.cfg.BannedFingerprints[0] != "SHA256:x" {
		t.Errorf("door got %+v", door.cfg)
	}

	// Guards: no config → InvalidArgument; persist failure → Internal; no door → Unimplemented.
	if _, err := srv.SetAnonymousDoorConfig(testCtx(), &pb.SetAnonymousDoorConfigRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil config: %v", err)
	}
	door.setErr = errors.New("disk full")
	if _, err := srv.SetAnonymousDoorConfig(testCtx(), &pb.SetAnonymousDoorConfigRequest{Config: &pb.AnonymousDoorConfig{Enabled: true}}); status.Code(err) != codes.Internal {
		t.Errorf("persist failure: %v", err)
	}
	if _, err := anonSrv(nil, nil).SetAnonymousDoorConfig(testCtx(), &pb.SetAnonymousDoorConfigRequest{Config: &pb.AnonymousDoorConfig{}}); status.Code(err) != codes.Unimplemented {
		t.Errorf("no door: %v", err)
	}
	// Still gated.
	user := auth.ContextWithTestSubject(context.Background(), "alice", "user")
	if _, err := srv.SetAnonymousDoorConfig(user, &pb.SetAnonymousDoorConfigRequest{Config: &pb.AnonymousDoorConfig{}}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("user: %v", err)
	}
}

func TestEnsureAnonymousBox_GuardrailErrorMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
		msg  string
	}{
		{"door closed", anonbox.DoorClosedError{Message: "closed for maintenance"}, codes.FailedPrecondition, "closed for maintenance"},
		{"door closed, default message", anonbox.DoorClosedError{}, codes.FailedPrecondition, "door is closed"},
		{"banned", anonbox.ErrBanned, codes.PermissionDenied, "banned"},
		{"rate limited", anonbox.ErrRateLimited, codes.ResourceExhausted, "slow down"},
		{"full", anonbox.ErrAtCapacity, codes.ResourceExhausted, "we're full"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := anonSrv(&fakeAnonEnsurer{err: tt.err}, nil)
			_, err := srv.EnsureAnonymousBox(testCtx(), &pb.EnsureAnonymousBoxRequest{PublicKey: "ssh-ed25519 AAAA x"})
			if status.Code(err) != tt.want || !strings.Contains(status.Convert(err).Message(), tt.msg) {
				t.Errorf("got %v / %q, want %v containing %q", status.Code(err), status.Convert(err).Message(), tt.want, tt.msg)
			}
			if strings.HasPrefix(status.Convert(err).Message(), "anonbox:") {
				t.Errorf("message leaks the package prefix: %q", status.Convert(err).Message())
			}
		})
	}
}

func TestAnonRouteGuard(t *testing.T) {
	labels := map[string]map[string]string{
		"anon-1a2b3c4d-container": {anonbox.LabelFingerprint: "SHA256:x"},
		"anon-ffffffff-container": {anonbox.LabelFingerprint: "SHA256:y", anonbox.LabelClaimedAt: "2026-10-01T00:00:00Z"},
		"alice-container":         {"team": "x"},
	}
	guard := AnonRouteGuard(func(name string) (map[string]string, error) {
		if l, ok := labels[name]; ok {
			return l, nil
		}
		return nil, errors.New("incus: not found")
	})
	tests := []struct {
		name string
		want codes.Code
	}{
		{"anon-1a2b3c4d-container", codes.FailedPrecondition}, // unclaimed
		{"anon-ffffffff-container", codes.OK},                 // claimed
		{"alice-container", codes.OK},                         // ordinary box
		{"", codes.OK},                                        // nothing resolved
		{"bob-container", codes.OK},                           // lookup failed, not anon-shaped: never block
		{"anon-00000000-container", codes.FailedPrecondition}, // lookup failed, anon-shaped: fail closed
	}
	for _, tt := range tests {
		if got := status.Code(guard(tt.name)); got != tt.want {
			t.Errorf("%q → %v, want %v", tt.name, got, tt.want)
		}
	}

	// NetworkServer runs it before touching any store; nil guard = no check.
	ns := &NetworkServer{}
	if err := ns.guardAnon("anon-1a2b3c4d-container"); err != nil {
		t.Errorf("no guard installed: %v", err)
	}
	ns.SetAnonGuard(guard)
	if status.Code(ns.guardAnon("anon-1a2b3c4d-container")) != codes.FailedPrecondition {
		t.Errorf("installed guard not applied")
	}
}
