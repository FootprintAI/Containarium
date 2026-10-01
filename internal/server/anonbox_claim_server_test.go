package server

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/anonbox"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fakeAnonClaimer struct {
	got anonbox.ClaimRequest
	res *anonbox.ClaimResult
	err error
}

func (f *fakeAnonClaimer) Claim(_ context.Context, req anonbox.ClaimRequest) (*anonbox.ClaimResult, error) {
	f.got = req
	return f.res, f.err
}

func TestClaimAnonymousBox_MapsRequestAndResponse(t *testing.T) {
	cl := &fakeAnonClaimer{res: &anonbox.ClaimResult{BoxName: "anon-1a2b3c4d-container", Tenant: "qa-claim", SSHUser: "anon-1a2b3c4d"}}
	srv := anonSrv(nil, nil)
	srv.SetClaimer(cl)

	out, err := srv.ClaimAnonymousBox(testCtx(), &pb.ClaimAnonymousBoxRequest{
		ClaimToken: " v1.anon-1a2b3c4d-container.ff.1.id.mac ", Tenant: "qa-claim", AuthorizedKeys: []string{"ssh-ed25519 AAAA k"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cl.got.Token != "v1.anon-1a2b3c4d-container.ff.1.id.mac" || cl.got.Tenant != "qa-claim" || len(cl.got.AuthorizedKeys) != 1 {
		t.Errorf("manager got %+v", cl.got)
	}
	if out.BoxName != "anon-1a2b3c4d-container" || out.Tenant != "qa-claim" {
		t.Errorf("response = %+v", out)
	}
}

func TestClaimAnonymousBox_ErrorMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"second redeem", anonbox.ErrClaimAlreadyClaimed, codes.AlreadyExists},
		{"expired", anonbox.ErrClaimExpired, codes.FailedPrecondition},
		{"bad signature", errors.Join(anonbox.ErrClaimInvalid, errors.New("sig")), codes.PermissionDenied},
		{"box gone", anonbox.ErrClaimNotFound, codes.NotFound},
		{"bad tenant", anonbox.InvalidRequestError{Err: errors.New("invalid tenant")}, codes.InvalidArgument},
		{"backend", errors.New("incus down"), codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := anonSrv(nil, nil)
			srv.SetClaimer(&fakeAnonClaimer{err: tt.err})
			_, err := srv.ClaimAnonymousBox(testCtx(), &pb.ClaimAnonymousBoxRequest{ClaimToken: "t", Tenant: "u"})
			if status.Code(err) != tt.want {
				t.Errorf("code = %v (%v), want %v", status.Code(err), err, tt.want)
			}
		})
	}
}

func TestClaimAnonymousBox_GuardsBeforeManager(t *testing.T) {
	// Not enabled → Unimplemented (still after authz).
	srv := anonSrv(nil, nil)
	if _, err := srv.ClaimAnonymousBox(testCtx(), &pb.ClaimAnonymousBoxRequest{ClaimToken: "t", Tenant: "u"}); status.Code(err) != codes.Unimplemented {
		t.Errorf("no claimer: %v", err)
	}
	// Missing fields → InvalidArgument, manager never called.
	cl := &fakeAnonClaimer{}
	srv.SetClaimer(cl)
	for _, req := range []*pb.ClaimAnonymousBoxRequest{{Tenant: "u"}, {ClaimToken: "t"}, {}} {
		if _, err := srv.ClaimAnonymousBox(testCtx(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("req %+v: %v", req, err)
		}
	}
	if cl.got.Token != "" {
		t.Errorf("manager called with an incomplete request")
	}
}
