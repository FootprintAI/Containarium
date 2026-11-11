package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeCheckoutSweeper struct {
	got  *pb.SweepBoxRunCheckoutsRequest
	resp *pb.SweepBoxRunCheckoutsResponse
	err  error
}

func (f *fakeCheckoutSweeper) SweepBoxRunCheckouts(req *pb.SweepBoxRunCheckoutsRequest) (*pb.SweepBoxRunCheckoutsResponse, error) {
	f.got = req
	return f.resp, f.err
}

func sweepResp(d pb.BoxRunCheckoutDisposition) *pb.SweepBoxRunCheckoutsResponse {
	at := timestamppb.New(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	return &pb.SweepBoxRunCheckoutsResponse{
		PlatformRuns: true,
		MaxAge:       durationpb.New(7 * 24 * time.Hour),
		Checkouts: []*pb.BoxRunCheckout{
			{User: "alice", Name: "repo-run-0123abcd", SizeBytes: 2048, NewestModification: at, Disposition: d},
			{User: "alice", Name: "repo-run-ffffffff", Disposition: pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_SYMLINK},
		},
	}
}

func TestCodeSweepCheckouts(t *testing.T) {
	tests := []struct {
		name         string
		dryRun, all  bool
		resp         *pb.SweepBoxRunCheckoutsResponse
		want, absent []string
	}{
		{"dry run lists the removal set only", true, false, sweepResp(pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_WOULD_REMOVE),
			[]string{"Would remove 1 per-run checkout(s) on alice, 2.0 KiB", "alice:~/work/repo-run-0123abcd  2.0 KiB  modified 2026-10-01T00:00:00Z"}, []string{"repo-run-ffffffff"}},
		{"real run", false, false, sweepResp(pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_REMOVED),
			[]string{"Removed 1 per-run checkout(s)", "repo-run-0123abcd"}, []string{"repo-run-ffffffff"}},
		{"--all adds the kept ones with a reason", true, true, sweepResp(pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_WOULD_REMOVE),
			[]string{"repo-run-0123abcd", "repo-run-ffffffff", "(kept: symlink)"}, nil},
		{"a failure is always shown", false, false, sweepResp(pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_REMOVE_FAILED),
			[]string{"Removed 0 per-run checkout(s)", "repo-run-0123abcd", "(removal failed)"}, []string{"repo-run-ffffffff"}},
		{"a box without platform runs", false, false, &pb.SweepBoxRunCheckoutsResponse{},
			[]string{"no platform-started run on this box"}, []string{"Removed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeCheckoutSweeper{resp: tt.resp}
			var out bytes.Buffer
			if err := codeSweepCheckouts(f, "alice", tt.dryRun, tt.all, &out); err != nil {
				t.Fatal(err)
			}
			if f.got.GetUsername() != "alice" || f.got.GetDryRun() != tt.dryRun {
				t.Errorf("request = %v", f.got)
			}
			for _, w := range tt.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output %q missing %q", out.String(), w)
				}
			}
			for _, a := range tt.absent {
				if strings.Contains(out.String(), a) {
					t.Errorf("output %q has %q", out.String(), a)
				}
			}
		})
	}
}

func TestCodeSweepCheckouts_OldDaemon(t *testing.T) {
	f := &fakeCheckoutSweeper{err: status.Error(codes.Unimplemented, "unknown method")}
	err := codeSweepCheckouts(f, "alice", true, false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("err = %v", err)
	}
}
