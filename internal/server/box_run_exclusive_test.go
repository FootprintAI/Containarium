//go:build !containarium_client

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// busyReason returns the typed refusal reason of err, or UNSPECIFIED.
func busyReason(err error) pb.BoxRunBusyReason {
	for _, d := range status.Convert(err).Details() {
		if pf, ok := d.(*errdetails.PreconditionFailure); ok && len(pf.GetViolations()) == 1 {
			return pb.BoxRunBusyReason(pb.BoxRunBusyReason_value[pf.GetViolations()[0].GetType()])
		}
	}
	return pb.BoxRunBusyReason_BOX_RUN_BUSY_REASON_UNSPECIFIED
}

// An exclusive start is refused while any other run is live on the box.
func TestStartBoxRun_ExclusiveRefusedWhileAnotherRunIsLive(t *testing.T) {
	u := newFakeBoxUser(t, 0, 2*time.Second)
	s, _, _ := boxRunStartServer(t, u)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "plain", RunName: "plain-run",
	}); err != nil {
		t.Fatalf("plain StartBoxRun: %v", err)
	}
	_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "exclusive", RunName: "excl-run", Exclusive: true,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("exclusive StartBoxRun err = %v, want FailedPrecondition", err)
	}
	if got := busyReason(err); got != pb.BoxRunBusyReason_BOX_RUN_BUSY_REASON_OTHER_RUN_LIVE {
		t.Errorf("busy reason = %v, want OTHER_RUN_LIVE (err: %v)", got, err)
	}
}

// While an exclusive run is live, every other start on the box is refused,
// whether or not it asks to be exclusive.
func TestStartBoxRun_LiveExclusiveRunRefusesEveryOtherStart(t *testing.T) {
	u := newFakeBoxUser(t, 0, 2*time.Second)
	s, _, _ := boxRunStartServer(t, u)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "holder", RunName: "holder", Exclusive: true,
	}); err != nil {
		t.Fatalf("exclusive StartBoxRun: %v", err)
	}
	for _, excl := range []bool{false, true} {
		_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
			Username: "alice", Prompt: "other", RunName: fmt.Sprintf("other-%v", excl), Exclusive: excl,
		})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("start (exclusive=%v) err = %v, want FailedPrecondition", excl, err)
		}
		if got := busyReason(err); got != pb.BoxRunBusyReason_BOX_RUN_BUSY_REASON_EXCLUSIVE_RUN_LIVE {
			t.Errorf("start (exclusive=%v) busy reason = %v, want EXCLUSIVE_RUN_LIVE", excl, got)
		}
	}
}

// Once the exclusive run has ended, the box takes new starts again.
func TestStartBoxRun_BoxIsFreeOnceTheExclusiveRunEnds(t *testing.T) {
	u := newFakeBoxUser(t, 0, 200*time.Millisecond)
	s, _, _ := boxRunStartServer(t, u)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "holder", RunName: "holder", Exclusive: true,
	}); err != nil {
		t.Fatalf("exclusive StartBoxRun: %v", err)
	}
	waitForOutcome(t, s, "alice", "holder", pb.BoxRunOutcome_BOX_RUN_OUTCOME_EXITED, 3*time.Second)
	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "next", RunName: "next",
	}); err != nil {
		t.Fatalf("start after the exclusive run ended: %v", err)
	}
}

// Of concurrent exclusive starts on one box exactly one succeeds, and a
// successful exclusive start is the only run that started.
func TestStartBoxRun_ConcurrentExclusiveStartsOneWins(t *testing.T) {
	u := newFakeBoxUser(t, 0, 2*time.Second)
	s, _, _ := boxRunStartServer(t, u)

	const n = 8
	var mu sync.Mutex
	var ok int
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
				Username: "alice", Prompt: "race", RunName: fmt.Sprintf("excl-%d", i), Exclusive: true,
			})
			switch {
			case err == nil:
				mu.Lock()
				ok++
				mu.Unlock()
			case status.Code(err) == codes.FailedPrecondition && busyReason(err) != pb.BoxRunBusyReason_BOX_RUN_BUSY_REASON_UNSPECIFIED:
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("%d concurrent exclusive starts succeeded, want exactly 1", ok)
	}
}

// Mixed concurrent starts: if an exclusive start wins, nothing else started.
func TestStartBoxRun_ExclusiveWinnerIsAloneOnTheBox(t *testing.T) {
	u := newFakeBoxUser(t, 0, 2*time.Second)
	s, _, _ := boxRunStartServer(t, u)

	const n = 8
	var mu sync.Mutex
	var okExcl, okPlain int
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		excl := i%2 == 0
		go func(i int, excl bool) {
			defer wg.Done()
			_, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
				Username: "alice", Prompt: "race", RunName: fmt.Sprintf("mix-%d", i), Exclusive: excl,
			})
			if err == nil {
				mu.Lock()
				if excl {
					okExcl++
				} else {
					okPlain++
				}
				mu.Unlock()
			}
		}(i, excl)
	}
	wg.Wait()
	if okExcl > 1 || (okExcl == 1 && okPlain > 0) {
		t.Errorf("exclusive starts=%d plain starts=%d: an exclusive run must be alone on the box", okExcl, okPlain)
	}
}

// The flag is recorded on the run, so a daemon restart still sees it.
func TestStartBoxRun_ExclusiveIsRecordedOnTheRun(t *testing.T) {
	u := newFakeBoxUser(t, 0, 2*time.Second)
	s, dir, _ := boxRunStartServer(t, u)

	if _, err := s.StartBoxRun(tenantCtx("alice"), &pb.StartBoxRunRequest{
		Username: "alice", Prompt: "holder", RunName: "holder", Exclusive: true,
	}); err != nil {
		t.Fatalf("StartBoxRun: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "holder.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"exclusive":true`) {
		t.Errorf("run record does not carry the exclusive flag: %s", b)
	}
}
