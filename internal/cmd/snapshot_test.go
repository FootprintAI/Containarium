package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// CLI surface for container snapshots (#1160).
//
// The CLI is the canonical interface (CLAUDE.md: CLI-first, MCP wraps it), so
// these check what an operator actually sees — including the two numbers that
// are easy to confuse and the warning that stops a snapshot being mistaken
// for a backup.

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
// The commands print for humans, so the human-visible text is the contract
// worth asserting.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	os.Stdout = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// captureErr runs fn with its output swallowed and returns only its error.
func captureErr(t *testing.T, fn func() error) error {
	t.Helper()
	var err error
	captureStdout(t, func() { err = fn() })
	return err
}

type fakeSnapshotAPI struct {
	created      *pb.CreateContainerSnapshotRequest
	deleted      *pb.DeleteContainerSnapshotRequest
	listResp     *pb.ListContainerSnapshotsResponse
	rolledBack   *pb.RollbackContainerSnapshotRequest
	rollbackResp *pb.RollbackContainerSnapshotResponse
	err          error
}

func (f *fakeSnapshotAPI) CreateContainerSnapshot(req *pb.CreateContainerSnapshotRequest) (*pb.CreateContainerSnapshotResponse, error) {
	f.created = req
	if f.err != nil {
		return nil, f.err
	}
	return &pb.CreateContainerSnapshotResponse{
		Snapshot: &pb.ContainerSnapshot{Name: req.GetName()},
	}, nil
}

func (f *fakeSnapshotAPI) ListContainerSnapshots(*pb.ListContainerSnapshotsRequest) (*pb.ListContainerSnapshotsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.listResp, nil
}

func (f *fakeSnapshotAPI) DeleteContainerSnapshot(req *pb.DeleteContainerSnapshotRequest) (*pb.DeleteContainerSnapshotResponse, error) {
	f.deleted = req
	if f.err != nil {
		return nil, f.err
	}
	return &pb.DeleteContainerSnapshotResponse{FreedBytes: 4096}, nil
}

func (f *fakeSnapshotAPI) RollbackContainerSnapshot(req *pb.RollbackContainerSnapshotRequest) (*pb.RollbackContainerSnapshotResponse, error) {
	f.rolledBack = req
	if f.err != nil {
		return nil, f.err
	}
	return f.rollbackResp, nil
}

func (f *fakeSnapshotAPI) Close() error { return nil }

func withSnapshotAPI(t *testing.T, api *fakeSnapshotAPI) {
	t.Helper()
	prev := newSnapshotClientFn
	newSnapshotClientFn = func() (snapshotAPI, error) { return api, nil }
	t.Cleanup(func() { newSnapshotClientFn = prev })
}

func TestSnapshotCreate_SendsTheNameAndUsername(t *testing.T) {
	api := &fakeSnapshotAPI{}
	withSnapshotAPI(t, api)
	snapshotCreateName = "before-upgrade"
	t.Cleanup(func() { snapshotCreateName = "" })

	out := captureStdout(t, func() {
		if err := runSnapshotCreate(nil, []string{"alice"}); err != nil {
			t.Fatalf("runSnapshotCreate: %v", err)
		}
	})

	if api.created.GetUsername() != "alice" || api.created.GetName() != "before-upgrade" {
		t.Fatalf("sent %+v, want alice/before-upgrade", api.created)
	}
	// The warning is not decoration: "snapshot" gets heard as "backup", and
	// the difference only surfaces on the day the pool is gone.
	if !strings.Contains(out, "backup") {
		t.Errorf("create output never mentions that this is not an off-host backup:\n%s", out)
	}
}

func TestSnapshotCreate_RequiresAName(t *testing.T) {
	api := &fakeSnapshotAPI{}
	withSnapshotAPI(t, api)
	snapshotCreateName = ""

	if err := runSnapshotCreate(nil, []string{"alice"}); err == nil {
		t.Fatal("a snapshot with no name was accepted")
	}
	if api.created != nil {
		t.Errorf("the daemon was called anyway: %+v", api.created)
	}
}

// USED and REFERENCED must both be shown and be distinguishable. Printing
// only one — or the wrong one — is how an operator concludes a 60 GiB
// snapshot is free and leaves it there.
func TestSnapshotList_ShowsUsedAndReferencedSeparately(t *testing.T) {
	withSnapshotAPI(t, &fakeSnapshotAPI{listResp: &pb.ListContainerSnapshotsResponse{
		Snapshots: []*pb.ContainerSnapshot{
			{Name: "nightly", UsedBytes: 1024, ReferencedBytes: 10 * 1024 * 1024 * 1024},
		},
	}})

	out := captureStdout(t, func() {
		if err := runSnapshotList(nil, []string{"alice"}); err != nil {
			t.Fatalf("runSnapshotList: %v", err)
		}
	})

	for _, want := range []string{"nightly", "1.0 KiB", "10.0 GiB", "USED", "REFERENCED"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output is missing %q:\n%s", want, out)
		}
	}
}

func TestSnapshotList_SaysSoWhenThereAreNone(t *testing.T) {
	withSnapshotAPI(t, &fakeSnapshotAPI{listResp: &pb.ListContainerSnapshotsResponse{}})

	out := captureStdout(t, func() {
		if err := runSnapshotList(nil, []string{"alice"}); err != nil {
			t.Fatalf("runSnapshotList: %v", err)
		}
	})
	if !strings.Contains(out, "No snapshots") {
		t.Errorf("an empty list printed nothing an operator can read:\n%s", out)
	}
}

func TestSnapshotDelete_ReportsWhatWasFreed(t *testing.T) {
	api := &fakeSnapshotAPI{}
	withSnapshotAPI(t, api)

	out := captureStdout(t, func() {
		if err := runSnapshotDelete(nil, []string{"alice", "nightly"}); err != nil {
			t.Fatalf("runSnapshotDelete: %v", err)
		}
	})

	if api.deleted.GetName() != "nightly" {
		t.Fatalf("deleted %+v, want nightly", api.deleted)
	}
	if !strings.Contains(out, "4.0 KiB") {
		t.Errorf("the reclaimed space is not reported:\n%s", out)
	}
}

// A daemon-side failure must reach the exit code, not just stdout.
func TestSnapshotCommands_PropagateTheDaemonError(t *testing.T) {
	withSnapshotAPI(t, &fakeSnapshotAPI{err: errors.New("dataset is busy")})

	snapshotCreateName = "x"
	t.Cleanup(func() { snapshotCreateName = "" })
	for name, run := range map[string]func() error{
		"create": func() error { return runSnapshotCreate(nil, []string{"alice"}) },
		"list":   func() error { return runSnapshotList(nil, []string{"alice"}) },
		"delete": func() error { return runSnapshotDelete(nil, []string{"alice", "x"}) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := captureErr(t, run); err == nil {
				t.Fatal("a daemon failure exited 0, so a script would carry on as if it worked")
			}
		})
	}
}

// humanBytes is shared with `backup`, and the snapshot list output above is
// asserted through it — so the sizes it produces are pinned here rather than
// left to the eye.
func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{3 * 1024 * 1024 * 1024, "3.0 GiB"},
		{2 * 1024 * 1024 * 1024 * 1024, "2.0 TiB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Rollback CLI (#1160b). The flags gate a destructive operation, so what
// matters is that they reach the daemon exactly as typed — a `--force` that
// silently does not travel turns a refusal into a confusing one, and a
// `--destroy-newer` that travels when unset destroys restore points nobody
// agreed to lose.
func TestSnapshotRollback_ForwardsTheDestructiveFlags(t *testing.T) {
	cases := []struct {
		name                      string
		force, destroyNewer       bool
		wantForce, wantDestroyNew bool
	}{
		{name: "neither"},
		{name: "force only", force: true, wantForce: true},
		{name: "destroy-newer only", destroyNewer: true, wantDestroyNew: true},
		{name: "both", force: true, destroyNewer: true, wantForce: true, wantDestroyNew: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := &fakeSnapshotAPI{rollbackResp: &pb.RollbackContainerSnapshotResponse{}}
			withSnapshotAPI(t, api)
			snapshotRollbackForce, snapshotRollbackDestroyNewer = c.force, c.destroyNewer
			t.Cleanup(func() { snapshotRollbackForce, snapshotRollbackDestroyNewer = false, false })

			captureStdout(t, func() {
				if err := runSnapshotRollback(nil, []string{"alice", "nightly"}); err != nil {
					t.Fatalf("runSnapshotRollback: %v", err)
				}
			})

			if api.rolledBack.GetForce() != c.wantForce {
				t.Errorf("force = %v, want %v", api.rolledBack.GetForce(), c.wantForce)
			}
			if api.rolledBack.GetDestroyNewer() != c.wantDestroyNew {
				t.Errorf("destroy_newer = %v, want %v", api.rolledBack.GetDestroyNewer(), c.wantDestroyNew)
			}
		})
	}
}

// Two things the operator must not have to discover for themselves: that the
// container is down, and which restore points are gone.
func TestSnapshotRollback_ReportsTheAftermath(t *testing.T) {
	withSnapshotAPI(t, &fakeSnapshotAPI{rollbackResp: &pb.RollbackContainerSnapshotResponse{
		ContainerStopped:   true,
		DestroyedSnapshots: []string{"weekly", "monthly"},
	}})

	out := captureStdout(t, func() {
		if err := runSnapshotRollback(nil, []string{"alice", "nightly"}); err != nil {
			t.Fatalf("runSnapshotRollback: %v", err)
		}
	})

	if !strings.Contains(out, "stopped") {
		t.Errorf("the output does not say the container is down, so an operator would assume it "+
			"came back up:\n%s", out)
	}
	for _, want := range []string{"weekly", "monthly"} {
		if !strings.Contains(out, want) {
			t.Errorf("the destroyed snapshot %q is not named — nothing else records which restore "+
				"points were lost:\n%s", want, out)
		}
	}
}

func TestSnapshotRollback_PropagatesTheRefusal(t *testing.T) {
	withSnapshotAPI(t, &fakeSnapshotAPI{err: errors.New("container alice is running")})

	if err := captureErr(t, func() error {
		return runSnapshotRollback(nil, []string{"alice", "nightly"})
	}); err == nil {
		t.Fatal("a refused rollback exited 0, so a script would carry on as if the data had been " +
			"restored")
	}
}
