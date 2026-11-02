//go:build !containarium_client

package server

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/network"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3441: the replay of remembered deletes must finish before the passthrough
// RPCs go live, and a failed replay must be findable in the log.

// scriptedPassthroughStore wraps a store with hooks on the replay's two calls.
type scriptedPassthroughStore struct {
	network.PassthroughStore

	// onList runs before ListByContainer; a non-nil error fails the call.
	onList func(name string) error
	// deleteErr fails Delete for rows owned by these boxes.
	deleteErr map[int]error
}

func (s *scriptedPassthroughStore) ListByContainer(ctx context.Context, name string) ([]*network.PassthroughRecord, error) {
	if s.onList != nil {
		if err := s.onList(name); err != nil {
			return nil, err
		}
	}
	return s.PassthroughStore.ListByContainer(ctx, name)
}

func (s *scriptedPassthroughStore) Delete(ctx context.Context, port int, protocol string) error {
	if err := s.deleteErr[port]; err != nil {
		return err
	}
	return s.PassthroughStore.Delete(ctx, port, protocol)
}

func captureReplayLog(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	t.Cleanup(func() { log.SetOutput(log.Default().Writer()) })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func seedBox(t *testing.T, st network.PassthroughStore, name string, port int) {
	t.Helper()
	if err := st.Save(context.Background(), &network.PassthroughRecord{
		ExternalPort: port, TargetIP: "10.0.3.5", TargetPort: 80,
		Protocol: "tcp", ContainerName: name, Active: true,
	}); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

func hasRow(st network.PassthroughStore, port int) bool {
	_, err := st.GetByPortProtocol(context.Background(), port, "tcp")
	return err == nil
}

// AC1: a route added through the RPC for a remembered name while the replay
// is still running is either refused or survives; it is never deleted by the
// replay. Red when the RPCs go live before the replay.
func TestPassthroughRecovery_RouteAddedDuringReplayIsNotDeleted(t *testing.T) {
	ctx := context.Background()
	inner := &lockedPassthroughStore{inner: newFakePassthroughStore()}
	seedBox(t, inner, "box-container", 6000) // the deleted box's old row

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	st := &scriptedPassthroughStore{PassthroughStore: inner, onList: func(string) error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}}

	g := newPassthroughRecoveryRig()
	g.network.requirePassthroughStore()
	g.containers.requirePassthroughStore()
	g.containers.passthroughStoreForCascade("box-container") // deleted while absent

	done := make(chan struct{})
	go func() {
		defer close(done)
		g.consumers().install(ctx, st)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("replay never listed the remembered box")
	}

	// The recreated box gets a new route while the replay is blocked.
	_, addErr := g.network.AddPassthroughRoute(adminCtx(), &pb.AddPassthroughRouteRequest{
		ExternalPort: 6001, TargetIp: "10.0.3.7", TargetPort: 80, ContainerName: "box-container",
	})
	if addErr != nil && status.Code(addErr) != codes.Unavailable {
		t.Fatalf("add during replay: %v, want success or UNAVAILABLE", addErr)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("install did not finish")
	}

	if addErr == nil && !hasRow(inner, 6001) {
		t.Error("route accepted during the replay was deleted by the replay")
	}
	if hasRow(inner, 6000) {
		t.Error("remembered box's old row survived the replay")
	}
}

// AC2: a failing ListByContainer or Delete gives a distinct warning naming
// the box, the other remembered boxes are still cleaned, and the install log
// line counts the failures.
func TestPassthroughRecovery_FailedReplayWarnsAndCleansTheOthers(t *testing.T) {
	ctx := context.Background()
	inner := &lockedPassthroughStore{inner: newFakePassthroughStore()}
	seedBox(t, inner, "list-fails-container", 7001)
	seedBox(t, inner, "delete-fails-container", 7002)
	seedBox(t, inner, "fine-container", 7003)
	st := &scriptedPassthroughStore{
		PassthroughStore: inner,
		onList: func(name string) error {
			if name == "list-fails-container" {
				return errors.New("list boom")
			}
			return nil
		},
		deleteErr: map[int]error{7002: errors.New("delete boom")},
	}
	logs := captureReplayLog(t)

	g := newPassthroughRecoveryRig()
	g.network.requirePassthroughStore()
	g.containers.requirePassthroughStore()
	for _, n := range []string{"list-fails-container", "delete-fails-container", "fine-container"} {
		g.containers.passthroughStoreForCascade(n)
	}
	g.consumers().install(ctx, st)

	if hasRow(inner, 7003) {
		t.Error("a box after the failures was not cleaned")
	}
	out := logs()
	for _, name := range []string{"list-fails-container", "delete-fails-container"} {
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "passthrough replay") && strings.Contains(line, name) &&
				strings.Contains(line, "rows remain") && strings.Contains(line, "reconciled") {
				found = true
			}
		}
		if !found {
			t.Errorf("no distinct replay warning naming %s in log:\n%s", name, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "passthrough replay") && strings.Contains(line, "fine-container") {
			t.Errorf("replay warning names a box that was cleaned: %s", line)
		}
	}
	if !strings.Contains(out, "2 failed") {
		t.Errorf("install log line does not count 2 failed replays:\n%s", out)
	}
}

// The sync job is still built after the replay, and a clean replay reports
// zero failures.
func TestPassthroughRecovery_CleanReplayReportsNoFailures(t *testing.T) {
	ctx := context.Background()
	inner := &lockedPassthroughStore{inner: newFakePassthroughStore()}
	seedBox(t, inner, "gone-container", 8001)
	logs := captureReplayLog(t)

	g := newPassthroughRecoveryRig()
	g.network.requirePassthroughStore()
	g.containers.requirePassthroughStore()
	g.containers.passthroughStoreForCascade("gone-container")
	g.consumers().install(ctx, inner)

	if hasRow(inner, 8001) {
		t.Error("remembered box's row survived")
	}
	if out := logs(); !strings.Contains(out, "0 failed") || strings.Contains(out, "passthrough replay") {
		t.Errorf("clean replay log wrong:\n%s", out)
	}
	if n := len(g.jobs.built()); n != 1 {
		t.Errorf("sync jobs built = %d, want 1", n)
	}
}
