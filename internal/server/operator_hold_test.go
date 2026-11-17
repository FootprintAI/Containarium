package server

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/wake"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	"github.com/footprintai/containarium/pkg/core/recipes"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// holdTestBox is one box behind a mock backend that keeps instance config in
// a map and mirrors the hold key into ContainerInfo.Held, the way the real
// client reads it back. starts counts backend StartContainer calls.
type holdTestBox struct {
	mock   *incustest.MockBackend
	cfg    map[string]string
	starts int
	name   string
}

func newHoldTestBox(username, state string, cfg map[string]string) *holdTestBox {
	b := &holdTestBox{mock: incustest.NewMockBackend(), cfg: cfg, name: username + "-container"}
	info := &incus.ContainerInfo{Name: b.name, State: state, Held: cfg[incus.HoldKey] == "true"}
	b.mock.Containers[b.name] = info
	b.mock.GetRawInstanceFunc = func(string) (map[string]string, string, error) {
		out := map[string]string{}
		for k, v := range b.cfg {
			out[k] = v
		}
		return out, "", nil
	}
	b.mock.SetConfigFunc = func(_, k, v string) error {
		b.cfg[k] = v
		info.Held = b.cfg[incus.HoldKey] == "true"
		return nil
	}
	b.mock.UnsetConfigFunc = func(_, k string) error {
		delete(b.cfg, k)
		info.Held = b.cfg[incus.HoldKey] == "true"
		return nil
	}
	b.mock.StartContainerFunc = func(string) error {
		b.starts++
		info.State = "Running"
		return nil
	}
	return b
}

func (b *holdTestBox) server() *ContainerServer {
	return &ContainerServer{
		manager: container.NewWithBackend(b.mock),
		emitter: events.NewEmitter(events.NewBus()),
	}
}

func (b *holdTestBox) state() string { return b.mock.Containers[b.name].State }

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// StopContainer with hold stops the box, stores the hold on the instance,
// turns boot.autostart off and reports the hold on the returned box.
func TestStopContainer_HoldStopsAndHoldsTheBox(t *testing.T) {
	b := newHoldTestBox("alice", "Running", map[string]string{incus.BootAutostartKey: "true"})
	resp, err := b.server().StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice", Hold: true})
	if err != nil {
		t.Fatalf("StopContainer: %v", err)
	}
	if b.state() != "Stopped" {
		t.Errorf("state = %q, want Stopped", b.state())
	}
	if b.cfg[incus.HoldKey] != "true" {
		t.Errorf("%s = %q, want true", incus.HoldKey, b.cfg[incus.HoldKey])
	}
	if b.cfg[incus.BootAutostartKey] != "false" {
		t.Errorf("%s = %q, want false while held", incus.BootAutostartKey, b.cfg[incus.BootAutostartKey])
	}
	if resp.GetContainer() == nil || !resp.GetContainer().GetHeld() {
		t.Errorf("response box does not report the hold: %+v", resp.GetContainer())
	}
}

// A box that is already stopped (auto-slept, say) can still be put on hold.
func TestStopContainer_HoldOnAlreadyStoppedBox(t *testing.T) {
	b := newHoldTestBox("alice", "Stopped", map[string]string{incus.BootAutostartKey: "true"})
	resp, err := b.server().StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice", Hold: true})
	if err != nil {
		t.Fatalf("StopContainer: %v", err)
	}
	if b.cfg[incus.HoldKey] != "true" || b.cfg[incus.BootAutostartKey] != "false" {
		t.Errorf("already-stopped box was not held: config = %v", b.cfg)
	}
	if !resp.GetContainer().GetHeld() {
		t.Error("response box does not report the hold")
	}
}

// A hold that cannot be stored fails the call and the box is not stopped, so
// the operator never believes a box is held when it is not.
func TestStopContainer_HoldWriteFailureFailsTheStop(t *testing.T) {
	b := newHoldTestBox("alice", "Running", map[string]string{})
	b.mock.SetConfigFunc = func(string, string, string) error { return errors.New("incus refused") }
	_, err := b.server().StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice", Hold: true})
	if err == nil {
		t.Fatal("StopContainer returned nil although the hold could not be stored")
	}
	if b.state() != "Running" {
		t.Errorf("state = %q; a failed hold must not half-apply the stop", b.state())
	}
}

// A stop without hold leaves an existing hold in place.
func TestStopContainer_PlainStopKeepsExistingHold(t *testing.T) {
	b := newHoldTestBox("alice", "Stopped", map[string]string{incus.HoldKey: "true", incus.BootAutostartKey: "false"})
	if _, err := b.server().StopContainer(testCtx(), &pb.StopContainerRequest{Username: "alice"}); err != nil {
		t.Fatalf("StopContainer: %v", err)
	}
	if b.cfg[incus.HoldKey] != "true" {
		t.Error("a plain stop released the hold")
	}
}

// An explicit StartContainer on a held box starts it and lifts the hold:
// boot.autostart is back to what it was, so the box behaves as before.
func TestStartContainer_ExplicitStartLiftsTheHold(t *testing.T) {
	b := newHoldTestBox("alice", "Stopped", map[string]string{
		incus.HoldKey:              "true",
		incus.HoldPrevAutostartKey: "true",
		incus.BootAutostartKey:     "false",
	})
	logs := captureLogs(t)
	resp, err := b.server().StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	if b.starts != 1 || b.state() != "Running" {
		t.Errorf("starts = %d, state = %q; want the box started once", b.starts, b.state())
	}
	if _, held := b.cfg[incus.HoldKey]; held {
		t.Error("the hold was not cleared by an explicit start")
	}
	if b.cfg[incus.BootAutostartKey] != "true" {
		t.Errorf("%s = %q, want true (restored)", incus.BootAutostartKey, b.cfg[incus.BootAutostartKey])
	}
	if resp.GetContainer().GetHeld() {
		t.Error("response box still reports the hold")
	}
	if !strings.Contains(logs.String(), `[hold] released box="alice"`) {
		t.Errorf("release was not logged:\n%s", logs.String())
	}
}

// A start that respects the hold is refused and changes nothing.
func TestStartContainer_RespectHoldRefusesHeldBox(t *testing.T) {
	b := newHoldTestBox("alice", "Stopped", map[string]string{incus.HoldKey: "true", incus.BootAutostartKey: "false"})
	_, err := b.server().StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice", RespectHold: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v (err %v), want FailedPrecondition", status.Code(err), err)
	}
	if b.starts != 0 || b.state() != "Stopped" {
		t.Errorf("starts = %d, state = %q; a held box must not be started", b.starts, b.state())
	}
	if b.cfg[incus.HoldKey] != "true" || b.cfg[incus.BootAutostartKey] != "false" {
		t.Errorf("the refused start changed the hold: config = %v", b.cfg)
	}
}

// respect_hold is a no-op on a box that is not held.
func TestStartContainer_RespectHoldStartsUnheldBox(t *testing.T) {
	b := newHoldTestBox("alice", "Stopped", map[string]string{})
	if _, err := b.server().StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice", RespectHold: true}); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	if b.starts != 1 {
		t.Errorf("starts = %d, want 1", b.starts)
	}
}

// The wake-on-HTTP starter never starts a held box: it reports
// wake.ErrBoxHeld and the hold stays.
func TestWakeStarter_HeldBoxIsNotStarted(t *testing.T) {
	b := newHoldTestBox("alice", "Stopped", map[string]string{incus.HoldKey: "true", incus.BootAutostartKey: "false"})
	ready, _, _, err := NewWakeStarter(b.server(), 1).WakeForRequest(testCtx(), "alice", 8080)
	if !errors.Is(err, wake.ErrBoxHeld) {
		t.Fatalf("err = %v, want wake.ErrBoxHeld", err)
	}
	if ready {
		t.Error("ready = true for a held box")
	}
	if b.starts != 0 || b.state() != "Stopped" {
		t.Errorf("starts = %d, state = %q; a wake must not start a held box", b.starts, b.state())
	}
	if b.cfg[incus.HoldKey] != "true" {
		t.Error("a wake released the hold")
	}
}

// A wake that does start a box logs one line with the box name and reason.
func TestWakeStarter_DaemonStartIsLogged(t *testing.T) {
	b := newHoldTestBox("alice", "Stopped", map[string]string{})
	logs := captureLogs(t)
	_, _, _, _ = NewWakeStarter(b.server(), 1).WakeForRequest(testCtx(), "alice", 8080)
	if b.starts != 1 {
		t.Fatalf("starts = %d, want 1 (an unheld box still wakes)", b.starts)
	}
	if !strings.Contains(logs.String(), `[wake] started box="alice" reason=wake-on-http`) {
		t.Errorf("the daemon's own start was not logged:\n%s", logs.String())
	}
}

// ProvisionSkillBox / RunAgentSkill / RunCrew all reach the skill's box
// through provisionBoxOnly: a held box makes it fail with FailedPrecondition
// instead of starting the box.
func TestProvisionBoxOnly_HeldBoxIsRefused(t *testing.T) {
	b := newHoldTestBox("agent-prep-skill", "Stopped", map[string]string{incus.HoldKey: "true", incus.BootAutostartKey: "false"})
	catalog := recipes.New()
	if err := catalog.LoadFromBytes([]byte(postStartSkillRecipeYAML)); err != nil {
		t.Fatal(err)
	}
	s := &AgentSkillServer{recipes: &RecipeServer{catalog: catalog, containers: b.server()}}
	skill := &pb.AgentSkill{Id: "prep-skill", Box: &pb.AgentSkill_RecipeId{RecipeId: "prep"}}

	_, _, _, err := s.provisionBoxOnly(ctxAs("admin", true), skill, "", "")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v (err %v), want FailedPrecondition", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "held") {
		t.Errorf("error %q does not say the box is held", err)
	}
	if b.starts != 0 || b.state() != "Stopped" {
		t.Errorf("starts = %d, state = %q; a skill run must not start a held box", b.starts, b.state())
	}
}

// The same path still starts a stopped box that is not held.
func TestProvisionBoxOnly_UnheldStoppedBoxStillStarts(t *testing.T) {
	b := newHoldTestBox("agent-prep-skill", "Stopped", map[string]string{})
	catalog := recipes.New()
	if err := catalog.LoadFromBytes([]byte(postStartSkillRecipeYAML)); err != nil {
		t.Fatal(err)
	}
	s := &AgentSkillServer{recipes: &RecipeServer{catalog: catalog, containers: b.server()}}
	skill := &pb.AgentSkill{Id: "prep-skill", Box: &pb.AgentSkill_RecipeId{RecipeId: "prep"}}

	if _, _, _, err := s.provisionBoxOnly(ctxAs("admin", true), skill, "", ""); err != nil {
		t.Fatalf("provisionBoxOnly: %v", err)
	}
	if b.starts != 1 {
		t.Errorf("starts = %d, want 1", b.starts)
	}
}

// GetContainer / ListContainers report the hold through toProtoContainer.
func TestToProtoContainer_ReportsHold(t *testing.T) {
	if !toProtoContainer(&box.BoxStatus{Ref: box.BoxRef{Tenant: "alice", Name: "alice-container"}, Held: true}).GetHeld() {
		t.Error("held box: Container.held = false")
	}
	if toProtoContainer(&box.BoxStatus{Ref: box.BoxRef{Tenant: "alice", Name: "alice-container"}}).GetHeld() {
		t.Error("unheld box: Container.held = true")
	}
}

// At daemon start, held boxes are logged and boot.autostart is turned off
// again where it drifted; a held box found running is reported, not stopped.
func TestReconcileHolds_LogsHeldBoxes(t *testing.T) {
	b := newHoldTestBox("alice", "Running", map[string]string{incus.HoldKey: "true", incus.BootAutostartKey: "true"})
	logs := captureLogs(t)
	b.server().ReconcileHolds()
	if b.cfg[incus.BootAutostartKey] != "false" {
		t.Errorf("%s = %q, want false re-asserted on a held box", incus.BootAutostartKey, b.cfg[incus.BootAutostartKey])
	}
	if !strings.Contains(logs.String(), `[hold] box="alice" is held`) {
		t.Errorf("held box was not logged at startup:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "WARNING") || b.state() != "Running" {
		t.Errorf("a held box found running must be reported and left as it is; state=%q logs:\n%s", b.state(), logs.String())
	}
}
