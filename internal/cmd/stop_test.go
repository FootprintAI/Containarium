package cmd

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// recordingStopper records the StopContainer call the stop command makes.
type recordingStopper struct {
	username    string
	force, hold bool
	calls       int
	held        bool
}

func (r *recordingStopper) StopContainer(username string, force, hold bool) (*pb.StopContainerResponse, error) {
	r.calls++
	r.username, r.force, r.hold = username, force, hold
	return &pb.StopContainerResponse{Message: "stopped", Container: &pb.Container{Held: r.held}}, nil
}

// `containarium stop --hold <box>` sends hold = true, and tells the operator
// the box is held and how the hold is lifted (#3721).
func TestStop_HoldFlagIsSent(t *testing.T) {
	if f := stopCmd.Flags().Lookup("hold"); f == nil {
		t.Fatal("stop has no --hold flag")
	}
	r := &recordingStopper{held: true}
	var out bytes.Buffer
	if err := stopBox(&out, r, "alice", false, true); err != nil {
		t.Fatalf("stopBox: %v", err)
	}
	if r.calls != 1 || r.username != "alice" || !r.hold || r.force {
		t.Errorf("call = %+v, want one StopContainer(alice, force=false, hold=true)", r)
	}
	if !strings.Contains(out.String(), "held") || !strings.Contains(out.String(), "containarium wake alice") {
		t.Errorf("output does not report the hold and how to lift it: %q", out.String())
	}
}

// Without --hold the stop is a plain stop.
func TestStop_PlainStopSendsNoHold(t *testing.T) {
	r := &recordingStopper{}
	var out bytes.Buffer
	if err := stopBox(&out, r, "alice", true, false); err != nil {
		t.Fatalf("stopBox: %v", err)
	}
	if r.hold || !r.force {
		t.Errorf("call = %+v, want hold=false force=true", r)
	}
	if strings.Contains(out.String(), "held") {
		t.Errorf("a plain stop reported a hold: %q", out.String())
	}
}

// A daemon that did not hold the box (an older one ignores the field) must
// not be reported as a successful hold.
func TestStop_HoldNotConfirmedIsAnError(t *testing.T) {
	r := &recordingStopper{held: false}
	var out bytes.Buffer
	if err := stopBox(&out, r, "alice", false, true); err == nil {
		t.Fatal("stopBox returned nil although the daemon did not report the box as held")
	}
}

func TestStop_RequiresOneBox(t *testing.T) {
	if err := stopCmd.Args(stopCmd, []string{}); err == nil {
		t.Fatal("expected Args validation error for zero positional args")
	}
}
