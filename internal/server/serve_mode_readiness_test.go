package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentengine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// serveBox scripts the box a serve-mode launch talks to. It tells the four
// commands startServeMode runs apart by what they contain: the prior-instance
// kill, the launch, the /agent-card probe and the log tail.
type serveBox struct {
	mu sync.Mutex

	launchExit int
	launchErr  error
	// probeFailures is how many probes fail before one succeeds; -1 = never.
	probeFailures int
	logTail       string

	cmds   []string
	probes int
}

func (b *serveBox) ExecWithExitCode(_ string, cmd []string) (string, string, int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	joined := strings.Join(cmd, " ")
	b.cmds = append(b.cmds, joined)
	switch {
	case strings.Contains(joined, "pkill"):
		return "", "", 1, nil // nothing matched: benign
	case strings.Contains(joined, "setsid agent-runtime"):
		return "", "", b.launchExit, b.launchErr
	case strings.Contains(joined, "/agent-card"):
		b.probes++
		if b.probeFailures >= 0 && b.probes > b.probeFailures {
			return "", "", 0, nil
		}
		return "", "", 1, nil
	case strings.Contains(joined, "tail -c"):
		return b.logTail, "", 0, nil
	}
	return "", "", 0, nil
}

func (b *serveBox) ReadFile(_, _ string) ([]byte, error) { return nil, errors.New("not used") }

func (b *serveBox) count(substr string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, c := range b.cmds {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

func serveServer(box *serveBox) *AgentSkillServer {
	s := &AgentSkillServer{inBoxOps: box}
	// Short, so a box that never answers fails the test in milliseconds.
	s.serveReadyTimeout = 60 * time.Millisecond
	s.serveReadyInterval = 5 * time.Millisecond
	return s
}

func startServe(s *AgentSkillServer, ctx context.Context) error {
	return s.startServeMode(ctx, "agent-relay-agent-container", "/etc/containarium/agent/runs/run-1", "relay-agent", agentengine.Resolved{}, "")
}

// #2936: a healthy member still gets the old behaviour (kill any prior
// instance, then launch once) and is only reported started after its A2A
// endpoint answers.
func TestStartServeMode_HealthyMemberKillsThenLaunchesThenWaitsForTheAgentCard(t *testing.T) {
	box := &serveBox{probeFailures: 2}
	if err := startServe(serveServer(box), context.Background()); err != nil {
		t.Fatalf("a member whose endpoint answers on the third probe failed: %v", err)
	}
	if box.count("pkill") != 1 || box.count("setsid agent-runtime") != 1 {
		t.Errorf("kill=%d launch=%d, want exactly one of each (the pkill-then-relaunch behaviour is unchanged)", box.count("pkill"), box.count("setsid agent-runtime"))
	}
	if box.probes != 3 {
		t.Errorf("probes = %d, want 3 (two failures then the answer)", box.probes)
	}
	if !strings.HasPrefix(box.cmds[0], "bash -lc pkill") && !strings.Contains(box.cmds[0], "pkill") {
		t.Errorf("first command = %q, want the prior-instance kill", box.cmds[0])
	}
	if !strings.Contains(box.cmds[1], "setsid agent-runtime") {
		t.Errorf("second command = %q, want the launch", box.cmds[1])
	}
	if !strings.Contains(strings.Join(box.cmds, "\n"), "/dev/tcp/127.0.0.1/8674") {
		t.Error("the probe does not target the A2A port 8674 inside the box")
	}
}

// The launch itself failing is reported, not logged and dropped.
func TestStartServeMode_LaunchFailureIsReported(t *testing.T) {
	t.Run("exec error", func(t *testing.T) {
		box := &serveBox{launchErr: errors.New("instance not running")}
		err := startServe(serveServer(box), context.Background())
		if err == nil || !strings.Contains(err.Error(), "agent-relay-agent-container") || !strings.Contains(err.Error(), "instance not running") {
			t.Fatalf("got %v, want an error naming the box and the cause", err)
		}
		if errors.Is(err, errInBoxRuntimeMissing) {
			t.Error("a transport failure is not 'agent-runtime is not installed'")
		}
		if box.probes != 0 {
			t.Errorf("probed %d times after a failed launch", box.probes)
		}
	})
	t.Run("exit 127 is a missing runtime", func(t *testing.T) {
		box := &serveBox{launchExit: exitCommandNotFound}
		err := startServe(serveServer(box), context.Background())
		if !errors.Is(err, errInBoxRuntimeMissing) {
			t.Fatalf("got %v, want errInBoxRuntimeMissing", err)
		}
	})
	t.Run("incus 'Command not found' is a missing runtime", func(t *testing.T) {
		box := &serveBox{launchErr: errors.New("Command not found")}
		if err := startServe(serveServer(box), context.Background()); !errors.Is(err, errInBoxRuntimeMissing) {
			t.Fatalf("got %v, want errInBoxRuntimeMissing", err)
		}
	})
}

// A launch that "succeeds" (the runtime is backgrounded, so its exit status
// never reaches us) but whose endpoint never answers is an error carrying the
// scrubbed tail of the box's own log: that is the only place the reason is.
func TestStartServeMode_NeverAnsweringIncludesTheScrubbedLogTail(t *testing.T) {
	const secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
	box := &serveBox{probeFailures: -1, logTail: "Error: listen EADDRINUSE: address already in use :::8674\nupstream said key " + secret}
	err := startServe(serveServer(box), context.Background())
	if err == nil {
		t.Fatal("a member that never answered was reported started")
	}
	for _, want := range []string{"agent-relay-agent-container", "relay-agent", "/agent-card", "EADDRINUSE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the error carries a credential from the box's log: %q", err)
	}
	if errors.Is(err, errInBoxRuntimeMissing) {
		t.Error("EADDRINUSE is a failed start, not a missing runtime")
	}
	if len(err.Error()) > 4*maxInBoxErrorBytes {
		t.Errorf("error is %d bytes: the log tail is not bounded", len(err.Error()))
	}
}

// The bash 'command not found' the backgrounded launch writes into the log is
// how a missing binary shows up here.
func TestStartServeMode_NeverAnsweringBecauseTheBinaryIsMissing(t *testing.T) {
	box := &serveBox{probeFailures: -1, logTail: "bash: line 1: agent-runtime: command not found"}
	if err := startServe(serveServer(box), context.Background()); !errors.Is(err, errInBoxRuntimeMissing) {
		t.Fatalf("got %v, want errInBoxRuntimeMissing", err)
	}
}

// A cancelled crew run does not wait out the readiness bound.
func TestStartServeMode_StopsWaitingWhenTheRunIsCancelled(t *testing.T) {
	box := &serveBox{probeFailures: -1}
	s := serveServer(box)
	s.serveReadyTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	start := time.Now()
	err := startServe(s, ctx)
	if err == nil {
		t.Fatal("a cancelled wait reported success")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %s to notice the cancellation", time.Since(start))
	}
}

// --- RunCrew: the member is named, the code is right, no lease is left ------

// serveMember is the production seam between provisionMemberBox and
// startServeMode: on a failure to start it must end the lease it was just
// handed, because runCrew only ends the leases of members that provisioned
// successfully.
func TestServeMember_FailureEndsThatMembersLeaseAndNamesIt(t *testing.T) {
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	box := &serveBox{probeFailures: -1, logTail: "Error: listen EADDRINUSE"}
	h.crew.agents.inBoxOps = box
	h.crew.agents.serveReadyTimeout, h.crew.agents.serveReadyInterval = 30*time.Millisecond, 5*time.Millisecond

	lease := crewMemberLease("run-9", "relay-agent")
	err := h.crew.serveMember(context.Background(), &pb.AgentSkill{Id: "relay-agent"}, lease.Box, lease, agentengine.Resolved{}, h.wiper)
	if err == nil || errors.Is(err, errInBoxRuntimeMissing) {
		t.Fatalf("got %v, want a failure that is not 'runtime missing'", err)
	}
	for _, want := range []string{"relay-agent", lease.Box} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should name %q (the member and its box)", err, want)
		}
	}
	assertLeaseEnded(t, h, "run-9", "relay-agent", provisionFailedReason)
}

func TestServeMember_MissingRuntimeWrapsTheSentinel(t *testing.T) {
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	h.crew.agents.inBoxOps = &serveBox{launchExit: exitCommandNotFound}

	lease := crewMemberLease("run-9", "relay-agent")
	err := h.crew.serveMember(context.Background(), &pb.AgentSkill{Id: "relay-agent"}, lease.Box, lease, agentengine.Resolved{}, h.wiper)
	if !errors.Is(err, errInBoxRuntimeMissing) {
		t.Fatalf("got %v, want it to wrap errInBoxRuntimeMissing", err)
	}
	assertLeaseEnded(t, h, "run-9", "relay-agent", provisionFailedReason)
}

func TestServeMember_HealthyMemberKeepsItsLease(t *testing.T) {
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	h.crew.agents.inBoxOps = &serveBox{probeFailures: 0}

	lease := crewMemberLease("run-9", "relay-agent")
	if err := h.crew.serveMember(context.Background(), &pb.AgentSkill{Id: "relay-agent"}, lease.Box, lease, agentengine.Resolved{}, h.wiper); err != nil {
		t.Fatalf("healthy member failed: %v", err)
	}
	if len(h.wiper.cmds) != 0 {
		t.Errorf("a member that started had its seed wiped: %v", h.wiper.cmds)
	}
}

// runCrew keeps the gRPC code of a missing runtime instead of flattening
// every provisioning failure to Internal, and still names the member.
func TestRunCrew_MemberThatCannotServeFailsTheRunNamingIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want codes.Code
	}{
		{"missing runtime", fmt.Errorf("crew member \"hello-agent\" did not start serving: %w", errInBoxRuntimeMissing), codes.FailedPrecondition},
		{"other failure", fmt.Errorf("crew member \"hello-agent\" did not start serving: serve mode did not answer"), codes.Internal},
		// An engine refusal is a FailedPrecondition status from provisioning
		// and has always been reported as Internal by RunCrew.
		{"engine refusal stays Internal", status.Error(codes.FailedPrecondition, "engine anthropic has no key"), codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
			h.provisioner.failOn = "hello-agent"
			h.provisioner.failErr = tc.err
			_, err := h.run(t, "run-1", func(context.Context, *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
				t.Fatal("the crew was driven although a member never started")
				return nil, nil
			})
			if status.Code(err) != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), "hello-agent") {
				t.Errorf("error %q does not name the member that failed", err)
			}
			assertLeaseEnded(t, h, "run-1", "relay-agent", provisionFailedReason)
		})
	}
}
