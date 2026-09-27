package server

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2100: RunCrew used to discard every member's lease, so a crew run's boxes
// kept a live gateway token and their fetched checkout of the customer's repo
// after the run reached a terminal state. These tests pin the three terminal
// paths — driveCrew success, driveCrew failure, and a mid-loop provisioning
// failure — each of which must end EVERY lease the run issued.
//
// What they assert is that CrewServer ends the right leases at the right
// moments, not that ending one works: endRunLease/runlease.End have their own
// coverage (agent_run_lease_test.go, internal/runlease/lease_test.go). The
// evidence per member is the revocation of both its credentials, the `rm -rf`
// of its seed dir + workspace in ITS box, and one agent.run_lease_end audit
// row — the crew-side half of the audit trail the issue asks for.

// crewMemberLease is the lease provisionSkillBox hands back for one crew
// member: the CREW RUN's id (every member shares it, #1817) and therefore the
// same per-run seed dir and workspace, but that member's own box, and jtis
// carrying the skill id so a test can tell whose credentials were revoked.
func crewMemberLease(runID, skillID string) runlease.Lease {
	exp := time.Now().Add(agentTokenTTL)
	return runlease.Lease{
		RunID:     runID,
		Box:       "agent-" + skillID + "-container",
		SeedDir:   seedDirFor(runID),
		Workspace: workspaceDirFor(runID),
		Credentials: []runlease.Credential{
			{Kind: runlease.KindPlatformJWT, JTI: "jti-platform-" + skillID, ExpiresAt: exp},
			{Kind: runlease.KindGatewayToken, JTI: "jti-gateway-" + skillID, ExpiresAt: exp},
		},
	}
}

// fakeCrewProvisioner stands in for provisionSkillBox + startServeMode. It
// exists because the real pair is unreachable from a unit test: the seed exec
// ALWAYS fails against a fake container backend ((*container.Manager).Exec
// type-asserts its backend to the concrete *incus.Client), so no fake can
// drive RunCrew past its first member.
type fakeCrewProvisioner struct {
	failOn   string   // skill id whose provisioning fails ("" = none fail)
	provided []string // skill ids provisioned successfully, in order
	leases   []runlease.Lease
}

func (p *fakeCrewProvisioner) provision(_ context.Context, skill *pb.AgentSkill, _ *pb.RunCrewRequest, runID string) (runlease.Lease, string, error) {
	if skill.Id == p.failOn {
		// Shaped like the real seed failure (see provisionSkillBoxWith).
		return runlease.Lease{}, "", status.Errorf(codes.Internal, "failed to seed agent box agent-%s-container: exec unsupported", skill.Id)
	}
	lease := crewMemberLease(runID, skill.Id)
	p.provided = append(p.provided, skill.Id)
	p.leases = append(p.leases, lease)
	return lease, "commit-" + skill.Id, nil
}

// crewLeaseHarness is a CrewServer whose lease-ending is fully observable:
// a fake revocation store, a fake wiper, a fake audit logger, and a fake
// provisioner — no container backend anywhere.
type crewLeaseHarness struct {
	crew        *CrewServer
	provisioner *fakeCrewProvisioner
	revocations *fakeRevocationStore
	wiper       *fakeSeedWiper
	audits      *fakeAuditLogger
}

// newCrewLeaseHarness wires a one-crew PIPELINE catalog over skillIDs (which
// must be really wired relay-agent -> hello-agent style in the embedded skill
// catalog, same constraint pipelineCrewCatalog documents).
func newCrewLeaseHarness(t *testing.T, skillIDs ...string) *crewLeaseHarness {
	t.Helper()
	revocations := newFakeRevocationStore()
	audits := &fakeAuditLogger{}
	agents := &AgentSkillServer{catalog: skills.GetDefault(), audit: audits}
	agents.SetRevocationStore(revocations)
	return &crewLeaseHarness{
		crew: &CrewServer{
			catalog: pipelineCrewCatalog(t, "test-crew", skillIDs...),
			skills:  skills.GetDefault(),
			agents:  agents,
			runs:    NewMemCrewRunStore(),
		},
		provisioner: &fakeCrewProvisioner{},
		revocations: revocations,
		wiper:       &fakeSeedWiper{},
		audits:      audits,
	}
}

// run drives the crew through RunCrew's own post-validation body with the
// harness's fakes substituted for the three collaborators a unit test cannot
// reach.
func (h *crewLeaseHarness) run(t *testing.T, runID string, send taskSender) (*pb.RunCrewResponse, error) {
	t.Helper()
	ctx := ctxAs("admin", true)
	crew, err := h.crew.catalog.Get("test-crew")
	if err != nil {
		t.Fatalf("catalog test-crew: %v", err)
	}
	return h.crew.runCrew(ctx, &pb.RunCrewRequest{
		CrewId:    "test-crew",
		RunId:     runID,
		GitSource: "https://github.com/org/repo",
		GitRef:    "main",
	}, crew, runID, crewRunDeps{
		provision: h.provisioner.provision,
		send:      send,
		wiper:     h.wiper,
	})
}

// assertLeaseEnded checks the full observable footprint of one member's lease
// having ended: both credentials revoked with `reason`, the seed files wiped
// and the seed dir + workspace removed from THAT member's box, and one
// agent.run_lease_end audit row naming the run.
func assertLeaseEnded(t *testing.T, h *crewLeaseHarness, runID, skillID, reason string) {
	t.Helper()

	for _, jti := range []string{"jti-platform-" + skillID, "jti-gateway-" + skillID} {
		revoked, err := h.revocations.IsRevoked(context.Background(), jti)
		if err != nil {
			t.Fatalf("IsRevoked(%s): %v", jti, err)
		}
		if !revoked {
			t.Errorf("member %s: credential %s was never revoked — its lease outlived the crew run", skillID, jti)
		}
	}
	for _, r := range listRevocations(t, h.revocations) {
		if strings.HasSuffix(r.JTI, "-"+skillID) && r.Reason != reason {
			t.Errorf("member %s: %s revoked with reason %q, want %q", skillID, r.JTI, r.Reason, reason)
		}
	}

	// The wipe + removal land in the member's OWN box, so "which box did the
	// rm -rf run in" is what distinguishes member leases from each other.
	box := "agent-" + skillID + "-container"
	seedDir, workspace := seedDirFor(runID), workspaceDirFor(runID)
	var wipes, removals int
	for i, cmd := range h.wiper.cmds {
		if h.wiper.boxes[i] != box {
			continue
		}
		joined := strings.Join(cmd, " ")
		switch {
		case joined == strings.Join([]string{"rm", "-f", seedDir + "/token", seedDir + "/gateway.env"}, " "):
			wipes++
		case joined == strings.Join([]string{"rm", "-rf", seedDir, workspace}, " "):
			removals++
		default:
			t.Errorf("member %s: unexpected exec in its box: %v", skillID, cmd)
		}
	}
	if wipes != 1 {
		t.Errorf("member %s: seed-file wipes in %s = %d, want 1", skillID, box, wipes)
	}
	if removals != 1 {
		t.Errorf("member %s: seed dir + workspace removals in %s = %d, want 1 — the fetched repo is still in the box", skillID, box, removals)
	}
}

// endRowsFor returns the run's agent.run_lease_end audit rows, decoded.
func endRowsFor(t *testing.T, h *crewLeaseHarness, runID string) []runLeaseEndDetail {
	t.Helper()
	var out []runLeaseEndDetail
	for _, e := range h.audits.byAction("agent.run_lease_end") {
		if e.RunID != runID {
			t.Errorf("agent.run_lease_end row run_id = %q, want the crew run's id %q", e.RunID, runID)
		}
		var d runLeaseEndDetail
		if err := json.Unmarshal([]byte(e.Detail), &d); err != nil {
			t.Fatalf("agent.run_lease_end detail is not the typed struct: %v", err)
		}
		out = append(out, d)
	}
	return out
}

// assertEndRows checks one agent.run_lease_end row per member, each recording
// the reason and that the wipe + directory removal actually happened.
func assertEndRows(t *testing.T, h *crewLeaseHarness, runID, reason string, wantMembers int) {
	t.Helper()
	rows := endRowsFor(t, h, runID)
	if len(rows) != wantMembers {
		t.Fatalf("agent.run_lease_end rows = %d, want one per member (%d) — a crew run's audit trail must show every member's lease closing",
			len(rows), wantMembers)
	}
	var revoked []string
	for _, d := range rows {
		if d.Reason != reason {
			t.Errorf("end row reason = %q, want %q", d.Reason, reason)
		}
		if !d.Wiped {
			t.Error("end row says the seed files were not wiped")
		}
		if !d.DirsRemoved {
			t.Error("end row says the seed dir + workspace were not removed")
		}
		if len(d.Errors) != 0 {
			t.Errorf("end row reports errors: %v", d.Errors)
		}
		revoked = append(revoked, d.Revoked...)
	}
	if len(revoked) != 2*wantMembers {
		t.Errorf("credentials revoked across the run = %d, want 2 per member (%d): %v", len(revoked), 2*wantMembers, revoked)
	}
}

// TestRunCrew_EndsEveryMemberLeaseOnSuccess is terminal path 1: driveCrew
// returns an artifact, the run lands COMPLETED, and no member is left holding
// a live gateway token or a checkout of the repo.
func TestRunCrew_EndsEveryMemberLeaseOnSuccess(t *testing.T) {
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	const runID = "run-crew-success"

	resp, err := h.run(t, runID, func(_ context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
		return completed("out-of-" + req.ToPeerId), nil
	})
	if err != nil {
		t.Fatalf("runCrew: %v", err)
	}
	if got := resp.GetRun().GetState(); got != pb.CrewRunState_CREW_RUN_STATE_COMPLETED {
		t.Fatalf("state = %v, want COMPLETED", got)
	}
	if got := h.provisioner.provided; len(got) != 2 {
		t.Fatalf("provisioned members = %v, want both", got)
	}

	for _, sid := range []string{"relay-agent", "hello-agent"} {
		assertLeaseEnded(t, h, runID, sid, runExitReason)
	}
	assertEndRows(t, h, runID, runExitReason, 2)
}

// TestRunCrew_EndsEveryMemberLeaseOnDriveFailure is terminal path 2: driveCrew
// fails (a member's A2A server never came up), the run lands FAILED rather
// than erroring the RPC — and every member's lease still ends. A FAILED run is
// exactly the case where credentials are most likely to be forgotten.
func TestRunCrew_EndsEveryMemberLeaseOnDriveFailure(t *testing.T) {
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	const runID = "run-crew-drive-failed"

	resp, err := h.run(t, runID, func(_ context.Context, _ *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
		return nil, errors.New("a2a server not up")
	})
	if err != nil {
		t.Fatalf("a driveCrew failure must land in the run, not error the RPC: %v", err)
	}
	if got := resp.GetRun().GetState(); got != pb.CrewRunState_CREW_RUN_STATE_FAILED {
		t.Fatalf("state = %v, want FAILED", got)
	}

	for _, sid := range []string{"relay-agent", "hello-agent"} {
		assertLeaseEnded(t, h, runID, sid, runExitReason)
	}
	assertEndRows(t, h, runID, runExitReason, 2)
}

// TestRunCrew_EndsAlreadyProvisionedLeasesOnProvisionFailure is terminal path
// 3, and the one the issue calls out specifically: member 2's provisioning
// fails, so the RPC returns an error — but member 1 is already provisioned and
// running in serve mode with live credentials and a checkout. Nothing will
// ever come back for it (this RPC IS the run), so its lease must end here.
// Asserting only "the RPC errored" would pass against the old, leaking code.
func TestRunCrew_EndsAlreadyProvisionedLeasesOnProvisionFailure(t *testing.T) {
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	h.provisioner.failOn = "hello-agent" // the SECOND member fails
	const runID = "run-crew-provision-failed"

	_, err := h.run(t, runID, func(_ context.Context, _ *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
		t.Error("driveCrew must not run when a member failed to provision")
		return nil, errors.New("unreachable")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal: %v", status.Code(err), err)
	}
	if got := h.provisioner.provided; len(got) != 1 || got[0] != "relay-agent" {
		t.Fatalf("provisioned members = %v, want only relay-agent", got)
	}

	// The already-provisioned member's lease is the whole point of this test.
	assertLeaseEnded(t, h, runID, "relay-agent", provisionFailedReason)

	// And the failed member has nothing to end — its credentials were never
	// issued (provisionSkillBox ends its own partial lease, #1817), so the
	// crew must not invent an end for it.
	for _, jti := range []string{"jti-platform-hello-agent", "jti-gateway-hello-agent"} {
		if revoked, _ := h.revocations.IsRevoked(context.Background(), jti); revoked {
			t.Errorf("%s was revoked, but the failed member never got a lease from the crew", jti)
		}
	}
	assertEndRows(t, h, runID, provisionFailedReason, 1)

	// The run row still reports the failure, unchanged from before #2100.
	run, ok, gerr := h.crew.runs.Get(context.Background(), runID)
	if gerr != nil || !ok {
		t.Fatalf("Get(%s) = ok %v, err %v", runID, ok, gerr)
	}
	if run.GetState() != pb.CrewRunState_CREW_RUN_STATE_FAILED {
		t.Errorf("state = %v, want FAILED", run.GetState())
	}
}

// TestRunCrew_EndsMemberLeasesUnderACancelledCaller: a cancelled or timed-out
// RunCrew must still kill every member's credentials — the whole point of an
// execution-scoped lease. endRunLease owns the detachment
// (context.WithoutCancel), so this pins that RunCrew does not defeat it by,
// say, skipping the loop on ctx.Err().
func TestRunCrew_EndsMemberLeasesUnderACancelledCaller(t *testing.T) {
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	h.crew.agents.SetRevocationStore(ctxAwareRevoker{h.revocations})
	const runID = "run-crew-cancelled"

	ctx, cancel := context.WithCancel(ctxAs("admin", true))
	crew, err := h.crew.catalog.Get("test-crew")
	if err != nil {
		t.Fatalf("catalog test-crew: %v", err)
	}
	cancel() // the caller is gone before the run reaches its terminal point

	if _, err := h.crew.runCrew(ctx, &pb.RunCrewRequest{CrewId: "test-crew", RunId: runID}, crew, runID, crewRunDeps{
		provision: h.provisioner.provision,
		send: func(_ context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
			return completed("out-of-" + req.ToPeerId), nil
		},
		wiper: h.wiper,
	}); err != nil {
		t.Fatalf("runCrew: %v", err)
	}

	got := make([]string, 0, 4)
	for _, r := range listRevocations(t, h.revocations) {
		got = append(got, r.JTI)
	}
	sort.Strings(got)
	want := []string{"jti-gateway-hello-agent", "jti-gateway-relay-agent", "jti-platform-hello-agent", "jti-platform-relay-agent"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("revoked %v, want every member's credentials %v — a cancelled RunCrew must still end its leases", got, want)
	}
}

// compile-time guards that the harness's fakes really are what the production
// code takes, so a signature change fails to build rather than silently
// drawing a test's teeth.
var (
	_ runlease.Wiper       = (*fakeSeedWiper)(nil)
	_ auth.RevocationStore = (*fakeRevocationStore)(nil)
	_ provisionMemberFunc  = (&fakeCrewProvisioner{}).provision
)
