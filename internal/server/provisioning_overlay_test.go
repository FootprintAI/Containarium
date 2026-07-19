package server

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// mkListEntry builds the minimal local list entry the overlay operates on.
func mkListEntry(username string, state pb.ContainerState) *pb.Container {
	return &pb.Container{
		Name:     username + "-container",
		Username: username,
		State:    state,
	}
}

func stateOf(t *testing.T, out []*pb.Container, username string) pb.ContainerState {
	t.Helper()
	for _, c := range out {
		if c.Username == username {
			return c.State
		}
	}
	t.Fatalf("container for %q not in overlay output", username)
	return pb.ContainerState_CONTAINER_STATE_UNSPECIFIED
}

func has(out []*pb.Container, username string) bool {
	for _, c := range out {
		if c.Username == username {
			return true
		}
	}
	return false
}

// TestApplyProvisioningOverlay_ReplacesRawRunning is the #1036 core case: a
// box mid-provisioning reads RUNNING from incus the moment it boots, minutes
// before SSH works — list must report the pending state instead, exactly as
// GetContainer already does.
func TestApplyProvisioningOverlay_ReplacesRawRunning(t *testing.T) {
	local := []*pb.Container{
		mkListEntry("alice", pb.ContainerState_CONTAINER_STATE_RUNNING),
		mkListEntry("bob", pb.ContainerState_CONTAINER_STATE_RUNNING),
	}
	pending := map[string]pb.ContainerState{
		"alice": pb.ContainerState_CONTAINER_STATE_PROVISIONING,
	}

	out := applyProvisioningOverlay(local, pending, "", pb.ContainerState_CONTAINER_STATE_UNSPECIFIED, false, "ssh.example.com")

	if got := stateOf(t, out, "alice"); got != pb.ContainerState_CONTAINER_STATE_PROVISIONING {
		t.Fatalf("alice: got %v, want PROVISIONING (raw incus RUNNING must not leak mid-provisioning)", got)
	}
	if got := stateOf(t, out, "bob"); got != pb.ContainerState_CONTAINER_STATE_RUNNING {
		t.Fatalf("bob: got %v, want RUNNING (non-pending entries untouched)", got)
	}
}

// TestApplyProvisioningOverlay_SynthesizesNotYetVisible: a just-accepted
// create has no incus instance yet — it must still appear in list (same
// synthetic shape GetContainer returns), carrying the daemon's ssh host.
func TestApplyProvisioningOverlay_SynthesizesNotYetVisible(t *testing.T) {
	pending := map[string]pb.ContainerState{
		"carol": pb.ContainerState_CONTAINER_STATE_CREATING,
	}

	out := applyProvisioningOverlay(nil, pending, "", pb.ContainerState_CONTAINER_STATE_UNSPECIFIED, false, "ssh.example.com")

	if len(out) != 1 {
		t.Fatalf("got %d entries, want 1 synthetic", len(out))
	}
	c := out[0]
	if c.Name != "carol-container" || c.Username != "carol" {
		t.Fatalf("synthetic identity wrong: name=%q username=%q", c.Name, c.Username)
	}
	if c.State != pb.ContainerState_CONTAINER_STATE_CREATING {
		t.Fatalf("synthetic state: got %v, want CREATING", c.State)
	}
	if c.SshHost != "ssh.example.com" {
		t.Fatalf("synthetic ssh host: got %q", c.SshHost)
	}
}

// TestApplyProvisioningOverlay_StateFilterSeesOverlaidState: filtering
// state=RUNNING must EXCLUDE a mid-provisioning box (its reported state is
// PROVISIONING even though incus says Running), and filtering
// state=PROVISIONING must include exactly it — the filter operates on what
// the response reports, not on the raw incus state.
func TestApplyProvisioningOverlay_StateFilterSeesOverlaidState(t *testing.T) {
	local := []*pb.Container{
		mkListEntry("alice", pb.ContainerState_CONTAINER_STATE_RUNNING), // provisioning underneath
		mkListEntry("bob", pb.ContainerState_CONTAINER_STATE_RUNNING),   // genuinely running
	}
	pending := map[string]pb.ContainerState{
		"alice": pb.ContainerState_CONTAINER_STATE_PROVISIONING,
		"carol": pb.ContainerState_CONTAINER_STATE_CREATING, // synthetic candidate
	}

	running := applyProvisioningOverlay(local, pending, "", pb.ContainerState_CONTAINER_STATE_RUNNING, false, "")
	if has(running, "alice") {
		t.Fatal("state=RUNNING filter must exclude the mid-provisioning box")
	}
	if !has(running, "bob") {
		t.Fatal("state=RUNNING filter must keep the genuinely running box")
	}
	if has(running, "carol") {
		t.Fatal("state=RUNNING filter must exclude the CREATING synthetic")
	}

	prov := applyProvisioningOverlay(local, pending, "", pb.ContainerState_CONTAINER_STATE_PROVISIONING, false, "")
	if !has(prov, "alice") || has(prov, "bob") || has(prov, "carol") {
		t.Fatalf("state=PROVISIONING filter wrong: got %v", prov)
	}
}

// TestApplyProvisioningOverlay_LabelFilterSuppressesSynthetics: a
// provisioning box's labels aren't stamped yet, so it can't genuinely match
// a label filter — synthetics are suppressed, but the overlay still applies
// to real entries that passed the label filter upstream.
func TestApplyProvisioningOverlay_LabelFilterSuppressesSynthetics(t *testing.T) {
	local := []*pb.Container{
		mkListEntry("alice", pb.ContainerState_CONTAINER_STATE_RUNNING),
	}
	pending := map[string]pb.ContainerState{
		"alice": pb.ContainerState_CONTAINER_STATE_PROVISIONING,
		"carol": pb.ContainerState_CONTAINER_STATE_CREATING,
	}

	out := applyProvisioningOverlay(local, pending, "", pb.ContainerState_CONTAINER_STATE_UNSPECIFIED, true, "")

	if has(out, "carol") {
		t.Fatal("synthetic must be suppressed under a label filter")
	}
	if got := stateOf(t, out, "alice"); got != pb.ContainerState_CONTAINER_STATE_PROVISIONING {
		t.Fatalf("overlay must still apply to real entries under a label filter, got %v", got)
	}
}

// TestApplyProvisioningOverlay_UsernameFilterScopesSynthetics: tenant
// isolation — a synthetic for another tenant's pending create must not leak
// into a username-scoped list (non-admin lists are always username-scoped).
func TestApplyProvisioningOverlay_UsernameFilterScopesSynthetics(t *testing.T) {
	pending := map[string]pb.ContainerState{
		"alice":   pb.ContainerState_CONTAINER_STATE_CREATING,
		"mallory": pb.ContainerState_CONTAINER_STATE_CREATING,
	}

	out := applyProvisioningOverlay(nil, pending, "alice", pb.ContainerState_CONTAINER_STATE_UNSPECIFIED, false, "")

	if !has(out, "alice") || has(out, "mallory") {
		t.Fatalf("username filter must scope synthetics to the caller, got %v", out)
	}
}

// TestApplyProvisioningOverlay_NoPendingPassthrough: with nothing pending the
// overlay is a pure state-filter pass — entries untouched, filter applied.
func TestApplyProvisioningOverlay_NoPendingPassthrough(t *testing.T) {
	local := []*pb.Container{
		mkListEntry("alice", pb.ContainerState_CONTAINER_STATE_RUNNING),
		mkListEntry("bob", pb.ContainerState_CONTAINER_STATE_STOPPED),
	}

	out := applyProvisioningOverlay(local, nil, "", pb.ContainerState_CONTAINER_STATE_RUNNING, false, "")

	if !has(out, "alice") || has(out, "bob") {
		t.Fatalf("passthrough state filter wrong: got %v", out)
	}
}
