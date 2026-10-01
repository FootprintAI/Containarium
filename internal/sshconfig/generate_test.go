package sshconfig

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

func TestGenerate_DirectMode(t *testing.T) {
	cs := []incus.ContainerInfo{
		{Name: "alice", State: "Running", IPAddress: "10.0.0.10"},
		{Name: "bob", State: "Running", IPAddress: "10.0.0.11"},
	}
	g := Generate(cs, Options{})
	if g.Count != 2 {
		t.Fatalf("Count = %d, want 2", g.Count)
	}
	if !strings.Contains(g.Content, "Host alice") || !strings.Contains(g.Content, "HostName 10.0.0.10") {
		t.Errorf("alice block missing or wrong:\n%s", g.Content)
	}
	if !strings.Contains(g.Content, "User ubuntu") {
		t.Errorf("expected default User=ubuntu in direct mode")
	}
	if !strings.Contains(g.Content, beginMarker) || !strings.Contains(g.Content, endMarker) {
		t.Errorf("missing managed-block markers")
	}
}

func TestGenerate_SentinelMode_UsesContainerNameAsUser(t *testing.T) {
	cs := []incus.ContainerInfo{
		{Name: "alice", State: "Running", IPAddress: "10.0.0.10"},
	}
	g := Generate(cs, Options{Sentinel: "sentinel.example.com"})
	if !strings.Contains(g.Content, "HostName sentinel.example.com") {
		t.Errorf("expected sentinel host:\n%s", g.Content)
	}
	if !strings.Contains(g.Content, "User alice") {
		t.Errorf("expected User=alice (container name as sshpiper route key):\n%s", g.Content)
	}
	if strings.Contains(g.Content, "10.0.0.10") {
		t.Errorf("container LAN IP should not leak in sentinel mode:\n%s", g.Content)
	}
}

func TestGenerate_SentinelMode_ExplicitPort(t *testing.T) {
	cs := []incus.ContainerInfo{
		{Name: "alice", State: "Running", IPAddress: "10.0.0.10"},
	}
	g := Generate(cs, Options{Sentinel: "sentinel.example.com:2222"})
	if !strings.Contains(g.Content, "Port 2222") {
		t.Errorf("expected Port 2222 from host:port form:\n%s", g.Content)
	}
}

func TestGenerate_StoppedSkippedByDefault(t *testing.T) {
	cs := []incus.ContainerInfo{
		{Name: "alive", State: "Running", IPAddress: "10.0.0.1"},
		{Name: "dead", State: "Stopped", IPAddress: "10.0.0.2"},
	}
	g := Generate(cs, Options{})
	if g.Count != 1 || g.SkippedStopped != 1 {
		t.Fatalf("Count=%d SkippedStopped=%d, want 1/1", g.Count, g.SkippedStopped)
	}
	if strings.Contains(g.Content, "Host dead") {
		t.Errorf("stopped container should be skipped:\n%s", g.Content)
	}
}

func TestGenerate_IncludeStopped(t *testing.T) {
	cs := []incus.ContainerInfo{
		{Name: "dead", State: "Stopped", IPAddress: "10.0.0.2"},
	}
	g := Generate(cs, Options{IncludeStopped: true})
	if g.Count != 1 {
		t.Errorf("expected stopped to be included, Count=%d", g.Count)
	}
}

func TestGenerate_DirectModeSkipsNoAddr(t *testing.T) {
	cs := []incus.ContainerInfo{
		{Name: "ghost", State: "Running", IPAddress: ""},
	}
	g := Generate(cs, Options{})
	if g.Count != 0 || g.SkippedNoAddr != 1 {
		t.Errorf("Count=%d SkippedNoAddr=%d, want 0/1", g.Count, g.SkippedNoAddr)
	}
}

func TestGenerate_StableOrder(t *testing.T) {
	cs := []incus.ContainerInfo{
		{Name: "zebra", State: "Running", IPAddress: "10.0.0.3"},
		{Name: "alpha", State: "Running", IPAddress: "10.0.0.1"},
		{Name: "mid", State: "Running", IPAddress: "10.0.0.2"},
	}
	g1 := Generate(cs, Options{})
	g2 := Generate(cs, Options{})
	if g1.Content != g2.Content {
		// time.Now() is in the comment header — strip first two lines for stability.
		strip := func(s string) string {
			parts := strings.SplitN(s, "\n", 4)
			return parts[3]
		}
		if strip(g1.Content) != strip(g2.Content) {
			t.Errorf("output is not stable across runs")
		}
	}
	idxA := strings.Index(g1.Content, "Host alpha")
	idxM := strings.Index(g1.Content, "Host mid")
	idxZ := strings.Index(g1.Content, "Host zebra")
	if idxA >= idxM || idxM >= idxZ {
		t.Errorf("Host blocks not sorted alphabetically:\n%s", g1.Content)
	}
}

func TestGenerate_IdentityFileEmitsIdentitiesOnly(t *testing.T) {
	cs := []incus.ContainerInfo{
		{Name: "alice", State: "Running", IPAddress: "10.0.0.1"},
	}
	g := Generate(cs, Options{IdentityFile: "~/.ssh/containarium_ed25519"})
	if !strings.Contains(g.Content, "IdentityFile ~/.ssh/containarium_ed25519") {
		t.Errorf("missing IdentityFile:\n%s", g.Content)
	}
	if !strings.Contains(g.Content, "IdentitiesOnly yes") {
		t.Errorf("IdentityFile should imply IdentitiesOnly:\n%s", g.Content)
	}
}

// splitHostPort's own coverage now lives in internal/hostport's tests --
// see containarium#1980 PR review finding 5 (this package, plugin.go, and
// egress_via_client.go each had their own copy; all three now share
// internal/hostport.Split).

// --- FootprintAI/Containarium-cloud#1851 ---------------------------------
//
// Against a remote daemon (`--server ... --http`, or gRPC) every container
// arrives with the *protobuf enum identifier* as its state, not incus's
// friendly "Running": the HTTP client copies protojson's
// "CONTAINER_STATE_RUNNING" straight through (internal/client/http.go
// containerToIncusInfo) and the gRPC client calls State.String(), which
// yields the same identifier. Generate compared against the local-incus
// spelling only, so against a hosted control plane it classified *every*
// box as stopped and wrote an ssh_config with zero Host blocks -- 41
// running boxes reported as "67 skipped stopped".
//
// Same normalization the `connect` verb already does
// (connectcore.IsRunning, OSS #1036).

func TestGenerate_ProtoEnumRunningRendersHost(t *testing.T) {
	// The single-box repro: a box the control plane reports RUNNING must
	// get a Host block, not be counted as "skipped stopped".
	cs := []incus.ContainerInfo{
		{Name: "alice", State: "CONTAINER_STATE_RUNNING", IPAddress: "10.0.0.10"},
	}
	g := Generate(cs, Options{Sentinel: "sentinel.example.com"})
	if g.Count != 1 || g.SkippedStopped != 0 {
		t.Fatalf("Count=%d SkippedStopped=%d, want 1/0 -- a RUNNING box was classified stopped", g.Count, g.SkippedStopped)
	}
	if !strings.Contains(g.Content, "Host alice") {
		t.Errorf("expected a Host block for the running box:\n%s", g.Content)
	}
}

func TestGenerate_RunningStateSpellings(t *testing.T) {
	// Every spelling a running box can arrive as, across transports.
	for _, state := range []string{
		"CONTAINER_STATE_RUNNING", // remote: protojson / State.String()
		"Running",                 // local incus
		"running",
		"RUNNING",
	} {
		t.Run(state, func(t *testing.T) {
			g := Generate([]incus.ContainerInfo{
				{Name: "box", State: state, IPAddress: "10.0.0.1"},
			}, Options{})
			if g.Count != 1 {
				t.Errorf("state %q: Count=%d SkippedStopped=%d, want 1 host", state, g.Count, g.SkippedStopped)
			}
		})
	}
}

func TestGenerate_ProtoEnumNonRunningStillSkipped(t *testing.T) {
	// The fix must not turn --include-stopped into the default: the other
	// proto enum states stay skipped. 18 of the fleet in cloud#1851 were
	// genuinely in ERROR and must not get Host blocks.
	for _, state := range []string{
		"CONTAINER_STATE_STOPPED",
		"CONTAINER_STATE_ERROR",
		"CONTAINER_STATE_CREATING",
		"CONTAINER_STATE_PROVISIONING",
		"CONTAINER_STATE_UNSPECIFIED",
		"",
	} {
		t.Run(state, func(t *testing.T) {
			g := Generate([]incus.ContainerInfo{
				{Name: "box", State: state, IPAddress: "10.0.0.1"},
			}, Options{})
			if g.Count != 0 || g.SkippedStopped != 1 {
				t.Errorf("state %q: Count=%d SkippedStopped=%d, want 0/1", state, g.Count, g.SkippedStopped)
			}
		})
	}
}

func TestGenerate_MixedFleetMatchesControlPlaneCounts(t *testing.T) {
	// The whole-fleet shape from the report: a remote daemon reporting a
	// mix of RUNNING/ERROR/STOPPED as proto enums. Only the running boxes
	// render; the rest are counted as skipped.
	cs := []incus.ContainerInfo{
		{Name: "alice", State: "CONTAINER_STATE_RUNNING", IPAddress: "10.0.0.10"},
		{Name: "bob", State: "CONTAINER_STATE_RUNNING", IPAddress: "10.0.0.11"},
		{Name: "broken", State: "CONTAINER_STATE_ERROR", IPAddress: "10.0.0.12"},
		{Name: "idle", State: "CONTAINER_STATE_STOPPED", IPAddress: "10.0.0.13"},
	}
	g := Generate(cs, Options{Sentinel: "sentinel.example.com"})
	if g.Count != 2 || g.SkippedStopped != 2 || g.SkippedNoAddr != 0 {
		t.Fatalf("Count=%d SkippedStopped=%d SkippedNoAddr=%d, want 2/2/0", g.Count, g.SkippedStopped, g.SkippedNoAddr)
	}
	for _, want := range []string{"Host alice", "Host bob"} {
		if !strings.Contains(g.Content, want) {
			t.Errorf("missing %q:\n%s", want, g.Content)
		}
	}
	for _, notWant := range []string{"Host broken", "Host idle"} {
		if strings.Contains(g.Content, notWant) {
			t.Errorf("unexpected %q rendered:\n%s", notWant, g.Content)
		}
	}
}

func TestGenerate_SentinelModeRunningWithNoIPStillRenders(t *testing.T) {
	// In sentinel mode routing is by username, so a running box with no
	// LAN IP visible to the client (the remote case -- the IP is inside
	// the backend's own network) still deserves a Host block.
	g := Generate([]incus.ContainerInfo{
		{Name: "alice", State: "CONTAINER_STATE_RUNNING"},
	}, Options{Sentinel: "sentinel.example.com"})
	if g.Count != 1 || g.SkippedNoAddr != 0 {
		t.Fatalf("Count=%d SkippedNoAddr=%d, want 1/0", g.Count, g.SkippedNoAddr)
	}
}

// --- FootprintAI/Containarium#2089 ---------------------------------------
//
// Against a hosted control plane the generated entries pointed at each
// container's private LAN IP with User=ubuntu, so `ssh <box>` could not
// reach anything even though `list` showed the boxes running. The daemon
// already reports the routable target per container (proto
// Container.ssh_host) plus the login it routes by (username); the
// generator ignored both, and neither remote client even carried them into
// ContainerInfo.

func TestGenerate_DirectModeUsesDaemonSSHHostAndUsername(t *testing.T) {
	g := Generate([]incus.ContainerInfo{{
		Name:      "alice",
		Username:  "u-alice",
		State:     "CONTAINER_STATE_RUNNING",
		SSHHost:   "<cluster>.example.com",
		IPAddress: "10.0.3.107",
	}}, Options{})
	if g.Count != 1 {
		t.Fatalf("Count = %d, want 1", g.Count)
	}
	if !strings.Contains(g.Content, "HostName <cluster>.example.com") {
		t.Errorf("expected the daemon-reported ssh_host as HostName:\n%s", g.Content)
	}
	if strings.Contains(g.Content, "10.0.3.107") {
		t.Errorf("the container's private IP is not reachable from a client and must not be the target:\n%s", g.Content)
	}
	if !strings.Contains(g.Content, "User u-alice") {
		t.Errorf("expected the daemon-assigned username as User:\n%s", g.Content)
	}
}

func TestGenerate_DirectModeSSHHostWithoutIPStillRenders(t *testing.T) {
	// A hosted control plane may report the SSH target without exposing
	// the container's address at all; that box is still reachable.
	g := Generate([]incus.ContainerInfo{{
		Name:     "alice",
		Username: "u-alice",
		State:    "CONTAINER_STATE_RUNNING",
		SSHHost:  "<cluster>.example.com",
	}}, Options{})
	if g.Count != 1 || g.SkippedNoAddr != 0 {
		t.Fatalf("Count=%d SkippedNoAddr=%d, want 1/0", g.Count, g.SkippedNoAddr)
	}
}

func TestGenerate_DirectModeFallsBackToIPWhenNoSSHHost(t *testing.T) {
	// A local / LAN daemon reports no ssh_host, so nothing changes there.
	g := Generate([]incus.ContainerInfo{
		{Name: "alice", State: "Running", IPAddress: "10.0.0.10"},
	}, Options{})
	if !strings.Contains(g.Content, "HostName 10.0.0.10") || !strings.Contains(g.Content, "User ubuntu") {
		t.Errorf("expected the IP/ubuntu fallback:\n%s", g.Content)
	}
}

func TestGenerate_UserOverrideBeatsDaemonUsername(t *testing.T) {
	g := Generate([]incus.ContainerInfo{
		{Name: "alice", Username: "u-alice", State: "Running", IPAddress: "10.0.0.10"},
	}, Options{User: "root"})
	if !strings.Contains(g.Content, "User root") || strings.Contains(g.Content, "User u-alice") {
		t.Errorf("--user must win over the daemon-reported username:\n%s", g.Content)
	}
}

func TestGenerate_IdentitiesOnlyEmittedWithoutIdentityFile(t *testing.T) {
	// Every rejected key offer counts toward the SSH front's failtoban
	// budget, so the pin is not conditional on --identity.
	g := Generate([]incus.ContainerInfo{
		{Name: "alice", State: "Running", IPAddress: "10.0.0.10"},
	}, Options{})
	if !strings.Contains(g.Content, "IdentitiesOnly yes") {
		t.Errorf("expected IdentitiesOnly in every Host block:\n%s", g.Content)
	}
	if strings.Contains(g.Content, "IdentityFile") {
		t.Errorf("no IdentityFile was requested:\n%s", g.Content)
	}
}
