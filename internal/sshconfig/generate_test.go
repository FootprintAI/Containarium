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
	if !(idxA < idxM && idxM < idxZ) {
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

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"sentinel.example.com", "sentinel.example.com", 22},
		{"sentinel.example.com:2222", "sentinel.example.com", 2222},
		{"[2001:db8::1]:2222", "2001:db8::1", 2222},
		{"[2001:db8::1]", "2001:db8::1", 22},
	}
	for _, tc := range cases {
		h, p := splitHostPort(tc.in, 22)
		if h != tc.wantHost || p != tc.wantPort {
			t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)",
				tc.in, h, p, tc.wantHost, tc.wantPort)
		}
	}
}
