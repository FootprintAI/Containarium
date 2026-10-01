package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestResolveAnonClaimKeys(t *testing.T) {
	f := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(f, []byte("# comment\nssh-ed25519 AAAA1 a\n\n  ssh-ed25519 AAAA2 b  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAnonClaimKeys([]string{" ssh-rsa AAAA0 z ", "", "@" + f})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ssh-rsa AAAA0 z", "ssh-ed25519 AAAA1 a", "ssh-ed25519 AAAA2 b"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := resolveAnonClaimKeys([]string{"@" + filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("missing key file must error")
	}
}

func TestFormatDoorConfig(t *testing.T) {
	open := &pb.AnonymousDoorConfig{Enabled: true, Limits: &pb.AnonymousBoxLimits{Cpu: "2", Memory: "4GB", Disk: "20GB", TtlSeconds: 14400, MaxBoxes: 20, PerFingerprintRps: 0.1 / 60, PerFingerprintBurst: 2, PerIpRps: 0.6 / 60, PerIpBurst: 6}}
	out := formatDoorConfig(open)
	for _, w := range []string{"Door: OPEN", "cap 20 boxes", "per key 0.1/min burst 2", "per IP 0.6/min burst 6", "TTL 4h0m0s", "Banned: none"} {
		if !strings.Contains(out, w) {
			t.Errorf("open: missing %q in\n%s", w, out)
		}
	}
	closed := &pb.AnonymousDoorConfig{Enabled: false, DisabledMessage: "closed for maintenance", BannedFingerprints: []string{"SHA256:a", "SHA256:b"}}
	out = formatDoorConfig(closed)
	for _, w := range []string{"Door: CLOSED — closed for maintenance", "Banned (2):", "  SHA256:a"} {
		if !strings.Contains(out, w) {
			t.Errorf("closed: missing %q in\n%s", w, out)
		}
	}
}

func TestFormatAnonBoxes(t *testing.T) {
	if got := formatAnonBoxes(nil); !strings.Contains(got, "No anonymous boxes") {
		t.Errorf("empty: %q", got)
	}
	out := formatAnonBoxes([]*pb.AnonymousBox{
		{BoxName: "anon-1a2b3c4d-container", FingerprintHash: "ff00ff00ff00ff00ff00", SshHost: "10.0.0.5", TtlExpiresAt: timestamppb.New(time.Date(2026, 10, 1, 16, 0, 0, 0, time.UTC))},
		{BoxName: "anon-ffffffff-container", FingerprintHash: "aa", Claimed: true},
	})
	for _, w := range []string{"anon-1a2b3c4d-container", "ff00ff00ff00ff00 ", "2026-10-01 16:00Z", "anon-ffffffff-container", "yes", "Total: 2"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
}

func TestRemoveString(t *testing.T) {
	got := removeString([]string{"a", "b", "a", "c"}, "a")
	if strings.Join(got, ",") != "b,c" {
		t.Errorf("got %v", got)
	}
}
