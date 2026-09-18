package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/releases"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func adminUpgradeCtx() context.Context {
	return auth.ContextWithTestSubject(context.Background(), "tester", auth.RoleAdmin)
}

// TriggerUpgrade and GetUpgradeStatus are admin-only (fleet-mutating /
// fleet-internal), matching the other System RPCs. #354.
func TestTriggerUpgrade_RequiresAdmin(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.TriggerUpgrade(context.Background(), &pb.TriggerUpgradeRequest{})
	if c := status.Code(err); c != codes.Unauthenticated && c != codes.PermissionDenied {
		t.Fatalf("want auth error, got %v", err)
	}
}

// A local upgrade with no auto-updater wired (no sentinel source) is Unavailable
// rather than a panic.
func TestTriggerUpgrade_LocalNoUpdater(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.TriggerUpgrade(adminUpgradeCtx(), &pb.TriggerUpgradeRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable (no auto-updater), got %v", err)
	}
}

func TestGetUpgradeStatus_RequiresAdmin(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.GetUpgradeStatus(context.Background(), &pb.GetUpgradeStatusRequest{UpgradeId: "x"})
	if c := status.Code(err); c != codes.Unauthenticated && c != codes.PermissionDenied {
		t.Fatalf("want auth error, got %v", err)
	}
}

// An unrecognized id (or a job lost to a self-upgrade restart) reports "unknown"
// so callers fall back to comparing the version in ListBackends.
func TestGetUpgradeStatus_UnknownID(t *testing.T) {
	s := &ContainerServer{}
	resp, err := s.GetUpgradeStatus(adminUpgradeCtx(), &pb.GetUpgradeStatusRequest{UpgradeId: "nope"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "unknown" {
		t.Fatalf("want status %q, got %q", "unknown", resp.Status)
	}
}

func TestGetUpgradeStatus_EmptyID(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.GetUpgradeStatus(adminUpgradeCtx(), &pb.GetUpgradeStatusRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}

// A github_tag upgrade with no binary path wired is Unavailable — same
// "misconfigured, don't panic" contract as the sentinel path, gated on its
// own field rather than autoUpdater (#1028).
func TestTriggerUpgrade_LocalNoBinaryPath_GithubTag(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.TriggerUpgrade(adminUpgradeCtx(), &pb.TriggerUpgradeRequest{GithubTag: "v0.99.0"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable (no binary path wired), got %v", err)
	}
}

// The github_tag path must work even when autoUpdater is nil (no sentinel
// configured) — that's the point of #1028: it has no sentinel dependency.
func TestTriggerUpgrade_GithubTag_DoesNotRequireAutoUpdater(t *testing.T) {
	// Point releases at a 404 server so the background goroutine's FetchSHA256
	// call fails fast instead of reaching real GitHub from a unit test.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	origBase := releases.GitHubReleaseBaseURL
	releases.GitHubReleaseBaseURL = srv.URL
	t.Cleanup(func() { releases.GitHubReleaseBaseURL = origBase })

	dir := t.TempDir()
	binaryPath := dir + "/containariumd"
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil { // #nosec G306 -- test fixture binary needs +x
		t.Fatalf("write fake binary: %v", err)
	}

	s := &ContainerServer{}
	s.SetBinaryPath(binaryPath) // autoUpdater stays nil — no sentinel configured

	resp, err := s.TriggerUpgrade(adminUpgradeCtx(), &pb.TriggerUpgradeRequest{GithubTag: "v0.99.0"})
	if err != nil {
		t.Fatalf("TriggerUpgrade: %v", err)
	}
	if resp.Status != "in_progress" || resp.UpgradeId == "" {
		t.Fatalf("want an in_progress job with an id, got %+v", resp)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		statusResp, err := s.GetUpgradeStatus(adminUpgradeCtx(), &pb.GetUpgradeStatusRequest{UpgradeId: resp.UpgradeId})
		if err != nil {
			t.Fatalf("GetUpgradeStatus: %v", err)
		}
		if statusResp.Status == "failed" {
			return // expected: the stubbed 404 SHA256SUMS.txt surfaces as a job failure
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job never reached a terminal \"failed\" status")
}
