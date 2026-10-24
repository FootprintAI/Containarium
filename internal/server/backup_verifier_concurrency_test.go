package server

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestBackupVerifierSlotConcurrent checks that simultaneous requests cannot
// reserve multiple slots for one tenant and that other tenants remain independent.
func TestBackupVerifierSlotConcurrent(t *testing.T) {
	s := &BackupServer{}
	var wins atomic.Int32
	var release func()
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, ok := s.acquireVerifier("alice"); ok {
				wins.Add(1)
				release = r
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("acquired %d slots for alice, want 1", wins.Load())
	}
	bobRelease, ok := s.acquireVerifier("bob")
	if !ok {
		t.Fatal("alice's slot blocked bob")
	}
	bobRelease()
	release()
	r, ok := s.acquireVerifier("alice")
	if !ok {
		t.Fatal("released slot was not reusable")
	}
	r()
}

// TestBackupVerifierBusyRefusedBeforeProvisioning exercises the RPC guard:
// a busy tenant receives ResourceExhausted even without a container manager.
func TestBackupVerifierBusyRefusedBeforeProvisioning(t *testing.T) {
	_, s := verifierServer(t)
	release, _ := s.acquireVerifier("alice")
	defer release()
	s.containers = nil
	_, err := s.VerifyBackup(verifierCtx("alice"), &pb.VerifyBackupRequest{
		Id: "alice-app-20261003T010000Z", TargetUsername: "alice",
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("VerifyBackup error = %v, want ResourceExhausted", err)
	}
}

// TestBackupVerifierSlotReleasedAfterRPC checks release after both success and
// provisioning failure, so a failed job cannot permanently block its tenant.
func TestBackupVerifierSlotReleasedAfterRPC(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "provisioning failure"
		}
		t.Run(name, func(t *testing.T) {
			_, s := verifierServer(t)
			if fail {
				backend := incustest.NewMockBackend()
				backend.StartContainerFunc = func(string) error {
					return status.Error(codes.Unavailable, "start failed")
				}
				s.containers.manager = container.NewWithBackend(backend)
			}
			_, err := s.VerifyBackup(verifierCtx("alice"), &pb.VerifyBackupRequest{
				Id: "alice-app-20261003T010000Z", TargetUsername: "alice",
			})
			if (err != nil) != fail {
				t.Fatalf("VerifyBackup: %v", err)
			}
			r, ok := s.acquireVerifier("alice")
			if !ok {
				t.Fatal("RPC left tenant slot occupied")
			}
			r()
		})
	}
}
