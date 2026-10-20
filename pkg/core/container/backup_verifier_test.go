package container

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// TestBackupVerifierLifecycle checks ownership, cleanup on provisioning failure,
// and propagation of deletion errors to the caller.
func TestBackupVerifierLifecycle(t *testing.T) {
	for _, stage := range []string{"success", "create", "start", "network", "provision", "cleanup"} {
		t.Run(stage, func(t *testing.T) {
			backend := incustest.NewMockBackend()
			var config incus.ContainerConfig
			deleted := 0
			backend.CreateContainerFunc = func(c incus.ContainerConfig) error {
				config = c
				if stage == "create" {
					return errors.New("create failed")
				}
				return nil
			}
			backend.StartContainerFunc = func(string) error {
				if stage == "start" {
					return errors.New("start failed")
				}
				return nil
			}
			backend.WaitForNetworkFunc = func(string, time.Duration) (string, error) {
				if stage == "network" {
					return "", errors.New("network failed")
				}
				return "127.0.0.1", nil
			}
			backend.ExecWithExitCodeFunc = func(string, []string) (string, string, int, error) {
				if stage == "provision" {
					return "", "package failure", 1, nil
				}
				return "", "", 0, nil
			}
			backend.DeleteContainerFunc = func(string) error {
				deleted++
				if stage == "cleanup" {
					return errors.New("delete failed")
				}
				return nil
			}
			name, password, cleanup, err := NewWithBackend(backend).CreateBackupVerifier("alice")
			if stage == "success" || stage == "cleanup" {
				if err != nil {
					t.Fatal(err)
				}
				if name == "alice-container" || !strings.HasPrefix(name, "backup-verify-") || password == "" {
					t.Fatalf("unsafe target: %q", name)
				}
				if config.ExtraConfig[incus.TenantLabelKey] != "alice" || config.ExtraConfig[incus.TTLExpiresAtKey] == "" {
					t.Fatalf("missing owner or expiry: %+v", config.ExtraConfig)
				}
				if cleanupErr := cleanup(); (cleanupErr != nil) != (stage == "cleanup") {
					t.Fatalf("cleanup: %v", cleanupErr)
				}
			} else if err == nil {
				t.Fatal("expected provisioning failure")
			}
			wantDeleted := 1
			if stage == "create" {
				wantDeleted = 0
			}
			if deleted != wantDeleted {
				t.Fatalf("deleted %d targets, want %d", deleted, wantDeleted)
			}
		})
	}
}
