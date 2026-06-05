package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2EPodmanRebootSurvival validates the #387 reboot-durability chain
// end-to-end on a real GCE host:
//
//	host reboot
//	  → Incus autostarts the tenant container (boot.autostart=true)
//	    → systemd in the container starts podman-restart.service
//	      → the workload (created --restart=always) comes back RUNNING
//
// The daemon's provisioning of this chain (system + user
// podman-restart.service + enable-linger) is unit-covered in
// pkg/core/container/podman_restart_test.go; this test exercises the OS
// path the unit test can't — that a real reboot actually brings the
// workload back without intervention. It is the "reboot-survival case in
// the acceptance suite" referenced by docs/PODMAN-REBOOT-DURABILITY.md.
//
// Rootful is used here (system podman-restart.service) to keep the test
// self-contained; the rootless linger path is the harder one the daemon
// wires and is asserted at the unit level.
//
// Gated exactly like TestE2ERebootPersistence: skipped in -short and when
// GCP_PROJECT is unset, because it creates and reboots a real instance.
func TestE2EPodmanRebootSurvival(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}
	projectID := os.Getenv("GCP_PROJECT")
	if projectID == "" {
		t.Skip("GCP_PROJECT not set, skipping E2E test")
	}

	zone := getEnv("GCP_ZONE", "asia-east1-a")
	instanceName := fmt.Sprintf("containarium-e2e-podman-%d", time.Now().Unix())
	const ctr = "podman-reboot-test"
	const svc = "e2e-svc"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	t.Logf("Starting E2E podman reboot-survival test (instance=%s zone=%s)", instanceName, zone)

	defer func() {
		if !t.Failed() || os.Getenv("KEEP_INSTANCE") != "true" {
			t.Log("Cleaning up test instance...")
			cleanupInstance(t, projectID, zone, instanceName)
		} else {
			t.Logf("Test failed - keeping instance %s (KEEP_INSTANCE=true)", instanceName)
		}
	}()

	t.Run("CreateInstance", func(t *testing.T) {
		createTestInstance(t, ctx, projectID, zone, instanceName)
	})
	t.Run("WaitForInstance", func(t *testing.T) {
		ip := waitForInstanceReady(t, ctx, projectID, zone, instanceName)
		require.NotEmpty(t, ip, "instance IP should not be empty")
	})

	// Provision a tenant container that survives host boot, install podman,
	// and start an always-restart workload — mirroring what a --podman
	// tenant ends up with.
	t.Run("ProvisionPodmanWorkload", func(t *testing.T) {
		// Launch the tenant container and mark it to autostart on host boot
		// (the daemon sets boot.autostart=true for tenants).
		sshOK(t, ctx, projectID, zone, instanceName,
			"sudo incus launch images:ubuntu/24.04 "+ctr+" -d root,size=20GB")
		// Container needs a moment to get networking before apt.
		time.Sleep(20 * time.Second)
		sshOK(t, ctx, projectID, zone, instanceName,
			"sudo incus config set "+ctr+" boot.autostart true")

		// Install podman inside the tenant.
		sshOK(t, ctx, projectID, zone, instanceName,
			"sudo incus exec "+ctr+" -- bash -lc 'export DEBIAN_FRONTEND=noninteractive; "+
				"apt-get update -qq && apt-get install -y -qq podman'")

		// Enable the system podman-restart.service — the rootful half of
		// what enablePodmanRestartDurability does.
		sshOK(t, ctx, projectID, zone, instanceName,
			"sudo incus exec "+ctr+" -- systemctl enable podman-restart.service")

		// Start a long-lived workload WITH a restart policy. Without the
		// policy, podman-restart.service would not bring it back — that's
		// the gap #387 is about.
		sshOK(t, ctx, projectID, zone, instanceName,
			"sudo incus exec "+ctr+" -- podman run -d --restart=always --name "+svc+
				" docker.io/library/alpine:3.20 sleep infinity")

		// Sanity: the workload is Up before we reboot.
		out := sshOK(t, ctx, projectID, zone, instanceName,
			"sudo incus exec "+ctr+" -- podman ps --filter name="+svc+" --format '{{.Status}}'")
		require.Contains(t, strings.ToLower(out), "up", "workload should be Up before reboot")
		t.Logf("✓ workload %q running before reboot", svc)
	})

	t.Run("RebootInstance", func(t *testing.T) {
		rebootInstance(t, ctx, projectID, zone, instanceName)
	})
	t.Run("WaitAfterReboot", func(t *testing.T) {
		waitForInstanceReady(t, ctx, projectID, zone, instanceName)
	})

	// The crux: after a real host reboot, with NO manual intervention, the
	// tenant container is RUNNING and the workload inside is back Up.
	t.Run("VerifyWorkloadSurvived", func(t *testing.T) {
		// 1. Incus autostarted the tenant container.
		requireEventually(t, 24, 5*time.Second, func() bool {
			out, err := ssh(ctx, projectID, zone, instanceName,
				"sudo incus list "+ctr+" --format csv -c ns")
			return err == nil && strings.Contains(strings.ToUpper(out), "RUNNING")
		}, "tenant container should be RUNNING (boot.autostart) after reboot")
		t.Log("✓ tenant container autostarted after reboot")

		// 2. podman-restart.service brought the workload back Up.
		requireEventually(t, 24, 5*time.Second, func() bool {
			out, err := ssh(ctx, projectID, zone, instanceName,
				"sudo incus exec "+ctr+" -- podman ps --filter name="+svc+" --format '{{.Status}}'")
			return err == nil && strings.Contains(strings.ToLower(out), "up")
		}, "workload should be Up again after reboot via podman-restart.service")
		t.Logf("✅ workload %q survived host reboot with no intervention", svc)
	})
}

// ssh runs a command on the instance over `gcloud compute ssh` and returns
// combined output. Mirrors the inline pattern used throughout
// e2e_reboot_test.go, factored out for the retry loops below.
func ssh(ctx context.Context, projectID, zone, instanceName, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instanceName,
		"--project="+projectID,
		"--zone="+zone,
		"--command="+command,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// sshOK runs a command and fails the test on error.
func sshOK(t *testing.T, ctx context.Context, projectID, zone, instanceName, command string) string {
	t.Helper()
	out, err := ssh(ctx, projectID, zone, instanceName, command)
	require.NoError(t, err, "ssh %q failed: %s", command, out)
	return out
}

// requireEventually polls cond up to attempts times, sleeping interval
// between tries, and fails with msg if it never becomes true. Reboots are
// asynchronous (autostart + in-container systemd take time), so the
// post-reboot assertions need to wait rather than check once.
func requireEventually(t *testing.T, attempts int, interval time.Duration, cond func() bool, msg string) {
	t.Helper()
	for i := 0; i < attempts; i++ {
		if cond() {
			return
		}
		time.Sleep(interval)
	}
	assert.Fail(t, "condition not met", msg)
	t.FailNow()
}
