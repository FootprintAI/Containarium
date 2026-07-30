package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2EInstallerQuickstart is the installer-level (Layer 3) e2e for
// `install.sh --quickstart`. It provisions a BARE Ubuntu 24.04 VM (not the
// containarium terraform module, which pre-installs the daemon), copies the
// tree's hacks/install.sh onto it, and runs the fresh-VM bootstrap:
//
//	sudo bash install.sh --quickstart alice --stack nodejs
//
// then asserts the daemon installed and the first box actually came up. This
// exercises the keyless path — the headline "skip bring-your-own-ssh-key"
// behavior — so it needs no key material and no SSH-into-the-box.
//
// Gated like the other GCP e2e tests: skips in -short and without GCP_PROJECT.
//
//	GCP_PROJECT=my-project GCP_ZONE=asia-east1-a \
//	  go test -v -run TestE2EInstallerQuickstart -timeout 40m ./test/integration/
//
// Env knobs: GCP_ZONE (default asia-east1-a), E2E_MACHINE_TYPE (default
// n2-standard-4), E2E_INSTALL_SCRIPT (default ../../hacks/install.sh),
// KEEP_INSTANCE=true to leave the VM for debugging.
func TestE2EInstallerQuickstart(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}
	project := os.Getenv("GCP_PROJECT")
	if project == "" {
		t.Skip("GCP_PROJECT not set, skipping installer E2E test")
	}

	zone := envOr("GCP_ZONE", "asia-east1-a")
	machine := envOr("E2E_MACHINE_TYPE", "n2-standard-4")
	script := envOr("E2E_INSTALL_SCRIPT", "../../hacks/install.sh")
	scriptAbs, err := filepath.Abs(script)
	require.NoError(t, err)
	require.FileExists(t, scriptAbs, "install.sh not found; set E2E_INSTALL_SCRIPT")

	// Unique per run so parallel/retried runs don't collide; cleaned up below.
	instance := fmt.Sprintf("qs-installer-e2e-%d", time.Now().Unix())
	const box = "alice"

	// The whole flow (provision + apt + Incus + a box with a stack) is slow.
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()

	// ── Provision a bare Ubuntu VM ──────────────────────────────────────
	t.Logf("Creating bare Ubuntu VM %q (%s, %s)...", instance, machine, zone)
	out, err := gcloud(ctx, "compute", "instances", "create", instance,
		"--project="+project, "--zone="+zone,
		"--machine-type="+machine,
		"--image-family=ubuntu-2404-lts-amd64",
		"--image-project=ubuntu-os-cloud",
		"--boot-disk-size=40GB",
	)
	require.NoError(t, err, "instance create failed:\n%s", out)

	t.Cleanup(func() {
		if os.Getenv("KEEP_INSTANCE") == "true" {
			t.Logf("KEEP_INSTANCE=true — leaving %q; delete with: gcloud compute instances delete %s --zone %s", instance, instance, zone)
			return
		}
		// Fresh context — the test's may be cancelled/expired by now.
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer dcancel()
		if o, derr := gcloud(dctx, "compute", "instances", "delete", instance,
			"--project="+project, "--zone="+zone, "--quiet"); derr != nil {
			t.Logf("cleanup: failed to delete %q: %v\n%s", instance, derr, o)
		}
	})

	// ── Wait for SSH ────────────────────────────────────────────────────
	waitForSSH(t, ctx, project, zone, instance)

	// ── Copy the tree's install.sh and run the quickstart bootstrap ─────
	t.Log("Copying install.sh to the VM...")
	out, err = gcloud(ctx, "compute", "scp", scriptAbs, instance+":/tmp/install.sh",
		"--project="+project, "--zone="+zone)
	require.NoError(t, err, "scp install.sh failed:\n%s", out)

	t.Log("Running install.sh --quickstart (keyless)... this takes several minutes")
	out, err = sshVM(t, ctx, project, zone, instance,
		"sudo bash /tmp/install.sh --quickstart "+box+" --stack nodejs")
	require.NoError(t, err, "installer --quickstart failed:\n%s", out)
	// The installer prints keyless next-steps; a cheap sanity check that it
	// took the keyless branch rather than erroring on a missing key.
	assert.Contains(t, out, "keyless", "expected the keyless bootstrap path")

	// ── Assert the daemon + box are actually up ─────────────────────────
	list, err := sshVM(t, ctx, project, zone, instance, "sudo containarium list")
	require.NoError(t, err, "containarium list failed:\n%s", list)
	assert.Contains(t, list, box, "box %q not listed after installer quickstart", box)
	t.Logf("containarium list:\n%s", list)
}

// ─── helpers (named to avoid clashing with the terraform e2e helpers) ────

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func gcloud(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "gcloud", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// sshVM runs a command on the instance over gcloud IAP-less SSH.
func sshVM(t *testing.T, ctx context.Context, project, zone, instance, command string) (string, error) {
	t.Helper()
	return gcloud(ctx, "compute", "ssh", instance,
		"--project="+project, "--zone="+zone,
		"--command="+command)
}

// waitForSSH polls until the VM accepts SSH (boot + sshd up), up to ~5 min.
func waitForSSH(t *testing.T, ctx context.Context, project, zone, instance string) {
	t.Helper()
	t.Log("Waiting for SSH on the VM...")
	for i := 0; i < 30; i++ {
		if _, err := gcloud(ctx, "compute", "ssh", instance,
			"--project="+project, "--zone="+zone,
			"--ssh-flag=-o ConnectTimeout=5",
			"--command=true"); err == nil {
			t.Logf("SSH ready after ~%ds", i*10)
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled while waiting for SSH: %v", ctx.Err())
		case <-time.After(10 * time.Second):
		}
	}
	t.Fatal("VM never became SSH-reachable")
}
