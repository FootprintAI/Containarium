//go:build incus

package incusenv

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// SocketPath is where the daemon's own client looks for Incus. Kept here
// rather than reaching into incus.New's default so a test failure names the
// path the environment was checked at.
const SocketPath = "/var/lib/incus/unix.socket"

// Require returns a client connected to the local Incus, having checked that
// one is actually usable.
//
// What happens when it is not usable is DispositionFor's call: a skip on a
// machine that never had Incus, a failure in the lane that set RequireEnv.
// Either way the reason is spelled out — "which step, which error" is what
// #1332's timebox asks for if the environment turns out to be impossible.
func Require(t *testing.T) *incus.Client {
	t.Helper()

	if os.Geteuid() != 0 {
		unusable(t, "Incus operations need root; run with sudo -E")
		return nil
	}
	if _, err := os.Stat(SocketPath); err != nil {
		unusable(t, "no Incus socket at %s, so the daemon's create path cannot be driven: %v", SocketPath, err)
		return nil
	}

	client, err := incus.NewWithSocket(SocketPath)
	if err != nil {
		unusable(t, "cannot connect to Incus at %s: %v", SocketPath, err)
		return nil
	}
	info, err := client.GetServerInfo()
	if err != nil {
		unusable(t, "connected to Incus at %s but it does not answer: %v", SocketPath, err)
		return nil
	}
	t.Logf("Incus %s on kernel %s", info.Environment.ServerVersion, info.Environment.KernelVersion)
	return client
}

// unusable reports an unusable environment as whatever RequireEnv says it is.
//
// Never Skipf without consulting DispositionFor: a lane whose entire purpose
// is to run this code must not be able to report green by not running it.
func unusable(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if DispositionFor(os.Getenv(RequireEnv)) == Fail {
		t.Fatalf("%s (%s is set, so this is a failure and not a skip)", msg, RequireEnv)
		return
	}
	t.Skipf("%s (set %s=1 to make this a failure instead)", msg, RequireEnv)
}

// DatasetFor returns the ZFS dataset backing an Incus instance, and "" when
// the instance has no dataset of its own.
//
// It searches by suffix rather than composing the name from the pool's
// source, because the layout is Incus's to choose: a pool sourced at
// `incus-local/containers` puts an instance at
// `incus-local/containers/containers/<name>`, and asserting that shape here
// would test our arithmetic instead of what Incus did.
//
// This lookup is also the shape #1199's datasetResolver needs — the hook has
// to name the dataset a container will live on before Incus creates the
// instance — which is why the lane proves it can be answered at all.
func DatasetFor(t *testing.T, instanceName string) string {
	t.Helper()

	out, err := exec.Command("zfs", "list", "-H", "-o", "name", "-r").CombinedOutput() // #nosec G204 -- no caller input
	if err != nil {
		t.Fatalf("zfs list: %v\n%s", err, out)
	}
	suffix := "/containers/" + instanceName
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if name := strings.TrimSpace(line); strings.HasSuffix(name, suffix) {
			return name
		}
	}
	return ""
}

// CreateZFSPool adds an Incus storage pool sourced at an existing ZFS
// dataset, and registers its removal.
//
// Shells out to the CLI because the daemon's client has no method for
// creating an arbitrary pool — EnsureStorage only ever provisions the one
// configured pool, which is the right production surface and the wrong one
// for a test that needs a second pool to compare against.
func CreateZFSPool(t *testing.T, poolName, sourceDataset string) {
	t.Helper()
	out, err := exec.Command("incus", "storage", "create", poolName, "zfs", // #nosec G204 -- test-controlled names
		"source="+sourceDataset).CombinedOutput()
	if err != nil {
		t.Fatalf("incus storage create %s zfs source=%s: %v\n%s", poolName, sourceDataset, err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("incus", "storage", "delete", poolName).CombinedOutput(); err != nil { // #nosec G204 -- test-controlled name
			t.Logf("cleanup: could not delete storage pool %s: %v\n%s", poolName, err, out)
		}
	})
}

// DeleteInstance removes an instance, tolerating one that was never created.
// Registered as cleanup so a failed test does not leave the runner — or a
// developer's box — carrying a container and its dataset.
func DeleteInstance(t *testing.T, name string) {
	t.Helper()
	if out, err := exec.Command("incus", "delete", "--force", name).CombinedOutput(); err != nil { // #nosec G204 -- test-controlled name
		if !strings.Contains(string(out), "not found") {
			t.Logf("cleanup: could not delete instance %s: %v\n%s", name, err, out)
		}
	}
}
