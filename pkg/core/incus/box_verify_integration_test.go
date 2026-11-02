//go:build incus

package incus_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// laneRestoreOps adds the import side to laneBoxOps, the way
// container.Manager does in the daemon, importing into the lane's pool.
type laneRestoreOps struct {
	laneBoxOps
	pool string
}

func (o laneRestoreOps) BoxState(name string) (backup.BoxState, error) {
	info, err := o.c.GetContainer(name)
	switch {
	case incus.IsNotFound(err) || (err == nil && info == nil):
		return backup.BoxAbsent, nil
	case err != nil:
		return backup.BoxAbsent, err
	case info.State == "Stopped":
		return backup.BoxStopped, nil
	default:
		return backup.BoxActive, nil
	}
}
func (o laneRestoreOps) ImportBox(name string, r io.Reader) error {
	return o.c.ImportInstance(name, o.pool, r, incus.ImportOptions{})
}
func (o laneRestoreOps) RenameBox(from, to string) error { return o.c.RenameInstance(from, to) }
func (o laneRestoreOps) DeleteBox(name string) error     { return o.c.DeleteContainer(name) }

// TestIntegrationIncusBoxVerify is the real-Incus half of #2802: a box with
// known files is backed up, VerifyBox restores it into a scratch box,
// compares every regular file with the manifest and deletes the scratch
// box; a flipped byte in the stored backup then fails verification by name,
// and again leaves no scratch box. Skipped where Incus is absent.
func TestIntegrationIncusBoxVerify(t *testing.T) {
	client := incusenv.Require(t)

	pid := os.Getpid()
	src := fmt.Sprintf("boxverify%d", pid)
	dataset := fmt.Sprintf("incus-local/boxverify%d", pid)
	run(t, "zfs", "create", dataset)
	t.Cleanup(func() { _ = exec.Command("zfs", "destroy", "-r", dataset).Run() }) // #nosec G204 -- test-controlled name
	pool := fmt.Sprintf("containarium-boxverify%d", pid)
	if err := client.CreateZFSPool(pool, dataset); err != nil {
		t.Fatalf("CreateZFSPool(%s, %s): %v", pool, dataset, err)
	}
	t.Cleanup(func() { _ = client.DeleteStoragePool(pool) })
	if err := client.CreateContainer(incus.ContainerConfig{
		Name: src, Image: incusenv.BoxImage(),
		Disk: &incus.DiskDevice{Path: "/", Pool: pool, Size: "3GB"},
	}); err != nil {
		t.Fatalf("create %s: %v", src, err)
	}
	t.Cleanup(func() { incusenv.DeleteInstance(t, src) })
	if err := client.StartContainer(src); err != nil {
		t.Fatalf("start %s: %v", src, err)
	}
	blob := make([]byte, 1<<20)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteFile(src, "/root/containarium-2802.bin", blob, "0644"); err != nil {
		t.Fatalf("write: %v", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ops := laneRestoreOps{laneBoxOps{client}, pool}
	m := backup.NewManager(nil, nil, t.TempDir(), backup.WithBoxOps(ops), backup.WithBoxStagingDirs("/var/lib/incus/backups"))
	rec, err := m.CreateBox(backup.BoxCreateOptions{
		Username: src, ContainerName: src, Destination: backup.DestLocal,
		AgeRecipient: id.Recipient().String(), KeyMode: backup.KeyModeAgeRecipient,
	})
	if err != nil {
		t.Fatalf("CreateBox(%s): %v", src, err)
	}

	verify := func(want backup.VerificationResult) *backup.Verification {
		t.Helper()
		v, err := m.VerifyBox(backup.BoxVerifyOptions{ID: rec.ID, AgeIdentity: id.String()})
		if err != nil {
			t.Fatalf("VerifyBox: %v", err)
		}
		t.Cleanup(func() { incusenv.DeleteInstance(t, v.TargetContainer) })
		for _, c := range v.Checks {
			t.Logf("check %-10s passed=%t %s", c.Name, c.Passed, c.Detail)
		}
		if v.Result != want {
			t.Fatalf("result = %s (%s), want %s", v.Result, v.Error, want)
		}
		if state, err := ops.BoxState(v.TargetContainer); err != nil || state != backup.BoxAbsent {
			t.Errorf("scratch box %s left behind: %v %v", v.TargetContainer, state, err)
		}
		return v
	}
	verify(backup.VerificationPassed)

	raw, err := os.ReadFile(rec.Location)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(rec.Location, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if v := verify(backup.VerificationFailed); !strings.Contains(v.Error, "checksum") {
		t.Errorf("tampered backup failed with %q, want the checksum named", v.Error)
	}
}
