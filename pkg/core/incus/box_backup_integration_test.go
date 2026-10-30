//go:build incus

package incus_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// laneBoxOps adapts the Incus client to backup.BoxOps the way
// container.Manager does in the daemon.
type laneBoxOps struct{ c *incus.Client }

func (o laneBoxOps) ExportInstance(name string) (io.ReadCloser, error) {
	return o.c.ExportInstance(name)
}
func (o laneBoxOps) BoxDiskUsage(name string) (int64, error) {
	m, err := o.c.GetContainerMetrics(name)
	if err != nil {
		return 0, err
	}
	return m.DiskUsageBytes, nil
}

// TestIntegrationIncusBoxBackup is the real-Incus half of the whole-box
// create path (#2801 PR B): a RUNNING box on a ZFS pool is backed up through
// backup.Manager.CreateBox, the stored file is an age ciphertext, the
// excluded directories' contents are gone, the manifest's digests match what
// was written, and Incus still imports the filtered archive (manifest entry
// included) as a box whose files are intact.
func TestIntegrationIncusBoxBackup(t *testing.T) {
	client := incusenv.Require(t)

	pid := os.Getpid()
	src := fmt.Sprintf("boxbackup%d", pid)
	dst := fmt.Sprintf("boxrestore%d", pid)
	dataset := fmt.Sprintf("incus-local/boxbackup%d", pid)
	run(t, "zfs", "create", dataset)
	t.Cleanup(func() { _ = exec.Command("zfs", "destroy", "-r", dataset).Run() }) // #nosec G204 -- test-controlled name
	pool := fmt.Sprintf("containarium-boxbackup%d", pid)
	if err := client.CreateZFSPool(pool, dataset); err != nil {
		t.Fatalf("CreateZFSPool(%s, %s): %v", pool, dataset, err)
	}
	t.Cleanup(func() { _ = client.DeleteStoragePool(pool) })

	if err := client.CreateContainer(incus.ContainerConfig{
		Name:  src,
		Image: incusenv.BoxImage(),
		Disk:  &incus.DiskDevice{Path: "/", Pool: pool, Size: "3GB"},
	}); err != nil {
		t.Fatalf("create %s: %v", src, err)
	}
	t.Cleanup(func() { incusenv.DeleteInstance(t, src) })
	if err := client.StartContainer(src); err != nil {
		t.Fatalf("start %s: %v", src, err)
	}
	// Without it the excluded /tmp probe could be removed by the boot's
	// tmpfiles run, and its absence would pass for the filter's work.
	waitForBoot(t, client, src)

	blob := make([]byte, 2<<20)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	kept := map[string][]byte{
		"/root/containarium-2801b/blob.bin": blob,
		"/etc/containarium-2801b.conf":      []byte("kept\n"),
	}
	excluded := map[string][]byte{
		"/tmp/containarium-2801b-probe":           []byte("tmp\n"),
		"/var/tmp/containarium-2801b-probe":       []byte("var-tmp\n"),
		"/var/cache/containarium-2801b/probe.bin": []byte("var-cache\n"),
	}
	for _, d := range []string{"/root/containarium-2801b", "/var/cache/containarium-2801b"} {
		if _, _, err := client.ExecWithOutput(src, []string{"mkdir", "-p", d}); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	for _, set := range []map[string][]byte{kept, excluded} {
		for p, b := range set {
			if err := client.WriteFile(src, p, b, "0644"); err != nil {
				t.Fatalf("write %s: %v", p, err)
			}
		}
	}

	// A file with two names: one in an excluded directory, one outside it.
	// Incus walks the root filesystem in path order, so "/tmp/..." comes
	// before "/usr/..." and the tar carries the content under the excluded
	// name and the kept one as a hard link to it. The backup must keep the
	// content at the kept name (it spills the excluded file and promotes the
	// link); only the lane can prove it against real Incus output (#3126).
	const linkContent = "hard link content\n"
	const linkExcluded = "/tmp/containarium-2801b-hl"
	const linkKept = "/usr/local/containarium-2801b-hl"
	if err := client.WriteFile(src, linkExcluded, []byte(linkContent), "0644"); err != nil {
		t.Fatalf("write %s: %v", linkExcluded, err)
	}
	if _, stderr, err := client.ExecWithOutput(src, []string{"ln", linkExcluded, linkKept}); err != nil {
		t.Fatalf("ln %s %s: %v (%s)", linkExcluded, linkKept, err, stderr)
	}
	kept[linkKept] = []byte(linkContent)
	excluded[linkExcluded] = []byte(linkContent)

	// The excluded probes must still be in the box when it is exported, or
	// their absence from the backup proves nothing about the filter.
	for p, b := range excluded {
		got, err := client.ReadFile(src, p)
		if err != nil || digest(got) != digest(b) {
			t.Fatalf("excluded probe %s is not in the source box before the backup: %v", p, err)
		}
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m := backup.NewManager(nil, nil, dir,
		backup.WithBoxOps(laneBoxOps{client}),
		backup.WithBoxStagingDirs("/var/lib/incus/backups"))
	start := time.Now()
	rec, err := m.CreateBox(backup.BoxCreateOptions{
		Username: src, ContainerName: src, Destination: backup.DestLocal,
		AgeRecipient: id.Recipient().String(), KeyMode: backup.KeyModeAgeRecipient,
	})
	if err != nil {
		t.Fatalf("CreateBox(%s): %v", src, err)
	}
	t.Logf("box backup of RUNNING %s: %d bytes stored in %s", src, rec.SizeBytes, time.Since(start).Round(time.Millisecond))
	if rec.Engine != backup.EngineBox || !rec.Encrypted {
		t.Fatalf("record = %+v", rec)
	}

	// Decrypt to a file, then read the archive.
	plain := filepath.Join(t.TempDir(), "box.tar.gz")
	decryptTo(t, rec.Location, plain, id)
	names, mf := readBoxArchive(t, plain)
	for p := range excluded {
		if names["backup/container/rootfs"+p] {
			t.Errorf("%s is in the box backup; it is excluded", p)
		}
	}
	files := map[string]string{}
	for _, f := range mf.Files {
		files[f.Path] = f.SHA256
	}
	for p, b := range kept {
		if files[p] != digest(b) {
			t.Errorf("manifest %s = %q, want %s", p, files[p], digest(b))
		}
	}
	for p := range excluded {
		if _, ok := files[p]; ok {
			t.Errorf("manifest lists excluded %s", p)
		}
	}
	// No spill file outlives the backup.
	if left, _ := filepath.Glob(filepath.Join(dir, ".box-spill-*.tmp")); len(left) != 0 {
		t.Errorf("spill files left in the backup directory: %v", left)
	}
	t.Logf("manifest: %d files, %d hard links, %d config entries", len(mf.Files), len(mf.Links), len(mf.Config))

	// The filtered archive, manifest entry and all, still imports.
	f, err := os.Open(plain) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	t.Cleanup(func() { incusenv.DeleteInstance(t, dst) })
	if err := client.ImportInstance(dst, pool, f, incus.ImportOptions{}); err != nil {
		t.Fatalf("ImportInstance(%s) of the filtered archive: %v", dst, err)
	}
	for p, b := range kept {
		got, err := client.ReadFile(dst, p)
		if err != nil {
			t.Errorf("%s missing from the imported box: %v", p, err)
			continue
		}
		if digest(got) != digest(b) {
			t.Errorf("%s digest %s after the round trip, want %s", p, digest(got), digest(b))
		}
	}
	for p := range excluded {
		if _, err := client.ReadFile(dst, p); err == nil {
			t.Errorf("excluded %s is present in the imported box", p)
		}
	}
}

func decryptTo(t *testing.T, src, dst string, id *age.X25519Identity) {
	t.Helper()
	in, err := os.Open(src) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	r, err := age.Decrypt(in, id)
	if err != nil {
		t.Fatalf("the stored box backup is not an age file for the recipient: %v", err)
	}
	out, err := os.Create(dst) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, r); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func readBoxArchive(t *testing.T, path string) (map[string]bool, backup.BoxManifest) {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("decrypted box backup is not gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	names := map[string]bool{}
	var last string
	var mf backup.BoxManifest
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		name := strings.TrimPrefix(h.Name, "./")
		names[name], last = true, name
		if name == backup.BoxManifestPath {
			if err := json.NewDecoder(tr).Decode(&mf); err != nil {
				t.Fatalf("manifest: %v", err)
			}
		}
	}
	if last != backup.BoxManifestPath {
		t.Fatalf("last entry %q, want the manifest", last)
	}
	return names, mf
}
