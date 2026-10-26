//go:build incus

package incus_test

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// TestIntegrationIncusExportImport is the real-Incus half of the whole-box
// backup seam (#2801 PR A): a RUNNING instance on a ZFS-backed pool is
// exported through the daemon's own ExportInstance, deleted, imported under a
// new name through ImportInstance, and every file written before the export
// must come back with the same digest.
//
// It also records, in the test log, the two facts the later slices need and
// a fake cannot give (docs/architecture/container-snapshots.md, "Whole-box
// export"):
//   - whether a live export is point-in-time: Incus's ZFS driver is expected
//     to take a temporary read-only snapshot for a non-optimized backup, and
//     the test watches the instance's dataset for one while the export runs;
//   - what the tarball contains: its layout, and whether files under /tmp,
//     /var/tmp, /var/cache and /run are in it (Incus has no per-path
//     exclude, so the excludes decided on #2800 have to be applied by us).
func TestIntegrationIncusExportImport(t *testing.T) {
	client := incusenv.Require(t)
	if info, err := client.GetServerInfo(); err == nil {
		t.Logf("server API extension direct_backup present: %v (false = stored-backup fallback path)",
			slices.Contains(info.APIExtensions, "direct_backup"))
	}

	pid := os.Getpid()
	src := fmt.Sprintf("exporttest%d", pid)
	dst := fmt.Sprintf("importtest%d", pid)

	// A pool of the test's own, sourced at a plain dataset on the lane's
	// zpool, so the test does not depend on another package having run the
	// daemon's InitializeInfrastructure first.
	dataset := fmt.Sprintf("incus-local/exporttest%d", pid)
	run(t, "zfs", "create", dataset)
	t.Cleanup(func() { _ = exec.Command("zfs", "destroy", "-r", dataset).Run() }) // #nosec G204 -- test-controlled name
	pool := fmt.Sprintf("containarium-exporttest%d", pid)
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
	waitForBoot(t, client, src)

	// Synthetic content: a random binary blob and a small text file that must
	// survive, plus one probe in each directory #2800 decided to exclude.
	big := make([]byte, 4<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("random content: %v", err)
	}
	files := map[string][]byte{
		"/root/containarium-2801a/blob.bin":   big,
		"/etc/containarium-2801a.conf":        []byte("written before the export\n"),
		"/tmp/containarium-2801a-probe":       []byte("tmp probe\n"),
		"/var/tmp/containarium-2801a-probe":   []byte("var-tmp probe\n"),
		"/var/cache/containarium-2801a-probe": []byte("var-cache probe\n"),
	}
	// /run is a tmpfs inside a running container: a snapshot of the
	// dataset cannot contain it. Logged, not compared.
	const runProbe = "/run/containarium-2801a-probe"
	if _, _, err := client.ExecWithOutput(src, []string{"mkdir", "-p", "/root/containarium-2801a"}); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for p, content := range files {
		if err := client.WriteFile(src, p, content, "0644"); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	if err := client.WriteFile(src, runProbe, []byte("run probe\n"), "0644"); err != nil {
		t.Logf("write %s: %v (recorded, not fatal)", runProbe, err)
	}
	if info, err := client.GetContainer(src); err != nil || info.State != "Running" {
		t.Fatalf("%s must be RUNNING when exported: %+v, %v", src, info, err)
	}

	// Watch the instance's dataset for a snapshot Incus takes on its own
	// while the export runs: the evidence for "is a live export consistent".
	instanceDataset := incusenv.DatasetFor(t, src)
	if instanceDataset == "" {
		t.Fatalf("%s has no ZFS dataset; the lane is not on ZFS", src)
	}
	stopWatch := make(chan struct{})
	var seen []string
	var watchWG sync.WaitGroup
	watchWG.Add(1)
	go func() {
		defer watchWG.Done()
		for {
			out, _ := exec.Command("zfs", "list", "-H", "-t", "snapshot", "-o", "name", "-r", instanceDataset).Output() // #nosec G204 -- test-controlled name
			for _, s := range strings.Fields(string(out)) {
				if !slices.Contains(seen, s) {
					seen = append(seen, s)
				}
			}
			select {
			case <-stopWatch:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()

	archivePath := filepath.Join(t.TempDir(), "export-2801a.tar")
	start := time.Now()
	n := exportTo(t, client, src, archivePath)
	close(stopWatch)
	watchWG.Wait()
	t.Logf("exported RUNNING %s: %d bytes in %s", src, n, time.Since(start).Round(time.Millisecond))
	if len(seen) == 0 {
		t.Logf("CONSISTENCY: no snapshot of %s observed during the live export", instanceDataset)
	} else {
		t.Logf("CONSISTENCY: snapshots of %s observed during the live export: %v", instanceDataset, seen)
	}
	if out, _ := exec.Command("zfs", "list", "-H", "-t", "snapshot", "-o", "name", "-r", instanceDataset).Output(); len(bytes.TrimSpace(out)) > 0 { // #nosec G204 -- test-controlled name
		t.Errorf("the export left snapshots behind on %s: %s", instanceDataset, out)
	}

	inspectArchive(t, archivePath, append(sortedKeys(files), runProbe))

	// Delete the source, then restore under a new name from the archive.
	if err := client.StopContainer(src, true); err != nil {
		t.Fatalf("stop %s: %v", src, err)
	}
	if err := client.DeleteContainer(src); err != nil {
		t.Fatalf("delete %s: %v", src, err)
	}
	f, err := os.Open(archivePath) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer func() { _ = f.Close() }()
	t.Cleanup(func() { incusenv.DeleteInstance(t, dst) })
	if err := client.ImportInstance(dst, pool, f, incus.ImportOptions{}); err != nil {
		t.Fatalf("ImportInstance(%s): %v", dst, err)
	}

	// Read the files from the STOPPED import: a boot runs systemd-tmpfiles,
	// which empties /tmp, and that is the guest's doing, not the backup's.
	for _, p := range sortedKeys(files) {
		got, err := client.ReadFile(dst, p)
		if err != nil {
			t.Errorf("%s missing from the imported instance: %v", p, err)
			continue
		}
		if digest(got) != digest(files[p]) {
			t.Errorf("%s digest %s after the round trip, want %s", p, digest(got), digest(files[p]))
		}
	}
	if _, err := client.ReadFile(dst, runProbe); err == nil {
		t.Logf("TARBALL: %s present in the imported rootfs", runProbe)
	} else {
		t.Logf("TARBALL: %s absent from the imported rootfs (%v)", runProbe, err)
	}

	// And the import is a box that boots, not just a dataset.
	if err := client.StartContainer(dst); err != nil {
		t.Fatalf("start the imported %s: %v", dst, err)
	}
	if out, _, err := client.ExecWithOutput(dst, []string{"sha256sum", "/root/containarium-2801a/blob.bin"}); err != nil {
		t.Errorf("exec in the imported box: %v", err)
	} else if !strings.HasPrefix(out, digest(big)) {
		t.Errorf("in-box sha256sum = %q, want prefix %s", out, digest(big))
	}
}

// exportTo streams the export to path and returns its size.
func exportTo(t *testing.T, client *incus.Client, name, path string) int64 {
	t.Helper()
	rc, err := client.ExportInstance(name)
	if err != nil {
		t.Fatalf("ExportInstance(%s): %v", name, err)
	}
	out, err := os.Create(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	n, copyErr := io.Copy(out, rc)
	closeErr := rc.Close()
	fileErr := out.Close()
	if copyErr != nil || closeErr != nil || fileErr != nil {
		t.Fatalf("export %s: copy=%v close=%v file=%v", name, copyErr, closeErr, fileErr)
	}
	return n
}

// inspectArchive logs the tarball's layout and, for each probe path, whether
// the rootfs in it carries the file.
func inspectArchive(t *testing.T, path string, probes []string) {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer func() { _ = f.Close() }()
	br := bufio.NewReader(f)
	magic, _ := br.Peek(4)
	var r io.Reader = br
	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		t.Logf("TARBALL: gzip-compressed tar")
		gz, err := gzip.NewReader(br)
		if err != nil {
			t.Fatalf("gzip: %v", err)
		}
		r = gz
	case bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		t.Logf("TARBALL: zstd-compressed; layout not inspected (no zstd in the standard library)")
		return
	default:
		t.Logf("TARBALL: uncompressed (magic %x)", magic)
	}

	tr := tar.NewReader(r)
	layout := map[string]int{}
	var meta []string
	found := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		name := strings.TrimPrefix(h.Name, "./")
		parts := strings.SplitN(name, "/", 4)
		if len(parts) >= 3 {
			layout[strings.Join(parts[:3], "/")]++
		} else {
			layout[name]++
		}
		if !strings.Contains(name, "/rootfs/") && h.Typeflag == tar.TypeReg {
			meta = append(meta, fmt.Sprintf("%s (%d bytes)", name, h.Size))
		}
		for _, p := range probes {
			if strings.HasSuffix(name, "/rootfs"+p) {
				found[p] = name
			}
		}
	}
	keys := make([]string, 0, len(layout))
	for k := range layout {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("TARBALL layout: %s (%d entries)", k, layout[k])
	}
	for _, m := range meta {
		t.Logf("TARBALL metadata file: %s", m)
	}
	for _, p := range probes {
		if at, ok := found[p]; ok {
			t.Logf("TARBALL: %s INCLUDED as %s", p, at)
		} else {
			t.Logf("TARBALL: %s NOT in the archive", p)
		}
	}
}

// waitForBoot blocks until the box's systemd has finished booting.
//
// A probe written while the box is still booting can be deleted under the
// test: systemd-tmpfiles-setup runs at boot with --remove, and Ubuntu's
// tmp.conf marks /tmp with "D", so a /tmp file written before it runs is
// gone by the export (/var/tmp is not "D" and survives). That race made
// TestIntegrationIncusExportImport report "/tmp probe NOT in the archive"
// on one lane run and "INCLUDED" on the next.
func waitForBoot(t *testing.T, client *incus.Client, name string) {
	t.Helper()
	// is-system-running --wait returns once the boot job queue is empty;
	// it exits non-zero for "degraded", which a container often is, so
	// the state it prints is what counts.
	out, _, _ := client.ExecWithOutput(name, []string{"timeout", "180", "systemctl", "is-system-running", "--wait"})
	state := strings.TrimSpace(out)
	switch state {
	case "running", "degraded":
		t.Logf("%s booted (systemd %s)", name, state)
	default:
		t.Fatalf("%s did not finish booting: systemd state %q", name, state)
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil { // #nosec G204 -- test-controlled args
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
