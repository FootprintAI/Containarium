//go:build zfs

// Package zfspool builds throwaway ZFS pools for integration tests (#1200).
//
// Kept out of normal builds by the `zfs` build tag, and out of production
// code entirely: nothing here is imported by anything that ships.
//
// Pools are file-backed — a sparse image under the test's temp dir, no real
// disks — and named after the test binary's PID so they can never collide
// with a pool on the host. They are destroyed on teardown, including when
// the test fails.
package zfspool

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// vdevSize is comfortably above ZFS's 64 MiB minimum.
const vdevSize = 512 << 20

// Require skips the test unless a usable ZFS is present.
//
// Skips rather than fails on purpose: a developer's laptop or a container
// dev box legitimately has no ZFS. The CI lane that exists to demonstrate
// the encryption claim asserts the environment separately and fails on a
// skip, so this cannot quietly turn that lane into a no-op.
func Require(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("ZFS pool operations need root; run with sudo -E")
	}
	for _, bin := range []string{"zfs", "zpool"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH; install zfsutils-linux", bin)
		}
	}
	if _, err := os.Stat("/dev/zfs"); err != nil {
		t.Skipf("/dev/zfs is absent, so the kernel module cannot be driven: %v", err)
	}
}

// Run executes a command and fails the test on error.
func Run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// Pool is a throwaway file-backed pool.
type Pool struct {
	Name  string // the ZFS pool name
	Mount string // its mountpoint
	Image string // the backing file
}

// New creates a pool and registers its teardown.
func New(t *testing.T) *Pool {
	t.Helper()
	dir := t.TempDir()
	p := &Pool{
		Name:  fmt.Sprintf("containarium-zfstest-%d", os.Getpid()),
		Mount: filepath.Join(dir, "mnt"),
		Image: filepath.Join(dir, "vdev.img"),
	}

	if err := os.MkdirAll(p.Mount, 0o755); err != nil {
		t.Fatalf("mkdir mountpoint: %v", err)
	}
	f, err := os.Create(p.Image)
	if err != nil {
		t.Fatalf("create vdev: %v", err)
	}
	if err := f.Truncate(vdevSize); err != nil {
		t.Fatalf("truncate vdev: %v", err)
	}
	_ = f.Close()

	Run(t, "zpool", "create", "-m", p.Mount, p.Name, p.Image)
	t.Cleanup(func() {
		// -f because a failed test may have left a dataset mounted.
		_ = exec.Command("zpool", "destroy", "-f", p.Name).Run()
	})
	return p
}

// Dataset returns a child dataset name under the pool.
func (p *Pool) Dataset(name string) string { return p.Name + "/" + name }

// ContainsPlaintext reports whether the pool's backing file contains the
// needle. The pool is synced first so writes have reached the vdev.
func (p *Pool) ContainsPlaintext(t *testing.T, needle []byte) bool {
	t.Helper()
	_ = exec.Command("zpool", "sync", p.Name).Run()

	data, err := os.ReadFile(p.Image)
	if err != nil {
		t.Fatalf("read vdev image: %v", err)
	}
	return bytes.Contains(data, needle)
}

// UnmountIfMounted unmounts a dataset, tolerating "not currently mounted".
//
// Needed because `zfs load-key` makes a dataset readable but does NOT
// remount it, so after an unload/load cycle a dataset has its key available
// and no mount. In production the mount is Incus's job, which is why the
// pre-start hook only loads the key.
func UnmountIfMounted(t *testing.T, dataset string) {
	t.Helper()
	out, err := exec.Command("zfs", "unmount", dataset).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "not currently mounted") {
		t.Fatalf("zfs unmount %s: %v\n%s", dataset, err, out)
	}
}

// IsMounted reports the dataset's `mounted` property.
func IsMounted(t *testing.T, dataset string) bool {
	t.Helper()
	out := Run(t, "zfs", "get", "-H", "-o", "value", "mounted", dataset)
	return strings.TrimSpace(out) == "yes"
}
