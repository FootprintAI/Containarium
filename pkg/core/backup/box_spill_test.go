package backup

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// The spill holds the (encrypted) content of excluded files, so it must not
// be readable by other users.
func TestBoxSpill_FileModeIs0600(t *testing.T) {
	s := &boxSpill{dir: t.TempDir()}
	defer s.close()
	if err := s.add("a", &tar.Header{Name: "a", Size: 1}, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("spill mode = %o, want 600", got)
	}
}

// A backup that fails after the spill was written deletes the spill.
func TestCreateBox_SpillDeletedOnErrorPath(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	good := buildArchive(t, incusLikeEntries())
	// The trailer is gone, so the failure comes after every entry, the
	// excluded files (and so the spill) included, has been read.
	box := newFakeBox(good[:len(good)-4])
	m := newBoxManager(t, box)
	if _, err := m.CreateBox(boxOpts(id.Recipient().String())); err == nil {
		t.Fatal("CreateBox succeeded on a truncated export")
	}
	assertNothingStaged(t, m.dir)
}

// ... and a successful one leaves only the finished archive and its sidecar.
func TestCreateBox_SpillDeletedOnSuccess(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	m := newBoxManager(t, newFakeBox(buildArchive(t, incusLikeEntries())))
	if _, err := m.CreateBox(boxOpts(id.Recipient().String())); err != nil {
		t.Fatal(err)
	}
	if left := spillFiles(t, m.dir); len(left) != 0 {
		t.Errorf("spill files left behind: %v", left)
	}
}

func spillFiles(t *testing.T, dir string) []string {
	t.Helper()
	got, err := filepath.Glob(filepath.Join(dir, ".box-spill-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func touchOld(t *testing.T, path string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// #3126: a SIGKILL mid-backup leaves its spill file behind. A sweep removes
// stale ones, and only those: exact name, regular file, old enough, not the
// spill of a backup running in this process, never through a symlink.
func TestSweepBoxSpills(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	writeFile(t, victim, "must survive")
	touchOld(t, victim, 72*time.Hour)

	stale := filepath.Join(dir, ".box-spill-111.tmp")
	fresh := filepath.Join(dir, ".box-spill-222.tmp")
	notSpill := filepath.Join(dir, "alice-box-20261027T000000Z.box.tar.gz.age")
	wrongExt := filepath.Join(dir, ".box-spill-333.txt")
	wrongPrefix := filepath.Join(dir, "box-spill-444.tmp")
	staleDirName := filepath.Join(dir, ".box-spill-555.tmp")
	link := filepath.Join(dir, ".box-spill-666.tmp")
	inFlight := filepath.Join(dir, ".box-spill-777.tmp")
	for _, p := range []string{stale, fresh, notSpill, wrongExt, wrongPrefix, inFlight} {
		writeFile(t, p, "x")
	}
	if err := os.Mkdir(staleDirName, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{stale, notSpill, wrongExt, wrongPrefix, inFlight} {
		touchOld(t, p, 72*time.Hour)
	}
	touchOld(t, staleDirName, 72*time.Hour)
	// The symlink keeps its creation time (there is no Lchtimes in the
	// standard library), so it is skipped here by TYPE, not by age. Its
	// target is aged above so that following the link would be caught.
	activeSpills.Store(inFlight, struct{}{})
	defer activeSpills.Delete(inFlight)

	m := NewManager(newFakeOps(nil), nil, dir)
	n, err := m.SweepStaleBoxSpills()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("swept %d files, want 1", n)
	}
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	if exists(stale) {
		t.Error("the stale spill was not removed")
	}
	for name, p := range map[string]string{
		"fresh spill": fresh, "unrelated file": notSpill, "wrong extension": wrongExt,
		"wrong prefix": wrongPrefix, "directory with the name": staleDirName,
		"symlink": link, "symlink target": victim, "in-flight spill": inFlight,
	} {
		if !exists(p) {
			t.Errorf("%s was removed", name)
		}
	}
}

// A missing backup directory is nothing to sweep, not an error.
func TestSweepBoxSpills_MissingDir(t *testing.T) {
	m := NewManager(newFakeOps(nil), nil, filepath.Join(t.TempDir(), "absent"))
	if n, err := m.SweepStaleBoxSpills(); err != nil || n != 0 {
		t.Errorf("= %d, %v; want 0, nil", n, err)
	}
}

// The spill of a running backup is registered, so a sweep from a second
// backup in the same process leaves it alone, and unregistered on close.
func TestBoxSpill_RegisteredWhileOpen(t *testing.T) {
	s := &boxSpill{dir: t.TempDir()}
	if err := s.add("a", &tar.Header{Name: "a", Size: 1}, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	name := s.f.Name()
	if _, ok := activeSpills.Load(name); !ok {
		t.Error("an open spill is not registered as active")
	}
	s.close()
	if _, ok := activeSpills.Load(name); ok {
		t.Error("a closed spill is still registered as active")
	}
}

// A backup sweeps stale spills before it starts.
func TestCreateBox_SweepsStaleSpillsFirst(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	m := newBoxManager(t, newFakeBox(buildArchive(t, incusLikeEntries())))
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(m.dir, ".box-spill-dead.tmp")
	writeFile(t, stale, "leftover")
	touchOld(t, stale, 72*time.Hour)
	if _, err := m.CreateBox(boxOpts(id.Recipient().String())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Errorf("the stale spill survived a backup: %v", err)
	}
}

// The in-flight guard must hold when the backup directory is not in clean
// form (double slash, trailing slash, ./): the spill is registered under one
// spelling of the path and found under another. Its mtime is made stale so
// only the guard can save it.
func TestSweepBoxSpills_InFlightGuardWithUncleanDir(t *testing.T) {
	base := t.TempDir()
	for _, dir := range []string{base + "//", base + "/./sub/", base + "//sub2//"} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		s := &boxSpill{dir: dir}
		if err := s.add("a", &tar.Header{Name: "a", Size: 1}, strings.NewReader("x")); err != nil {
			t.Fatal(err)
		}
		touchOld(t, s.f.Name(), 72*time.Hour)
		m := NewManager(newFakeOps(nil), nil, dir)
		n, err := m.SweepStaleBoxSpills()
		if err != nil || n != 0 {
			t.Errorf("dir %q: swept %d, %v; want the in-flight spill left alone", dir, n, err)
		}
		if _, err := os.Stat(s.f.Name()); err != nil {
			t.Errorf("dir %q: in-flight spill removed: %v", dir, err)
		}
		s.close()
	}
}
