package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"filippo.io/age"
)

// --- #2801 PR B: the whole-box create path ---

// tarEntry is one entry of a synthetic Incus instance backup tarball.
type tarEntry struct {
	name     string
	typ      byte
	body     string
	linkname string
	pax      map[string]string
}

// incusLikeEntries mirrors the layout the lane recorded for a real Incus 6.0
// export (docs/architecture/container-snapshots.md, "Whole-box export"):
// index and config at the top, the root filesystem under
// backup/container/rootfs/. It carries one probe in each excluded directory
// and the edge cases the filter has to get right.
func incusLikeEntries() []tarEntry {
	return []tarEntry{
		{name: "backup/", typ: tar.TypeDir},
		{name: "backup/index.yaml", typ: tar.TypeReg, body: "name: alice-container\nbackend: zfs\n"},
		{name: "backup/container/", typ: tar.TypeDir},
		{name: "backup/container/backup.yaml", typ: tar.TypeReg, body: "container:\n  name: alice-container\n  devices: {}\n"},
		{name: "backup/container/rootfs/", typ: tar.TypeDir},
		{name: "backup/container/rootfs/etc/", typ: tar.TypeDir},
		{name: "backup/container/rootfs/etc/hostname", typ: tar.TypeReg, body: "alice\n"},
		// File capabilities ride as PAX xattr records: dropping them would
		// break ping and friends in the restored box.
		{name: "backup/container/rootfs/usr/bin/ping", typ: tar.TypeReg, body: "ELF-ping", pax: map[string]string{"SCHILY.xattr.security.capability": "\x01\x00\x00\x02"}},
		{name: "backup/container/rootfs/usr/bin/vi", typ: tar.TypeLink, linkname: "backup/container/rootfs/usr/bin/ping"},
		{name: "backup/container/rootfs/var/run", typ: tar.TypeSymlink, linkname: "/run"},
		// Excluded directories: the directory entry stays, its contents go.
		{name: "backup/container/rootfs/tmp/", typ: tar.TypeDir},
		{name: "backup/container/rootfs/tmp/probe", typ: tar.TypeReg, body: "tmp probe"},
		{name: "backup/container/rootfs/tmp/sub/", typ: tar.TypeDir},
		{name: "backup/container/rootfs/var/tmp/", typ: tar.TypeDir},
		{name: "backup/container/rootfs/var/tmp/probe", typ: tar.TypeReg, body: "var-tmp probe"},
		{name: "backup/container/rootfs/var/cache/", typ: tar.TypeDir},
		{name: "backup/container/rootfs/var/cache/apt/pkgcache.bin", typ: tar.TypeReg, body: "cache"},
		{name: "backup/container/rootfs/run/", typ: tar.TypeDir},
		{name: "backup/container/rootfs/run/probe", typ: tar.TypeReg, body: "run probe"},
		// A file with one name in an excluded directory and another outside
		// it. The tar carries the content under the first name (here the
		// excluded one) and makes the kept name a hard link to it. The kept
		// name must keep the content: it becomes a regular file, and a
		// second kept link then points at it.
		{name: "backup/container/rootfs/root/tmp-link", typ: tar.TypeLink, linkname: "backup/container/rootfs/tmp/probe"},
		{name: "backup/container/rootfs/srv/second-link", typ: tar.TypeLink, linkname: "./backup/container/rootfs/tmp/probe"},
		// A link inside an excluded directory goes, whatever it points at.
		{name: "backup/container/rootfs/tmp/link-to-kept", typ: tar.TypeLink, linkname: "backup/container/rootfs/etc/hostname"},
		// Look-alikes that are NOT excluded.
		{name: "backup/container/rootfs/var/cachefile", typ: tar.TypeReg, body: "not a cache dir"},
		{name: "backup/container/rootfs/home/alice/tmp/notes", typ: tar.TypeReg, body: "a home tmp dir is data"},
	}
}

func buildArchive(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Linkname: e.linkname, PAXRecords: e.pax}
		if e.typ == tar.TypeDir {
			h.Mode = 0o1777
		}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("write header %s: %v", e.name, err)
		}
		if e.typ == tar.TypeReg {
			if _, err := io.WriteString(tw, e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeBox is the Incus side of a whole-box backup.
type fakeBox struct {
	archive   func() io.Reader
	usage     int64
	usageErr  error
	exportErr error
	exported  []string
	closed    int
}

func (f *fakeBox) ExportInstance(name string) (io.ReadCloser, error) {
	f.exported = append(f.exported, name)
	if f.exportErr != nil {
		return nil, f.exportErr
	}
	return ownedReader{Reader: f.archive(), close: func() { f.closed++ }}, nil
}

func (f *fakeBox) BoxDiskUsage(string) (int64, error) { return f.usage, f.usageErr }

func newFakeBox(archive []byte) *fakeBox {
	return &fakeBox{archive: func() io.Reader { return bytes.NewReader(archive) }, usage: 1 << 20}
}

func newBoxManager(t *testing.T, box BoxOps, opts ...Option) *Manager {
	t.Helper()
	m := NewManager(newFakeOps(nil), nil, t.TempDir(), append([]Option{WithBoxOps(box)}, opts...)...)
	m.clock = fixedClock
	return m
}

func boxOpts(recipient string) BoxCreateOptions {
	return BoxCreateOptions{
		Username:      "alice",
		ContainerName: "alice-container",
		Destination:   DestLocal,
		AgeRecipient:  recipient,
		KeyMode:       KeyModeAgeRecipient,
	}
}

// openBoxBackup decrypts a stored whole-box backup and returns its entries
// (name -> header, body) in archive order.
func openBoxBackup(t *testing.T, path, identity string) ([]string, map[string]*tar.Header, map[string][]byte) {
	t.Helper()
	ct, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(ct, []byte("age-encryption.org/")) || bytes.Contains(ct, []byte("alice-container")) {
		t.Fatal("stored whole-box backup is not an age ciphertext")
	}
	pt, err := decryptWithIdentity(ct, identity)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(pt))
	if err != nil {
		t.Fatalf("stored plaintext is not gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	var order []string
	hdrs := map[string]*tar.Header{}
	bodies := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, h.Name)
		hdrs[h.Name], bodies[h.Name] = h, b
	}
	return order, hdrs, bodies
}

func sha(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}

// The create path end to end: export, exclude, digest, encrypt, record.
func TestCreateBox_FiltersExcludesEncryptsAndWritesManifest(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	box := newFakeBox(buildArchive(t, incusLikeEntries()))
	m := newBoxManager(t, box)

	rec, err := m.CreateBox(boxOpts(id.Recipient().String()))
	if err != nil {
		t.Fatalf("CreateBox: %v", err)
	}
	if len(box.exported) != 1 || box.exported[0] != "alice-container" || box.closed != 1 {
		t.Fatalf("exported %v, closed %d times; want alice-container once, closed once", box.exported, box.closed)
	}

	// The record.
	if rec.ID != "alice-box-20260605T130405Z" {
		t.Errorf("id = %q", rec.ID)
	}
	if rec.Engine != EngineBox || rec.Database != "alice-container" || !rec.Encrypted || rec.AgeRecipient != id.Recipient().String() {
		t.Errorf("record = %+v", rec)
	}
	if !strings.HasSuffix(rec.Location, ".box.tar.gz.age") {
		t.Errorf("location %q does not say what it holds", rec.Location)
	}
	ct, _ := os.ReadFile(rec.Location)
	if rec.SizeBytes != int64(len(ct)) || rec.SHA256 != sha(string(ct)) {
		t.Errorf("size/sha256 do not describe the stored ciphertext")
	}
	if got, err := m.Get(rec.ID); err != nil || got.Engine != EngineBox {
		t.Errorf("sidecar: %+v, %v", got, err)
	}
	// Only the archive and its sidecar stay: the spill of excluded content
	// is gone.
	if entries, _ := os.ReadDir(m.dir); len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("backup dir holds %v, want the archive and its sidecar only", names)
	}

	order, hdrs, bodies := openBoxBackup(t, rec.Location, id.String())

	// Excluded contents are gone; the directories themselves stay.
	for _, gone := range []string{
		"backup/container/rootfs/tmp/probe", "backup/container/rootfs/tmp/sub/",
		"backup/container/rootfs/var/tmp/probe", "backup/container/rootfs/var/cache/apt/pkgcache.bin",
		"backup/container/rootfs/run/probe", "backup/container/rootfs/tmp/link-to-kept",
	} {
		if _, ok := hdrs[gone]; ok {
			t.Errorf("%s is in the backup; it is excluded", gone)
		}
	}
	for _, kept := range []string{
		"backup/index.yaml", "backup/container/backup.yaml",
		"backup/container/rootfs/tmp/", "backup/container/rootfs/var/tmp/",
		"backup/container/rootfs/var/cache/", "backup/container/rootfs/run/",
		"backup/container/rootfs/etc/hostname", "backup/container/rootfs/var/run",
		"backup/container/rootfs/var/cachefile", "backup/container/rootfs/home/alice/tmp/notes",
		"backup/container/rootfs/usr/bin/vi",
	} {
		if _, ok := hdrs[kept]; !ok {
			t.Errorf("%s is missing from the backup", kept)
		}
	}
	if h := hdrs["backup/container/rootfs/root/tmp-link"]; h == nil || h.Typeflag != tar.TypeReg || string(bodies["backup/container/rootfs/root/tmp-link"]) != "tmp probe" {
		t.Errorf("kept name of an excluded file lost its content: %+v %q", h, bodies["backup/container/rootfs/root/tmp-link"])
	}
	if h := hdrs["backup/container/rootfs/srv/second-link"]; h == nil || h.Typeflag != tar.TypeLink || h.Linkname != "backup/container/rootfs/root/tmp-link" {
		t.Errorf("second kept link = %+v, want a hard link to the promoted file", h)
	}
	if h := hdrs["backup/container/rootfs/tmp/"]; h != nil && h.Mode != 0o1777 {
		t.Errorf("excluded dir mode = %o, want 1777 kept", h.Mode)
	}
	if string(bodies["backup/container/rootfs/etc/hostname"]) != "alice\n" {
		t.Errorf("kept file content changed")
	}
	if got := hdrs["backup/container/rootfs/usr/bin/ping"].PAXRecords["SCHILY.xattr.security.capability"]; got != "\x01\x00\x00\x02" {
		t.Errorf("file capability xattr lost: %q", got)
	}
	if hdrs["backup/container/rootfs/var/run"].Linkname != "/run" {
		t.Errorf("symlink target changed")
	}

	// The manifest is the last entry, inside the encryption.
	if order[len(order)-1] != BoxManifestPath {
		t.Fatalf("last entry = %q, want the manifest %q", order[len(order)-1], BoxManifestPath)
	}
	var mf BoxManifest
	if err := json.Unmarshal(bodies[BoxManifestPath], &mf); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if mf.Version != 1 || mf.Box != "alice-container" || mf.CreatedAt.IsZero() {
		t.Errorf("manifest header = %+v", mf)
	}
	if strings.Join(mf.Excluded, ",") != "/tmp,/var/tmp,/var/cache,/run" {
		t.Errorf("manifest excluded = %v", mf.Excluded)
	}
	want := map[string]string{
		"/etc/hostname":         sha("alice\n"),
		"/usr/bin/ping":         sha("ELF-ping"),
		"/var/cachefile":        sha("not a cache dir"),
		"/home/alice/tmp/notes": sha("a home tmp dir is data"),
		"/root/tmp-link":        sha("tmp probe"),
	}
	got := map[string]string{}
	for _, f := range mf.Files {
		got[f.Path] = f.SHA256
		if f.Size < 0 {
			t.Errorf("%s: negative size", f.Path)
		}
	}
	if len(got) != len(want) {
		t.Errorf("manifest files = %v, want exactly %v", got, want)
	}
	for p, d := range want {
		if got[p] != d {
			t.Errorf("manifest %s = %q, want %q", p, got[p], d)
		}
	}
	if len(mf.Links) != 2 || mf.Links[0] != (BoxManifestLink{Path: "/usr/bin/vi", Target: "/usr/bin/ping"}) ||
		mf.Links[1] != (BoxManifestLink{Path: "/srv/second-link", Target: "/root/tmp-link"}) {
		t.Errorf("manifest links = %+v", mf.Links)
	}
	cfg := map[string]string{}
	for _, f := range mf.Config {
		cfg[f.Path] = f.SHA256
	}
	if cfg["backup/container/backup.yaml"] != sha("container:\n  name: alice-container\n  devices: {}\n") || cfg["backup/index.yaml"] == "" {
		t.Errorf("manifest config digests = %v", cfg)
	}
}

// Tar names may carry a leading "./"; the excludes still apply.
func TestCreateBox_DotSlashNamesAreFiltered(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	box := newFakeBox(buildArchive(t, []tarEntry{
		{name: "./backup/index.yaml", typ: tar.TypeReg, body: "x"},
		{name: "./backup/container/rootfs/tmp/probe", typ: tar.TypeReg, body: "p"},
		{name: "./backup/container/rootfs/etc/hostname", typ: tar.TypeReg, body: "h"},
	}))
	m := newBoxManager(t, box)
	rec, err := m.CreateBox(boxOpts(id.Recipient().String()))
	if err != nil {
		t.Fatal(err)
	}
	_, hdrs, _ := openBoxBackup(t, rec.Location, id.String())
	if _, ok := hdrs["./backup/container/rootfs/tmp/probe"]; ok {
		t.Error("./-prefixed excluded file survived")
	}
	if _, ok := hdrs["./backup/container/rootfs/etc/hostname"]; !ok {
		t.Error("./-prefixed kept file dropped")
	}
}

// Every refusal happens before the export starts and leaves nothing behind.
func TestCreateBox_Refusals(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	recipient := id.Recipient().String()
	archive := buildArchive(t, incusLikeEntries())
	for _, tc := range []struct {
		name    string
		mutate  func(*BoxCreateOptions)
		box     func(*fakeBox)
		mgrOpts []Option
		noBox   bool
		wantErr string
		is      error
	}{
		{name: "plaintext is forbidden", mutate: func(o *BoxCreateOptions) { o.KeyMode = ""; o.AgeRecipient = "" }, wantErr: "plaintext"},
		{name: "plaintext is forbidden even with a recipient", mutate: func(o *BoxCreateOptions) { o.KeyMode = "" }, wantErr: "plaintext"},
		{name: "recipient mode needs a recipient", mutate: func(o *BoxCreateOptions) { o.AgeRecipient = "" }, wantErr: "recipient"},
		{name: "managed mode needs a wrapper", mutate: func(o *BoxCreateOptions) { o.KeyMode = KeyModeManaged }, wantErr: "wrapper"},
		{name: "a bad recipient", mutate: func(o *BoxCreateOptions) { o.AgeRecipient = "age1nope" }, wantErr: "recipient"},
		{name: "no container", mutate: func(o *BoxCreateOptions) { o.ContainerName = "" }, wantErr: "container"},
		{name: "no destination", mutate: func(o *BoxCreateOptions) { o.Destination = "" }, wantErr: "destination"},
		{name: "gcs without uploader", mutate: func(o *BoxCreateOptions) { o.Destination = DestGCS; o.GCSBucket = "gs://b" }, wantErr: "uploader"},
		{name: "a username that escapes the dir", mutate: func(o *BoxCreateOptions) { o.Username = "../x" }, wantErr: "safe backup id"},
		{name: "a daemon with no Incus export", noBox: true, wantErr: "not available"},
		{name: "the box size cannot be read", box: func(b *fakeBox) { b.usageErr = errors.New("state unavailable") }, wantErr: "state unavailable"},
		{name: "an unknown box size", box: func(b *fakeBox) { b.usage = 0 }, wantErr: "disk usage"},
		{
			name:    "not enough free space in the staging directory",
			mgrOpts: []Option{withFreeSpace(func(string) (diskSpace, error) { return diskSpace{Free: 1 << 10, Device: 1}, nil })},
			is:      ErrInsufficientSpace,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			box := newFakeBox(archive)
			if tc.box != nil {
				tc.box(box)
			}
			var m *Manager
			if tc.noBox {
				m = NewManager(newFakeOps(nil), nil, t.TempDir())
				m.clock = fixedClock
			} else {
				m = newBoxManager(t, box, tc.mgrOpts...)
			}
			o := boxOpts(recipient)
			if tc.mutate != nil {
				tc.mutate(&o)
			}
			_, err := m.CreateBox(o)
			if err == nil {
				t.Fatal("CreateBox succeeded, want a refusal")
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantErr)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want errors.Is %v", err, tc.is)
			}
			if len(box.exported) != 0 {
				t.Errorf("the box was exported before the refusal")
			}
			assertNothingStaged(t, m.dir)
		})
	}
}

func assertNothingStaged(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("left behind in the backup dir: %s", e.Name())
	}
}

// The free-space pre-flight counts the box once per staging area, and twice
// on a filesystem that holds both Incus's staged export and ours.
func TestCreateBox_FreeSpacePreflight(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	const usage = 100 << 20
	incusDir := t.TempDir()
	for _, tc := range []struct {
		name    string
		space   func(ours bool) diskSpace
		wantErr bool
	}{
		{"separate filesystems, each fits", func(ours bool) diskSpace {
			if ours {
				return diskSpace{Free: 150 << 20, Device: 1}
			}
			return diskSpace{Free: 150 << 20, Device: 2}
		}, false},
		{"one filesystem, each fits alone but not both", func(bool) diskSpace { return diskSpace{Free: 150 << 20, Device: 7} }, true},
		{"one filesystem with room for both", func(bool) diskSpace { return diskSpace{Free: 250 << 20, Device: 7} }, false},
		{"incus staging area too small", func(ours bool) diskSpace {
			if ours {
				return diskSpace{Free: 1 << 30, Device: 1}
			}
			return diskSpace{Free: 50 << 20, Device: 2}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			box := newFakeBox(buildArchive(t, incusLikeEntries()))
			box.usage = usage
			var m *Manager
			m = newBoxManager(t, box, WithBoxStagingDirs(incusDir), withFreeSpace(func(p string) (diskSpace, error) {
				return tc.space(p == m.dir), nil
			}))
			_, err := m.CreateBox(boxOpts(id.Recipient().String()))
			if tc.wantErr {
				if !errors.Is(err, ErrInsufficientSpace) {
					t.Fatalf("err = %v, want ErrInsufficientSpace", err)
				}
				if len(box.exported) != 0 {
					t.Error("exported despite the failed pre-flight")
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateBox: %v", err)
			}
		})
	}
}

// A staging dir that does not exist (a different Incus layout, or a server
// that streams directly) is not counted, and does not fail the backup.
func TestCreateBox_MissingIncusStagingDirIsSkipped(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	box := newFakeBox(buildArchive(t, incusLikeEntries()))
	m := newBoxManager(t, box, WithBoxStagingDirs(filepath.Join(t.TempDir(), "absent")))
	if _, err := m.CreateBox(boxOpts(id.Recipient().String())); err != nil {
		t.Fatalf("CreateBox: %v", err)
	}
}

// The BOX cap defaults to 256 GiB, separate from the 16 GiB dump cap, and
// a stream over the cap fails without leaving a partial backup.
func TestCreateBox_SizeCap(t *testing.T) {
	if DefaultMaxBoxBytes != 256<<30 {
		t.Errorf("DefaultMaxBoxBytes = %d, want 256 GiB", DefaultMaxBoxBytes)
	}
	if m := NewManager(newFakeOps(nil), nil, t.TempDir()); m.maxBoxBytes != DefaultMaxBoxBytes || m.maxDumpBytes != DefaultMaxDumpBytes {
		t.Errorf("defaults: box %d dump %d", m.maxBoxBytes, m.maxDumpBytes)
	}
	if m := NewManager(newFakeOps(nil), nil, t.TempDir(), WithMaxBoxBytes(-1)); m.maxBoxBytes != DefaultMaxBoxBytes {
		t.Errorf("a non-positive cap must keep the default, got %d", m.maxBoxBytes)
	}

	id, _ := age.GenerateX25519Identity()
	raw := make([]byte, 64<<10)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	big := string(raw) // incompressible, so the stored archive outgrows the cap
	entries := append(incusLikeEntries(), tarEntry{name: "backup/container/rootfs/srv/random", typ: tar.TypeReg, body: big})
	box := newFakeBox(buildArchive(t, entries))
	m := newBoxManager(t, box, WithMaxBoxBytes(2<<10))
	_, err := m.CreateBox(boxOpts(id.Recipient().String()))
	if !errors.Is(err, ErrDumpTooLarge) {
		t.Fatalf("err = %v, want ErrDumpTooLarge", err)
	}
	if box.closed != 1 {
		t.Errorf("export closed %d times, want 1", box.closed)
	}
	assertNothingStaged(t, m.dir)
}

// The cap also bounds the uncompressed content, as DefaultMaxDumpBytes does
// for a dump: a box of zeros (or a sparse file) compresses to almost
// nothing, and must not make the daemon decompress without limit.
func TestCreateBox_CapBoundsUncompressedContent(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	entries := append(incusLikeEntries(), tarEntry{name: "backup/container/rootfs/srv/zeros", typ: tar.TypeReg, body: strings.Repeat("\x00", 1<<20)})
	archive := buildArchive(t, entries)
	if len(archive) > 64<<10 {
		t.Fatalf("fixture archive is %d bytes; it must be far below the cap to test the uncompressed bound", len(archive))
	}
	box := newFakeBox(archive)
	m := newBoxManager(t, box, WithMaxBoxBytes(256<<10))
	_, err := m.CreateBox(boxOpts(id.Recipient().String()))
	if !errors.Is(err, ErrDumpTooLarge) {
		t.Fatalf("err = %v, want ErrDumpTooLarge for 1 MiB of content under a 256 KiB cap", err)
	}
	assertNothingStaged(t, m.dir)
}

// After the tar end marker only zero padding may follow, and only so much.
func TestCreateBox_TrailingData(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	for _, tc := range []struct {
		name    string
		tail    []byte
		wantErr bool
	}{
		{"zero padding is accepted", make([]byte, 64<<10), false},
		{"a little non-zero data is refused", bytes.Repeat([]byte{0xAA}, 100), true},
		{"too much zero padding is refused", make([]byte, 2<<20), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			_ = tw.WriteHeader(&tar.Header{Name: "backup/index.yaml", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
			_, _ = tw.Write([]byte("x"))
			_ = tw.Close()
			_, _ = gz.Write(tc.tail)
			_ = gz.Close()
			m := newBoxManager(t, newFakeBox(buf.Bytes()))
			_, err := m.CreateBox(boxOpts(id.Recipient().String()))
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("CreateBox: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "trailing") {
				t.Fatalf("err = %v, want a trailing-data refusal", err)
			}
			assertNothingStaged(t, m.dir)
		})
	}
}

// A broken or unexpected export fails the backup and leaves nothing behind.
func TestCreateBox_BadExports(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	good := buildArchive(t, incusLikeEntries())
	forged := buildArchive(t, append(incusLikeEntries(), tarEntry{name: BoxManifestPath, typ: tar.TypeReg, body: "{}"}))
	for _, tc := range []struct {
		name    string
		box     *fakeBox
		wantErr string
	}{
		{"export refused", &fakeBox{exportErr: errors.New("instance busy"), usage: 1}, "instance busy"},
		{"truncated stream", &fakeBox{archive: func() io.Reader { return bytes.NewReader(good[:len(good)/2]) }, usage: 1}, "export"},
		{"stream error", &fakeBox{archive: func() io.Reader {
			return io.MultiReader(bytes.NewReader(good[:100]), iotestErrReader{errors.New("connection reset")})
		}, usage: 1}, "connection reset"},
		// The tar end marker arrives intact but the gzip trailer (CRC and
		// length) does not: still a broken export, never a short backup.
		{"truncated gzip trailer", &fakeBox{archive: func() io.Reader { return bytes.NewReader(good[:len(good)-4]) }, usage: 1}, "export"},
		{"not gzip", &fakeBox{archive: func() io.Reader { return strings.NewReader("(\xb5/\xfd zstd frame") }, usage: 1}, "gzip"},
		{"an archive that already carries a manifest", &fakeBox{archive: func() io.Reader { return bytes.NewReader(forged) }, usage: 1}, "manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newBoxManager(t, tc.box)
			_, err := m.CreateBox(boxOpts(id.Recipient().String()))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
			if tc.box.exportErr == nil && tc.box.closed != 1 {
				t.Errorf("export closed %d times, want 1", tc.box.closed)
			}
			assertNothingStaged(t, m.dir)
		})
	}
}

type iotestErrReader struct{ err error }

func (r iotestErrReader) Read([]byte) (int, error) { return 0, r.err }

// Managed key mode wraps a per-backup identity as for a database backup.
func TestCreateBox_ManagedKeyMode(t *testing.T) {
	w := newTestWrapper(t)
	box := newFakeBox(buildArchive(t, incusLikeEntries()))
	m := newManagedManager(t, newFakeOps(nil), nil, w)
	WithBoxOps(box)(m)
	o := boxOpts("")
	o.KeyMode = KeyModeManaged
	rec, err := m.CreateBox(o)
	if err != nil {
		t.Fatalf("CreateBox: %v", err)
	}
	if rec.KeyMode != KeyModeManaged || len(rec.WrappedKey) == 0 || rec.KEKID == "" {
		t.Fatalf("record key fields = mode %q wrapped %d kek %q", rec.KeyMode, len(rec.WrappedKey), rec.KEKID)
	}
	_, hdrs, _ := openBoxBackup(t, rec.Location, unwrapIdentity(t, w, rec))
	if _, ok := hdrs[BoxManifestPath]; !ok {
		t.Error("managed backup has no manifest")
	}
}

// GCS: the encrypted archive and its sidecar go to the bucket, and no local
// copy of the archive stays behind.
func TestCreateBox_GCS(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	up := &fakeUploader{}
	box := newFakeBox(buildArchive(t, incusLikeEntries()))
	m := NewManager(newFakeOps(nil), up, t.TempDir(), WithBoxOps(box))
	m.clock = fixedClock
	o := boxOpts(id.Recipient().String())
	o.Destination, o.GCSBucket = DestGCS, "gs://bucket/boxes/"
	rec, err := m.CreateBox(o)
	if err != nil {
		t.Fatalf("CreateBox: %v", err)
	}
	wantObj := "gs://bucket/boxes/alice-box-20260605T130405Z.box.tar.gz.age"
	if rec.Location != wantObj {
		t.Errorf("location = %q, want %q", rec.Location, wantObj)
	}
	if strings.Join(up.uploadOrder, " ") != wantObj+" gs://bucket/boxes/alice-box-20260605T130405Z.meta.json" {
		t.Errorf("upload order = %v", up.uploadOrder)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "alice-box-20260605T130405Z.box.tar.gz.age")); !os.IsNotExist(err) {
		t.Errorf("local archive copy left behind: %v", err)
	}
}

// Two backups of the same box in the same second must not overwrite each
// other's record.
func TestCreateBox_RefusesToOverwriteARecord(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	box := newFakeBox(buildArchive(t, incusLikeEntries()))
	m := newBoxManager(t, box)
	if _, err := m.CreateBox(boxOpts(id.Recipient().String())); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateBox(boxOpts(id.Recipient().String())); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second create err = %v, want already exists", err)
	}
	if len(box.exported) != 1 {
		t.Errorf("second create exported the box")
	}
}

// Restoring or restore-testing a BOX record through the database path would
// feed a tarball to pg_restore; both refuse until the BOX restore lands.
func TestBoxRecord_DatabaseRestoreAndVerifyRefuse(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	ops := newFakeOps(nil)
	m := NewManager(ops, nil, t.TempDir(), WithBoxOps(newFakeBox(buildArchive(t, incusLikeEntries()))))
	m.clock = fixedClock
	rec, err := m.CreateBox(boxOpts(id.Recipient().String()))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "alice-container", TargetContainer: "bob-container", AgeIdentity: id.String()}); err == nil || !strings.Contains(err.Error(), "whole-box") {
		t.Errorf("Restore err = %v, want a whole-box refusal", err)
	}
	if _, err := m.Verify(VerifyOptions{ID: rec.ID, TargetContainer: "bob-container", AgeIdentity: id.String()}); err == nil || !strings.Contains(err.Error(), "whole-box") {
		t.Errorf("Verify err = %v, want a whole-box refusal", err)
	}
	if len(ops.written) != 0 || len(ops.execLog) != 0 {
		t.Errorf("container touched: written %d, exec %v", len(ops.written), ops.execLog)
	}
}

// Memory stays bounded for a large box: the archive is streamed through the
// filter and the encryption, never held whole. The source is generated as it
// is read, so the only large allocations would be the code under test's.
func TestCreateBox_StreamsLargeBoxInBoundedMemory(t *testing.T) {
	const fileSize = 8 << 20
	const files = 16 // 128 MiB of incompressible file content
	id, _ := age.GenerateX25519Identity()
	var peak atomic.Uint64
	box := &fakeBox{usage: files * fileSize, archive: func() io.Reader {
		pr, pw := io.Pipe()
		go func() {
			gz, _ := gzip.NewWriterLevel(pw, gzip.BestSpeed)
			tw := tar.NewWriter(gz)
			buf := make([]byte, 1<<20)
			rng := mrand.NewChaCha8([32]byte{1})
			for i := 0; i < files; i++ {
				name := "backup/container/rootfs/srv/f" + string(rune('a'+i%26)) + string(rune('a'+i/26))
				if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: fileSize}); err != nil {
					pw.CloseWithError(err)
					return
				}
				for w := 0; w < fileSize; w += len(buf) {
					_, _ = rng.Read(buf)
					if _, err := tw.Write(buf); err != nil {
						pw.CloseWithError(err)
						return
					}
					var ms runtime.MemStats
					runtime.ReadMemStats(&ms)
					if ms.HeapAlloc > peak.Load() {
						peak.Store(ms.HeapAlloc)
					}
				}
			}
			_ = tw.Close()
			pw.CloseWithError(gz.Close())
		}()
		return pr
	}}
	m := newBoxManager(t, box)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	peak.Store(before.HeapAlloc)
	rec, err := m.CreateBox(boxOpts(id.Recipient().String()))
	if err != nil {
		t.Fatalf("CreateBox: %v", err)
	}
	var grew uint64
	if p := peak.Load(); p > before.HeapAlloc {
		grew = p - before.HeapAlloc
	}
	t.Logf("%d MiB box: peak live heap delta %d bytes, stored %d bytes", files*fileSize>>20, grew, rec.SizeBytes)
	// A filter that buffered the export, or the archive, would hold at
	// least the 128 MiB it streamed.
	if grew > 48<<20 {
		t.Fatalf("peak heap grew by %d bytes streaming a %d MiB box", grew, files*fileSize>>20)
	}
	_, hdrs, _ := openBoxBackup(t, rec.Location, id.String())
	if len(hdrs) != files+1 {
		t.Errorf("backup has %d entries, want %d files plus the manifest", len(hdrs), files)
	}
}

// The spill of excluded content is ciphertext on disk, and reads back.
func TestBoxSpill_EncryptsAndReadsBack(t *testing.T) {
	s := &boxSpill{dir: t.TempDir()}
	defer s.close()
	for name, body := range map[string]string{"a": "first secret body", "b": "second secret body"} {
		if err := s.add(name, &tar.Header{Name: name, Size: int64(len(body))}, strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(s.f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret body")) {
		t.Fatal("the spill holds plaintext")
	}
	for name, want := range map[string]string{"b": "second secret body", "a": "first secret body"} {
		r, hdr, ok, err := s.open(name)
		if err != nil || !ok || hdr.Name != name {
			t.Fatalf("open %s: ok=%v hdr=%v err=%v", name, ok, hdr, err)
		}
		got, err := io.ReadAll(r)
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, _, ok, _ := s.open("absent"); ok {
		t.Error("open of a name never set aside succeeded")
	}
	name := s.f.Name()
	s.close()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Errorf("spill not removed: %v", err)
	}
}
