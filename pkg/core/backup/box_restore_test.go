package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"filippo.io/age"
)

// --- #3357: restoring a whole-box backup into a new box ---

// fakeRestoreBox is the Incus side of a whole-box backup and restore: it
// exports one archive, and keeps the boxes it knows by name with their
// state and the archive each was imported from.
type fakeRestoreBox struct {
	*fakeBox
	mu       sync.Mutex
	states   map[string]BoxState
	imported map[string][]byte
	calls    []string
	// importFn replaces the default import (read everything, then add the
	// box stopped). It runs with the lock released.
	importFn func(name string, r io.Reader) error
	// deleteErr fails every DeleteBox, leaving the box in place.
	deleteErr error
}

func newFakeRestoreBox(archive []byte) *fakeRestoreBox {
	return &fakeRestoreBox{
		fakeBox:  newFakeBox(archive),
		states:   map[string]BoxState{},
		imported: map[string][]byte{},
	}
}

func (f *fakeRestoreBox) log(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeRestoreBox) BoxState(name string) (BoxState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[name], nil // the zero value is BoxAbsent
}

func (f *fakeRestoreBox) ImportBox(name string, r io.Reader) error {
	f.log("import " + name)
	if f.importFn != nil {
		return f.importFn(name, r)
	}
	f.mu.Lock()
	if f.states[name] != BoxAbsent {
		f.mu.Unlock()
		return fmt.Errorf("import %s: instance already exists", name)
	}
	f.mu.Unlock()
	b, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("import %s: %w", name, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[name] = BoxStopped
	f.imported[name] = b
	return nil
}

func (f *fakeRestoreBox) RenameBox(from, to string) error {
	f.log("rename " + from + " " + to)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states[to] != BoxAbsent {
		return fmt.Errorf("rename %s: %s already exists", from, to)
	}
	f.states[to], f.imported[to] = f.states[from], f.imported[from]
	delete(f.states, from)
	delete(f.imported, from)
	return nil
}

func (f *fakeRestoreBox) DeleteBox(name string) error {
	f.log("delete " + name)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.states, name)
	delete(f.imported, name)
	return nil
}

// boxes lists the boxes the fake knows, sorted.
func (f *fakeRestoreBox) boxes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for n := range f.states {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// backedUpBox takes a whole-box backup of the Incus-like fixture and returns
// the manager, the fake, the record and the identity that opens it.
func backedUpBox(t *testing.T) (*Manager, *fakeRestoreBox, *Record, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	box := newFakeRestoreBox(buildArchive(t, incusLikeEntries()))
	m := newBoxManager(t, box)
	rec, err := m.CreateBox(boxOpts(id.Recipient().String()))
	if err != nil {
		t.Fatalf("CreateBox: %v", err)
	}
	return m, box, rec, id
}

// importedEntries reads an imported archive: entry names in order, and the
// regular files' contents.
func importedEntries(t *testing.T, archive []byte) ([]string, map[string]*tar.Header, map[string][]byte) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("imported archive is not gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	var names []string
	hdrs := map[string]*tar.Header{}
	bodies := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("imported archive: %v", err)
		}
		names = append(names, hdr.Name)
		hdrs[hdr.Name] = hdr
		if hdr.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			bodies[hdr.Name] = b
		}
	}
	return names, hdrs, bodies
}

// The restore of a fixture box hands Incus an archive whose files have the
// manifest's digests, with the manifest entry stripped, the hard links kept
// as links, and the box under the requested name, stopped. No staging box
// is left behind.
func TestRestoreBox_RoundTripMatchesManifest(t *testing.T) {
	m, box, rec, id := backedUpBox(t)
	_, _, stored := openBoxBackup(t, rec.Location, id.String())
	var mf BoxManifest
	if err := json.Unmarshal(stored[BoxManifestPath], &mf); err != nil {
		t.Fatal(err)
	}

	if err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "alice-restored-container", AgeIdentity: id.String()}); err != nil {
		t.Fatalf("RestoreBox: %v", err)
	}
	if got := box.boxes(); strings.Join(got, ",") != "alice-restored-container" {
		t.Fatalf("boxes after restore = %v, want only alice-restored-container", got)
	}
	if box.states["alice-restored-container"] != BoxStopped {
		t.Errorf("restored box state = %v, want stopped", box.states["alice-restored-container"])
	}
	names, hdrs, bodies := importedEntries(t, box.imported["alice-restored-container"])
	for _, n := range names {
		if strings.TrimPrefix(n, "./") == BoxManifestPath {
			t.Errorf("the manifest entry reached Incus")
		}
	}
	if len(mf.Files) == 0 || len(mf.Config) == 0 || len(mf.Links) == 0 {
		t.Fatalf("fixture manifest too thin to prove anything: %+v", mf)
	}
	for _, f := range mf.Files {
		body, ok := bodies[boxRootfsPrefix+strings.TrimPrefix(f.Path, "/")]
		if !ok {
			t.Errorf("manifest file %s missing from the restored archive", f.Path)
			continue
		}
		if got := sha256.Sum256(body); hex.EncodeToString(got[:]) != f.SHA256 || int64(len(body)) != f.Size {
			t.Errorf("%s: restored digest/size differ from the manifest", f.Path)
		}
	}
	for _, c := range mf.Config {
		body, ok := bodies[c.Path]
		if got := sha256.Sum256(body); !ok || hex.EncodeToString(got[:]) != c.SHA256 {
			t.Errorf("config %s: missing or digest differs", c.Path)
		}
	}
	for _, l := range mf.Links {
		h, ok := hdrs[boxRootfsPrefix+strings.TrimPrefix(l.Path, "/")]
		if !ok || h.Typeflag != tar.TypeLink {
			t.Errorf("hard link %s not restored as a link: %+v", l.Path, h)
		}
	}
	if h := hdrs["backup/container/rootfs/usr/bin/ping"]; h == nil || h.PAXRecords["SCHILY.xattr.security.capability"] == "" {
		t.Errorf("file capability xattr lost on restore: %+v", h)
	}
}

// An existing target is refused without force; a running one is refused
// even with force. Neither refusal imports anything or touches the target.
func TestRestoreBox_TargetRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state BoxState
		force bool
		want  error
	}{
		{"stopped target without force", BoxStopped, false, ErrBoxRestoreTargetExists},
		{"running target without force", BoxActive, false, ErrBoxRestoreTargetRunning},
		{"running target with force", BoxActive, true, ErrBoxRestoreTargetRunning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, box, rec, id := backedUpBox(t)
			box.states["bob-container"] = tc.state
			box.imported["bob-container"] = []byte("original")
			err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "bob-container", Force: tc.force, AgeIdentity: id.String()})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if len(box.calls) != 0 {
				t.Errorf("refused restore still called Incus: %v", box.calls)
			}
			if string(box.imported["bob-container"]) != "original" || box.states["bob-container"] != tc.state {
				t.Errorf("target changed by a refused restore")
			}
		})
	}
}

// With force a stopped target is replaced, and only once the new box is
// fully imported: the old one is deleted after the import, never before.
func TestRestoreBox_ForceReplacesStoppedTargetAfterImport(t *testing.T) {
	m, box, rec, id := backedUpBox(t)
	box.states["bob-container"] = BoxStopped
	box.imported["bob-container"] = []byte("original")
	if err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "bob-container", Force: true, AgeIdentity: id.String()}); err != nil {
		t.Fatalf("RestoreBox: %v", err)
	}
	if got := box.boxes(); strings.Join(got, ",") != "bob-container" {
		t.Fatalf("boxes = %v, want only bob-container", got)
	}
	if string(box.imported["bob-container"]) == "original" {
		t.Fatal("target was not replaced")
	}
	var importAt, deleteAt = -1, -1
	for i, c := range box.calls {
		switch {
		case strings.HasPrefix(c, "import "):
			importAt = i
		case c == "delete bob-container":
			deleteAt = i
		}
	}
	if importAt < 0 || deleteAt < importAt {
		t.Errorf("calls %v: the old box must be deleted only after the import", box.calls)
	}
}

// A wrong or malformed identity, or none, fails with the named key error
// before any box exists, and the identity never appears in the error.
func TestRestoreBox_WrongKeyFailsBeforeAnyBox(t *testing.T) {
	other, _ := age.GenerateX25519Identity()
	for _, tc := range []struct {
		name, identity string
	}{
		{"another identity", other.String()},
		{"malformed identity", "AGE-SECRET-KEY-1NOTAREALKEYATALLXYZ"},
		{"no identity", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, box, rec, _ := backedUpBox(t)
			err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "alice-restored-container", AgeIdentity: tc.identity})
			if !errors.Is(err, ErrBoxBackupKey) {
				t.Fatalf("err = %v, want ErrBoxBackupKey", err)
			}
			if tc.identity != "" && strings.Contains(err.Error(), tc.identity) {
				t.Errorf("error text carries the identity")
			}
			if strings.Contains(err.Error(), "AGE-SECRET-KEY") {
				t.Errorf("error text carries key material: %q", err)
			}
			if len(box.calls) != 0 || len(box.boxes()) != 0 {
				t.Errorf("wrong key reached Incus: calls %v boxes %v", box.calls, box.boxes())
			}
		})
	}
}

// A stored backup with a flipped byte fails the integrity check with the
// named error before any box exists.
func TestRestoreBox_TamperedBackupFailsBeforeAnyBox(t *testing.T) {
	m, box, rec, id := backedUpBox(t)
	raw, err := os.ReadFile(rec.Location)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(rec.Location, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "alice-restored-container", AgeIdentity: id.String()})
	if !errors.Is(err, ErrBoxBackupCorrupt) {
		t.Fatalf("err = %v, want ErrBoxBackupCorrupt", err)
	}
	if len(box.calls) != 0 || len(box.boxes()) != 0 {
		t.Errorf("tampered backup reached Incus: calls %v boxes %v", box.calls, box.boxes())
	}
}

// rewriteBoxBackup replaces a stored box backup's plaintext archive (and
// the record's checksum and size to match), as a forger holding only the
// recipient could: the ciphertext authenticates, the content does not.
func rewriteBoxBackup(t *testing.T, m *Manager, rec *Record, recipient string, mutate func([]tarEntry) []tarEntry, entries []tarEntry) {
	t.Helper()
	plain := buildArchive(t, mutate(entries))
	ct, err := encryptWithRecipients(plain, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rec.Location, ct, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ct)
	rec.SHA256, rec.SizeBytes = hex.EncodeToString(sum[:]), int64(len(ct))
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.sidecarPath(rec.ID), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// storedEntries returns the decrypted entries of a stored box backup as
// tarEntry values, manifest included, ready to be mutated and re-sealed.
func storedEntries(t *testing.T, rec *Record, id *age.X25519Identity) []tarEntry {
	t.Helper()
	names, hdrs, bodies := openBoxBackup(t, rec.Location, id.String())
	var out []tarEntry
	for _, n := range names {
		h := hdrs[n]
		out = append(out, tarEntry{name: n, typ: h.Typeflag, body: string(bodies[n]), linkname: h.Linkname, pax: h.PAXRecords})
	}
	return out
}

// A backup whose content does not match its manifest — a changed file, a
// missing manifest, an entry after it — fails with the named integrity
// error. The import has already started by then (the manifest is the last
// entry), so the half-imported staging box is removed: no box is left.
func TestRestoreBox_ManifestMismatchLeavesNoBox(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]tarEntry) []tarEntry
	}{
		{"a file's content changed", func(es []tarEntry) []tarEntry {
			for i := range es {
				if es[i].name == "backup/container/rootfs/etc/hostname" {
					es[i].body = "mallory\n"
				}
			}
			return es
		}},
		{"a file added", func(es []tarEntry) []tarEntry {
			extra := tarEntry{name: "backup/container/rootfs/etc/cron.d/x", typ: tar.TypeReg, body: "* * * * * root sh"}
			return append(es[:len(es)-1:len(es)-1], extra, es[len(es)-1])
		}},
		{"the manifest removed", func(es []tarEntry) []tarEntry { return es[:len(es)-1] }},
		{"an entry after the manifest", func(es []tarEntry) []tarEntry {
			return append(es, tarEntry{name: "backup/container/rootfs/late", typ: tar.TypeReg, body: "late"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, box, rec, id := backedUpBox(t)
			box.states["bob-container"] = BoxStopped
			box.imported["bob-container"] = []byte("original")
			rewriteBoxBackup(t, m, rec, id.Recipient().String(), tc.mutate, storedEntries(t, rec, id))
			// An importer that stops at the end of the gzip member, as one
			// that does not read to EOF could, must still never see a
			// complete archive: the end is withheld until the manifest
			// matches.
			var sawComplete bool
			box.importFn = func(name string, r io.Reader) error {
				box.mu.Lock()
				box.states[name] = BoxStopped
				box.mu.Unlock()
				gz, err := gzip.NewReader(r)
				if err != nil {
					return err
				}
				gz.Multistream(false)
				tr := tar.NewReader(gz)
				for {
					if _, err := tr.Next(); errors.Is(err, io.EOF) {
						break
					} else if err != nil {
						return err
					}
				}
				if _, err := io.Copy(io.Discard, gz); err != nil {
					return err
				}
				sawComplete = true
				return nil
			}
			err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "bob-container", Force: true, AgeIdentity: id.String()})
			if !errors.Is(err, ErrBoxBackupCorrupt) {
				t.Fatalf("err = %v, want ErrBoxBackupCorrupt", err)
			}
			if sawComplete {
				t.Errorf("the importer was handed a complete archive whose content does not match its manifest")
			}
			if got := box.boxes(); strings.Join(got, ",") != "bob-container" || string(box.imported["bob-container"]) != "original" {
				t.Errorf("after a failed restore boxes = %v (target %q), want only the untouched original", got, box.imported["bob-container"])
			}
		})
	}
}

// An import that fails part-way — Incus created the instance and then
// failed — leaves no partial box, and a forced restore's old target
// survives.
func TestRestoreBox_FailedImportLeavesNoPartialBox(t *testing.T) {
	m, box, rec, id := backedUpBox(t)
	box.states["bob-container"] = BoxStopped
	box.imported["bob-container"] = []byte("original")
	box.importFn = func(name string, r io.Reader) error {
		box.mu.Lock()
		box.states[name] = BoxStopped // Incus got as far as creating it
		box.mu.Unlock()
		_, _ = io.CopyN(io.Discard, r, 64)
		return errors.New("storage pool is full")
	}
	err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "bob-container", Force: true, AgeIdentity: id.String()})
	if err == nil || !strings.Contains(err.Error(), "storage pool is full") {
		t.Fatalf("err = %v, want the import failure", err)
	}
	if got := box.boxes(); strings.Join(got, ",") != "bob-container" || string(box.imported["bob-container"]) != "original" {
		t.Errorf("after a failed import boxes = %v, want only the untouched original", got)
	}
}

// A record that is not a whole-box backup, an over-cap record, a missing
// target, and a daemon with no import are refused before anything runs.
func TestRestoreBox_Refusals(t *testing.T) {
	t.Run("database record", func(t *testing.T) {
		m, box, _, id := backedUpBox(t)
		dbRec := &Record{ID: "alice-app-20261003T010000Z", Username: "alice", Engine: EnginePostgres, Destination: DestLocal}
		b, _ := json.Marshal(dbRec)
		if err := os.WriteFile(m.sidecarPath(dbRec.ID), b, 0o600); err != nil {
			t.Fatal(err)
		}
		err := m.RestoreBox(BoxRestoreOptions{ID: dbRec.ID, TargetContainer: "x-container", AgeIdentity: id.String()})
		if !errors.Is(err, ErrNotBoxBackup) {
			t.Fatalf("err = %v, want ErrNotBoxBackup", err)
		}
		if len(box.calls) != 0 {
			t.Errorf("calls %v", box.calls)
		}
	})
	t.Run("over the cap", func(t *testing.T) {
		m, box, rec, id := backedUpBox(t)
		WithMaxBoxBytes(rec.SizeBytes - 1)(m)
		err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "x-container", AgeIdentity: id.String()})
		if !errors.Is(err, ErrDumpTooLarge) {
			t.Fatalf("err = %v, want ErrDumpTooLarge", err)
		}
		if len(box.calls) != 0 {
			t.Errorf("calls %v", box.calls)
		}
	})
	t.Run("no target", func(t *testing.T) {
		m, _, rec, id := backedUpBox(t)
		if err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, AgeIdentity: id.String()}); err == nil {
			t.Fatal("restore with no target succeeded")
		}
	})
	t.Run("no import on this daemon", func(t *testing.T) {
		id, _ := age.GenerateX25519Identity()
		m := newBoxManager(t, newFakeBox(buildArchive(t, incusLikeEntries())))
		rec, err := m.CreateBox(boxOpts(id.Recipient().String()))
		if err != nil {
			t.Fatal(err)
		}
		err = m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "x-container", AgeIdentity: id.String()})
		if !errors.Is(err, ErrBoxRestoreUnavailable) {
			t.Fatalf("err = %v, want ErrBoxRestoreUnavailable", err)
		}
	})
}

// A restore takes the same per-box claim as a backup: a second restore
// into a box that is being restored (or backed up) is refused, not queued.
func TestRestoreBox_TakesThePerBoxClaim(t *testing.T) {
	m, box, rec, id := backedUpBox(t)
	release, err := m.claimBox("bob-container")
	if err != nil {
		t.Fatal(err)
	}
	err = m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "bob-container", AgeIdentity: id.String()})
	if !errors.Is(err, ErrBoxRestoreInProgress) {
		t.Fatalf("err = %v, want ErrBoxRestoreInProgress", err)
	}
	if len(box.calls) != 0 {
		t.Errorf("calls %v", box.calls)
	}
	release()
	if err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "bob-container", AgeIdentity: id.String()}); err != nil {
		t.Fatalf("RestoreBox after release: %v", err)
	}
}

// Memory stays bounded for a large box: the stored archive is decrypted,
// checked and handed to Incus as a stream, never held whole. A 128 MiB
// incompressible box restores with the live heap growing by well under the
// archive's size.
func TestRestoreBox_StreamsLargeBoxInBoundedMemory(t *testing.T) {
	const fileSize = 8 << 20
	const files = 16 // 128 MiB of incompressible file content
	id, _ := age.GenerateX25519Identity()
	gen := func() io.Reader {
		pr, pw := io.Pipe()
		go func() {
			gz, _ := gzip.NewWriterLevel(pw, gzip.BestSpeed)
			tw := tar.NewWriter(gz)
			buf := make([]byte, 1<<20)
			rng := mrand.NewChaCha8([32]byte{2})
			for i := 0; i < files; i++ {
				name := fmt.Sprintf("backup/container/rootfs/srv/f%02d", i)
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
				}
			}
			_ = tw.Close()
			pw.CloseWithError(gz.Close())
		}()
		return pr
	}
	box := &fakeRestoreBox{
		fakeBox: &fakeBox{usage: files * fileSize, archive: gen},
		states:  map[string]BoxState{}, imported: map[string][]byte{},
	}
	m := newBoxManager(t, box)
	rec, err := m.CreateBox(boxOpts(id.Recipient().String()))
	if err != nil {
		t.Fatalf("CreateBox: %v", err)
	}

	var peak atomic.Uint64
	var consumed int64
	box.importFn = func(name string, r io.Reader) error {
		buf := make([]byte, 1<<20)
		for {
			n, err := r.Read(buf)
			consumed += int64(n)
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak.Load() {
				peak.Store(ms.HeapAlloc)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
		}
		box.mu.Lock()
		box.states[name] = BoxStopped
		box.mu.Unlock()
		return nil
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	peak.Store(before.HeapAlloc)
	if err := m.RestoreBox(BoxRestoreOptions{ID: rec.ID, TargetContainer: "big-container", AgeIdentity: id.String()}); err != nil {
		t.Fatalf("RestoreBox: %v", err)
	}
	var grew uint64
	if p := peak.Load(); p > before.HeapAlloc {
		grew = p - before.HeapAlloc
	}
	t.Logf("%d MiB box: Incus read %d bytes, peak live heap delta %d bytes", files*fileSize>>20, consumed, grew)
	if consumed < files*fileSize {
		t.Fatalf("Incus read %d bytes, less than the box's %d bytes of content", consumed, files*fileSize)
	}
	if grew > 48<<20 {
		t.Fatalf("peak heap grew by %d bytes restoring a %d MiB box", grew, files*fileSize>>20)
	}
}
