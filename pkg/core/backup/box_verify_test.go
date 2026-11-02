package backup

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// --- #2802: verify a whole-box backup by restoring it into a scratch box ---

// verifyBox is the Incus side of a verify: the export of an imported box
// returns what was imported, rewritten by reexport when set, as an import
// that changed a box's files would.
type verifyBox struct {
	*fakeRestoreBox
	reexport func(t *testing.T, archive []byte) []byte
	t        *testing.T
}

func (v *verifyBox) ExportInstance(name string) (io.ReadCloser, error) {
	v.mu.Lock()
	b, ok := v.imported[name]
	v.mu.Unlock()
	if !ok {
		return v.fakeRestoreBox.ExportInstance(name)
	}
	v.log("export " + name)
	if v.reexport != nil {
		b = v.reexport(v.t, b)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// backedUpVerifyBox takes a whole-box backup of the Incus-like fixture on a
// manager that can also back up a database (for the refusal test).
func backedUpVerifyBox(t *testing.T, opts ...Option) (*Manager, *verifyBox, *Record, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	box := &verifyBox{fakeRestoreBox: newFakeRestoreBox(buildArchive(t, incusLikeEntries())), t: t}
	m := NewManager(newFakeOps([]byte("PGDMP")), nil, t.TempDir(), append([]Option{WithBoxOps(box)}, opts...)...)
	m.clock = fixedClock
	rec, err := m.CreateBox(boxOpts(id.Recipient().String()))
	if err != nil {
		t.Fatalf("CreateBox: %v", err)
	}
	box.calls = nil
	return m, box, rec, id
}

// rewriteFile changes one rootfs file's content in an archive.
func rewriteFile(path, body string) func(*testing.T, []byte) []byte {
	return func(t *testing.T, archive []byte) []byte {
		names, hdrs, bodies := importedEntries(t, archive)
		var es []tarEntry
		for _, n := range names {
			h := hdrs[n]
			e := tarEntry{name: n, typ: h.Typeflag, body: string(bodies[n]), linkname: h.Linkname, pax: h.PAXRecords}
			if n == boxRootfsPrefix+strings.TrimPrefix(path, "/") {
				e.body = body
			}
			es = append(es, e)
		}
		return buildArchive(t, es)
	}
}

func checkNamed(v *Verification, name string) *Check {
	for i := range v.Checks {
		if v.Checks[i].Name == name {
			return &v.Checks[i]
		}
	}
	return nil
}

// assertScratchGone: the verify imported only into a scratch box, never
// touched a tenant's box, and deleted the scratch box.
func assertScratchGone(t *testing.T, box *verifyBox) {
	t.Helper()
	if left := box.boxes(); len(left) != 0 {
		t.Errorf("boxes left after verify: %v", left)
	}
	for _, c := range box.calls {
		if strings.HasPrefix(c, "import ") && !strings.HasPrefix(c, "import "+boxVerifyScratchPrefix) {
			t.Errorf("verify imported outside a scratch box: %q", c)
		}
		if strings.HasSuffix(c, "-container") {
			t.Errorf("verify touched a tenant box: %q", c)
		}
	}
}

// A good backup restores into a scratch box, the restored box's files match
// the manifest, the scratch box is deleted, and the evidence is recorded.
func TestVerifyBox_PassesAndDeletesScratchBox(t *testing.T) {
	m, box, rec, id := backedUpVerifyBox(t)
	v, err := m.VerifyBox(BoxVerifyOptions{ID: rec.ID, AgeIdentity: id.String(), VerifiedBy: "alice"})
	if err != nil {
		t.Fatalf("VerifyBox: %v", err)
	}
	if v.Result != VerificationPassed || v.Error != "" {
		t.Fatalf("result = %s (%s), checks %+v", v.Result, v.Error, v.Checks)
	}
	for _, name := range []string{"integrity", "decrypt", "restore", "manifest", "cleanup"} {
		if c := checkNamed(v, name); c == nil || !c.Passed {
			t.Errorf("check %s = %+v, want passed", name, c)
		}
	}
	if !strings.HasPrefix(v.TargetContainer, boxVerifyScratchPrefix) {
		t.Errorf("target = %q, want a scratch box", v.TargetContainer)
	}
	if !strings.Contains(strings.Join(box.calls, ","), "export "+v.TargetContainer) {
		t.Errorf("the restored box was not read back: calls %v", box.calls)
	}
	assertScratchGone(t, box)
	got, err := m.Get(rec.ID)
	if err != nil || got.LastVerification == nil || got.LastVerification.Result != VerificationPassed {
		t.Errorf("recorded verification = %+v (%v)", got, err)
	}
}

// A tampered backup fails and names the failure; the scratch box is gone
// whichever step failed.
func TestVerifyBox_TamperedBackupFailsAndNamesIt(t *testing.T) {
	type tamperFn func(t *testing.T, m *Manager, box *verifyBox, rec *Record, id *age.X25519Identity) string
	for _, tc := range []struct {
		name       string
		tamper     tamperFn
		check, has string
	}{
		{"a flipped byte in the stored backup", func(t *testing.T, _ *Manager, _ *verifyBox, rec *Record, id *age.X25519Identity) string {
			raw, err := os.ReadFile(rec.Location)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)/2] ^= 0x01
			if err := os.WriteFile(rec.Location, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			return id.String()
		}, "integrity", "checksum"},
		{"the wrong identity", func(t *testing.T, _ *Manager, _ *verifyBox, _ *Record, _ *age.X25519Identity) string {
			other, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			return other.String()
		}, "decrypt", "does not open this backup"},
		{"content that differs from the manifest", func(t *testing.T, m *Manager, _ *verifyBox, rec *Record, id *age.X25519Identity) string {
			rewriteBoxBackup(t, m, rec, id.Recipient().String(), func(es []tarEntry) []tarEntry {
				for i := range es {
					if es[i].name == "backup/container/rootfs/etc/hostname" {
						es[i].body = "mallory\n"
					}
				}
				return es
			}, storedEntries(t, rec, id))
			return id.String()
		}, "restore", "/etc/hostname"},
		{"a restored box whose file differs from the manifest", func(_ *testing.T, _ *Manager, box *verifyBox, _ *Record, id *age.X25519Identity) string {
			box.reexport = rewriteFile("/etc/hostname", "mallory\n")
			return id.String()
		}, "manifest", "/etc/hostname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, box, rec, id := backedUpVerifyBox(t)
			use := tc.tamper(t, m, box, rec, id)
			v, err := m.VerifyBox(BoxVerifyOptions{ID: rec.ID, AgeIdentity: use})
			if err != nil {
				t.Fatalf("VerifyBox: %v (a tampered backup is a FAILED result, not an error)", err)
			}
			if v.Result != VerificationFailed {
				t.Fatalf("result = %s, want failed; checks %+v", v.Result, v.Checks)
			}
			c := checkNamed(v, tc.check)
			if c == nil || c.Passed || !strings.Contains(c.Detail, tc.has) || !strings.Contains(v.Error, tc.has) {
				t.Errorf("check %s = %+v, error %q; want a failed check naming %q", tc.check, c, v.Error, tc.has)
			}
			if strings.Contains(v.Error, "AGE-SECRET-KEY") {
				t.Errorf("error carries key material")
			}
			assertScratchGone(t, box)
		})
	}
}

// Q-C (#2809): the comparison is capped by time, and a capped run is
// INCOMPLETE with its coverage, never a pass.
func TestVerifyBox_TimeCapIsIncompleteNeverPass(t *testing.T) {
	m, box, rec, id := backedUpVerifyBox(t, WithBoxVerifyTimeLimit(time.Second))
	tick := fixedClock()
	m.clock = func() time.Time { tick = tick.Add(time.Second); return tick }
	v, err := m.VerifyBox(BoxVerifyOptions{ID: rec.ID, AgeIdentity: id.String()})
	if err != nil {
		t.Fatalf("VerifyBox: %v", err)
	}
	if v.Result != VerificationIncomplete {
		t.Fatalf("result = %s, want incomplete; checks %+v", v.Result, v.Checks)
	}
	if c := checkNamed(v, "manifest"); c == nil || c.Passed || !strings.Contains(c.Detail, " of ") {
		t.Errorf("manifest check = %+v, want coverage reported", c)
	}
	assertScratchGone(t, box)
}

// A scratch box that cannot be deleted is never a pass: the operator has to
// learn there is a box to remove by hand.
func TestVerifyBox_UndeletedScratchBoxFails(t *testing.T) {
	m, box, rec, id := backedUpVerifyBox(t)
	box.deleteErr = errors.New("instance is busy")
	v, err := m.VerifyBox(BoxVerifyOptions{ID: rec.ID, AgeIdentity: id.String()})
	if err != nil {
		t.Fatalf("VerifyBox: %v", err)
	}
	if c := checkNamed(v, "cleanup"); v.Result != VerificationFailed || c == nil || c.Passed || !strings.Contains(c.Detail, v.TargetContainer) {
		t.Errorf("result %s, cleanup check %+v; want failed naming the scratch box", v.Result, c)
	}
}

// Refusals come before any box exists: no identity, an unknown id, a
// database record, a daemon that cannot import.
func TestVerifyBox_Refusals(t *testing.T) {
	m, box, rec, id := backedUpVerifyBox(t)
	if _, err := m.VerifyBox(BoxVerifyOptions{ID: rec.ID}); err == nil {
		t.Error("no identity: want a refusal")
	}
	if _, err := m.VerifyBox(BoxVerifyOptions{ID: "nope", AgeIdentity: id.String()}); err == nil {
		t.Error("unknown id: want a refusal")
	}
	db, err := m.Create(CreateOptions{Username: "alice", ContainerName: "alice-container", Conn: PgConn{Database: "app"}, Destination: DestLocal})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyBox(BoxVerifyOptions{ID: db.ID, AgeIdentity: id.String()}); !errors.Is(err, ErrNotBoxBackup) {
		t.Errorf("database record: err = %v, want ErrNotBoxBackup", err)
	}
	if len(box.calls) != 0 {
		t.Errorf("a refused verify reached Incus: %v", box.calls)
	}
	noImport := NewManager(nil, nil, m.dir, WithBoxOps(newFakeBox(nil)))
	if _, err := noImport.VerifyBox(BoxVerifyOptions{ID: rec.ID, AgeIdentity: id.String()}); !errors.Is(err, ErrBoxRestoreUnavailable) {
		t.Errorf("no import: err = %v, want ErrBoxRestoreUnavailable", err)
	}
}
