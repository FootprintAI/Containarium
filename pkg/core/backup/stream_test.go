package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// generatedDump never owns a dump-sized allocation. Sampling at each MiB
// measures live heap while the consumer is running, rather than only after
// its buffers have been collected.
type generatedDump struct {
	remaining, read int64
	peak            uint64
}

func (r *generatedDump) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	clear(p)
	r.remaining -= int64(len(p))
	r.read += int64(len(p))
	if r.read%(1<<20) == 0 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapAlloc > r.peak {
			r.peak = m.HeapAlloc
		}
	}
	return len(p), nil
}

type streamingOps struct {
	*fakeOps
	source       io.Reader
	closed       bool
	writeErr     error
	shortWrite   bool
	digest       string
	bytesWritten int64
}
type ownedReader struct {
	io.Reader
	close func()
}

func (r ownedReader) Close() error { r.close(); return nil }
func (s *streamingOps) ReadFileStream(string, string) (io.ReadCloser, error) {
	return ownedReader{Reader: s.source, close: func() { s.closed = true }}, nil
}
func (s *streamingOps) WriteFileStream(_, _ string, content io.Reader, _ string) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	if s.shortWrite {
		return nil
	}
	h := sha256.New()
	n, err := io.Copy(h, content)
	s.bytesWritten, s.digest = n, hex.EncodeToString(h.Sum(nil))
	return err
}

func TestCreate_StreamsLargeDump(t *testing.T) {
	if testing.Short() {
		t.Skip("1 GiB streaming allocation test")
	}
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%v", encrypted), func(t *testing.T) {
			const size int64 = 1 << 30
			source := &generatedDump{remaining: size}
			ops := &streamingOps{fakeOps: newFakeOps(nil), source: source}
			m := newTestManager(t, ops)
			opts := CreateOptions{Username: "alice", ContainerName: "alice-container", Conn: PgConn{Database: "app"}, Destination: DestLocal}
			id, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			if encrypted {
				opts.AgeRecipient = id.Recipient().String()
			}
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			source.peak = before.HeapAlloc
			rec, err := m.Create(opts)
			if err != nil {
				t.Fatal(err)
			}
			if !ops.closed || source.read != size {
				t.Fatalf("read=%d closed=%v", source.read, ops.closed)
			}
			if source.peak > before.HeapAlloc+(64<<20) {
				t.Fatalf("peak heap grew by %d bytes", source.peak-before.HeapAlloc)
			}
			t.Logf("1 GiB create: peak live heap delta %d bytes", source.peak-before.HeapAlloc)
			// Restore and Verify consume through the real streaming hash and
			// decrypt paths; the fake target hashes rather than storing bytes.
			if err := m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "target", AgeIdentity: id.String()}); err != nil {
				t.Fatal(err)
			}
			if ops.bytesWritten != size {
				t.Fatalf("restored %d bytes", ops.bytesWritten)
			}
			v, err := m.Verify(VerifyOptions{ID: rec.ID, SourceContainer: "source", TargetContainer: "target", AgeIdentity: id.String()})
			if err != nil || v.Result != VerificationPassed {
				t.Fatalf("Verify: %+v %v", v, err)
			}
			if ops.bytesWritten != size {
				t.Fatalf("verified %d bytes", ops.bytesWritten)
			}
		})
	}
}

func TestCreate_SizeBoundAndCleanup(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, size := range []int{0, 32, 33, 1024} {
			t.Run(fmt.Sprintf("encrypted=%v/size=%d", encrypted, size), func(t *testing.T) {
				ops := &streamingOps{fakeOps: newFakeOps(nil), source: strings.NewReader(strings.Repeat("x", size))}
				m := newTestManager(t, ops)
				m.maxDumpBytes = 32
				opts := CreateOptions{Username: "alice", ContainerName: "source", Conn: PgConn{Database: "app"}, Destination: DestLocal}
				if encrypted {
					id, err := age.GenerateX25519Identity()
					if err != nil {
						t.Fatal(err)
					}
					opts.AgeRecipient = id.Recipient().String()
				}
				_, err := m.Create(opts)
				if size == 32 && !encrypted {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				if err == nil {
					t.Fatal("expected refusal")
				}
				if size > 32 && !errors.Is(err, ErrDumpTooLarge) {
					t.Fatalf("err=%v", err)
				}
				entries, e := os.ReadDir(m.dir)
				if e != nil {
					t.Fatal(e)
				}
				if len(entries) != 0 {
					t.Fatalf("partial files left behind: %v", entries)
				}
				if !ops.closed {
					t.Fatal("source stream not closed")
				}
				if !strings.Contains(strings.Join(ops.execLog, "\n"), "rm -f") {
					t.Fatal("container staging not cleaned")
				}
			})
		}
	}
}

func TestFetchDump_RefusesActualAndRecordedOversize(t *testing.T) {
	for _, metadataOnly := range []bool{false, true} {
		t.Run(fmt.Sprint(metadataOnly), func(t *testing.T) {
			m, rec := seedBackup(t, newVerifyOps([]byte("PGDMP-test")))
			m.maxDumpBytes = 4
			if !metadataOnly {
				rec.SizeBytes = 0
			}
			_, err := m.fetchDump(rec)
			if !errors.Is(err, ErrDumpTooLarge) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestWriteDump_RefusesIncompleteUpload(t *testing.T) {
	for _, kind := range []string{"short", "transport", "read", "oversize", "truncated-age"} {
		t.Run(kind, func(t *testing.T) {
			ops := &streamingOps{fakeOps: newFakeOps(nil)}
			m := newTestManager(t, ops)
			var src io.Reader = strings.NewReader("payload")
			encrypted, identity := false, ""
			switch kind {
			case "short":
				ops.shortWrite = true
			case "transport":
				ops.writeErr = errors.New("transport failed")
			case "read":
				src = io.MultiReader(src, failingReader{})
			case "oversize":
				m.maxDumpBytes = 4
			case "truncated-age":
				id, e := age.GenerateX25519Identity()
				if e != nil {
					t.Fatal(e)
				}
				ct, e := encryptWithRecipients(bytes.Repeat([]byte("x"), 128<<10), id.Recipient().String())
				if e != nil {
					t.Fatal(e)
				}
				src = bytes.NewReader(ct[:len(ct)-1])
				encrypted = true
				identity = id.String()
			}
			_, err := m.writeDump("target", "/tmp/dump", src, encrypted, identity)
			if err == nil {
				t.Fatal("incomplete upload accepted")
			}
			if kind == "truncated-age" {
				var de *decryptionError
				if !errors.As(err, &de) {
					t.Fatalf("not a decrypt failure: %v", err)
				}
			}
			if !strings.Contains(strings.Join(ops.execLog, "\n"), "rm -f /tmp/dump") {
				t.Fatal("partial target file not cleaned")
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("source read failed") }

type oversizedDownload struct {
	fakeUploader
	source generatedDump
	calls  int
}

func (u *oversizedDownload) DownloadStream(_ string, dst io.Writer) error {
	u.calls++
	_, err := io.Copy(dst, &u.source)
	return err
}

func TestFetchDump_GCSBoundAndCleanup(t *testing.T) {
	for _, recordedSize := range []int64{0, 1024} {
		t.Run(fmt.Sprint(recordedSize), func(t *testing.T) {
			u := &oversizedDownload{source: generatedDump{remaining: 1 << 30}}
			m := NewManager(newFakeOps(nil), u, t.TempDir(), WithMaxDumpBytes(64))
			_, err := m.fetchDump(&Record{Destination: DestGCS, Location: "gs://backup-test/dump", SizeBytes: recordedSize})
			if !errors.Is(err, ErrDumpTooLarge) {
				t.Fatalf("err=%v", err)
			}
			if recordedSize > 64 && u.calls != 0 {
				t.Fatal("known oversize object was downloaded")
			}
			if u.source.read > 32<<10 {
				t.Fatalf("download read %d bytes past bound", u.source.read)
			}
			files, err := os.ReadDir(m.dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 0 {
				t.Fatalf("download staging leaked: %v", files)
			}
		})
	}
}

func TestRestoreVerify_RejectLateAgeAuthenticationFailure(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ops := newVerifyOps(bytes.Repeat([]byte("x"), 128<<10))
	m := newTestManager(t, ops)
	rec, err := m.Create(CreateOptions{Username: "alice", ContainerName: "source", Conn: PgConn{Database: "app"}, Destination: DestLocal, AgeRecipient: id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := os.ReadFile(rec.Location)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 1
	if err := os.WriteFile(rec.Location, ct, 0o600); err != nil {
		t.Fatal(err)
	}
	// Deliberately update the stored checksum so only age's final chunk
	// authentication catches the corruption, after some plaintext was read.
	sum := sha256.Sum256(ct)
	rec.SHA256 = hex.EncodeToString(sum[:])
	if err := m.writeSidecar(rec); err != nil {
		t.Fatal(err)
	}
	ops.execLog = nil
	err = m.Restore(RestoreOptions{ID: rec.ID, ContainerName: "target", AgeIdentity: id.String()})
	if err == nil {
		t.Fatal("restore accepted unauthenticated tail")
	}
	v, err := m.Verify(VerifyOptions{ID: rec.ID, SourceContainer: "source", TargetContainer: "target", AgeIdentity: id.String()})
	if err != nil || v.Result != VerificationFailed {
		t.Fatalf("Verify=%+v err=%v", v, err)
	}
	if len(v.Checks) != 2 || v.Checks[1].Name != "decrypt" || v.Checks[1].Passed {
		t.Fatalf("checks=%+v", v.Checks)
	}
	for _, command := range ops.execLog {
		if strings.Contains(command, "pg_restore") || strings.Contains(command, "CREATE DATABASE") {
			t.Fatalf("engine ran before authentication completed: %s", command)
		}
	}
}

type waitingDump struct{ started, release chan struct{} }

func (r waitingDump) Read([]byte) (int, error) { close(r.started); <-r.release; return 0, io.EOF }

type earlyResponseOps struct {
	*fakeOps
	started, done chan struct{}
}

func (o *earlyResponseOps) WriteFileStream(_, _ string, src io.Reader, _ string) error {
	go func() { _, _ = io.Copy(io.Discard, src); close(o.done) }()
	<-o.started
	return nil
}

func TestWriteDump_EarlyResponseWhileReadIsBlocked(t *testing.T) {
	r := waitingDump{started: make(chan struct{}), release: make(chan struct{})}
	ops := &earlyResponseOps{fakeOps: newFakeOps(nil), started: r.started, done: make(chan struct{})}
	m := newTestManager(t, ops)
	result := make(chan error, 1)
	go func() { _, err := m.writeDump("target", "/tmp/dump", r, false, ""); result <- err }()
	select {
	case err := <-result:
		if err == nil {
			t.Error("early response accepted before EOF")
		}
	case <-time.After(5 * time.Second):
		t.Error("upload completion check blocked on source I/O")
	}
	close(r.release)
	<-ops.done
}
