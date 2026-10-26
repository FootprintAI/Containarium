package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"

	"filippo.io/age"

	"github.com/footprintai/containarium/pkg/core/backup"
)

// --- #2801 PR B: server fixtures for the whole-box create path ---

// serverFakeBox exports a minimal Incus-shaped archive.
type serverFakeBox struct {
	archive  []byte
	exported []string
}

func (b *serverFakeBox) ExportInstance(name string) (io.ReadCloser, error) {
	b.exported = append(b.exported, name)
	return io.NopCloser(bytes.NewReader(b.archive)), nil
}

func (b *serverFakeBox) BoxDiskUsage(string) (int64, error) { return 1 << 20, nil }

type serverFakeUploader struct{}

func (serverFakeUploader) Upload(string, string) error            { return nil }
func (serverFakeUploader) DownloadStream(string, io.Writer) error { return os.ErrNotExist }
func (serverFakeUploader) Delete(string) error                    { return nil }

func minimalBoxArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"backup/index.yaml":                    "name: alice-container\n",
		"backup/container/rootfs/etc/hostname": "alice\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
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

// newBoxServer is newRestoreTargetServer with a backup core that can export
// a box and upload to GCS.
func newBoxServer(t *testing.T) (*BackupServer, *restoreTargetOps, *serverFakeBox) {
	t.Helper()
	s, ops, _ := newRestoreTargetServer(t)
	box := &serverFakeBox{archive: minimalBoxArchive(t)}
	s.mgr = backup.NewManager(ops, serverFakeUploader{}, t.TempDir(), backup.WithBoxOps(box))
	return s, ops, box
}

// testBoxRealRecipient is a recipient the create path can actually encrypt
// to (testBoxRecipient is only ever seen by the refusals).
func testBoxRealRecipient(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient().String()
}
