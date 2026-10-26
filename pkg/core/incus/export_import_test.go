package incus

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
)

// doneOp is an incus operation that has already finished with err.
type doneOp struct {
	incusclient.Operation
	err error
}

func (o doneOp) Wait() error { return o.err }

// exportServer fakes the slice of the Incus API ExportInstance and
// ImportInstance touch (#2801). Anything else panics on the nil embed.
type exportServer struct {
	incusclient.InstanceServer
	direct  bool   // whether the server advertises direct_backup
	archive []byte // what the server streams as the backup tarball

	streamPost  *api.InstanceBackupsPost // direct path: the request it got
	createdPost *api.InstanceBackupsPost // fallback path: the backup it created
	fetched     string                   // fallback path: the backup it served
	deleted     []string                 // fallback path: backups removed

	imported *incusclient.InstanceBackupArgs
	body     []byte
}

func (s *exportServer) HasExtension(ext string) bool { return ext == "direct_backup" && s.direct }

func (s *exportServer) GetInstance(name string) (*api.Instance, string, error) {
	if name == "missing" {
		return nil, "", api.StatusErrorf(404, "Instance not found")
	}
	return &api.Instance{Name: name}, "", nil
}

func (s *exportServer) CreateInstanceBackupStream(name string, post api.InstanceBackupsPost, req *incusclient.BackupFileRequest) error {
	s.streamPost = &post
	_, err := req.BackupFile.Write(s.archive)
	return err
}

func (s *exportServer) CreateInstanceBackup(name string, post api.InstanceBackupsPost) (incusclient.Operation, error) {
	s.createdPost = &post
	return doneOp{}, nil
}

func (s *exportServer) GetInstanceBackupFile(name, backup string, req *incusclient.BackupFileRequest) (*incusclient.BackupFileResponse, error) {
	s.fetched = backup
	n, err := req.BackupFile.Write(s.archive)
	return &incusclient.BackupFileResponse{Size: int64(n)}, err
}

func (s *exportServer) DeleteInstanceBackup(name, backup string) (incusclient.Operation, error) {
	s.deleted = append(s.deleted, backup)
	return doneOp{}, nil
}

func (s *exportServer) CreateInstanceFromBackup(args incusclient.InstanceBackupArgs) (incusclient.Operation, error) {
	s.imported = &args
	b, err := io.ReadAll(args.BackupFile)
	s.body = b
	return doneOp{err: err}, nil
}

// exportRequestIsWholeBox asserts the backup request is the one #2800's
// decisions call for: a portable (non-optimized) tarball of the instance
// without its snapshot history.
func exportRequestIsWholeBox(t *testing.T, post *api.InstanceBackupsPost) {
	t.Helper()
	if post == nil {
		t.Fatal("no backup request reached the server")
	}
	if !post.InstanceOnly {
		t.Error("InstanceOnly = false: snapshot history would be exported, and it is excluded")
	}
	if post.OptimizedStorage {
		t.Error("OptimizedStorage = true: a driver-specific stream is not restorable on another pool driver")
	}
}

func TestExportInstance_DirectBackupStreams(t *testing.T) {
	srv := &exportServer{direct: true, archive: bytes.Repeat([]byte("tarball"), 1<<16)}
	c := &Client{server: srv}

	rc, err := c.ExportInstance("box")
	if err != nil {
		t.Fatalf("ExportInstance: %v", err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !bytes.Equal(got, srv.archive) {
		t.Fatalf("exported %d bytes, want the server's %d", len(got), len(srv.archive))
	}
	exportRequestIsWholeBox(t, srv.streamPost)
	if srv.createdPost != nil {
		t.Error("a server with direct_backup still got a stored backup created")
	}
}

func TestExportInstance_FallbackUsesAndRemovesServerBackup(t *testing.T) {
	srv := &exportServer{archive: []byte("older-server tarball")}
	c := &Client{server: srv}

	rc, err := c.ExportInstance("box")
	if err != nil {
		t.Fatalf("ExportInstance: %v", err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !bytes.Equal(got, srv.archive) {
		t.Fatalf("exported %q, want %q", got, srv.archive)
	}
	exportRequestIsWholeBox(t, srv.createdPost)
	if srv.createdPost.ExpiresAt.IsZero() {
		t.Error("the server-side backup has no expiry: a crashed export would leak it forever")
	}
	if srv.fetched != srv.createdPost.Name {
		t.Errorf("fetched backup %q, created %q", srv.fetched, srv.createdPost.Name)
	}
	if len(srv.deleted) != 1 || srv.deleted[0] != srv.createdPost.Name {
		t.Errorf("deleted %v, want exactly the backup the export created (%q)", srv.deleted, srv.createdPost.Name)
	}
}

func TestExportInstance_MissingInstanceIsNotFound(t *testing.T) {
	c := &Client{server: &exportServer{direct: true}}
	if _, err := c.ExportInstance("missing"); !IsNotFound(err) {
		t.Fatalf("err = %v, want not-found before any stream starts", err)
	}
}

func TestImportInstance_StreamsIntoNamedInstanceOnPool(t *testing.T) {
	srv := &exportServer{}
	c := &Client{server: srv}
	archive := "the tarball"

	err := c.ImportInstance("restored", "tenant-pool", strings.NewReader(archive),
		ImportOptions{Config: map[string]string{"user.b": "2", "user.a": "1"}})
	if err != nil {
		t.Fatalf("ImportInstance: %v", err)
	}
	if srv.imported == nil {
		t.Fatal("no import reached the server")
	}
	if srv.imported.Name != "restored" || srv.imported.PoolName != "tenant-pool" {
		t.Errorf("imported as %q on %q, want restored on tenant-pool", srv.imported.Name, srv.imported.PoolName)
	}
	if string(srv.body) != archive {
		t.Errorf("server read %q, want %q", srv.body, archive)
	}
	if want := []string{"user.a=1", "user.b=2"}; strings.Join(srv.imported.Config, " ") != strings.Join(want, " ") {
		t.Errorf("config overrides = %v, want %v (sorted, key=value)", srv.imported.Config, want)
	}
}

func TestImportInstance_RejectsEmptyName(t *testing.T) {
	c := &Client{server: &exportServer{}}
	if err := c.ImportInstance("", "p", strings.NewReader("x"), ImportOptions{}); err == nil {
		t.Fatal("import with no name succeeded: Incus would take the name from the archive, possibly over the original")
	}
}

func TestImportInstance_OperationFailureSurfaces(t *testing.T) {
	boom := errors.New("short read")
	c := &Client{server: &exportServer{}}
	err := c.ImportInstance("r", "p", io.MultiReader(strings.NewReader("x"), errReader{boom}), ImportOptions{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the stream's failure", err)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
