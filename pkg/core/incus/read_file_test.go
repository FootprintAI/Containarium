package incus

import (
	"io"
	"strings"
	"testing"

	incusclient "github.com/lxc/incus/v6/client"
)

// These pin ReadFile's contract: the bytes it returns are the bytes of
// the file inside the instance — following symlinks, byte-identical,
// never the symlink's target path.
//
// Why this matters: Incus's file API answers a read of a symlink with
// the link *target path* as the response body (Type "symlink"), not
// the file's content. k3s creates its join token at
// /var/lib/rancher/k3s/server/node-token as a symlink to
// <datadir>/token, so a ReadFile that ignores the type metadata hands
// the caller the literal path string instead of the token — which is
// exactly how workers ended up joining with a token that "lacks the
// CA hash" (#1446).

// fakeFileServer implements only the file half of incus.InstanceServer.
//
// The embedded interface is nil on purpose: any method these tests do
// not stub panics rather than silently returning a zero value.
type fakeFileServer struct {
	incusclient.InstanceServer

	// files maps path -> regular file content.
	files map[string]string
	// symlinks maps path -> link target (what the incus API returns
	// as the body of a symlink read).
	symlinks map[string]string
	// dirs is the set of paths that answer as directories.
	dirs map[string]bool

	// reads records every path requested, in order.
	reads []string
}

func (f *fakeFileServer) GetInstanceFile(instance, path string) (io.ReadCloser, *incusclient.InstanceFileResponse, error) {
	f.reads = append(f.reads, path)
	if target, ok := f.symlinks[path]; ok {
		return io.NopCloser(strings.NewReader(target)),
			&incusclient.InstanceFileResponse{Type: "symlink"}, nil
	}
	if f.dirs[path] {
		return nil, &incusclient.InstanceFileResponse{Type: "directory"}, nil
	}
	if content, ok := f.files[path]; ok {
		return io.NopCloser(strings.NewReader(content)),
			&incusclient.InstanceFileResponse{Type: "file"}, nil
	}
	return nil, nil, notFoundErr()
}

// fullToken mirrors the shape of a real k3s node-token: CA hash,
// separator, credential. The value is synthetic.
const fullToken = "K10aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899::server:0123456789abcdef\n"

func TestReadFile_FollowsSymlinkToAbsoluteTarget(t *testing.T) {
	// The real k3s layout: node-token is a symlink with an absolute
	// target (k3s-io/k3s pkg/server: os.Symlink(serverTokenFile, np)).
	f := &fakeFileServer{
		files:    map[string]string{"/var/lib/rancher/k3s/server/token": fullToken},
		symlinks: map[string]string{"/var/lib/rancher/k3s/server/node-token": "/var/lib/rancher/k3s/server/token"},
	}
	c := &Client{server: f}

	got, err := c.ReadFile("cp", "/var/lib/rancher/k3s/server/node-token")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != fullToken {
		t.Errorf("ReadFile returned %q, want the symlink target's content %q", got, fullToken)
	}
}

func TestReadFile_FollowsSymlinkToRelativeTarget(t *testing.T) {
	// A relative target resolves against the symlink's own directory.
	f := &fakeFileServer{
		files:    map[string]string{"/var/lib/rancher/k3s/server/token": fullToken},
		symlinks: map[string]string{"/var/lib/rancher/k3s/server/node-token": "token"},
	}
	c := &Client{server: f}

	got, err := c.ReadFile("cp", "/var/lib/rancher/k3s/server/node-token")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != fullToken {
		t.Errorf("ReadFile returned %q, want %q", got, fullToken)
	}
}

func TestReadFile_SymlinkChainResolves(t *testing.T) {
	f := &fakeFileServer{
		files: map[string]string{"/data/real": "payload"},
		symlinks: map[string]string{
			"/a": "/b",
			"/b": "/data/real",
		},
	}
	c := &Client{server: f}

	got, err := c.ReadFile("cp", "/a")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("ReadFile returned %q, want %q", got, "payload")
	}
}

func TestReadFile_SymlinkLoopErrors(t *testing.T) {
	f := &fakeFileServer{
		symlinks: map[string]string{
			"/a": "/b",
			"/b": "/a",
		},
	}
	c := &Client{server: f}

	_, err := c.ReadFile("cp", "/a")
	if err == nil {
		t.Fatal("ReadFile on a symlink loop returned nil error, want a bounded failure")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error %q does not name the symlink loop", err)
	}
}

func TestReadFile_RegularFileBytesAreExact(t *testing.T) {
	// Guard against any transformation of a regular file's bytes —
	// trailing newline, interior newlines, and the token's own
	// separators must all survive the round trip untouched.
	content := "line1\nline2\n\ttrailing whitespace \nK10hash::server:pw\n"
	f := &fakeFileServer{files: map[string]string{"/etc/some-file": content}}
	c := &Client{server: f}

	got, err := c.ReadFile("cp", "/etc/some-file")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != content {
		t.Errorf("ReadFile returned %q, want byte-identical %q", got, content)
	}
	if len(f.reads) != 1 {
		t.Errorf("regular file was read %d times, want 1 (%v)", len(f.reads), f.reads)
	}
}

func TestReadFile_DirectoryErrorsInsteadOfPanicking(t *testing.T) {
	// Incus returns a nil reader for directories; ReadFile must
	// answer with an error, not a nil dereference.
	f := &fakeFileServer{dirs: map[string]bool{"/etc": true}}
	c := &Client{server: f}

	_, err := c.ReadFile("cp", "/etc")
	if err == nil {
		t.Fatal("ReadFile on a directory returned nil error, want an error")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error %q does not say it is a directory", err)
	}
}
