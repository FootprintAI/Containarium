//go:build !containarium_client

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// WriteBoxFile (#3548): one file into the box user's home through the file
// API, confined to the home, atomic, checksummed. The root half (the file API
// and a chown) is faked; the user half is the REAL script run with sh against a
// temp home, so the tests prove what the box would do.

type boxFileHarness struct {
	s     *ContainerServer
	home  string
	stage string

	mu       sync.Mutex
	rootCmds []string
	pushed   []string // stage paths the file API wrote
}

func newBoxFileHarness(t *testing.T) *boxFileHarness {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the box-side script needs GNU coreutils; it runs inside Linux boxes")
	}
	h := &boxFileHarness{home: t.TempDir(), stage: t.TempDir()}
	h.s = &ContainerServer{
		boxFileStageDir: h.stage,
		boxRunCollaborator: func(owner, subject string) (bool, error) {
			return false, nil
		},
		boxRunExec: func(box, script string) (string, error) {
			h.mu.Lock()
			h.rootCmds = append(h.rootCmds, script)
			h.mu.Unlock()
			return "", nil // chown cannot run unprivileged here
		},
		boxRunStartExec: func(box, username, script string) (string, error) {
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "HOME="+h.home)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
			}
			return string(out), nil
		},
		boxFileWrite: func(box, path string, content []byte, mode string) error {
			h.mu.Lock()
			h.pushed = append(h.pushed, path)
			h.mu.Unlock()
			return os.WriteFile(path, content, 0o600)
		},
	}
	return h
}

func (h *boxFileHarness) write(t *testing.T, req *pb.WriteBoxFileRequest) (*pb.WriteBoxFileResponse, error) {
	t.Helper()
	if req.Username == "" {
		req.Username = "alice"
	}
	return h.s.WriteBoxFile(tenantCtx("alice"), req)
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestWriteBoxFile_WritesAtomicallyWithModeAndChecksum(t *testing.T) {
	h := newBoxFileHarness(t)
	body := []byte("# brief\nmake a deck\n")

	resp, err := h.write(t, &pb.WriteBoxFileRequest{Path: "attachments/turn-1/brief.md", Content: body, Sha256: sum(body)})
	if err != nil {
		t.Fatalf("WriteBoxFile: %v", err)
	}
	want := filepath.Join(h.home, "attachments/turn-1/brief.md")
	if resp.GetPath() != want || resp.GetSize() != int64(len(body)) || resp.GetSha256() != sum(body) {
		t.Fatalf("resp = %+v, want path %s size %d sha %s", resp, want, len(body), sum(body))
	}
	got, err := os.ReadFile(want)
	if err != nil || string(got) != string(body) {
		t.Fatalf("file = %q, %v", got, err)
	}
	st, _ := os.Stat(want)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Dir(want))
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("parent mode = %v, want 0700", dst.Mode().Perm())
	}
	left, _ := os.ReadDir(h.stage)
	if len(left) != 0 {
		t.Errorf("staging not cleaned: %v", left)
	}
	left, _ = os.ReadDir(filepath.Dir(want))
	if len(left) != 1 {
		t.Errorf("temp file left beside the target: %v", left)
	}
	if len(h.rootCmds) != 1 || !strings.Contains(h.rootCmds[0], "chown") {
		t.Errorf("root commands = %v, want one chown of the staged file", h.rootCmds)
	}
}

func TestWriteBoxFile_ReadOnlyModeAndReplace(t *testing.T) {
	h := newBoxFileHarness(t)
	if _, err := h.write(t, &pb.WriteBoxFileRequest{Path: "a.txt", Content: []byte("one")}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.write(t, &pb.WriteBoxFileRequest{Path: "a.txt", Content: []byte("two"), Mode: "0400"}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	p := filepath.Join(h.home, "a.txt")
	got, _ := os.ReadFile(p)
	st, _ := os.Stat(p)
	if string(got) != "two" || st.Mode().Perm() != 0o400 {
		t.Errorf("file = %q mode %v, want two / 0400", got, st.Mode().Perm())
	}
}

func TestWriteBoxFile_ChecksumMismatchLeavesNoFile(t *testing.T) {
	h := newBoxFileHarness(t)
	_, err := h.write(t, &pb.WriteBoxFileRequest{Path: "x/y.txt", Content: []byte("data"), Sha256: sum([]byte("other"))})
	if status.Code(err) != codes.DataLoss {
		t.Fatalf("err = %v, want DataLoss", err)
	}
	if _, serr := os.Stat(filepath.Join(h.home, "x/y.txt")); !os.IsNotExist(serr) {
		t.Errorf("a file exists after a checksum mismatch: %v", serr)
	}
	if left, _ := os.ReadDir(h.stage); len(left) != 0 {
		t.Errorf("staging not cleaned after a mismatch: %v", left)
	}
}

func TestWriteBoxFile_DirectoryAtTargetIsRefused(t *testing.T) {
	h := newBoxFileHarness(t)
	if err := os.MkdirAll(filepath.Join(h.home, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := h.write(t, &pb.WriteBoxFileRequest{Path: "d", Content: []byte("x")})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

func TestWriteBoxFile_RefusesBadInputBeforeTouchingTheBox(t *testing.T) {
	big := make([]byte, MaxBoxFileBytes+1)
	cases := []struct {
		name string
		req  *pb.WriteBoxFileRequest
	}{
		{"empty path", &pb.WriteBoxFileRequest{Path: "", Content: []byte("x")}},
		{"absolute path", &pb.WriteBoxFileRequest{Path: "/etc/passwd", Content: []byte("x")}},
		{"dotdot", &pb.WriteBoxFileRequest{Path: "../outside", Content: []byte("x")}},
		{"dotdot inside", &pb.WriteBoxFileRequest{Path: "a/../../outside", Content: []byte("x")}},
		{"home itself", &pb.WriteBoxFileRequest{Path: ".", Content: []byte("x")}},
		{"ssh dir", &pb.WriteBoxFileRequest{Path: ".ssh/authorized_keys", Content: []byte("x")}},
		{"containarium dir", &pb.WriteBoxFileRequest{Path: ".containarium/code.json", Content: []byte("x")}},
		{"dotted ssh via clean", &pb.WriteBoxFileRequest{Path: "a/../.ssh/x", Content: []byte("x")}},
		{"nul byte", &pb.WriteBoxFileRequest{Path: "a\x00b", Content: []byte("x")}},
		{"newline", &pb.WriteBoxFileRequest{Path: "a\nb", Content: []byte("x")}},
		{"too big", &pb.WriteBoxFileRequest{Path: "big", Content: big}},
		{"mode 0644", &pb.WriteBoxFileRequest{Path: "a", Content: []byte("x"), Mode: "0644"}},
		{"mode garbage", &pb.WriteBoxFileRequest{Path: "a", Content: []byte("x"), Mode: "rw"}},
		{"sha not hex", &pb.WriteBoxFileRequest{Path: "a", Content: []byte("x"), Sha256: "zz"}},
		{"bad username", &pb.WriteBoxFileRequest{Username: "a b", Path: "a", Content: []byte("x")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBoxFileHarness(t)
			if _, err := h.write(t, tc.req); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if len(h.pushed) != 0 || len(h.rootCmds) != 0 {
				t.Errorf("the box was touched: pushed %v, root %v", h.pushed, h.rootCmds)
			}
		})
	}
}

func TestWriteBoxFile_RequiresBoxOwnerOrCollaborator(t *testing.T) {
	h := newBoxFileHarness(t)
	_, err := h.s.WriteBoxFile(tenantCtx("mallory"), &pb.WriteBoxFileRequest{Username: "alice", Path: "a", Content: []byte("x")})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if len(h.pushed) != 0 {
		t.Errorf("a refused caller reached the box")
	}
}

func TestWriteBoxFile_AdvertisedAsACapability(t *testing.T) {
	for _, c := range daemonCapabilities() {
		if c == DaemonCapBoxFiles {
			return
		}
	}
	t.Fatalf("daemonCapabilities() lacks %q", DaemonCapBoxFiles)
}

var _ = context.Background

// A symlink at the target is replaced, never written through: the rename swaps
// the link itself, so the file it pointed at is left alone.
func TestWriteBoxFile_ReplacesASymlinkInsteadOfWritingThroughIt(t *testing.T) {
	h := newBoxFileHarness(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(h.home, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.write(t, &pb.WriteBoxFileRequest{Path: "link", Content: []byte("new")}); err != nil {
		t.Fatalf("WriteBoxFile: %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Errorf("the symlink target was written through: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(h.home, "link")); string(got) != "new" {
		t.Errorf("link now holds %q, want new", got)
	}
}
