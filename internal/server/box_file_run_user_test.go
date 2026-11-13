//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// WriteBoxFile for a run (for_run) on a box with a recorded tool-access level
// (#3678): platform runs execute as the unprivileged run user, whose home is
// private to it, so the file is placed in that home, as that user. Without
// for_run the file stays the owner's. The same harness as the
// unary tests; the provisioning step (root) is faked to answer with a temp
// directory standing in for the run user's home, and every user-side script
// records who it ran as.

type boxFileRunUserHarness struct {
	*boxFileHarness
	runHome string
	// asUsers is every user a box-user script ran as, in order.
	asUsers []string
}

func newBoxFileRunUserHarness(t *testing.T, level string) *boxFileRunUserHarness {
	t.Helper()
	h := &boxFileRunUserHarness{boxFileHarness: newBoxFileHarness(t), runHome: t.TempDir()}
	if err := os.Chmod(h.runHome, 0o700); err != nil {
		t.Fatal(err)
	}
	h.s.boxRunToolAccess = func(ctx context.Context, username string) (string, error) { return level, nil }
	rootExec := h.s.boxRunExec
	h.s.boxRunExec = func(box, script string) (string, error) {
		if script == boxRunProvisionScript() {
			h.mu.Lock()
			h.rootCmds = append(h.rootCmds, script)
			h.mu.Unlock()
			return "uid line\n" + h.runHome + "\n", nil
		}
		return rootExec(box, script)
	}
	userExec := h.s.boxRunStartExec
	h.s.boxRunStartExec = func(box, username, script string) (string, error) {
		h.mu.Lock()
		h.asUsers = append(h.asUsers, username)
		h.mu.Unlock()
		return userExec(box, username, script)
	}
	return h
}

// chowns lists the users the staged file was handed to.
func (h *boxFileRunUserHarness) chowns() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, c := range h.rootCmds {
		if rest, ok := strings.CutPrefix(c, "chown -- "); ok {
			user, _, _ := strings.Cut(rest, " ")
			out = append(out, user)
		}
	}
	return out
}

func (h *boxFileRunUserHarness) provisioned() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.rootCmds {
		if c == boxRunProvisionScript() {
			return true
		}
	}
	return false
}

func TestWriteBoxFile_ForRunOnALevelledBoxPlacesTheFileInTheRunUsersHome(t *testing.T) {
	for _, level := range []string{"none", "build_tools", "full_sudo"} {
		t.Run(level, func(t *testing.T) {
			h := newBoxFileRunUserHarness(t, level)
			body := []byte("# brief\n")

			resp, err := h.write(t, &pb.WriteBoxFileRequest{Path: "attachments/turn-1/brief.md", Content: body, Sha256: sum(body), ForRun: true})
			if err != nil {
				t.Fatalf("WriteBoxFile: %v", err)
			}
			want := filepath.Join(h.runHome, "attachments/turn-1/brief.md")
			if resp.GetPath() != want || resp.GetSha256() != sum(body) {
				t.Fatalf("resp = %+v, want path %s", resp, want)
			}
			if got, err := os.ReadFile(want); err != nil || string(got) != string(body) {
				t.Fatalf("file = %q, %v", got, err)
			}
			if st, _ := os.Stat(want); st.Mode().Perm() != 0o600 {
				t.Errorf("mode = %v, want 0600", st.Mode().Perm())
			}
			if st, _ := os.Stat(filepath.Dir(want)); st.Mode().Perm() != 0o700 {
				t.Errorf("parent mode = %v, want 0700", st.Mode().Perm())
			}
			if !h.provisioned() {
				t.Error("the run user was not provisioned before the write")
			}
			if got := h.chowns(); len(got) != 1 || got[0] != shellSingleQuote(boxRunUnprivilegedUser) {
				t.Errorf("staged file handed to %v, want only %s", got, boxRunUnprivilegedUser)
			}
			// Only the run user's placement script ran; the owner's home was not
			// resolved or written.
			if len(h.asUsers) != 1 || h.asUsers[0] != boxRunUnprivilegedUser {
				t.Errorf("box-user scripts ran as %v, want only %s", h.asUsers, boxRunUnprivilegedUser)
			}
			if left, _ := os.ReadDir(h.home); len(left) != 0 {
				t.Errorf("the owner's home was written: %v", left)
			}
			if left, _ := os.ReadDir(h.stage); len(left) != 0 {
				t.Errorf("staging not cleaned: %v", left)
			}
		})
	}
}

func TestWriteBoxFile_ForRunWithNoRecordedLevelKeepsTheOwner(t *testing.T) {
	h := newBoxFileRunUserHarness(t, "")
	resp, err := h.write(t, &pb.WriteBoxFileRequest{Path: "brief.md", Content: []byte("x"), ForRun: true})
	if err != nil {
		t.Fatalf("WriteBoxFile: %v", err)
	}
	if want := filepath.Join(h.home, "brief.md"); resp.GetPath() != want {
		t.Fatalf("path = %s, want %s", resp.GetPath(), want)
	}
	if st, _ := os.Stat(resp.GetPath()); st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
	if h.provisioned() {
		t.Error("the run user was provisioned on a box with no recorded level")
	}
	if got := h.chowns(); len(got) != 1 || got[0] != shellSingleQuote("alice") {
		t.Errorf("staged file handed to %v, want only alice", got)
	}
	for _, u := range h.asUsers {
		if u != "alice" {
			t.Errorf("a box-user script ran as %s, want alice", u)
		}
	}
	if left, _ := os.ReadDir(h.runHome); len(left) != 0 {
		t.Errorf("the run user's home was written: %v", left)
	}
}

// A write not made for a run is the owner's even on a levelled box: an SSH
// session runs as the owner and could not read the run user's home. The level
// is not even read, so an unreadable level does not refuse it.
func TestWriteBoxFile_WithoutForRunKeepsTheOwnerOnALevelledBox(t *testing.T) {
	h := newBoxFileRunUserHarness(t, "build_tools")
	h.s.boxRunToolAccess = func(ctx context.Context, username string) (string, error) {
		return "", errors.New("the level must not be read")
	}
	resp, err := h.write(t, &pb.WriteBoxFileRequest{Path: "brief.md", Content: []byte("x")})
	if err != nil {
		t.Fatalf("WriteBoxFile: %v", err)
	}
	if want := filepath.Join(h.home, "brief.md"); resp.GetPath() != want {
		t.Fatalf("path = %s, want %s", resp.GetPath(), want)
	}
	if h.provisioned() {
		t.Error("the run user was provisioned for a write not made for a run")
	}
	if got := h.chowns(); len(got) != 1 || got[0] != shellSingleQuote("alice") {
		t.Errorf("staged file handed to %v, want only alice", got)
	}
	if left, _ := os.ReadDir(h.runHome); len(left) != 0 {
		t.Errorf("the run user's home was written: %v", left)
	}
}

func TestWriteBoxFileStream_ForRunOnALevelledBoxPlacesTheFileInTheRunUsersHome(t *testing.T) {
	h := newBoxFileRunUserHarness(t, "build_tools")
	body := []byte(strings.Repeat("slide ", 1000))
	resp, err := h.stream(tenantCtx("alice"), chunked(&pb.WriteBoxFileStreamHeader{Path: "attachments/deck.txt", Size: int64(len(body)), Sha256: sum(body), ForRun: true}, body, 1024), nil)
	if err != nil {
		t.Fatalf("WriteBoxFileStream: %v", err)
	}
	want := filepath.Join(h.runHome, "attachments/deck.txt")
	if resp.GetPath() != want {
		t.Fatalf("path = %s, want %s", resp.GetPath(), want)
	}
	if got, err := os.ReadFile(want); err != nil || string(got) != string(body) {
		t.Fatalf("file differs: %v", err)
	}
	if got := h.chowns(); len(got) != 1 || got[0] != shellSingleQuote(boxRunUnprivilegedUser) {
		t.Errorf("staged file handed to %v, want only %s", got, boxRunUnprivilegedUser)
	}
}

// A level that cannot be read refuses the write before the box is touched,
// rather than placing the file where the run cannot read it.
func TestWriteBoxFile_LevelReadErrorTouchesNothing(t *testing.T) {
	h := newBoxFileRunUserHarness(t, "")
	h.s.boxRunToolAccess = func(ctx context.Context, username string) (string, error) {
		return "", errors.New("incus: connection refused")
	}
	_, err := h.write(t, &pb.WriteBoxFileRequest{Path: "brief.md", Content: []byte("x"), ForRun: true})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "tool-access level") {
		t.Fatalf("err = %v, want Unavailable naming the tool-access level", err)
	}
	if len(h.pushed) != 0 || len(h.rootCmds) != 0 || len(h.asUsers) != 0 {
		t.Errorf("the box was touched: pushed %v, root %v, user scripts as %v", h.pushed, h.rootCmds, h.asUsers)
	}
}

func TestWriteBoxFile_RunUserProvisionFailureWritesNothing(t *testing.T) {
	cases := map[string]func(box, script string) (string, error){
		"provision fails": func(box, script string) (string, error) {
			return "", fmt.Errorf("useradd: exit status 1")
		},
		"unexpected home": func(box, script string) (string, error) {
			return "home/ctn-run\n", nil
		},
	}
	for name, provision := range cases {
		t.Run(name, func(t *testing.T) {
			h := newBoxFileRunUserHarness(t, "none")
			h.s.boxRunExec = func(box, script string) (string, error) {
				h.mu.Lock()
				h.rootCmds = append(h.rootCmds, script)
				h.mu.Unlock()
				if script == boxRunProvisionScript() {
					return provision(box, script)
				}
				return "", nil
			}
			_, err := h.write(t, &pb.WriteBoxFileRequest{Path: "brief.md", Content: []byte("x"), ForRun: true})
			if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "run user") {
				t.Fatalf("err = %v, want Unavailable naming the run user", err)
			}
			if len(h.pushed) != 0 || len(h.asUsers) != 0 || len(h.chowns()) != 0 {
				t.Errorf("the box was written: pushed %v, chowns %v, user scripts as %v", h.pushed, h.chowns(), h.asUsers)
			}
		})
	}
}

func TestWriteBoxFile_RunUserCapabilityAdvertised(t *testing.T) {
	for _, c := range daemonCapabilities() {
		if c == DaemonCapBoxFilesRunUser {
			return
		}
	}
	t.Fatalf("daemonCapabilities() lacks %q", DaemonCapBoxFilesRunUser)
}

// The run staging step rewrites some paths at each run start, so a run-user
// write to one is refused before anything is written (#3701).
func TestBoxRunManagedPath(t *testing.T) {
	for _, rel := range []string{".claude/settings.json", ".claude/containarium-mcp.json", ".gitconfig", ".config/containarium/manifest.json", ".local/bin/claude", ".claude/skills", ".claude/skills/x/SKILL.md", ".gitconfig.new"} {
		if !boxRunManagedPath(rel) {
			t.Errorf("%q should be managed", rel)
		}
	}
	// Beneath a managed file: the file would become a directory the staging step
	// cannot write over (#3701 finding A).
	for _, rel := range []string{".gitconfig/x", ".local/bin/claude/x", ".claude/settings.json/x", ".config/containarium/manifest.json/x"} {
		if !boxRunManagedPath(rel) {
			t.Errorf("%q is beneath a managed file and should be refused", rel)
		}
	}
	for _, rel := range []string{"attachments/turn-1/brief.md", ".claude/notes.md", ".config/other.json", ".claudeish/skills", ".config/containarium/other.json"} {
		if boxRunManagedPath(rel) {
			t.Errorf("%q should not be managed", rel)
		}
	}
}

func TestWriteBoxFile_ForRunRefusesAManagedPath(t *testing.T) {
	h := newBoxFileRunUserHarness(t, "build_tools")
	body := []byte("{}\n")
	_, err := h.write(t, &pb.WriteBoxFileRequest{Path: ".claude/settings.json", Content: body, Sha256: sum(body), ForRun: true})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("managed path: err = %v, want InvalidArgument", err)
	}
	if len(h.pushed) != 0 || len(h.chowns()) != 0 || len(h.asUsers) != 0 {
		t.Errorf("the box was written: pushed %v, chowns %v, user scripts as %v", h.pushed, h.chowns(), h.asUsers)
	}
}

// The owner's placement has no such reserved paths: an SSH session owns them.
func TestWriteBoxFile_OwnerMayWriteAManagedPath(t *testing.T) {
	h := newBoxFileRunUserHarness(t, "build_tools")
	if _, err := h.write(t, &pb.WriteBoxFileRequest{Path: ".gitconfig", Content: []byte("[user]\n")}); err != nil {
		t.Fatalf("WriteBoxFile: %v", err)
	}
}
