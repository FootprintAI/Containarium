package agentbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// callTool builds a CallToolRequest with the given args and runs the
// supplied handler. Returns the text from the first content block, plus
// the result for callers that want to assert the IsError flag.
func callTool(t *testing.T, h func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error), args map[string]interface{}) (string, *mcp.CallToolResult) {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if res == nil || len(res.Content) == 0 {
		t.Fatalf("empty result")
	}
	tc, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("first content block is not text: %T", res.Content[0])
	}
	return tc.Text, res
}

// ----- shell_exec ------------------------------------------------------

func TestShellExec_Basic(t *testing.T) {
	out, _ := callTool(t, handleShellExec, map[string]interface{}{
		"command": "echo hello && echo bye >&2",
	})
	if !strings.Contains(out, "exit_code: 0") {
		t.Errorf("missing exit_code 0 in:\n%s", out)
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("stdout missing 'hello' in:\n%s", out)
	}
	if !strings.Contains(out, "bye") {
		t.Errorf("stderr missing 'bye' in:\n%s", out)
	}
}

func TestShellExec_NonZeroExit(t *testing.T) {
	out, _ := callTool(t, handleShellExec, map[string]interface{}{
		"command": "exit 7",
	})
	if !strings.Contains(out, "exit_code: 7") {
		t.Errorf("expected exit 7, got:\n%s", out)
	}
}

func TestShellExec_Timeout(t *testing.T) {
	out, _ := callTool(t, handleShellExec, map[string]interface{}{
		"command":         "sleep 5",
		"timeout_seconds": float64(1),
	})
	if !strings.Contains(out, "timeout") {
		t.Errorf("expected timeout marker in:\n%s", out)
	}
}

func TestShellExec_OutputTruncation(t *testing.T) {
	// Generate ~512 KiB of output so we cross the 256 KiB cap.
	out, _ := callTool(t, handleShellExec, map[string]interface{}{
		"command": "head -c 524288 /dev/urandom | base64 -w0 | head -c 524288",
	})
	if !strings.Contains(out, "output truncated") {
		t.Errorf("expected truncation marker in capped output, got len=%d", len(out))
	}
}

func TestShellExec_MissingCommand(t *testing.T) {
	_, res := callTool(t, handleShellExec, map[string]interface{}{})
	if !res.IsError {
		t.Errorf("expected IsError when command missing")
	}
}

// ----- read_file -------------------------------------------------------

func TestReadFile_Basic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(p, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := callTool(t, handleReadFile, map[string]interface{}{"path": p})
	if !strings.Contains(out, "bytes_returned: 11") {
		t.Errorf("wrong bytes_returned in:\n%s", out)
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("missing content in:\n%s", out)
	}
	if !strings.Contains(out, "truncated: false") {
		t.Errorf("should not be truncated for 11-byte file:\n%s", out)
	}
}

func TestReadFile_OffsetAndLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data")
	if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := callTool(t, handleReadFile, map[string]interface{}{
		"path":   p,
		"offset": float64(3),
		"limit":  float64(4),
	})
	if !strings.Contains(out, "3456") {
		t.Errorf("expected '3456' content, got:\n%s", out)
	}
	if !strings.Contains(out, "truncated: true") {
		t.Errorf("expected truncated=true:\n%s", out)
	}
}

func TestReadFile_RefusesDirectory(t *testing.T) {
	_, res := callTool(t, handleReadFile, map[string]interface{}{"path": t.TempDir()})
	if !res.IsError {
		t.Errorf("expected error reading a directory")
	}
}

func TestReadFile_NotFound(t *testing.T) {
	_, res := callTool(t, handleReadFile, map[string]interface{}{
		"path": "/nonexistent/path/please",
	})
	if !res.IsError {
		t.Errorf("expected error for missing file")
	}
}

// ----- write_file ------------------------------------------------------

func TestWriteFile_AtomicMkdirp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "dir", "out.txt")
	out, _ := callTool(t, handleWriteFile, map[string]interface{}{
		"path":    p,
		"content": "atomic\nwrite",
		"mode":    "0600",
	})
	if !strings.Contains(out, "bytes_written: 12") {
		t.Errorf("wrong bytes_written in:\n%s", out)
	}
	read, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("file not at destination: %v", err)
	}
	if string(read) != "atomic\nwrite" {
		t.Errorf("content mismatch: %q", read)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestWriteFile_NoTempFileLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	_, _ = callTool(t, handleWriteFile, map[string]interface{}{
		"path": p, "content": "ok",
	})
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".agent-box.") {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}

// ----- list_directory --------------------------------------------------

func TestListDirectory_HidesDotFilesByDefault(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "visible"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, ".hidden"), []byte("x"), 0o644)
	out, _ := callTool(t, handleListDirectory, map[string]interface{}{"path": dir})
	if !strings.Contains(out, "visible") {
		t.Errorf("visible file missing:\n%s", out)
	}
	if strings.Contains(out, ".hidden") {
		t.Errorf("hidden file should be excluded by default:\n%s", out)
	}
}

func TestListDirectory_IncludeHidden(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".rc"), []byte("x"), 0o644)
	out, _ := callTool(t, handleListDirectory, map[string]interface{}{
		"path": dir, "include_hidden": true,
	})
	if !strings.Contains(out, ".rc") {
		t.Errorf("expected .rc with include_hidden=true:\n%s", out)
	}
}

func TestListDirectory_ReportsType(t *testing.T) {
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644)
	out, _ := callTool(t, handleListDirectory, map[string]interface{}{"path": dir})
	// columns are "type\tsize\tmtime\tname"
	if !strings.Contains(out, "d\t") {
		t.Errorf("expected directory marker 'd':\n%s", out)
	}
	if !strings.Contains(out, "f\t") {
		t.Errorf("expected file marker 'f':\n%s", out)
	}
}

// ----- read_file head/tail --------------------------------------------

func TestReadFile_HeadLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte("a\nb\nc\nd\ne\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := callTool(t, handleReadFile, map[string]interface{}{
		"path": p, "head": float64(2),
	})
	if !strings.Contains(out, "mode: head") {
		t.Errorf("expected mode: head in:\n%s", out)
	}
	if !strings.Contains(out, "lines_returned: 2") {
		t.Errorf("expected 2 lines returned in:\n%s", out)
	}
	if !strings.Contains(out, "a\nb\n") {
		t.Errorf("expected first two lines in:\n%s", out)
	}
	if strings.Contains(out, "c\n") {
		t.Errorf("third line should not appear in head=2:\n%s", out)
	}
}

func TestReadFile_TailLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte("a\nb\nc\nd\ne\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := callTool(t, handleReadFile, map[string]interface{}{
		"path": p, "tail": float64(2),
	})
	if !strings.Contains(out, "mode: tail") {
		t.Errorf("expected mode: tail in:\n%s", out)
	}
	if !strings.Contains(out, "lines_returned: 2") {
		t.Errorf("expected 2 lines in:\n%s", out)
	}
	if !strings.Contains(out, "d\ne\n") {
		t.Errorf("expected last two lines in:\n%s", out)
	}
}

func TestReadFile_HeadAndTailMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	_ = os.WriteFile(p, []byte("x\n"), 0o644)
	_, res := callTool(t, handleReadFile, map[string]interface{}{
		"path": p, "head": float64(1), "tail": float64(1),
	})
	if !res.IsError {
		t.Errorf("expected error when both head and tail set")
	}
}

// ----- move_file -------------------------------------------------------

func TestMoveFile_Basic(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a")
	dst := filepath.Join(dir, "b")
	_ = os.WriteFile(src, []byte("hello"), 0o644)
	out, _ := callTool(t, handleMoveFile, map[string]interface{}{
		"source": src, "destination": dst,
	})
	if !strings.Contains(out, "destination:") {
		t.Errorf("expected destination in:\n%s", out)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("source still exists after move")
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "hello" {
		t.Errorf("destination missing or wrong content: %v %q", err, data)
	}
}

func TestMoveFile_CreatesParent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a")
	dst := filepath.Join(dir, "nested", "deep", "b")
	_ = os.WriteFile(src, []byte("x"), 0o644)
	_, res := callTool(t, handleMoveFile, map[string]interface{}{
		"source": src, "destination": dst,
	})
	if res.IsError {
		t.Errorf("unexpected error creating parent dirs")
	}
	if _, err := os.Stat(dst); err != nil {
		t.Errorf("destination not created: %v", err)
	}
}

func TestMoveFile_SourceNotFound(t *testing.T) {
	dir := t.TempDir()
	_, res := callTool(t, handleMoveFile, map[string]interface{}{
		"source":      filepath.Join(dir, "nope"),
		"destination": filepath.Join(dir, "x"),
	})
	if !res.IsError {
		t.Errorf("expected error for missing source")
	}
}

// ----- delete_file -----------------------------------------------------

func TestDeleteFile_Basic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "victim")
	_ = os.WriteFile(p, []byte("doomed"), 0o644)
	out, _ := callTool(t, handleDeleteFile, map[string]interface{}{"path": p})
	if !strings.Contains(out, "bytes_deleted: 6") {
		t.Errorf("expected bytes_deleted: 6 in:\n%s", out)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("file still exists after delete")
	}
}

func TestDeleteFile_RefusesDirectory(t *testing.T) {
	_, res := callTool(t, handleDeleteFile, map[string]interface{}{"path": t.TempDir()})
	if !res.IsError {
		t.Errorf("expected error deleting a directory")
	}
}

func TestDeleteFile_NotFound(t *testing.T) {
	_, res := callTool(t, handleDeleteFile, map[string]interface{}{
		"path": "/nonexistent/path/please-no",
	})
	if !res.IsError {
		t.Errorf("expected error for missing file")
	}
}

// ----- sandbox root (AGENTBOX_ROOT) -----------------------------------

func TestSandboxRoot_RejectsOutsidePath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(sandboxRootEnv, dir)
	resetSandboxOnceForTest()
	t.Cleanup(resetSandboxOnceForTest)

	outside := filepath.Join(t.TempDir(), "evil") // different temp tree
	_ = os.WriteFile(outside, []byte("x"), 0o644)

	_, res := callTool(t, handleReadFile, map[string]interface{}{"path": outside})
	if !res.IsError {
		t.Errorf("expected sandbox to reject path outside AGENTBOX_ROOT")
	}
}

func TestSandboxRoot_AcceptsInsidePath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(sandboxRootEnv, dir)
	resetSandboxOnceForTest()
	t.Cleanup(resetSandboxOnceForTest)

	inside := filepath.Join(dir, "ok.txt")
	_ = os.WriteFile(inside, []byte("hi"), 0o644)

	_, res := callTool(t, handleReadFile, map[string]interface{}{"path": inside})
	if res.IsError {
		t.Errorf("sandbox rejected a path inside AGENTBOX_ROOT")
	}
}

func TestSandboxRoot_RejectsLookalikePrefix(t *testing.T) {
	// root="/tmp/foo" must not allow "/tmp/foo-evil/x" via prefix match.
	root := filepath.Join(t.TempDir(), "foo")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sandboxRootEnv, root)
	resetSandboxOnceForTest()
	t.Cleanup(resetSandboxOnceForTest)

	evil := root + "-evil"
	if err := os.Mkdir(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(evil, "x")
	_ = os.WriteFile(target, []byte("x"), 0o644)

	_, res := callTool(t, handleReadFile, map[string]interface{}{"path": target})
	if !res.IsError {
		t.Errorf("sandbox accepted lookalike-prefix escape")
	}
}

// ----- tail_log --------------------------------------------------------

func TestTailLog_DefaultStartIsEOF(t *testing.T) {
	// Pre-existing content shouldn't be returned when start_offset is
	// omitted — the tool defaults to "watch from now".
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte("preexisting\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := callTool(t, handleTailLog, map[string]interface{}{
		"path":           p,
		"follow_seconds": float64(0.3), // tight window — nothing else writes
	})
	if !strings.Contains(out, "bytes_returned: 0") {
		t.Errorf("expected zero bytes (default starts at EOF):\n%s", out)
	}
	if !strings.Contains(out, "start_offset: 12") { // len("preexisting\n")
		t.Errorf("start_offset should be initial file size (12):\n%s", out)
	}
}

func TestTailLog_FollowsAppendedContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	// Append a line ~100ms after the call starts. The follow window
	// is 1s, which is more than enough for the polling loop
	// (200ms interval) to pick it up.
	go func() {
		time.Sleep(100 * time.Millisecond)
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = f.WriteString("hello from a goroutine\n")
	}()

	out, _ := callTool(t, handleTailLog, map[string]interface{}{
		"path":           p,
		"follow_seconds": float64(1.0),
	})
	if !strings.Contains(out, "hello from a goroutine") {
		t.Errorf("expected appended content in:\n%s", out)
	}
	if !strings.Contains(out, "bytes_returned: 23") {
		t.Errorf("expected 23 bytes_returned in:\n%s", out)
	}
}

func TestTailLog_StartOffsetReturnsBackfill(t *testing.T) {
	// start_offset=0 means "include preexisting content".
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte("line1\nline2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := callTool(t, handleTailLog, map[string]interface{}{
		"path":           p,
		"start_offset":   float64(0),
		"follow_seconds": float64(0.3),
	})
	if !strings.Contains(out, "line1\nline2\n") {
		t.Errorf("expected backfilled content:\n%s", out)
	}
	if !strings.Contains(out, "end_offset: 12") {
		t.Errorf("expected end_offset 12:\n%s", out)
	}
}

func TestTailLog_RefusesDirectory(t *testing.T) {
	_, res := callTool(t, handleTailLog, map[string]interface{}{
		"path":           t.TempDir(),
		"follow_seconds": float64(0.1),
	})
	if !res.IsError {
		t.Errorf("expected error tailing a directory")
	}
}

func TestTailLog_MissingPath(t *testing.T) {
	_, res := callTool(t, handleTailLog, map[string]interface{}{})
	if !res.IsError {
		t.Errorf("expected error when path missing")
	}
}

func TestTailLog_NotFound(t *testing.T) {
	_, res := callTool(t, handleTailLog, map[string]interface{}{
		"path":           "/nonexistent/log/please-no",
		"follow_seconds": float64(0.1),
	})
	if !res.IsError {
		t.Errorf("expected error for missing file")
	}
}

func TestTailLog_RespectsSandboxRoot(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(sandboxRootEnv, dir)
	resetSandboxOnceForTest()
	t.Cleanup(resetSandboxOnceForTest)

	outside := filepath.Join(t.TempDir(), "log")
	_ = os.WriteFile(outside, []byte("x"), 0o644)

	_, res := callTool(t, handleTailLog, map[string]interface{}{
		"path":           outside,
		"follow_seconds": float64(0.1),
	})
	if !res.IsError {
		t.Errorf("sandbox should reject path outside AGENTBOX_ROOT")
	}
}

// ----- MCP Roots / sandbox helpers -------------------------------------

func TestRootURIsToPaths_ParsesFileURIs(t *testing.T) {
	roots := []mcp.Root{
		{URI: "file:///home/alice/project"},
		{URI: "file://localhost/srv/box"},
		{URI: "https://example.com/oops"}, // non-file scheme: dropped
		{URI: "not-a-uri-at-all"},         // unparseable: dropped
		{URI: "file://"},                  // empty path: dropped
	}
	got := rootURIsToPaths(roots)
	if len(got) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(got), got)
	}
	if got[0] != "/home/alice/project" {
		t.Errorf("first path = %q, want /home/alice/project", got[0])
	}
	if got[1] != "/srv/box" {
		t.Errorf("second path = %q, want /srv/box", got[1])
	}
}

func TestPathUnderAny(t *testing.T) {
	roots := []string{"/home/alice/project", "/srv/box"}
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"under first root", "/home/alice/project/file.txt", true},
		{"equals first root", "/home/alice/project", true},
		{"under second root", "/srv/box/data", true},
		{"under no root", "/etc/passwd", false},
		{"lookalike prefix", "/srv/box-evil/x", false},
		{"close but no", "/home/alice/projects-other", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathUnderAny(tc.path, roots); got != tc.want {
				t.Errorf("pathUnderAny(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestValidatePathAgainstRoots(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		root    string
		wantErr bool
	}{
		{"no root, any path ok", "/etc/passwd", "", false},
		{"under explicit root", "/srv/box/file", "/srv/box", false},
		{"equals explicit root", "/srv/box", "/srv/box", false},
		{"outside explicit root", "/etc/passwd", "/srv/box", true},
		{"lookalike prefix rejected", "/srv/box-evil/x", "/srv/box", true},
		{"empty path rejected", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validatePathAgainstRoots(tc.path, tc.root)
			if (err != nil) != tc.wantErr {
				t.Errorf("validatePathAgainstRoots(%q, %q) err=%v, wantErr=%v",
					tc.path, tc.root, err, tc.wantErr)
			}
		})
	}
}

// ----- process_* -------------------------------------------------------

// killAllAndReset kills every registered process and clears the registry.
// Tests register this via t.Cleanup so a panicked test can't leak a
// running sleep into the suite.
func killAllAndReset(t *testing.T) {
	t.Helper()
	processRegistryMu.Lock()
	pids := make([]int, 0, len(processRegistry))
	for _, mp := range processRegistry {
		pids = append(pids, mp.PID)
	}
	processRegistryMu.Unlock()
	for _, pid := range pids {
		_ = killProcessGroup(pid, 9) // SIGKILL
	}
	resetProcessRegistryForTest()
}

// killProcessGroup is a thin wrapper used only by killAllAndReset.
// In production the real handleProcessKill does the kill; this is a
// best-effort cleanup so tests don't leak.
func killProcessGroup(pid int, sig int) error {
	// Best-effort; ignore error in cleanup.
	return syscall.Kill(-pid, syscall.Signal(sig))
}

func TestProcessStart_AutoGeneratesName(t *testing.T) {
	t.Cleanup(func() { killAllAndReset(t) })
	out, _ := callTool(t, handleProcessStart, map[string]interface{}{
		"command": "sleep 5",
	})
	if !strings.Contains(out, "name: proc-") {
		t.Errorf("expected auto-generated name beginning with 'proc-':\n%s", out)
	}
	if !strings.Contains(out, "pid: ") {
		t.Errorf("expected pid line:\n%s", out)
	}
}

func TestProcessStart_RespectsExplicitName(t *testing.T) {
	t.Cleanup(func() { killAllAndReset(t) })
	out, _ := callTool(t, handleProcessStart, map[string]interface{}{
		"command": "sleep 5",
		"name":    "test-server",
	})
	if !strings.Contains(out, "name: test-server\n") {
		t.Errorf("expected explicit name preserved:\n%s", out)
	}
}

func TestProcessStart_RejectsDuplicateName(t *testing.T) {
	t.Cleanup(func() { killAllAndReset(t) })
	_, _ = callTool(t, handleProcessStart, map[string]interface{}{
		"command": "sleep 5",
		"name":    "dup",
	})
	_, res := callTool(t, handleProcessStart, map[string]interface{}{
		"command": "sleep 5",
		"name":    "dup",
	})
	if !res.IsError {
		t.Errorf("expected error on duplicate name")
	}
}

func TestProcessStart_RejectsMissingCommand(t *testing.T) {
	_, res := callTool(t, handleProcessStart, map[string]interface{}{})
	if !res.IsError {
		t.Errorf("expected error when command missing")
	}
}

func TestProcessList_ShowsRegisteredProcesses(t *testing.T) {
	t.Cleanup(func() { killAllAndReset(t) })
	_, _ = callTool(t, handleProcessStart, map[string]interface{}{
		"command": "sleep 5",
		"name":    "alpha",
	})
	_, _ = callTool(t, handleProcessStart, map[string]interface{}{
		"command": "sleep 5",
		"name":    "beta",
	})
	out, _ := callTool(t, handleProcessList, map[string]interface{}{})
	if !strings.Contains(out, "Found 2 process(es)") {
		t.Errorf("expected 2 processes:\n%s", out)
	}
	if !strings.Contains(out, "alpha") || !strings.Contains(out, "beta") {
		t.Errorf("expected both names in list:\n%s", out)
	}
}

func TestProcessList_EmptyWhenNothingRegistered(t *testing.T) {
	resetProcessRegistryForTest()
	out, _ := callTool(t, handleProcessList, map[string]interface{}{})
	if !strings.Contains(out, "No background processes registered") {
		t.Errorf("expected empty-state message:\n%s", out)
	}
}

func TestProcessKill_RemovesFromRegistry(t *testing.T) {
	t.Cleanup(func() { killAllAndReset(t) })
	_, _ = callTool(t, handleProcessStart, map[string]interface{}{
		"command": "sleep 30",
		"name":    "kill-me",
	})
	out, _ := callTool(t, handleProcessKill, map[string]interface{}{
		"name": "kill-me",
	})
	if !strings.Contains(out, "signal: SIGTERM") {
		t.Errorf("expected SIGTERM in output:\n%s", out)
	}
	// Verify removal
	listOut, _ := callTool(t, handleProcessList, map[string]interface{}{})
	if strings.Contains(listOut, "kill-me") {
		t.Errorf("process should be gone from list after kill:\n%s", listOut)
	}
}

func TestProcessKill_ForceUsesSIGKILL(t *testing.T) {
	t.Cleanup(func() { killAllAndReset(t) })
	_, _ = callTool(t, handleProcessStart, map[string]interface{}{
		"command": "sleep 30",
		"name":    "stubborn",
	})
	out, _ := callTool(t, handleProcessKill, map[string]interface{}{
		"name":  "stubborn",
		"force": true,
	})
	if !strings.Contains(out, "signal: SIGKILL") {
		t.Errorf("expected SIGKILL in output:\n%s", out)
	}
}

func TestProcessKill_RejectsUnknownName(t *testing.T) {
	resetProcessRegistryForTest()
	_, res := callTool(t, handleProcessKill, map[string]interface{}{
		"name": "no-such-thing",
	})
	if !res.IsError {
		t.Errorf("expected error for unknown name")
	}
}

func TestProcessStart_CapturesStdoutToLog(t *testing.T) {
	t.Cleanup(func() { killAllAndReset(t) })
	out, _ := callTool(t, handleProcessStart, map[string]interface{}{
		"command": "echo 'hello from process'; sleep 5",
		"name":    "logged",
	})
	// Pull log_path from output
	var logPath string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "log_path: ") {
			logPath = strings.TrimPrefix(line, "log_path: ")
			break
		}
	}
	if logPath == "" {
		t.Fatalf("no log_path in output:\n%s", out)
	}
	// Wait briefly for the echo to land in the log
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(logPath)
		if err == nil && strings.Contains(string(data), "hello from process") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("log file %s never contained 'hello from process'", logPath)
}
