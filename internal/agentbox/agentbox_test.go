package agentbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
