package agentbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// readFileLimit is the maximum bytes returned in a single read_file call.
// Agents that need more pull additional ranges via offset/limit. The cap
// keeps a single tool call below MCP's reasonable message size.
const readFileLimit = 512 * 1024 // 512 KiB

func registerFileTools(s *server.MCPServer) {
	s.AddTool(readFileTool(), handleReadFile)
	s.AddTool(writeFileTool(), handleWriteFile)
	s.AddTool(listDirTool(), handleListDir)
}

// ----- read_file -------------------------------------------------------

func readFileTool() mcp.Tool {
	return mcp.NewTool(
		"read_file",
		mcp.WithDescription(
			"Read a file from the Containarium box's filesystem. Returns up to "+
				"512 KiB; use offset+limit to page through larger files. "+
				"Binary files are returned as-is — the caller should detect content type "+
				"if it matters (e.g. by extension or magic bytes).",
		),
		mcp.WithString("path",
			mcp.Description("Absolute or relative path to the file."),
			mcp.Required(),
		),
		mcp.WithNumber("offset",
			mcp.Description("Byte offset to start reading from. Default 0."),
			mcp.DefaultNumber(0),
		),
		mcp.WithNumber("limit",
			mcp.Description(fmt.Sprintf("Max bytes to return. Default and max: %d.", readFileLimit)),
			mcp.DefaultNumber(float64(readFileLimit)),
		),
	)
}

func handleReadFile(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("read_file: 'path' is required"), nil
	}

	offset := int64(0)
	if v, ok := args["offset"].(float64); ok && v >= 0 {
		offset = int64(v)
	}
	limit := int64(readFileLimit)
	if v, ok := args["limit"].(float64); ok && v > 0 && int64(v) < readFileLimit {
		limit = int64(v)
	}

	f, err := os.Open(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("read_file: %v", err)), nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("read_file: stat: %v", err)), nil
	}
	if info.IsDir() {
		return mcp.NewToolResultError(fmt.Sprintf("read_file: %s is a directory (use list_dir)", path)), nil
	}

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("read_file: seek to %d: %v", offset, err)), nil
		}
	}

	buf := make([]byte, limit)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return mcp.NewToolResultError(fmt.Sprintf("read_file: %v", err)), nil
	}
	body := fmt.Sprintf(
		"path: %s\nsize: %d\noffset: %d\nbytes_returned: %d\ntruncated: %v\n--- content ---\n%s",
		path, info.Size(), offset, n, int64(n) < info.Size()-offset, string(buf[:n]),
	)
	return mcp.NewToolResultText(body), nil
}

// ----- write_file ------------------------------------------------------

func writeFileTool() mcp.Tool {
	return mcp.NewTool(
		"write_file",
		mcp.WithDescription(
			"Write a file atomically (write to temp then rename). Creates parent "+
				"directories as needed. Mode defaults to 0644; pass an octal string "+
				"like \"0755\" for executables.",
		),
		mcp.WithString("path",
			mcp.Description("Path to write to. Parent dirs are created if missing."),
			mcp.Required(),
		),
		mcp.WithString("content",
			mcp.Description("File content as a string. Binary should be base64-encoded by the caller and decoded post-write via shell_exec — write_file does not interpret encoding."),
			mcp.Required(),
		),
		mcp.WithString("mode",
			mcp.Description("Octal file mode, e.g. \"0644\" (default) or \"0755\"."),
			mcp.DefaultString("0644"),
		),
	)
}

func handleWriteFile(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("write_file: 'path' is required"), nil
	}
	content, ok := args["content"].(string)
	if !ok {
		return mcp.NewToolResultError("write_file: 'content' is required"), nil
	}
	modeStr, _ := args["mode"].(string)
	if modeStr == "" {
		modeStr = "0644"
	}
	mode, err := parseFileMode(modeStr)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("write_file: invalid mode %q: %v", modeStr, err)), nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("write_file: mkdir parent: %v", err)), nil
	}

	// Atomic write: temp + rename, so a half-written file never appears at
	// the destination path even if the agent kills us mid-write.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent-box.*.tmp")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("write_file: temp create: %v", err)), nil
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		cleanup()
		return mcp.NewToolResultError(fmt.Sprintf("write_file: write: %v", err)), nil
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return mcp.NewToolResultError(fmt.Sprintf("write_file: close: %v", err)), nil
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		cleanup()
		return mcp.NewToolResultError(fmt.Sprintf("write_file: chmod: %v", err)), nil
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return mcp.NewToolResultError(fmt.Sprintf("write_file: rename: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf(
		"path: %s\nbytes_written: %d\nmode: %s\n",
		path, len(content), modeStr,
	)), nil
}

func parseFileMode(s string) (os.FileMode, error) {
	s = strings.TrimPrefix(s, "0o")
	s = strings.TrimPrefix(s, "0")
	var n int64
	if _, err := fmt.Sscanf(s, "%o", &n); err != nil {
		return 0, err
	}
	return os.FileMode(n), nil
}

// ----- list_dir --------------------------------------------------------

func listDirTool() mcp.Tool {
	return mcp.NewTool(
		"list_dir",
		mcp.WithDescription(
			"List entries in a directory with name, type, size, and mtime. "+
				"Hidden files (leading dot) are excluded by default; pass "+
				"include_hidden=true to see them.",
		),
		mcp.WithString("path",
			mcp.Description("Directory to list."),
			mcp.Required(),
		),
		mcp.WithBoolean("include_hidden",
			mcp.Description("Include dotfiles. Default false."),
			mcp.DefaultBool(false),
		),
	)
}

func handleListDir(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("list_dir: 'path' is required"), nil
	}
	includeHidden, _ := args["include_hidden"].(bool)

	entries, err := os.ReadDir(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("list_dir: %v", err)), nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var b strings.Builder
	fmt.Fprintf(&b, "path: %s\nentry_count: %d\n", path, len(entries))
	fmt.Fprintln(&b, "--- entries ---")
	fmt.Fprintln(&b, "type\tsize\tmtime\tname")
	for _, e := range entries {
		name := e.Name()
		if !includeHidden && strings.HasPrefix(name, ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			fmt.Fprintf(&b, "?\t?\t?\t%s\t(stat failed: %v)\n", name, err)
			continue
		}
		t := "f"
		switch {
		case info.IsDir():
			t = "d"
		case info.Mode()&os.ModeSymlink != 0:
			t = "l"
		}
		fmt.Fprintf(&b, "%s\t%d\t%s\t%s\n", t, info.Size(), info.ModTime().UTC().Format(time.RFC3339), name)
	}
	return mcp.NewToolResultText(b.String()), nil
}
