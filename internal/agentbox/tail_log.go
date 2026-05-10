package agentbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// tail_log lets an agent watch a file as new content is appended,
// bounded by a wall-clock follow window. The MCP transport is
// request/response (no streaming), so this tool is the request/response
// equivalent of "tail -f for N seconds": collect what arrived during
// the window and return it.
//
// Typical use: after `shell_exec systemctl start caddy`, the agent
// calls tail_log on /var/log/caddy/access.log with follow_seconds=10
// to confirm the service actually started serving (or to capture the
// crash message if it didn't).
const (
	tailLogDefaultFollowSec = 10
	tailLogMaxFollowSec     = 60
	tailLogOutputLimit      = 256 * 1024 // 256 KiB — same as shell_exec
	tailLogPollInterval     = 200 * time.Millisecond
)

func registerTailLogTool(s *server.MCPServer) {
	s.AddTool(tailLogTool(), handleTailLog)
}

func tailLogTool() mcp.Tool {
	return mcp.NewTool(
		"tail_log",
		mcp.WithDescription(
			"Watch a file as new content is appended, bounded by follow_seconds. "+
				"Returns the bytes written to the file during the window plus a new "+
				"end_offset suitable for resuming on the next call. If start_offset "+
				"is omitted, watching begins at the current end-of-file (\"tail -f "+
				"from now\"). Capped at 256 KiB output; longer streams set the "+
				"truncated flag — the agent can resume by passing the returned "+
				"end_offset as start_offset on the next call.",
		),
		mcp.WithString("path",
			mcp.Description("Absolute or relative path to the log file."),
			mcp.Required(),
		),
		mcp.WithNumber("start_offset",
			mcp.Description("Byte offset to start reading from. Default: file size at call time (i.e. only new content)."),
		),
		mcp.WithNumber("follow_seconds",
			mcp.Description(fmt.Sprintf("How long to watch for new content. Default %d, max %d.",
				tailLogDefaultFollowSec, tailLogMaxFollowSec)),
			mcp.DefaultNumber(float64(tailLogDefaultFollowSec)),
		),
	)
}

func handleTailLog(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	rawPath, ok := args["path"].(string)
	if !ok || rawPath == "" {
		return mcp.NewToolResultError("tail_log: 'path' is required"), nil
	}
	path, err := validatePathCtx(ctx, rawPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("tail_log: %v", err)), nil
	}

	followSec := float64(tailLogDefaultFollowSec)
	if v, ok := args["follow_seconds"].(float64); ok && v > 0 {
		followSec = v
		if followSec > tailLogMaxFollowSec {
			followSec = tailLogMaxFollowSec
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("tail_log: %v", err)), nil
	}
	if info.IsDir() {
		return mcp.NewToolResultError(fmt.Sprintf("tail_log: %s is a directory", path)), nil
	}

	// Default start_offset is the file's current size — "tail -f from
	// now". If the caller wants to backfill, they pass start_offset=0
	// (or any earlier offset) explicitly. We don't reject offsets past
	// EOF; they just mean "wait for the file to grow that far," which
	// is fine for the use case but documented as agent-suspect.
	startOffset := info.Size()
	if v, ok := args["start_offset"].(float64); ok && v >= 0 {
		startOffset = int64(v)
	}

	// #nosec G304 -- path was sanitized by validatePath; tail_log's
	// contract is to read agent-supplied paths.
	f, err := os.Open(path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("tail_log: %v", err)), nil
	}
	defer f.Close()

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("tail_log: seek to %d: %v", startOffset, err)), nil
	}

	deadline := time.Now().Add(time.Duration(followSec * float64(time.Second)))
	var buf bytes.Buffer
	truncated := false
	chunk := make([]byte, 64*1024)

	for time.Now().Before(deadline) {
		// Honor an outer cancellation (e.g. MCP transport closed) so
		// we don't block past the host's wishes.
		select {
		case <-ctx.Done():
			return mcp.NewToolResultError(fmt.Sprintf("tail_log: cancelled: %v", ctx.Err())), nil
		default:
		}

		remaining := tailLogOutputLimit - buf.Len()
		if remaining <= 0 {
			truncated = true
			break
		}
		readSize := len(chunk)
		if readSize > remaining {
			readSize = remaining
		}
		n, err := f.Read(chunk[:readSize])
		if n > 0 {
			buf.Write(chunk[:n])
		}
		if err == io.EOF {
			// No more content available right now — sleep briefly,
			// then retry. The Read returned io.EOF without a fatal
			// error; the file descriptor is still good and the file
			// may grow before the deadline.
			//
			// We don't seek to End here: the kernel keeps the file
			// position, and io.EOF leaves it at the current size.
			// When the file grows, the next Read picks up new bytes.
			select {
			case <-ctx.Done():
				return mcp.NewToolResultError(fmt.Sprintf("tail_log: cancelled: %v", ctx.Err())), nil
			case <-time.After(tailLogPollInterval):
			}
			continue
		}
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("tail_log: read: %v", err)), nil
		}
	}

	endOffset := startOffset + int64(buf.Len())
	body := fmt.Sprintf(
		"path: %s\nstart_offset: %d\nend_offset: %d\nbytes_returned: %d\ntruncated: %v\nfollow_seconds: %v\n--- content ---\n%s",
		path, startOffset, endOffset, buf.Len(), truncated, followSec, buf.String(),
	)
	return mcp.NewToolResultText(body), nil
}
