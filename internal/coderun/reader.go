// Package coderun implements the client half of `containarium code`
// (#1674): a resumable reader over agent-box's tail_log, so a run started
// on a box survives the local client's connection dying mid-stream. See
// docs/architecture/remote-coding-agent.md, Part B.
package coderun

import (
	"context"
	"io"
	"time"
)

// LogReader abstracts tail_log so the resume logic in StreamOutput is
// testable without a live box — "that seam is the whole design for
// testability" (design doc). A real implementation (session.go) reconnects
// its own underlying SSH/MCP session on a transport failure, internally;
// StreamOutput only needs to know that a failed Read can be retried from
// the same offset.
type LogReader interface {
	// Read returns bytes from startOffset, the new end offset, and whether
	// the read was cut short by tail_log's output cap (never EOF — more
	// data may already exist past endOffset).
	Read(ctx context.Context, path string, startOffset int64, follow time.Duration) (data []byte, endOffset int64, truncated bool, err error)
}

// retryBackoff bounds how long StreamOutput waits before retrying a failed
// Read. Short: a dropped SSH connection reconnects in well under a second
// in practice, and the whole point of this loop is not making the user
// re-issue a command.
const retryBackoff = 250 * time.Millisecond

// StreamOutput reads path via r from startOffset, writing bytes to w as
// they arrive, until ctx is cancelled. Returns the final offset reached.
//
// Two rules carry the north-star metric (0 bytes missing or duplicated
// across >=20 forced mid-run disconnects):
//
//   - On a Read error, retry from the SAME offset after a brief backoff —
//     never skip ahead, never re-derive a new starting point. onErr, if
//     non-nil, is called with each error (for logging/diagnostics); it does
//     not affect retry behavior.
//   - On truncated:true (tail_log hit its output cap), re-read
//     IMMEDIATELY — no backoff, no waiting out `follow`. Treating a capped
//     read like "no more data yet" silently slow-drips the run's output;
//     since more data is already known to exist, sleeping here has no
//     upside and only means an agent watching the stream sees an
//     artificial stall.
func StreamOutput(ctx context.Context, r LogReader, w io.Writer, path string, startOffset int64, follow time.Duration, onErr func(error)) (int64, error) {
	offset := startOffset
	for {
		select {
		case <-ctx.Done():
			return offset, ctx.Err()
		default:
		}

		// truncated is not branched on: every non-error path already loops
		// back to the top immediately, with no client-side delay of any
		// kind — the only throttle anywhere in this loop is retryBackoff
		// on an actual error. So a truncated read is, by construction,
		// already re-read as fast as any other read; there is no separate
		// "sleep the poll interval" behavior here to skip.
		data, end, _, err := r.Read(ctx, path, offset, follow)
		if err != nil {
			if onErr != nil {
				onErr(err)
			}
			select {
			case <-ctx.Done():
				return offset, ctx.Err()
			case <-time.After(retryBackoff):
			}
			continue
		}

		if len(data) > 0 {
			if _, werr := w.Write(data); werr != nil {
				return offset, werr
			}
		}
		offset = end
	}
}
