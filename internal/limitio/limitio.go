// Package limitio caps how many bytes the daemon buffers from a source it
// does not control: command output and files read out of a box, and HTTP
// response bodies from peers, boxes and the daemon API (#3469). Without a
// cap, a box that prints without end or a peer that answers with an endless
// body grows the reader's memory until the process is killed.
//
// ReadAll is the capped replacement for io.ReadAll. Buffer is the capped
// replacement for a bytes.Buffer handed to a producer as an io.Writer. Both
// behave exactly like their uncapped counterparts for input at or under the
// limit, and report *TooLargeError (errors.Is(err, ErrTooLarge)) for input
// over it.
package limitio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
)

// Named caps for the read paths routed through this package. Each is far
// above what the path legitimately carries; the point is a ceiling, not a
// budget.
const (
	// MaxExecOutputBytes caps each of stdout and stderr captured from a
	// command run in a box. 64x the 256 KiB per-stream cap the in-box
	// shell_exec tool already applies; daemon-side exec callers read
	// probe, status and log-tail output, not bulk data (bulk data moves
	// through the file API).
	MaxExecOutputBytes int64 = 16 << 20 // 16 MiB

	// MaxFileReadBytes caps a whole-file read out of a box. Above the
	// largest caller-side limit on that path, the 50 MiB tracker-submit
	// bundle cap, so that check keeps reporting its own error. Larger
	// transfers use the streaming read.
	MaxFileReadBytes int64 = 64 << 20 // 64 MiB

	// MaxHTTPResponseBytes caps an HTTP response body read whole into
	// memory from a peer daemon, a box's A2A server or the daemon API.
	// Those bodies are grpc-gateway JSON renderings of gRPC messages,
	// which gRPC's default 4 MiB receive limit already bounds at the
	// source; 16 MiB leaves room for the JSON encoding's overhead.
	MaxHTTPResponseBytes int64 = 16 << 20 // 16 MiB
)

// ErrTooLarge is the sentinel every *TooLargeError matches with errors.Is.
var ErrTooLarge = errors.New("data exceeds the byte limit")

// TooLargeError reports that a source produced more than Limit bytes. The
// data returned alongside it is the first Limit bytes; the rest was not kept.
type TooLargeError struct {
	Limit int64
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("data exceeds the %d-byte limit (truncated)", e.Limit)
}

// Is makes errors.Is(err, ErrTooLarge) true for every *TooLargeError.
func (e *TooLargeError) Is(target error) bool { return target == ErrTooLarge }

// ReadAll reads r until EOF, like io.ReadAll, but keeps at most limit bytes.
// If r has more than limit bytes it stops reading (at most one buffer past
// the limit, to see that there is more) and returns the first limit bytes
// with a *TooLargeError. A read error from r is returned as is, with the
// bytes read before it. A negative limit is treated as zero.
func ReadAll(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		limit = 0
	}
	probe := limit
	if probe < math.MaxInt64 {
		probe++ // one byte past the limit tells "exactly limit" from "more"
	}
	data, err := io.ReadAll(io.LimitReader(r, probe))
	if int64(len(data)) > limit {
		return data[:limit], &TooLargeError{Limit: limit}
	}
	return data, err
}

// Buffer is an io.Writer that keeps the first limit bytes written to it and
// drops the rest. Writes past the limit still report success: a producer that
// sees a write error may stop draining its source, which can leave the
// process on the other end blocked on a full pipe. Check Err (or Truncated)
// once the producer is done. The zero value is not usable; call NewBuffer.
type Buffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

// NewBuffer returns an empty Buffer that keeps at most limit bytes. A
// negative limit is treated as zero.
func NewBuffer(limit int64) *Buffer {
	if limit < 0 {
		limit = 0
	}
	return &Buffer{limit: limit}
}

// Write keeps what fits under the limit and drops the rest. It always
// returns len(p), nil.
func (b *Buffer) Write(p []byte) (int, error) {
	room := b.limit - int64(b.buf.Len())
	if int64(len(p)) > room {
		b.truncated = true
		b.buf.Write(p[:room])
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}

// String returns the kept bytes as a string.
func (b *Buffer) String() string { return b.buf.String() }

// Bytes returns the kept bytes. The slice aliases the buffer's storage.
func (b *Buffer) Bytes() []byte { return b.buf.Bytes() }

// Len returns the number of kept bytes.
func (b *Buffer) Len() int { return b.buf.Len() }

// Reset empties the buffer and clears the truncation flag.
func (b *Buffer) Reset() {
	b.buf.Reset()
	b.truncated = false
}

// Truncated reports whether any write was dropped because of the limit.
func (b *Buffer) Truncated() bool { return b.truncated }

// Err returns a *TooLargeError if any write was dropped, nil otherwise.
func (b *Buffer) Err() error {
	if b.truncated {
		return &TooLargeError{Limit: b.limit}
	}
	return nil
}
