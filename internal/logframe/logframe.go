// Package logframe implements the #1674 text-safe framing format shared by
// agent-box's writer (internal/agentbox, framed capture_mode) and the
// `containarium code` client's demuxer: one frame per line,
// "<stream> <base64(payload)>\n". See
// docs/architecture/remote-coding-agent.md, Part A "Framing" for why: the
// log is read back through tail_log inside an MCP TEXT result
// (mcp.NewToolResultText), so raw binary framing bytes — and any multi-byte
// rune split across a read/write boundary — would be mangled by JSON's
// UTF-8 encoding. base64 makes every frame valid UTF-8 regardless of what
// bytes it carries.
package logframe

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

// Stream identifies which of a spawned process's two output streams a
// frame belongs to.
type Stream byte

const (
	Stdout Stream = '1'
	Stderr Stream = '2'
)

// EncodeFrame renders payload as one frame: "<stream> <base64(payload)>\n".
// payload may be any byte slice, including one that splits a UTF-8 rune —
// base64 doesn't care about rune boundaries. The decoder reassembles
// complete runes by concatenating consecutive same-stream frames' decoded
// bytes, never by inspecting a single frame in isolation.
func EncodeFrame(stream Stream, payload []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(payload)
	out := make([]byte, 0, 3+len(encoded))
	out = append(out, byte(stream), ' ')
	out = append(out, encoded...)
	out = append(out, '\n')
	return out
}

// Frame is one decoded frame: which stream it belongs to, and its raw
// (already base64-decoded) payload bytes.
type Frame struct {
	Stream  Stream
	Payload []byte
}

// Demuxer incrementally decodes a framed byte stream that may arrive in
// arbitrary chunks — including mid-line, e.g. tail_log resuming right in
// the middle of a not-yet-fully-written frame (a read cut mid-line must be
// detectable and completed on the next read, per the design doc). Feed it
// every chunk, in stream order, via Write; it returns every complete frame
// it can now decode, leaving any trailing partial line buffered internally
// for the next call. Zero value is ready to use.
type Demuxer struct {
	buf []byte
}

// Write appends chunk to the internal buffer and returns every complete
// frame it can now decode, in order. A malformed line (this should never
// happen against a real agent-box writer, only against corrupted/foreign
// input) stops decoding and returns an error alongside whatever valid
// frames were already decoded from this call.
func (d *Demuxer) Write(chunk []byte) ([]Frame, error) {
	d.buf = append(d.buf, chunk...)

	var frames []Frame
	for {
		i := bytes.IndexByte(d.buf, '\n')
		if i < 0 {
			break // no complete line yet — wait for more
		}
		line := d.buf[:i]
		d.buf = d.buf[i+1:]

		if len(line) < 2 || line[1] != ' ' {
			return frames, fmt.Errorf("logframe: malformed frame line %q", line)
		}
		stream := Stream(line[0])
		if stream != Stdout && stream != Stderr {
			return frames, fmt.Errorf("logframe: unknown stream id %q", line[0])
		}
		payload, err := base64.StdEncoding.DecodeString(string(line[2:]))
		if err != nil {
			return frames, fmt.Errorf("logframe: decode frame: %w", err)
		}
		frames = append(frames, Frame{Stream: stream, Payload: payload})
	}
	return frames, nil
}
