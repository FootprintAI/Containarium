package sentinel

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandshakeDecoderOverReads is the QA reproducer for Bug A: when the
// peer side reads the handshake response with json.NewDecoder over a stream
// that has additional bytes appended (e.g., a yamux SYN frame written by
// the sentinel right after the JSON), the decoder's internal buffer
// swallows those extra bytes. They never reach yamux.Server, and yamux
// then misaligns its frame reader.
//
// This test FAILS on the buggy code path (json.NewDecoder.Decode) and
// PASSES on the line-delimited fix (readJSONLine). Keep both forms here
// so future changes can't silently regress.
func TestHandshakeDecoderOverReads(t *testing.T) {
	jsonResponse := `{"ok":true,"assigned_ip":"127.0.0.7"}` + "\n"
	yamuxSYN := []byte{
		0x00,       // version 0
		0x00,       // type SYN
		0x00, 0x01, // flags = SYN
		0x00, 0x00, 0x00, 0x01, // stream ID 1
		0x00, 0x00, 0x00, 0x00, // length 0
	}

	// Simulate the wire: JSON response immediately followed by a yamux
	// SYN frame, both in one io.Reader. This is what the spot sees when
	// the sentinel writes the response and immediately initiates keysync.
	combined := bytes.NewReader(append([]byte(jsonResponse), yamuxSYN...))

	t.Run("buggy: json.Decoder over-reads", func(t *testing.T) {
		r := bytes.NewReader(append([]byte(jsonResponse), yamuxSYN...))
		dec := json.NewDecoder(r)
		var resp TunnelHandshakeResponse
		require.NoError(t, dec.Decode(&resp))
		assert.True(t, resp.OK)

		// dec.Buffered() returns whatever the decoder pre-fetched but did
		// not consume. If yamux frame bytes are in here, they are LOST
		// when we hand the underlying reader to yamux.
		buffered, _ := io.ReadAll(dec.Buffered())
		t.Logf("decoder buffered %d bytes after Decode (these are LOST when handed to yamux)", len(buffered))

		// What yamux would see if it reads from r directly:
		fromUnderlying, _ := io.ReadAll(r)
		t.Logf("underlying reader still holds %d bytes", len(fromUnderlying))

		// On the buggy path, the decoder ate the yamux SYN.
		// Total bytes still reachable by yamux = len(fromUnderlying), which
		// will be SHORTER than the SYN frame because the decoder buffered
		// some of them. yamux then reads garbage.
		assert.NotEqual(t, len(yamuxSYN), len(fromUnderlying),
			"DEMONSTRATING BUG: yamux can no longer reach the full SYN frame")
	})

	t.Run("fix: production readHandshakeResponse leaves yamux frame intact", func(t *testing.T) {
		_, _ = combined.Seek(0, io.SeekStart)

		resp, err := readHandshakeResponse(combined)
		require.NoError(t, err)
		assert.True(t, resp.OK)
		assert.Equal(t, "127.0.0.7", resp.AssignedIP)

		// Everything after the first '\n' should still be on the reader.
		fromUnderlying, _ := io.ReadAll(combined)
		assert.Equal(t, yamuxSYN, fromUnderlying,
			"after the fix, the full yamux SYN frame is still reachable")
	})

	t.Run("fix: production readHandshake (sentinel side) is also safe", func(t *testing.T) {
		// Same race exists on the sentinel side: spot writes JSON handshake
		// then enters yamux.Server. If sentinel's readHandshake over-read,
		// it would lose yamux frame bytes coming the OTHER direction.
		// (Less likely to trigger in practice — spot doesn't immediately
		// initiate streams — but the fix should be symmetric.)
		jsonHS := `{"token":"abc","spot_id":"x","ports":[80]}` + "\n"
		extra := []byte{0xCA, 0xFE, 0xBA, 0xBE} // arbitrary trailing bytes
		buf := bytes.NewReader(append([]byte(jsonHS), extra...))

		hs, err := readHandshake(buf)
		require.NoError(t, err)
		assert.Equal(t, "x", hs.SpotID)

		fromUnderlying, _ := io.ReadAll(buf)
		assert.Equal(t, extra, fromUnderlying,
			"readHandshake must not over-read past the newline")
	})
}
