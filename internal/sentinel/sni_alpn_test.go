package sentinel

import (
	"bufio"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureClientHello drives a stdlib TLS client into a pipe and returns the
// record-framed ClientHello bytes it emitted.
func captureClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	go func() { _ = tls.Client(clientConn, cfg).Handshake() }()

	require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(5*time.Second)))
	br := bufio.NewReaderSize(serverConn, 16389)
	hdr, err := br.Peek(5)
	require.NoError(t, err)
	full, err := br.Peek(5 + (int(hdr[3])<<8 | int(hdr[4])))
	require.NoError(t, err)
	return append([]byte(nil), full...)
}

// buildClientHello hand-assembles a record-framed ClientHello carrying the
// given raw extensions block.
func buildClientHello(exts []byte) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)          // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id length
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00) // compression
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func ext(typ int, data []byte) []byte {
	out := []byte{byte(typ >> 8), byte(typ), byte(len(data) >> 8), byte(len(data))}
	return append(out, data...)
}

func TestPeekClientHelloALPN(t *testing.T) {
	t.Run("alpn list and sni parsed from real hello", func(t *testing.T) {
		full := captureClientHello(t, &tls.Config{
			ServerName:         "prod.example.com",
			NextProtos:         []string{"h2", "http/1.1", "acme-tls/1"},
			InsecureSkipVerify: true,
		})
		got, err := parseClientHello(full)
		require.NoError(t, err)
		assert.Equal(t, "prod.example.com", got.SNI)
		assert.Equal(t, []string{"h2", "http/1.1", "acme-tls/1"}, got.ALPN)
	})

	t.Run("absent alpn", func(t *testing.T) {
		full := captureClientHello(t, &tls.Config{ServerName: "a.example.com", InsecureSkipVerify: true})
		got, err := parseClientHello(full)
		require.NoError(t, err)
		assert.Equal(t, "a.example.com", got.SNI)
		assert.Empty(t, got.ALPN)
	})

	t.Run("alpn without sni", func(t *testing.T) {
		alpn := []byte{0x00, 0x03, 0x02, 'h', '2'}
		got, err := parseClientHello(buildClientHello(ext(16, alpn)))
		require.NoError(t, err)
		assert.Empty(t, got.SNI)
		assert.Equal(t, []string{"h2"}, got.ALPN)
	})

	t.Run("malformed alpn extensions return error without panic", func(t *testing.T) {
		cases := map[string][]byte{
			"empty extension":        {},
			"one byte":               {0x00},
			"list length overruns":   {0x00, 0x09, 0x02, 'h', '2'},
			"entry length overruns":  {0x00, 0x03, 0x09, 'h', '2'},
			"zero-length entry":      {0x00, 0x01, 0x00},
			"list shorter than data": {0x00, 0x01, 0x02, 'h', '2'},
			"empty list":             {0x00, 0x00},
		}
		for name, data := range cases {
			t.Run(name, func(t *testing.T) {
				assert.NotPanics(t, func() {
					_, err := parseClientHello(buildClientHello(ext(16, data)))
					assert.Error(t, err)
				})
			})
		}
	})

	t.Run("truncated hello never panics", func(t *testing.T) {
		full := captureClientHello(t, &tls.Config{
			ServerName: "x.example.com", NextProtos: []string{"h2"}, InsecureSkipVerify: true,
		})
		for i := 0; i < len(full); i++ {
			assert.NotPanics(t, func() { _, _ = parseClientHello(full[:i]) })
		}
	})

	t.Run("peekClientHello replays bytes", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer func() { _ = clientConn.Close() }()
		defer func() { _ = serverConn.Close() }()
		go func() {
			_ = tls.Client(clientConn, &tls.Config{
				ServerName: "p.example.com", NextProtos: []string{"h2"}, InsecureSkipVerify: true,
			}).Handshake()
		}()
		require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(5*time.Second)))
		got, wrapped, err := peekClientHello(serverConn)
		require.NoError(t, err)
		assert.Equal(t, "p.example.com", got.SNI)
		assert.Equal(t, []string{"h2"}, got.ALPN)
		buf := make([]byte, 1)
		_, err = wrapped.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, byte(0x16), buf[0], "peeked bytes must be replayed")
	})

	t.Run("sni extraction ignores malformed alpn", func(t *testing.T) {
		sni := []byte{0x00, 0x08, 0x00, 0x00, 0x05, 'a', '.', 'b', 'c', 'd'}
		exts := append(ext(0, sni), ext(16, []byte{0x00})...)
		got, err := extractSNI(buildClientHello(exts))
		require.NoError(t, err)
		assert.Equal(t, "a.bcd", got)
	})
}
