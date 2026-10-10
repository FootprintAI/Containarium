package sentinel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingListener captures every byte the server reads from each
// accepted connection: the raw wire bytes as the peer sent them. Under a
// TLS session that is ciphertext; under the cleartext path it is the JSON
// handshake itself.
type recordingListener struct {
	net.Listener
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &recordingConn{Conn: c, l: l}, nil
}

func (l *recordingListener) captured() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.buf.Bytes()...)
}

type recordingConn struct {
	net.Conn
	l *recordingListener
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.l.mu.Lock()
	c.l.buf.Write(p[:n])
	c.l.mu.Unlock()
	return n, err
}

// serveV2Tunnel starts a TunnelServer holding id on a recording listener
// and returns the server, the listener (for its capture) and its address.
func serveV2Tunnel(t *testing.T, ctx context.Context, policy *TokenPolicy, registry *TunnelRegistry, id *TunnelIdentity) (*TunnelServer, *recordingListener, string) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln := &recordingListener{Listener: raw}
	ts := NewTunnelServer("", policy, registry, 0)
	ts.SetTunnelIdentity(id)
	go func() { _ = ts.Serve(ctx, ln) }()
	waitForListener(t, raw.Addr().String())
	return ts, ln, raw.Addr().String()
}

// dialTunnelTLS opens a TLS tunnel session to addr the way TunnelClient
// does (TLS 1.3, tunnel ALPN, pinned identity) and returns the connection
// after the handshake, so a test can write its own application bytes.
func dialTunnelTLS(t *testing.T, addr string, id *TunnelIdentity) *tls.Conn {
	t.Helper()
	tc := &TunnelClient{SentinelAddr: addr, SentinelPins: []TunnelPin{id.Pin()}}
	cfg, err := tc.tlsConfig()
	require.NoError(t, err)
	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	require.NoError(t, err)
	conn := tls.Client(raw, cfg)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, conn.Handshake())
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestTunnelTokenNeverOnTheWire: the raw bytes of a successful TLS tunnel
// session never contain the token. The control variant runs the same
// capture under the legacy cleartext handshake, where the token IS in the
// capture, so the assertion is known to be able to fail.
func TestTunnelTokenNeverOnTheWire(t *testing.T) {
	stubLoopbackAliases(t)
	const token = "wire-token-0123456789abcdef"

	t.Run("tls session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		id := newTestTunnelIdentity(t)
		registry := NewTunnelRegistry()
		ts, ln, addr := serveV2Tunnel(t, ctx, policyAny(token), registry, id)
		connectCh := make(chan *TunnelSpot, 1)
		ts.OnConnect = func(spot *TunnelSpot) {
			select {
			case connectCh <- spot:
			default:
			}
		}

		client := &TunnelClient{
			SentinelAddr: addr,
			SentinelPins: []TunnelPin{id.Pin()},
			Token:        token,
			SpotID:       "v2-spot",
			Ports:        []int{22},
		}
		go func() { _ = client.connectAndServe(ctx) }()

		select {
		case spot := <-connectCh:
			assert.Equal(t, "v2-spot", spot.ID)
			assert.Equal(t, TunnelTransportTLS, spot.Transport)
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for the TLS registration")
		}
		wire := ln.captured()
		require.NotEmpty(t, wire)
		assert.Equal(t, byte(0x16), wire[0], "session must open with a TLS record")
		assert.False(t, bytes.Contains(wire, []byte(token)), "token must not appear in the raw bytes")
		assert.False(t, bytes.Contains(wire, []byte(`"spot_id"`)), "handshake JSON must not be visible on the wire")
	})

	t.Run("legacy cleartext control", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		registry := NewTunnelRegistry()
		_, ln, addr := serveV2Tunnel(t, ctx, policyAny(token), registry, newTestTunnelIdentity(t))

		conn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.NoError(t, writeHandshake(conn, &TunnelHandshake{Token: token, SpotID: "legacy", Ports: []int{22}}))
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := readHandshakeResponse(conn)
		require.NoError(t, err)
		require.True(t, resp.OK, "error: %s", resp.Error)

		assert.True(t, bytes.Contains(ln.captured(), []byte(token)), "the cleartext variant must expose the token to the same capture")
	})
}

// TestHandshakeV2ProofRejectsWrongToken: a client holding the sentinel's
// pin but a token the policy does not know is rejected and nothing
// registers.
func TestHandshakeV2ProofRejectsWrongToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := newTestTunnelIdentity(t)
	registry := NewTunnelRegistry()
	ts, _, addr := serveV2Tunnel(t, ctx, policyAny("right-token"), registry, id)
	var connects atomic.Int32
	ts.OnConnect = func(*TunnelSpot) { connects.Add(1) }

	client := &TunnelClient{
		SentinelAddr: addr,
		SentinelPins: []TunnelPin{id.Pin()},
		Token:        "wrong-token",
		SpotID:       "wrong-spot",
		Ports:        []int{22},
	}
	err := client.connectAndServe(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "handshake rejected")
	assert.Zero(t, registry.Count())
	assert.Zero(t, connects.Load())
}

// TestHandshakeV2ProofReplayAcrossSessionsRejected: the proof is bound to
// the TLS session it was computed in. The handshake line captured from a
// successful session, presented verbatim in a second session, is rejected.
func TestHandshakeV2ProofReplayAcrossSessionsRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stubLoopbackAliases(t)
	const token = "replay-token"
	id := newTestTunnelIdentity(t)
	registry := NewTunnelRegistry()
	_, _, addr := serveV2Tunnel(t, ctx, policyAny(token), registry, id)

	// Session 1: a correct v2 handshake registers.
	first := dialTunnelTLS(t, addr, id)
	ekm1, err := tunnelTokenEKM(first.ConnectionState())
	require.NoError(t, err)
	client := &TunnelClient{Token: token, SpotID: "replay-spot", Ports: []int{22}}
	hs := client.handshakeV2(ekm1)
	require.Empty(t, hs.Token, "v2 handshake must not carry the token")
	require.NoError(t, writeHandshake(first, hs))
	resp, err := readHandshakeResponse(first)
	require.NoError(t, err)
	require.True(t, resp.OK, "error: %s", resp.Error)
	require.Equal(t, 1, registry.Count())

	// Session 2: the same token_id and proof, a fresh TLS session.
	second := dialTunnelTLS(t, addr, id)
	ekm2, err := tunnelTokenEKM(second.ConnectionState())
	require.NoError(t, err)
	require.NotEqual(t, ekm1, ekm2, "each session must export distinct keying material")
	require.NoError(t, writeHandshake(second, hs))
	resp, err = readHandshakeResponse(second)
	require.NoError(t, err)
	assert.False(t, resp.OK, "a proof from another session must be rejected")
	assert.Contains(t, resp.Error, "proof")
	assert.Equal(t, 1, registry.Count(), "only the first session is registered")
}

// TestHandshakeV1InsideTLSRejected: the v1 handshake shape (a raw token
// field) is not accepted inside a TLS session.
func TestHandshakeV1InsideTLSRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const token = "v1-token"
	id := newTestTunnelIdentity(t)
	registry := NewTunnelRegistry()
	ts, _, addr := serveV2Tunnel(t, ctx, policyAny(token), registry, id)
	var connects atomic.Int32
	ts.OnConnect = func(*TunnelSpot) { connects.Add(1) }

	conn := dialTunnelTLS(t, addr, id)
	require.NoError(t, writeHandshake(conn, &TunnelHandshake{Token: token, SpotID: "v1-spot", Ports: []int{22}}))
	resp, err := readHandshakeResponse(conn)
	require.NoError(t, err)
	assert.False(t, resp.OK)
	assert.Contains(t, resp.Error, "v2")
	assert.Zero(t, registry.Count())
	assert.Zero(t, connects.Load())
}

// TestHandshakeV2OnCleartextRejected: a v2 handshake has no session to bind
// its proof to outside TLS, so the cleartext path does not accept it.
func TestHandshakeV2OnCleartextRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const token = "v2-clear-token"
	registry := NewTunnelRegistry()
	_, _, addr := serveV2Tunnel(t, ctx, policyAny(token), registry, newTestTunnelIdentity(t))

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	client := &TunnelClient{Token: token, SpotID: "v2-clear", Ports: []int{22}}
	require.NoError(t, writeHandshake(conn, client.handshakeV2(bytes.Repeat([]byte{7}, tunnelTokenProofLen))))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := readHandshakeResponse(conn)
	require.NoError(t, err)
	assert.False(t, resp.OK)
	assert.Zero(t, registry.Count())
}

// TestTunnelTokenIDAndProof pins the derivations the two sides must agree
// on: token_id is the first 16 hex characters of SHA-256(token); proof is
// base64 of HMAC-SHA256 keyed by the token over the exported keying
// material.
func TestTunnelTokenIDAndProof(t *testing.T) {
	sum := sha256.Sum256([]byte("abc"))
	assert.Equal(t, hex.EncodeToString(sum[:])[:16], tunnelTokenID("abc"))
	assert.Equal(t, "ba7816bf8f01cfea", tunnelTokenID("abc"))
	assert.Len(t, tunnelTokenID("another"), tunnelTokenIDLen)

	ekm := bytes.Repeat([]byte{0x42}, tunnelTokenProofLen)
	mac := hmac.New(sha256.New, []byte("abc"))
	mac.Write(ekm)
	assert.Equal(t, base64.StdEncoding.EncodeToString(mac.Sum(nil)), tunnelTokenProof("abc", ekm))
	assert.NotEqual(t, tunnelTokenProof("abc", ekm), tunnelTokenProof("abd", ekm))
	assert.NotEqual(t, tunnelTokenProof("abc", ekm), tunnelTokenProof("abc", append([]byte{1}, ekm[1:]...)))
}

// TestTunnelTokenEKMMatchesAcrossPeers: both ends of one TLS 1.3 session
// export the same 32 bytes, and another session exports different ones.
func TestTunnelTokenEKMMatchesAcrossPeers(t *testing.T) {
	id := newTestTunnelIdentity(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tunnelTLSServerConfig(id))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	serverEKM := make(chan []byte, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				return
			}
			ekm, _ := tunnelTokenEKM(tc.ConnectionState())
			serverEKM <- ekm
			_ = tc.Close()
		}
	}()

	var client []byte
	for i := 0; i < 2; i++ {
		conn := dialTunnelTLS(t, ln.Addr().String(), id)
		got, err := tunnelTokenEKM(conn.ConnectionState())
		require.NoError(t, err)
		require.Len(t, got, tunnelTokenProofLen)
		select {
		case srv := <-serverEKM:
			assert.Equal(t, srv, got, "both peers must derive the same keying material")
		case <-time.After(3 * time.Second):
			t.Fatal("timeout waiting for the server's keying material")
		}
		if i == 1 {
			assert.NotEqual(t, client, got, "a new session must export new keying material")
		}
		client = got
	}
}

// TestTokenPolicyIDIndex: the policy resolves a token_id to the token it
// was derived from, and Deny/DenyPrefix/re-Allow keep the index in step
// with the rules.
func TestTokenPolicyIDIndex(t *testing.T) {
	ekm := bytes.Repeat([]byte{9}, tunnelTokenProofLen)
	proofFor := func(token string) string { return tunnelTokenProof(token, ekm) }

	tp := NewTokenPolicy()
	tp.Allow("host-a.secret", "lab")
	tp.Allow("host-b.secret", PoolAny)

	assert.NoError(t, tp.ValidateProof(tunnelTokenID("host-a.secret"), proofFor("host-a.secret"), ekm, "lab"))
	assert.Error(t, tp.ValidateProof(tunnelTokenID("host-a.secret"), proofFor("host-a.secret"), ekm, "prod"), "pool rules still apply")
	assert.NoError(t, tp.ValidateProof(tunnelTokenID("host-b.secret"), proofFor("host-b.secret"), ekm, "prod"))
	assert.Error(t, tp.ValidateProof(tunnelTokenID("host-a.secret"), proofFor("host-b.secret"), ekm, "lab"), "proof must match the token behind the id")
	assert.Error(t, tp.ValidateProof(tunnelTokenID("unknown"), proofFor("unknown"), ekm, "lab"))
	assert.Error(t, tp.ValidateProof(tunnelTokenID("host-a.secret"), "not base64!", ekm, "lab"))

	tp.Deny("host-a.secret")
	assert.Error(t, tp.ValidateProof(tunnelTokenID("host-a.secret"), proofFor("host-a.secret"), ekm, "lab"), "denied token must not resolve by id")
	assert.NoError(t, tp.ValidateProof(tunnelTokenID("host-b.secret"), proofFor("host-b.secret"), ekm, "lab"))

	tp.DenyPrefix("host-b.")
	assert.Error(t, tp.ValidateProof(tunnelTokenID("host-b.secret"), proofFor("host-b.secret"), ekm, "lab"))

	tp.Allow("host-a.secret", "lab")
	tp.Allow("host-a.secret", "prod")
	assert.NoError(t, tp.ValidateProof(tunnelTokenID("host-a.secret"), proofFor("host-a.secret"), ekm, "prod"), "re-Allow replaces the rule")
	assert.Error(t, tp.ValidateProof(tunnelTokenID("host-a.secret"), proofFor("host-a.secret"), ekm, "lab"))

	var nilPolicy *TokenPolicy
	assert.Error(t, validateHandshakeV2(&TunnelHandshake{V: tunnelHandshakeV2, TokenID: "x", Proof: "y", SpotID: "s", Ports: []int{1}}, nilPolicy, ekm))
}

// TestValidateHandshakeV2 is the table of v2 shape checks run inside TLS.
func TestValidateHandshakeV2(t *testing.T) {
	const token = "v2-table-token"
	ekm := bytes.Repeat([]byte{3}, tunnelTokenProofLen)
	good := func() *TunnelHandshake {
		return (&TunnelClient{Token: token, SpotID: "spot-1", Ports: []int{80}, Pool: "lab"}).handshakeV2(ekm)
	}
	tests := []struct {
		name    string
		mutate  func(*TunnelHandshake)
		wantErr string
	}{
		{name: "valid", mutate: func(*TunnelHandshake) {}},
		{name: "v1 shape", mutate: func(h *TunnelHandshake) { h.V = 0; h.TokenID = ""; h.Proof = ""; h.Token = token }, wantErr: "v2"},
		{name: "token field present", mutate: func(h *TunnelHandshake) { h.Token = token }, wantErr: "token"},
		{name: "missing token_id", mutate: func(h *TunnelHandshake) { h.TokenID = "" }, wantErr: "token_id"},
		{name: "missing proof", mutate: func(h *TunnelHandshake) { h.Proof = "" }, wantErr: "proof"},
		{name: "unknown token_id", mutate: func(h *TunnelHandshake) { h.TokenID = tunnelTokenID("other") }, wantErr: "invalid token"},
		{name: "proof for another session", mutate: func(h *TunnelHandshake) {
			h.Proof = tunnelTokenProof(token, bytes.Repeat([]byte{4}, tunnelTokenProofLen))
		}, wantErr: "proof"},
		{name: "wrong pool", mutate: func(h *TunnelHandshake) { h.Pool = "prod" }, wantErr: "pool"},
		{name: "missing spot id", mutate: func(h *TunnelHandshake) { h.SpotID = "" }, wantErr: "spot_id"},
		{name: "no ports", mutate: func(h *TunnelHandshake) { h.Ports = nil }, wantErr: "port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := NewTokenPolicy()
			policy.Allow(token, "lab")
			hs := good()
			tt.mutate(hs)
			err := validateHandshakeV2(hs, policy, ekm)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestValidateHandshakeV1RejectsV2Shape: the cleartext validator does not
// accept a v2 handshake, which it has no session to check against.
func TestValidateHandshakeV1RejectsV2Shape(t *testing.T) {
	policy := policyAny("tok")
	hs := (&TunnelClient{Token: "tok", SpotID: "s", Ports: []int{22}}).handshakeV2(bytes.Repeat([]byte{1}, tunnelTokenProofLen))
	err := validateHandshake(hs, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls")
}
