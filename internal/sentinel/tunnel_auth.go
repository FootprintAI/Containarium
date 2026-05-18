package sentinel

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// TokenPolicy maps tunnel tokens to the set of pools each token is allowed
// to join. Used by validateHandshake to reject pool spoofing — a token
// restricted to "lab" cannot register a tunnel claiming pool="prod".
//
// Special pool values:
//
//	"*" — matches any pool (including the empty/unpooled case). Used for
//	      legacy single-token deployments where pool isn't a security
//	      boundary.
//	""  — matches the unpooled/legacy backend explicitly.
type TokenPolicy struct {
	mu    sync.RWMutex
	rules map[string][]Pool
}

// NewTokenPolicy returns an empty policy. With no entries, every handshake
// is rejected — Allow at least one token before serving traffic.
func NewTokenPolicy() *TokenPolicy {
	return &TokenPolicy{rules: make(map[string][]Pool)}
}

// Allow registers a token authorized for the given pools. Pass PoolAny
// as a single entry to permit any pool (legacy single-token behavior).
// Repeated calls for the same token replace the previous rule.
func (tp *TokenPolicy) Allow(token string, pools ...Pool) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.rules[token] = pools
}

// PolicyFromCLI builds a TokenPolicy from a single back-compat token (any
// pool allowed) plus a list of "token=pool1,pool2,…" specs. Either may be
// empty. Returns an error if any spec is malformed. The returned policy is
// nil-safe but rejects all handshakes if no rules are added.
func PolicyFromCLI(legacyToken string, specs []string) (*TokenPolicy, error) {
	policy := NewTokenPolicy()
	if legacyToken != "" {
		policy.Allow(legacyToken, PoolAny)
	}
	for _, spec := range specs {
		eq := strings.Index(spec, "=")
		if eq <= 0 || eq == len(spec)-1 {
			return nil, fmt.Errorf("invalid token policy %q: expected token=pool1,pool2,…", spec)
		}
		token := spec[:eq]
		raw := spec[eq+1:]
		var pools []Pool
		for _, p := range strings.Split(raw, ",") {
			pools = append(pools, Pool(p))
		}
		policy.Allow(token, pools...)
	}
	return policy, nil
}

// Validate returns nil if the token is registered and the pool is one of
// its allowed pools. Returns an error otherwise.
func (tp *TokenPolicy) Validate(token string, pool Pool) error {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	pools, ok := tp.rules[token]
	if !ok {
		return fmt.Errorf("invalid token")
	}
	for _, p := range pools {
		if p == PoolAny || p == pool {
			return nil
		}
	}
	return fmt.Errorf("token not authorized for pool %q", pool)
}

// TunnelHandshake is sent by the spot (tunnel client) to the sentinel (tunnel server)
// immediately after the TCP connection is established.
type TunnelHandshake struct {
	Token  string `json:"token"`
	SpotID string `json:"spot_id"`
	Ports  []int  `json:"ports"`
	Pool   Pool   `json:"pool,omitempty"`

	// Optional primary registration (slice 6). When PublicHostname is set,
	// the sentinel auto-registers this tunnel as the primary for its pool,
	// pointing at the tunnel's loopback alias on the sentinel side. This
	// avoids the daemon needing direct HTTP access to /sentinel/primaries
	// from networks that can only reach the sentinel via the tunnel.
	PublicHostname    string   `json:"public_hostname,omitempty"`
	PublicAliases     []string `json:"public_aliases,omitempty"`
	PublicBaseDomains []string `json:"public_base_domains,omitempty"`
	PublicPort        int      `json:"public_port,omitempty"`
}

// TunnelHandshakeResponse is sent by the sentinel back to the spot after
// validating the handshake.
type TunnelHandshakeResponse struct {
	OK         bool   `json:"ok"`
	AssignedIP string `json:"assigned_ip,omitempty"`
	Error      string `json:"error,omitempty"`
}

// maxHandshakeBytes caps how much we'll read for a single handshake line.
// 4 KB is generous — handshake JSON is typically <300 bytes.
const maxHandshakeBytes = 4096

// readHandshakeLine reads exactly one newline-terminated JSON line from r,
// without buffering bytes that come after the newline.
//
// We deliberately avoid json.Decoder here. Its internal buffer can swallow
// bytes that arrive in the same TCP packet as the JSON (e.g., the yamux
// SYN frame the sentinel writes immediately after the handshake response).
// Those buffered bytes are unreachable once we discard the decoder, and
// yamux on the other side then misaligns its frame reader, producing
// "Invalid protocol version: <random byte>" errors.
//
// json.NewEncoder(w).Encode() writes JSON terminated by '\n', so reading
// up to '\n' gives us exactly one record with no over-read.
func readHandshakeLine(r io.Reader, out interface{}) error {
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if err != nil {
			return fmt.Errorf("read handshake: %w", err)
		}
		if n == 0 {
			continue
		}
		if one[0] == '\n' {
			break
		}
		buf = append(buf, one[0])
		if len(buf) > maxHandshakeBytes {
			return fmt.Errorf("handshake exceeded %d bytes", maxHandshakeBytes)
		}
	}
	if err := json.Unmarshal(buf, out); err != nil {
		return fmt.Errorf("decode handshake: %w", err)
	}
	return nil
}

// readHandshake reads and decodes a TunnelHandshake from the connection.
func readHandshake(r io.Reader) (*TunnelHandshake, error) {
	var hs TunnelHandshake
	if err := readHandshakeLine(r, &hs); err != nil {
		return nil, err
	}
	return &hs, nil
}

// writeHandshake encodes and writes a TunnelHandshake to the connection.
func writeHandshake(w io.Writer, hs *TunnelHandshake) error {
	return json.NewEncoder(w).Encode(hs)
}

// readHandshakeResponse reads and decodes a TunnelHandshakeResponse.
func readHandshakeResponse(r io.Reader) (*TunnelHandshakeResponse, error) {
	var resp TunnelHandshakeResponse
	if err := readHandshakeLine(r, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// writeHandshakeResponse encodes and writes a TunnelHandshakeResponse.
func writeHandshakeResponse(w io.Writer, resp *TunnelHandshakeResponse) error {
	return json.NewEncoder(w).Encode(resp)
}

// validateHandshake checks required fields, then asks the policy whether
// the presented token is authorized for the claimed pool.
func validateHandshake(hs *TunnelHandshake, policy *TokenPolicy) error {
	if hs.SpotID == "" {
		return fmt.Errorf("spot_id is required")
	}
	if len(hs.Ports) == 0 {
		return fmt.Errorf("at least one port is required")
	}
	if hs.PublicHostname != "" {
		if hs.PublicPort == 0 {
			return fmt.Errorf("public_port is required when public_hostname is set")
		}
		if hs.Pool == "" {
			return fmt.Errorf("pool is required when public_hostname is set")
		}
	}
	if policy == nil {
		return fmt.Errorf("no token policy configured")
	}
	return policy.Validate(hs.Token, hs.Pool)
}
