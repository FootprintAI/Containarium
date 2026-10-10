package sentinel

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Handshake v2 is the shape a tunnel client sends inside a TLS session. It
// carries no token. Instead it names the token by a short id and proves
// possession of it with an HMAC over keying material exported from the
// TLS session (RFC 8446 §7.5), so the proof is only meaningful to the two
// ends of that one session.
const (
	tunnelHandshakeV2     = 2
	tunnelTokenIDLen      = 16
	tunnelTokenProofLabel = "containarium-tunnel-token-proof/1" // #nosec G101 -- a keying-material export label, not a credential value
	tunnelTokenProofLen   = 32
)

// tunnelTokenID is the public name of a token: the first 16 hex characters
// of its SHA-256. It lets the policy find the token without the client
// sending it.
func tunnelTokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:tunnelTokenIDLen]
}

// tunnelTokenProof is base64(HMAC-SHA256(key = token, msg = ekm)).
func tunnelTokenProof(token string, ekm []byte) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(ekm)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// tunnelTokenEKM exports the per-session keying material both peers derive
// from the same TLS session, which the proof is computed over.
func tunnelTokenEKM(cs tls.ConnectionState) ([]byte, error) {
	ekm, err := cs.ExportKeyingMaterial(tunnelTokenProofLabel, nil, tunnelTokenProofLen)
	if err != nil {
		return nil, fmt.Errorf("export tunnel keying material: %w", err)
	}
	return ekm, nil
}

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
	// byID indexes rules by tunnelTokenID so a v2 handshake, which names
	// the token by id only, resolves to the token(s) to check its proof
	// against. Normally one token per id.
	byID map[string][]string
}

// NewTokenPolicy returns an empty policy. With no entries, every handshake
// is rejected — Allow at least one token before serving traffic.
func NewTokenPolicy() *TokenPolicy {
	return &TokenPolicy{rules: make(map[string][]Pool), byID: make(map[string][]string)}
}

// indexLocked adds token to the id index; the caller holds mu.
func (tp *TokenPolicy) indexLocked(token string) {
	id := tunnelTokenID(token)
	for _, t := range tp.byID[id] {
		if t == token {
			return
		}
	}
	tp.byID[id] = append(tp.byID[id], token)
}

// unindexLocked removes token from the id index; the caller holds mu.
func (tp *TokenPolicy) unindexLocked(token string) {
	id := tunnelTokenID(token)
	kept := tp.byID[id][:0]
	for _, t := range tp.byID[id] {
		if t != token {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(tp.byID, id)
		return
	}
	tp.byID[id] = kept
}

// Allow registers a token authorized for the given pools. Pass PoolAny
// as a single entry to permit any pool (legacy single-token behavior).
// Repeated calls for the same token replace the previous rule.
func (tp *TokenPolicy) Allow(token string, pools ...Pool) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.rules[token] = pools
	tp.indexLocked(token)
}

// Deny removes token's rule, so a future handshake presenting it is
// rejected exactly as if it had never been registered. A token that was
// never Allow'd is a no-op, not an error — a decommission caller cannot
// know in advance whether registration ever landed, and the end state is
// identical either way.
func (tp *TokenPolicy) Deny(token string) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	delete(tp.rules, token)
	tp.unindexLocked(token)
}

// DenyPrefix removes every rule whose token starts with prefix — the
// host-id-prefix sibling of Deny (#1963). Registered tokens are shaped
// "<host-id>.<secret>"; a registrar that mints a join token and (correctly)
// discards the plaintext afterwards has no token to pass to Deny when the
// host is decommissioned, but it does know the host id, so it can revoke
// every rule under that host — the original join token and any reissued
// reconnect token alike — in one call. prefix is matched literally via
// strings.HasPrefix; callers are expected to pass the full "<host-id>."
// literal (dot included) so "abc" cannot accidentally match "abcd.xyz". A
// prefix matching nothing is a no-op, not an error, for the same reason
// Deny's no-match case is a no-op.
func (tp *TokenPolicy) DenyPrefix(prefix string) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	for token := range tp.rules {
		if strings.HasPrefix(token, prefix) {
			delete(tp.rules, token)
			tp.unindexLocked(token)
		}
	}
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

// ValidateProof is the v2 counterpart of Validate: it resolves tokenID to
// the registered token(s), checks that proof is the HMAC of this session's
// keying material under one of them, and then applies the same pool rule
// as Validate. Comparison is constant-time. A nil policy rejects.
func (tp *TokenPolicy) ValidateProof(tokenID, proof string, ekm []byte, pool Pool) error {
	if tp == nil {
		return fmt.Errorf("no token policy configured")
	}
	got, err := base64.StdEncoding.DecodeString(proof)
	if err != nil {
		return fmt.Errorf("invalid proof encoding")
	}
	tp.mu.RLock()
	candidates := append([]string(nil), tp.byID[tokenID]...)
	tp.mu.RUnlock()
	if len(candidates) == 0 {
		return fmt.Errorf("invalid token")
	}
	for _, token := range candidates {
		mac := hmac.New(sha256.New, []byte(token))
		mac.Write(ekm)
		if subtle.ConstantTimeCompare(mac.Sum(nil), got) == 1 {
			return tp.Validate(token, pool)
		}
	}
	return fmt.Errorf("invalid token proof")
}

// TunnelHandshake is sent by the spot (tunnel client) to the sentinel (tunnel server)
// immediately after the TCP connection is established.
type TunnelHandshake struct {
	// V is the handshake version: absent (0) for the legacy cleartext
	// shape that carries Token, tunnelHandshakeV2 for the shape sent
	// inside TLS that carries TokenID and Proof instead.
	V int `json:"v,omitempty"`
	// Token is the legacy credential field, accepted only on the cleartext
	// path. A v2 handshake leaves it empty.
	Token string `json:"token,omitempty"`
	// TokenID names the token (tunnelTokenID) and Proof demonstrates
	// possession of it for this TLS session (tunnelTokenProof).
	TokenID string `json:"token_id,omitempty"`
	Proof   string `json:"proof,omitempty"`
	SpotID  string `json:"spot_id"`
	Ports   []int  `json:"ports"`
	Pool    Pool   `json:"pool,omitempty"`

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

// validateHandshakeFields checks the fields every handshake version
// shares.
func validateHandshakeFields(hs *TunnelHandshake) error {
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
	return nil
}

// validateHandshake is the legacy (cleartext) validator: required fields,
// then the policy's answer for the presented token and pool. A v2
// handshake is not accepted here — its proof is bound to a TLS session
// this path does not have.
func validateHandshake(hs *TunnelHandshake, policy *TokenPolicy) error {
	if err := validateHandshakeFields(hs); err != nil {
		return err
	}
	if hs.V >= tunnelHandshakeV2 {
		return fmt.Errorf("handshake v%d is only accepted over tls", hs.V)
	}
	if policy == nil {
		return fmt.Errorf("no token policy configured")
	}
	return policy.Validate(hs.Token, hs.Pool)
}

// validateHandshakeV2 is the validator for handshakes read inside a TLS
// session: the v2 shape is required (no token field; token_id and proof
// present), and the proof must match ekm, the keying material this end
// exported from the same session.
func validateHandshakeV2(hs *TunnelHandshake, policy *TokenPolicy, ekm []byte) error {
	if err := validateHandshakeFields(hs); err != nil {
		return err
	}
	if hs.V != tunnelHandshakeV2 {
		return fmt.Errorf("handshake v%d is required inside tls, got v%d", tunnelHandshakeV2, hs.V)
	}
	if hs.Token != "" {
		return fmt.Errorf("token field is not accepted inside tls; send token_id and proof")
	}
	if hs.TokenID == "" {
		return fmt.Errorf("token_id is required")
	}
	if hs.Proof == "" {
		return fmt.Errorf("proof is required")
	}
	if len(ekm) != tunnelTokenProofLen {
		return fmt.Errorf("no session keying material to check the proof against")
	}
	return policy.ValidateProof(hs.TokenID, hs.Proof, ekm, hs.Pool)
}
