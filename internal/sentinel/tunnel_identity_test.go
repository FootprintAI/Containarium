package sentinel

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// certForKeyWithValidity builds a self-signed certificate over the identity's
// own key with the given validity window, to prove the pin verifier looks at
// the key only and never at the dates.
func certForKeyWithValidity(t *testing.T, id *TunnelIdentity, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      id.cert.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &id.key.PublicKey, id.key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

func TestTunnelIdentityPinRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnel-identity.pem")

	id, err := GenerateTunnelIdentity()
	if err != nil {
		t.Fatalf("GenerateTunnelIdentity: %v", err)
	}
	pin := id.Pin()
	if !strings.HasPrefix(string(pin), "sha256:") || len(pin) != len("sha256:")+64 {
		t.Fatalf("pin %q is not sha256:<64 hex>", pin)
	}
	if id.Pin() != pin {
		t.Fatalf("pin not stable across calls")
	}

	if err := id.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("identity file mode = %o, want 600", mode)
	}

	loaded, err := LoadTunnelIdentity(path)
	if err != nil {
		t.Fatalf("LoadTunnelIdentity: %v", err)
	}
	if loaded.Pin() != pin {
		t.Fatalf("pin after load = %q, want %q", loaded.Pin(), pin)
	}

	// The pin must be parseable by the client-side parser.
	parsed, err := ParsePins(string(pin))
	if err != nil {
		t.Fatalf("ParsePins(own pin): %v", err)
	}
	verify := VerifyPinned(parsed)

	t.Run("accepts matching SPKI", func(t *testing.T) {
		if err := verify(loaded.TLSCertificate().Certificate, nil); err != nil {
			t.Fatalf("verifier rejected matching identity: %v", err)
		}
	})

	t.Run("rejects different key with same subject", func(t *testing.T) {
		other, err := GenerateTunnelIdentity()
		if err != nil {
			t.Fatalf("GenerateTunnelIdentity: %v", err)
		}
		if other.cert.Subject.String() != id.cert.Subject.String() {
			t.Fatalf("test precondition: subjects differ (%q vs %q)", other.cert.Subject, id.cert.Subject)
		}
		if err := verify(other.TLSCertificate().Certificate, nil); err == nil {
			t.Fatalf("verifier accepted a different key with the same subject")
		}
	})

	t.Run("ignores validity dates", func(t *testing.T) {
		expired := certForKeyWithValidity(t, id, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
		if err := verify([][]byte{expired}, nil); err != nil {
			t.Fatalf("verifier rejected expired cert with pinned key: %v", err)
		}
		notYet := certForKeyWithValidity(t, id, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
		if err := verify([][]byte{notYet}, nil); err != nil {
			t.Fatalf("verifier rejected not-yet-valid cert with pinned key: %v", err)
		}
	})
}

func TestTunnelIdentitySaveTightensExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.pem")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil { //nolint:gosec // test fixture with deliberately loose mode
		t.Fatal(err)
	}
	id, err := GenerateTunnelIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %o, want 600", mode)
	}
}

func TestLoadOrGenerateTunnelIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "id.pem")

	first, generated, err := LoadOrGenerateTunnelIdentity(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !generated {
		t.Fatalf("first call should generate")
	}
	second, generated, err := LoadOrGenerateTunnelIdentity(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if generated {
		t.Fatalf("second call should load, not generate")
	}
	if first.Pin() != second.Pin() {
		t.Fatalf("pin changed across restarts: %q vs %q", first.Pin(), second.Pin())
	}

	// A present but corrupt file is an error, never silently replaced:
	// regenerating would invalidate every client's pin.
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerateTunnelIdentity(path); err == nil {
		t.Fatalf("corrupt identity file must not be silently regenerated")
	}
}

func TestLoadTunnelIdentityRejectsBadFiles(t *testing.T) {
	a, err := GenerateTunnelIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateTunnelIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aPEM, err := a.marshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	bPEM, err := b.marshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	const keyHeader = "-----BEGIN PRIVATE KEY-----"
	aCert := aPEM[:strings.Index(string(aPEM), keyHeader)]
	bKey := bPEM[strings.Index(string(bPEM), keyHeader):]

	cases := map[string][]byte{
		"empty":           nil,
		"garbage":         []byte("not a pem file"),
		"cert only":       aCert,
		"key only":        bKey,
		"mismatched pair": append(append([]byte{}, aCert...), bKey...),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "id.pem")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadTunnelIdentity(path); err == nil {
				t.Fatalf("LoadTunnelIdentity accepted %s", name)
			}
		})
	}

	if _, err := LoadTunnelIdentity(filepath.Join(t.TempDir(), "missing.pem")); !os.IsNotExist(err) {
		t.Fatalf("missing file: err = %v, want IsNotExist", err)
	}
}

func TestParsePins(t *testing.T) {
	h1 := strings.Repeat("ab", 32)
	h2 := strings.Repeat("0c", 32)
	p1 := TunnelPin("sha256:" + h1)
	p2 := TunnelPin("sha256:" + h2)
	tests := []struct {
		name    string
		in      string
		want    []TunnelPin
		wantErr bool
	}{
		{name: "single", in: string(p1), want: []TunnelPin{p1}},
		{name: "rotation overlap", in: string(p1) + "," + string(p2), want: []TunnelPin{p1, p2}},
		{name: "whitespace around entries", in: " " + string(p1) + " , " + string(p2) + " ", want: []TunnelPin{p1, p2}},
		{name: "uppercase hex normalised", in: "sha256:" + strings.ToUpper(h1), want: []TunnelPin{p1}},
		{name: "duplicates collapsed", in: string(p1) + "," + string(p1), want: []TunnelPin{p1}},
		{name: "empty", in: "", wantErr: true},
		{name: "only spaces", in: "   ", wantErr: true},
		{name: "empty entry", in: string(p1) + ",," + string(p2), wantErr: true},
		{name: "trailing comma", in: string(p1) + ",", wantErr: true},
		{name: "missing prefix", in: h1, wantErr: true},
		{name: "wrong algorithm", in: "sha1:" + h1, wantErr: true},
		{name: "short digest", in: "sha256:" + h1[:62], wantErr: true},
		{name: "long digest", in: "sha256:" + h1 + "00", wantErr: true},
		{name: "non-hex", in: "sha256:" + strings.Repeat("zz", 32), wantErr: true},
		{name: "one bad entry poisons the list", in: string(p1) + ",sha256:nope", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePins(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePins(%q) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePins(%q): %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParsePins(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParsePins(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestVerifyPinnedEdgeCases(t *testing.T) {
	id, err := GenerateTunnelIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateTunnelIdentity()
	if err != nil {
		t.Fatal(err)
	}
	leaf := id.TLSCertificate().Certificate

	if err := VerifyPinned(nil)(leaf, nil); err == nil {
		t.Fatalf("empty pin set must reject every peer")
	}
	if err := VerifyPinned([]TunnelPin{id.Pin()})(nil, nil); err == nil {
		t.Fatalf("no peer certificate must be rejected")
	}
	if err := VerifyPinned([]TunnelPin{id.Pin()})([][]byte{[]byte("junk")}, nil); err == nil {
		t.Fatalf("unparseable peer certificate must be rejected")
	}
	// Any pin in the list matches (rotation overlap).
	if err := VerifyPinned([]TunnelPin{other.Pin(), id.Pin()})(leaf, nil); err != nil {
		t.Fatalf("second pin in list should match: %v", err)
	}
	// Only the leaf is pinned: a pinned cert presented after an unpinned
	// leaf does not satisfy the pin.
	chain := [][]byte{other.TLSCertificate().Certificate[0], leaf[0]}
	if err := VerifyPinned([]TunnelPin{id.Pin()})(chain, nil); err == nil {
		t.Fatalf("pinned key in a non-leaf position must not satisfy the pin")
	}
}

// TestVerifyPinnedInTLSHandshake exercises the verifier as a
// tls.Config.VerifyPeerCertificate callback on a TLS 1.3 client.
func TestVerifyPinnedInTLSHandshake(t *testing.T) {
	id, err := GenerateTunnelIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateTunnelIdentity()
	if err != nil {
		t.Fatal(err)
	}

	handshake := func(t *testing.T, pins []TunnelPin) error {
		t.Helper()
		cConn, sConn := net.Pipe()
		defer func() { _ = cConn.Close() }()
		defer func() { _ = sConn.Close() }()
		srv := tls.Server(sConn, &tls.Config{
			Certificates: []tls.Certificate{id.TLSCertificate()},
			MinVersion:   tls.VersionTLS13,
		})
		go func() { _ = srv.Handshake(); _ = srv.Close() }()
		cli := tls.Client(cConn, &tls.Config{
			InsecureSkipVerify:    true, //nolint:gosec // test: chain verification is replaced by VerifyPinned
			VerifyPeerCertificate: VerifyPinned(pins),
			MinVersion:            tls.VersionTLS13,
		})
		_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
		return cli.Handshake()
	}

	if err := handshake(t, []TunnelPin{id.Pin()}); err != nil {
		t.Fatalf("handshake with matching pin failed: %v", err)
	}
	if err := handshake(t, []TunnelPin{other.Pin()}); err == nil {
		t.Fatalf("handshake with wrong pin succeeded")
	}
}
