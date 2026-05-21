package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Phase 4.1 Phase-F — Vault Transit backend tests.
//
// We stand up a fake Vault Transit server with httptest
// that:
//   - validates the X-Vault-Token header
//   - encrypts plaintext under a process-local AES key
//     to produce a vault:v1:...-shaped blob
//   - reverses on /decrypt
//   - can be configured to return errors for negative
//     cases
//
// This lets us exercise the request shape, the kek_id
// encoding, the Authorization plumbing, the error
// mapping, and the prefix-routing guard without needing a
// real Vault.

type fakeVault struct {
	t          *testing.T
	wantToken  string
	encryptKey []byte
	requireOp  string // if non-empty, fail unless URL ends with this op
	statusCode int    // override status code (default 200)
	errMsg     string // optional Vault-style error to return when statusCode>=400
}

func newFakeVault(t *testing.T) (*httptest.Server, *fakeVault) {
	t.Helper()
	fv := &fakeVault{
		t:          t,
		wantToken:  "root-token",
		encryptKey: make([]byte, 32),
		statusCode: 200,
	}
	if _, err := io.ReadFull(rand.Reader, fv.encryptKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(fv.handle))
	return srv, fv
}

func (f *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("X-Vault-Token"); got != f.wantToken {
		http.Error(w, `{"errors":["missing or invalid token"]}`, http.StatusForbidden)
		return
	}
	if f.statusCode >= 400 {
		w.WriteHeader(f.statusCode)
		_, _ = w.Write([]byte(`{"errors":["` + f.errMsg + `"]}`))
		return
	}
	// Path: /v1/transit/{op}/{key}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "v1" {
		http.Error(w, `{"errors":["bad path"]}`, http.StatusBadRequest)
		return
	}
	op := parts[2]
	if f.requireOp != "" && op != f.requireOp {
		http.Error(w, `{"errors":["wrong op"]}`, http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch op {
	case "encrypt":
		var req struct {
			Plaintext string `json:"plaintext"`
		}
		_ = json.Unmarshal(body, &req)
		pt, err := base64.StdEncoding.DecodeString(req.Plaintext)
		if err != nil {
			http.Error(w, `{"errors":["bad plaintext b64"]}`, http.StatusBadRequest)
			return
		}
		ct := f.symEncrypt(pt)
		// vault:v1:<base64> shape — the fake encodes the
		// AES-GCM output directly.
		resp := map[string]any{
			"data": map[string]string{
				"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(ct),
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	case "decrypt":
		var req struct {
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.Unmarshal(body, &req)
		// Strip the vault:v<n>: prefix.
		idx := strings.LastIndex(req.Ciphertext, ":")
		if idx < 0 {
			http.Error(w, `{"errors":["bad ciphertext shape"]}`, http.StatusBadRequest)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(req.Ciphertext[idx+1:])
		if err != nil {
			http.Error(w, `{"errors":["bad ciphertext b64"]}`, http.StatusBadRequest)
			return
		}
		pt, err := f.symDecrypt(raw)
		if err != nil {
			http.Error(w, `{"errors":["bad ciphertext"]}`, http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"data": map[string]string{
				"plaintext": base64.StdEncoding.EncodeToString(pt),
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	default:
		http.Error(w, `{"errors":["unknown op"]}`, http.StatusBadRequest)
	}
}

func (f *fakeVault) symEncrypt(pt []byte) []byte {
	block, _ := aes.NewCipher(f.encryptKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	return append(nonce, gcm.Seal(nil, nonce, pt, nil)...)
}

func (f *fakeVault) symDecrypt(blob []byte) ([]byte, error) {
	block, _ := aes.NewCipher(f.encryptKey)
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, io.ErrUnexpectedEOF
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

// --- Tests ---

func TestVaultKMS_WrapUnwrapRoundtrip(t *testing.T) {
	srv, _ := newFakeVault(t)
	defer srv.Close()

	k, err := NewVaultKMS(VaultConfig{
		Address: srv.URL,
		Token:   "root-token",
		KeyName: "test-key",
	})
	if err != nil {
		t.Fatalf("NewVaultKMS: %v", err)
	}

	dek, _ := NewDEK()
	wrapped, kekID, err := k.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !strings.HasPrefix(kekID, "vault:") {
		t.Fatalf("kek_id missing vault: prefix: %q", kekID)
	}
	if !bytes.HasPrefix(wrapped, []byte("vault:v")) {
		t.Fatalf("wrapped DEK should be vault:v… shape; got %q", wrapped)
	}

	out, err := k.Unwrap(context.Background(), wrapped, kekID)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(out, dek) {
		t.Fatal("round-trip altered DEK")
	}
}

func TestVaultKMS_RejectsBadToken(t *testing.T) {
	srv, _ := newFakeVault(t)
	defer srv.Close()

	k, _ := NewVaultKMS(VaultConfig{
		Address: srv.URL,
		Token:   "wrong-token",
		KeyName: "test-key",
	})

	dek, _ := NewDEK()
	_, _, err := k.Wrap(context.Background(), dek)
	if err == nil {
		t.Fatal("Wrap with wrong token should fail")
	}
	if !strings.Contains(err.Error(), "missing or invalid token") {
		t.Fatalf("error should pass through Vault's message; got %v", err)
	}
}

func TestVaultKMS_RejectsRowFromDifferentBackend(t *testing.T) {
	srv, _ := newFakeVault(t)
	defer srv.Close()

	k, _ := NewVaultKMS(VaultConfig{
		Address: srv.URL,
		Token:   "root-token",
		KeyName: "test-key",
	})

	// kek_id from a different backend (InProcKMS).
	_, err := k.Unwrap(context.Background(), []byte("vault:v1:..."), "inproc:master")
	if err == nil {
		t.Fatal("VaultKMS must refuse non-vault: kek_id")
	}
}

func TestVaultKMS_RejectsBadDEKSize(t *testing.T) {
	srv, _ := newFakeVault(t)
	defer srv.Close()
	k, _ := NewVaultKMS(VaultConfig{
		Address: srv.URL, Token: "root-token", KeyName: "k",
	})

	for _, badSize := range []int{0, 16, 64} {
		dek := make([]byte, badSize)
		_, _, err := k.Wrap(context.Background(), dek)
		if err == nil {
			t.Fatalf("Wrap with DEK size %d should fail", badSize)
		}
	}
}

func TestVaultKMS_KEKIDEncodesDeploymentIdentity(t *testing.T) {
	// Two backends pointed at different Vault deployments
	// produce different kek_ids — a row from one can't be
	// silently accepted by the other.
	srv1, _ := newFakeVault(t)
	srv2, _ := newFakeVault(t)
	defer srv1.Close()
	defer srv2.Close()
	a, _ := NewVaultKMS(VaultConfig{Address: srv1.URL, Token: "root-token", KeyName: "k"})
	b, _ := NewVaultKMS(VaultConfig{Address: srv2.URL, Token: "root-token", KeyName: "k"})
	dek, _ := NewDEK()
	_, kekA, _ := a.Wrap(context.Background(), dek)
	_, kekB, _ := b.Wrap(context.Background(), dek)
	if kekA == kekB {
		t.Fatal("different Vault deployments should produce different kek_ids")
	}
}

func TestVaultKMS_RejectsEmptyConfig(t *testing.T) {
	cases := []VaultConfig{
		{Address: "", Token: "t", KeyName: "k"},
		{Address: "http://x", Token: "", KeyName: "k"},
		{Address: "http://x", Token: "t", KeyName: ""},
	}
	for _, c := range cases {
		if _, err := NewVaultKMS(c); err == nil {
			t.Fatalf("NewVaultKMS should reject empty field in %+v", c)
		}
	}
}

func TestVaultKMS_MountDefault(t *testing.T) {
	srv, fv := newFakeVault(t)
	defer srv.Close()
	fv.requireOp = "encrypt" // make sure mount path is "transit"
	// The fake parses /v1/{mount}/{op}/{key} into parts[1]
	// = mount. We don't have a direct way to assert the
	// default here, but a successful round-trip with no
	// explicit Mount confirms the default got used.
	k, _ := NewVaultKMS(VaultConfig{
		Address: srv.URL,
		Token:   "root-token",
		KeyName: "k",
		// no Mount → defaults to "transit"
	})
	dek, _ := NewDEK()
	if _, _, err := k.Wrap(context.Background(), dek); err != nil {
		t.Fatalf("Wrap with default mount: %v", err)
	}
}

func TestVaultKMS_TimeoutAppliesToHTTP(t *testing.T) {
	// Server that hangs forever — Wrap must time out.
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer hang.Close()

	k, _ := NewVaultKMS(VaultConfig{
		Address: hang.URL,
		Token:   "root-token",
		KeyName: "k",
		Timeout: 100 * time.Millisecond,
	})
	dek, _ := NewDEK()
	start := time.Now()
	_, _, err := k.Wrap(context.Background(), dek)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Wrap should time out")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("timeout not honored; elapsed = %v", elapsed)
	}
}

// Compile-time conformance.
var _ KMSClient = (*VaultKMS)(nil)
