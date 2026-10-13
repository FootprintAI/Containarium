package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- #2402: KMSClient as the backup key wrapper ---
//
// Two contract changes the managed-backup design relies on:
//
//  1. kek_id from the GCP backend is the CryptoKeyVersion resource name the
//     Encrypt response carries, not the CryptoKey the client was configured
//     with — so destruction of a key version can be guarded by "are there
//     backups wrapped under it".
//  2. Wrap accepts a small secret of any length (an age identity string is
//     ~74 bytes), not only a 32-byte DEK.

// recordedEncryptResponse is the shape Cloud KMS actually returns from
// cryptoKeys.encrypt: the `name` is the key VERSION used.
const recordedKeyVersion = testKeyName + "/cryptoKeyVersions/7"

// recordedGCPKMS serves one recorded :encrypt response and a :decrypt that
// echoes back whatever was last encrypted. It also records every request
// path so the test can assert which resource the client addressed.
func recordedGCPKMS(t *testing.T, encryptName string) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	var lastPlaintext string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, ":encrypt"):
			var req struct {
				Plaintext string `json:"plaintext"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			lastPlaintext = req.Plaintext
			resp := map[string]any{
				"ciphertext":       "CiQAZ3ZmV2hhdGV2ZXIgY2lwaGVydGV4dCBieXRlcyBoZXJlEkQAbWFkZQ==",
				"ciphertextCrc32c": "3522255473",
				"protectionLevel":  "SOFTWARE",
			}
			if encryptName != "" {
				resp["name"] = encryptName
			}
			_ = json.NewEncoder(w).Encode(resp)
		case strings.HasSuffix(r.URL.Path, ":decrypt"):
			_ = json.NewEncoder(w).Encode(map[string]any{"plaintext": lastPlaintext, "plaintextCrc32c": "0"})
		default:
			http.Error(w, `{"error":{"message":"unknown op"}}`, http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

func TestKMSClientGCP_KekIDIsVersionName(t *testing.T) {
	srv, paths := recordedGCPKMS(t, recordedKeyVersion)
	k, err := NewGCPKMS(GCPConfig{KeyName: testKeyName, Token: "tok", Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE")
	wrapped, kekID, err := k.Wrap(context.Background(), secret)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if want := GCPKEKPrefix + recordedKeyVersion; kekID != want {
		t.Fatalf("kek_id = %q, want the CryptoKeyVersion the response named, %q", kekID, want)
	}
	// Encrypt is addressed to the CryptoKey (the primary version is the
	// server's choice); the version comes back, it is never sent.
	if (*paths)[0] != "/v1/"+testKeyName+":encrypt" {
		t.Errorf("encrypt path = %q", (*paths)[0])
	}

	// A version-name kek_id still unwraps: decrypt is addressed to the
	// CryptoKey, and Cloud KMS picks the version from the ciphertext.
	pt, err := k.Unwrap(context.Background(), wrapped, kekID)
	if err != nil {
		t.Fatalf("Unwrap with a version-name kek_id: %v", err)
	}
	if !bytes.Equal(pt, secret) {
		t.Errorf("Unwrap = %q, want the wrapped secret", pt)
	}
	if (*paths)[1] != "/v1/"+testKeyName+":decrypt" {
		t.Errorf("decrypt path = %q, want the CryptoKey, not the version", (*paths)[1])
	}
}

// Without a version name there is no way to honour the contract; a
// backend that answers without one is refused rather than recorded as
// "some version of this key".
func TestKMSClientGCP_WrapRefusesResponseWithoutVersionName(t *testing.T) {
	srv, _ := recordedGCPKMS(t, "")
	k, err := NewGCPKMS(GCPConfig{KeyName: testKeyName, Token: "tok", Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Wrap(context.Background(), []byte("secret")); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("Wrap = %v, want a refusal naming the missing key version", err)
	}
}

func TestGCPCryptoKeyFromKEKID(t *testing.T) {
	for _, tc := range []struct {
		kekID string
		want  string
		ok    bool
	}{
		{GCPKEKPrefix + recordedKeyVersion, testKeyName, true},
		{GCPKEKPrefix + testKeyName, testKeyName, true}, // rows written before #2402
		{"inproc:master", "", false},
		{"vault:" + testKeyName, "", false},
		{"", "", false},
	} {
		got, ok := GCPCryptoKeyFromKEKID(tc.kekID)
		if got != tc.want || ok != tc.ok {
			t.Errorf("GCPCryptoKeyFromKEKID(%q) = (%q, %v), want (%q, %v)", tc.kekID, got, ok, tc.want, tc.ok)
		}
	}
}

// Wrap takes the backup identity string as-is (#2402): the cloud-side
// verifier and the host-less restore runbook both expect KMS decrypt of
// wrapped_key to yield the identity directly.
func TestKMSClient_WrapsAgeIdentityString(t *testing.T) {
	secret := []byte("AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE")
	if len(secret) == DEKSize {
		t.Fatal("test secret must not be DEK-sized, or the test proves nothing")
	}

	gcpSrv, _ := newFakeGCPKMS(t)
	defer gcpSrv.Close()
	gcp, err := NewGCPKMS(GCPConfig{KeyName: testKeyName, Token: "access-token-xyz", Endpoint: gcpSrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	inproc, err := NewInProcKMS(makeMasterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]KMSClient{"inproc": inproc, "gcp": gcp} {
		t.Run(name, func(t *testing.T) {
			wrapped, kekID, err := k.Wrap(context.Background(), secret)
			if err != nil {
				t.Fatalf("Wrap(%d-byte identity): %v", len(secret), err)
			}
			if bytes.Contains(wrapped, secret) {
				t.Fatal("wrapped bytes contain the secret in clear")
			}
			got, err := k.Unwrap(context.Background(), wrapped, kekID)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if !bytes.Equal(got, secret) {
				t.Errorf("round trip = %q, want %q", got, secret)
			}
		})
	}
}

// The size guard that remains: empty, and anything over the smallest
// backend limit (AWS KMS Encrypt: 4 KiB), so a value wrapped under one
// backend is portable to every other.
func TestKMSClient_RejectsEmptyAndOversizedPlaintext(t *testing.T) {
	gcpSrv, _ := newFakeGCPKMS(t)
	defer gcpSrv.Close()
	gcp, _ := NewGCPKMS(GCPConfig{KeyName: testKeyName, Token: "access-token-xyz", Endpoint: gcpSrv.URL})
	inproc, _ := NewInProcKMS(makeMasterKey(t))
	for name, k := range map[string]KMSClient{"inproc": inproc, "gcp": gcp} {
		for _, n := range []int{0, MaxWrapPlaintext + 1} {
			if _, _, err := k.Wrap(context.Background(), make([]byte, n)); err == nil {
				t.Errorf("%s: Wrap(%d bytes) succeeded, want a refusal", name, n)
			}
		}
		if _, _, err := k.Wrap(context.Background(), make([]byte, MaxWrapPlaintext)); err != nil {
			t.Errorf("%s: Wrap(%d bytes) = %v, want accepted at the limit", name, MaxWrapPlaintext, err)
		}
	}
}
