package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestPinnedArtifacts is the golden pin: what a release ships into
// tenant clusters is reviewable as this one diff. Bumping k3s means
// changing BOTH constants and this test, on purpose.
func TestPinnedArtifacts(t *testing.T) {
	if K3sVersion != "v1.33.4+k3s1" {
		t.Fatalf("K3sVersion pin changed to %q — update the golden and re-verify the checksum against the upstream release", K3sVersion)
	}
	if K3sSHA256 != "10da34c350ab8a02e4513a6021046db9e9afecc31bae77419bc6444cbd7b1400" {
		t.Fatalf("K3sSHA256 pin changed — update the golden from the upstream sha256sum-amd64.txt")
	}
	// "+" is a legal literal in a URL path segment (only query strings
	// read it as a space), so PathEscape leaves it alone.
	if got := k3sDownloadURL(); got != "https://github.com/k3s-io/k3s/releases/download/v1.33.4+k3s1/k3s" {
		t.Fatalf("download URL = %q", got)
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	content := []byte("managed-cluster test artifact")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	if err := verifySHA256(path, want); err != nil {
		t.Fatalf("matching checksum rejected: %v", err)
	}
	if err := verifySHA256(path, "deadbeef"); err == nil {
		t.Fatal("wrong checksum accepted")
	}
	if err := verifySHA256(filepath.Join(dir, "missing"), want); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestFetchVerified(t *testing.T) {
	good := []byte("the pinned artifact bytes")
	sum := sha256.Sum256(good)
	goodSHA := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/good":
			_, _ = w.Write(good)
		case "/tampered":
			_, _ = w.Write([]byte("something else entirely"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()

	// Happy path: fetched, verified, executable, atomic.
	dst := filepath.Join(dir, "k3s")
	if err := fetchVerified(context.Background(), srv.URL+"/good", dst, goodSHA); err != nil {
		t.Fatalf("fetchVerified: %v", err)
	}
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat fetched artifact: %v", err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("fetched artifact mode = %v, want 0755", st.Mode().Perm())
	}

	// Tampered payload fails closed and leaves nothing at the target.
	dst2 := filepath.Join(dir, "k3s2")
	if err := fetchVerified(context.Background(), srv.URL+"/tampered", dst2, goodSHA); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	if _, err := os.Stat(dst2); !os.IsNotExist(err) {
		t.Fatalf("tampered fetch left a file behind: %v", err)
	}

	// HTTP error fails.
	if err := fetchVerified(context.Background(), srv.URL+"/missing", dst2, goodSHA); err == nil {
		t.Fatal("404 accepted")
	}
}
