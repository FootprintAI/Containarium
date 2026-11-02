package sentinel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// The checksum a daemon will trust before executing a download must carry the
// sentinel's signature.
func TestServedChecksum_IsSigned(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "containarium")
	if err := os.WriteFile(bin, []byte("binary-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := []byte(testPrimariesSecret)
	m := &Manager{
		backends: NewBackendPool(), primaries: NewPrimaryRegistry(), certStore: NewCertStore(),
		hmacSecret: secret, adminSecret: []byte(testAdminSecret),
	}
	m.state.Store(StateProxy)
	srv := httptest.NewServer(buildBinaryServerMux(bin, m))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/containarium/checksum")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 64 {
		t.Fatalf("checksum body %q", body)
	}
	if err := auth.VerifySentinelResponse(resp, secret, body, time.Now()); err != nil {
		t.Fatalf("checksum response not validly signed: %v", err)
	}
	// A tampered body must not verify against the same headers.
	if err := auth.VerifySentinelResponse(resp, secret, append([]byte("0"), body[1:]...), time.Now()); err == nil && body[0] != '0' {
		t.Fatal("tampered checksum verified")
	}
}
