package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func anonTestClient(t *testing.T, h http.HandlerFunc) *HTTPClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewHTTPClient(srv.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The HTTP client speaks protojson both ways on the REST shim and reports
// the daemon's error text verbatim; a 404 is "service not exposed".
func TestHTTPClient_EnsureAnonymousBox(t *testing.T) {
	var gotPath, gotBody string
	c := anonTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		_, _ = w.Write([]byte(`{"boxName":"anon-1a2b3c4d-container","sshHost":"10.0.0.9","sshPort":22,"sshUser":"anon-1a2b3c4d","ttlExpiresAt":"2026-10-01T16:00:00Z","reused":true}`))
	})

	out, err := c.EnsureAnonymousBox(&pb.EnsureAnonymousBoxRequest{PublicKey: "ssh-ed25519 AAAA x", SourceIp: "198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/anon/boxes:ensure" {
		t.Errorf("path = %s", gotPath)
	}
	if !strings.Contains(gotBody, `"publicKey":"ssh-ed25519 AAAA x"`) || !strings.Contains(gotBody, `"sourceIp":"198.51.100.7"`) {
		t.Errorf("body = %s", gotBody)
	}
	if out.BoxName != "anon-1a2b3c4d-container" || out.SshPort != 22 || !out.Reused || out.TtlExpiresAt == nil || out.TtlExpiresAt.AsTime().Hour() != 16 {
		t.Errorf("decoded = %+v", out)
	}
}

func TestHTTPClient_AnonErrors(t *testing.T) {
	c := anonTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/anon/door":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"requires role \"admin\" or scope \"anon:admin\""}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	_, err := c.GetAnonymousDoorConfig()
	if err == nil || !strings.Contains(err.Error(), `scope "anon:admin"`) {
		t.Errorf("want the daemon's error text, got %v", err)
	}
	_, err = c.ListAnonymousBoxes()
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("404 must read as Unimplemented, got %v", err)
	}
}
