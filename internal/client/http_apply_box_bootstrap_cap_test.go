package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/limitio"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3684: the ApplyBoxBootstrap response body is read through the shared
// capped reader; over the cap it is an error that names the call, not a
// silently truncated body.

// bootstrapBody is a valid JSON response of exactly n bytes.
func bootstrapBody(n int) string {
	const head, tail = `{"bundleRevision":11,"manifestFound":true,"pad":"`, `"}`
	return head + strings.Repeat("x", n-len(head)-len(tail)) + tail
}

func startCappedBootstrapServer(t *testing.T, body string) *HTTPClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHTTPApplyBoxBootstrap_BodyAtCapDecodes(t *testing.T) {
	c := startCappedBootstrapServer(t, bootstrapBody(int(limitio.MaxHTTPResponseBytes)))
	got, err := c.ApplyBoxBootstrap(&pb.ApplyBoxBootstrapRequest{Name: "box"})
	if err != nil {
		t.Fatalf("ApplyBoxBootstrap at exactly the cap: %v", err)
	}
	if got.GetBundleRevision() != 11 {
		t.Fatalf("decoded = %v", got)
	}
}

func TestHTTPApplyBoxBootstrap_BodyOverCapIsAnError(t *testing.T) {
	c := startCappedBootstrapServer(t, bootstrapBody(int(limitio.MaxHTTPResponseBytes)+1))
	_, err := c.ApplyBoxBootstrap(&pb.ApplyBoxBootstrapRequest{Name: "box"})
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
	if !strings.Contains(err.Error(), "apply bootstrap bundle") {
		t.Fatalf("err = %v, want it to name the call", err)
	}
}
