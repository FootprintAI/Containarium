package mcp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/limitio"
)

// #3469: the MCP server's daemon client reads each response body whole, so
// it is capped at limitio.MaxHTTPResponseBytes.

func cappedBodyServer(t *testing.T, size int64) *httptest.Server {
	t.Helper()
	body := `{"containers":[]}`
	body += strings.Repeat(" ", int(size)-len(body))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoRequest_ExactCapUnchanged(t *testing.T) {
	srv := cappedBodyServer(t, limitio.MaxHTTPResponseBytes)
	got, err := NewClient(srv.URL, "t").doRequest(http.MethodGet, "/v1/containers", nil)
	if err != nil {
		t.Fatalf("doRequest at exactly the cap: %v", err)
	}
	if int64(len(got)) != limitio.MaxHTTPResponseBytes {
		t.Fatalf("len = %d, want %d", len(got), limitio.MaxHTTPResponseBytes)
	}
}

func TestDoRequest_OverCapStopsAtCap(t *testing.T) {
	srv := cappedBodyServer(t, limitio.MaxHTTPResponseBytes+1)
	_, err := NewClient(srv.URL, "t").ListContainers()
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
}
