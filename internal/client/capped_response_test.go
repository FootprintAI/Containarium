package client

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/limitio"
)

// A response body over the HTTP cap is rejected, not buffered (#3687).
func TestParseResponseRejectsAnOverCapBody(t *testing.T) {
	big := strings.Repeat("x", int(limitio.MaxHTTPResponseBytes)+1)
	resp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(big))}
	_, err := parseResponse[map[string]any](resp)
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("over-cap body: err = %v, want ErrTooLarge", err)
	}
}

// A normal body under the cap still parses.
func TestParseResponseParsesAnUnderCapBody(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}
	got, err := parseResponse[map[string]any](resp)
	if err != nil {
		t.Fatalf("under-cap body: %v", err)
	}
	if (*got)["ok"] != true {
		t.Errorf("parsed %v, want ok=true", *got)
	}
}
