package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// bodyRecorder serves a canned 200 and captures the raw request body, so
// a test can assert what actually went on the wire rather than what the
// caller believed it sent.
type bodyRecorder struct {
	raw      []byte
	path     string
	method   string
	response string
}

func newBodyRecorder(t *testing.T, response string) (*bodyRecorder, *HTTPClient) {
	t.Helper()
	rec := &bodyRecorder{response: response}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.raw, _ = io.ReadAll(r.Body)
		rec.path = r.URL.Path
		rec.method = r.Method
		w.Header().Set("Content-Type", "application/json")
		if rec.response != "" {
			_, _ = w.Write([]byte(rec.response))
		}
	}))
	t.Cleanup(srv.Close)

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return rec, c
}

// object decodes the captured body as a JSON object, failing the test
// with a readable message when the body is anything else — which is
// exactly the #887 failure: a base64 JSON *string* instead of an object.
func (b *bodyRecorder) object(t *testing.T) map[string]any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b.raw, &v); err != nil {
		t.Fatalf("request body is not valid JSON (%v): %s", err, b.raw)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("request body is a %T, not a JSON object — the daemon cannot parse this into a proto.\n"+
			"got: %s", v, b.raw)
	}
	return obj
}

// TestHTTPRequestBodiesAreJSONObjects is the regression guard for #887.
//
// doRequest marshals whatever it is handed. A caller that hands it an
// already-marshalled []byte gets that []byte base64-encoded into a JSON
// string, so the daemon receives `"eyJ1c2Vy..."` instead of an object and
// grpc-gateway rejects it with `proto: syntax error (line 1:1):
// unexpected token "<base64>"`. The reporter decoded that base64 and
// found their own request body inside it.
//
// Three client methods pre-marshalled their payload this way. Only
// SetSecret was reported; ToggleMonitoring and ResizeContainer are the
// same defect and were silently broken over --http too.
func TestHTTPRequestBodiesAreJSONObjects(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
		call     func(*HTTPClient) error
		wantPath string
		want     map[string]any
	}{
		{
			name:     "SetSecret (#887, reported)",
			response: `{"message":"secret created"}`,
			call: func(c *HTTPClient) error {
				_, err := c.SetSecret("alice", "API_KEY", "s3cr3t", "compose")
				return err
			},
			wantPath: "/v1/secrets",
			want: map[string]any{
				"username": "alice",
				"name":     "API_KEY",
				"value":    "s3cr3t",
				"delivery": "compose",
			},
		},
		{
			name:     "ToggleMonitoring (same defect, unreported)",
			response: `{"message":"ok","enabled":true}`,
			call: func(c *HTTPClient) error {
				_, _, err := c.ToggleMonitoring("alice", true)
				return err
			},
			wantPath: "/v1/containers/alice/monitoring",
			want:     map[string]any{"enabled": true},
		},
		{
			name:     "ResizeContainer (same defect, unreported)",
			response: `{"message":"resized"}`,
			call: func(c *HTTPClient) error {
				_, err := c.ResizeContainer("alice", "4", "8GB", "50GB", "", "")
				return err
			},
			wantPath: "/v1/containers/alice/resize",
			want: map[string]any{
				"cpu":    "4",
				"memory": "8GB",
				"disk":   "50GB",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, c := newBodyRecorder(t, tc.response)
			if err := tc.call(c); err != nil {
				t.Fatalf("call: %v", err)
			}
			if rec.path != tc.wantPath {
				t.Errorf("path = %q, want %q", rec.path, tc.wantPath)
			}
			got := rec.object(t)
			for k, want := range tc.want {
				if got[k] != want {
					t.Errorf("body[%q] = %#v, want %#v (full body: %s)", k, got[k], want, rec.raw)
				}
			}
		})
	}
}

// SetSecret omits `delivery` when the caller left it empty, so the daemon
// applies its own default rather than being handed "".
func TestSetSecretOmitsEmptyDelivery(t *testing.T) {
	rec, c := newBodyRecorder(t, `{"message":"ok"}`)
	if _, err := c.SetSecret("alice", "API_KEY", "s3cr3t", ""); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	got := rec.object(t)
	if _, present := got["delivery"]; present {
		t.Errorf("delivery should be omitted when empty, got %#v", got["delivery"])
	}
	if got["username"] != "alice" {
		t.Errorf("username = %#v", got["username"])
	}
}

// The wire format of the endpoints that were already correct must not
// shift while doRequest's contract changes underneath them. These lock
// the field names the daemon's protos expect.
func TestUnaffectedRequestBodiesKeepTheirWireFormat(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
		call     func(*HTTPClient) error
		want     map[string]any
	}{
		{
			name:     "SetContainerTTL",
			response: `{"ttlExpiresAt":"2030-01-01T00:00:00Z"}`,
			call: func(c *HTTPClient) error {
				_, err := c.SetContainerTTL("alice", 3600)
				return err
			},
			want: map[string]any{"duration_seconds": float64(3600)},
		},
		{
			name:     "SetLabels",
			response: `{"message":"ok"}`,
			call: func(c *HTTPClient) error {
				return c.SetLabels("alice", map[string]string{"team": "core"})
			},
			want: map[string]any{"labels": map[string]any{"team": "core"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, c := newBodyRecorder(t, tc.response)
			if err := tc.call(c); err != nil {
				t.Fatalf("call: %v", err)
			}
			got := rec.object(t)
			for k, want := range tc.want {
				if !jsonEqual(got[k], want) {
					t.Errorf("body[%q] = %#v, want %#v", k, got[k], want)
				}
			}
		})
	}
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}
