package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestListSecretsDecodesGatewayCamelCase pins the JSON tags on
// SecretMetadata (#1219).
//
// The daemon serves this through grpc-gateway with UseProtoNames=false,
// so protojson emits lowerCamelCase: `createdAt`, `updatedAt`. These tags
// are hand-written on the MCP side (this client does not import the
// generated protos), which makes a snake_case typo the exact failure this
// issue is about — the field decodes to "" and the agent sees a blank
// value, with nothing failing.
func TestListSecretsDecodesGatewayCamelCase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/v1/secrets/alice" {
			t.Errorf("path = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[{
			"username":"alice",
			"name":"API_KEY",
			"version":3,
			"createdAt":"2026-08-01T10:00:00Z",
			"updatedAt":"2026-08-07T12:30:00Z",
			"delivery":"compose"
		}]}`))
	}))
	defer srv.Close()

	list, err := NewClient(srv.URL, "t").ListSecrets("alice")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d secrets, want 1", len(list))
	}

	got := list[0]
	for _, tc := range []struct{ field, got, want string }{
		{"Username", got.Username, "alice"},
		{"Name", got.Name, "API_KEY"},
		{"CreatedAt", got.CreatedAt, "2026-08-01T10:00:00Z"},
		{"UpdatedAt", got.UpdatedAt, "2026-08-07T12:30:00Z"},
		{"Delivery", got.Delivery, "compose"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q — check the json tag against the gateway's camelCase output",
				tc.field, tc.got, tc.want)
		}
	}
	if got.Version != 3 {
		t.Errorf("Version = %d, want 3", got.Version)
	}
}
