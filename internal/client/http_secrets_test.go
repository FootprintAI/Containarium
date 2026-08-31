package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestListSecretsDecodesGatewayCamelCase is the regression guard for
// #1219.
//
// The daemon serves this endpoint through grpc-gateway, whose marshaller
// is configured with `UseProtoNames: false`
// (internal/gateway/gateway.go). protojson therefore emits **lowerCamelCase**
// field names: `createdAt`, `updatedAt`.
//
// The client used to return []map[string]interface{} and the CLI read
// `row["updated_at"]` — a key the server never sends. That lookup yields
// nil, so `containarium secrets list --http` printed `<nil>` in its
// UPDATED column. Nothing failed; the column was simply wrong.
//
// That is the whole argument for typing this response: a snake_case/
// camelCase mismatch is invisible to a map and a compile-or-decode
// concern for a struct.
func TestListSecretsDecodesGatewayCamelCase(t *testing.T) {
	// Exactly what grpc-gateway emits for ListSecretsResponse.
	const gatewayJSON = `{
	  "secrets": [
	    {
	      "username": "alice",
	      "name": "API_KEY",
	      "version": 3,
	      "createdAt": "2026-08-01T10:00:00Z",
	      "updatedAt": "2026-08-07T12:30:00Z",
	      "delivery": "compose",
	      "deliveryMode": "SECRET_DELIVERY_COMPOSE"
	    },
	    {
	      "username": "alice",
	      "name": "DB_PASSWORD",
	      "version": 1,
	      "createdAt": "2026-08-02T09:00:00Z",
	      "updatedAt": "2026-08-02T09:00:00Z",
	      "delivery": "env",
	      "deliveryMode": "SECRET_DELIVERY_ENV"
	    }
	  ]
	}`

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gatewayJSON))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	list, err := c.ListSecrets("alice")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if gotPath != "/v1/secrets/alice" {
		t.Errorf("path = %q, want /v1/secrets/alice", gotPath)
	}
	if len(list) != 2 {
		t.Fatalf("got %d secrets, want 2", len(list))
	}

	first := list[0]
	if first.GetName() != "API_KEY" {
		t.Errorf("Name = %q, want API_KEY", first.GetName())
	}
	if first.GetUsername() != "alice" {
		t.Errorf("Username = %q, want alice", first.GetUsername())
	}
	if first.GetVersion() != 3 {
		t.Errorf("Version = %d, want 3", first.GetVersion())
	}
	// The two fields the old map-based path silently lost.
	if first.GetUpdatedAt() != "2026-08-07T12:30:00Z" {
		t.Errorf("UpdatedAt = %q — this is the field that printed as <nil>", first.GetUpdatedAt())
	}
	if first.GetCreatedAt() != "2026-08-01T10:00:00Z" {
		t.Errorf("CreatedAt = %q", first.GetCreatedAt())
	}
	// The typed field is the one new code reads.
	if first.GetDeliveryMode() != pb.SecretDelivery_SECRET_DELIVERY_COMPOSE {
		t.Errorf("DeliveryMode = %v, want SECRET_DELIVERY_COMPOSE", first.GetDeliveryMode())
	}
	// The legacy string must keep decoding alongside it. This assertion
	// deliberately reads the deprecated field: the enum migration's whole
	// contract is that responses populate both and they always agree, so
	// dropping this check would remove the only guard on the half of that
	// promise existing REST/MCP clients actually depend on.
	//nolint:staticcheck // SA1019: exercising the deprecated field is the point
	if first.GetDelivery() != "compose" {
		//nolint:staticcheck // SA1019: see above
		t.Errorf("legacy Delivery = %q, want compose — back-compat broken", first.GetDelivery())
	}

	if list[1].GetName() != "DB_PASSWORD" || list[1].GetVersion() != 1 {
		t.Errorf("second secret decoded wrong: %+v", list[1])
	}
}

// An empty list decodes to an empty slice, not an error — the CLI prints
// "(no secrets for X)" off the length.
func TestListSecretsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	list, err := c.ListSecrets("alice")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("got %d secrets, want 0", len(list))
	}
}

// A malformed body must surface as an error rather than silently
// decoding to an empty list — the old code discarded the unmarshal error
// entirely (`_ = json.Unmarshal(...)`), so a broken response looked
// identical to a tenant with no secrets.
func TestListSecretsReportsDecodeFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets": "not-an-array"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if _, err := c.ListSecrets("alice"); err == nil {
		t.Error("a malformed response must be an error, not an empty list")
	}
}

// TestSetTenantKMSKeyDecodesGatewayCamelCase (#1630) pins the same class
// of bug TestListSecretsDecodesGatewayCamelCase guards against:
// grpc-gateway emits lowerCamelCase (hasTenantKey), not the Go struct's
// snake_case json tag (has_tenant_key) — decoding against the wrong key
// silently produces the zero value instead of an error.
func TestSetTenantKMSKeyDecodesGatewayCamelCase(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"tenant alice now on its own KMS key","hasTenantKey":true}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	msg, hasKey, err := c.SetTenantKMSKey("alice", "projects/p/locations/l/keyRings/r/cryptoKeys/k")
	if err != nil {
		t.Fatalf("SetTenantKMSKey: %v", err)
	}
	if !hasKey {
		t.Error("hasTenantKey decoded false; the gateway sent true — camelCase mismatch")
	}
	if msg != "tenant alice now on its own KMS key" {
		t.Errorf("message = %q", msg)
	}
	if gotPath != "/v1/secrets/alice/kms-key" {
		t.Errorf("path = %q, want /v1/secrets/alice/kms-key", gotPath)
	}
	// username must NOT be repeated in the body — it's path-bound, same
	// convention as RefreshSecretsRequest.
	if strings.Contains(gotBody, "username") {
		t.Errorf("body should not repeat the path-bound username: %s", gotBody)
	}
	if !strings.Contains(gotBody, "kek_resource_name") {
		t.Errorf("body missing kek_resource_name: %s", gotBody)
	}
}

// Clearing (empty keyResourceName) must still round-trip cleanly — the
// json tag is `omitempty`, so the field is simply absent from the body,
// which the server-side proto treats identically to an explicit "".
func TestSetTenantKMSKeyClearOmitsField(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"tenant alice reverted to the shared KEK","hasTenantKey":false}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	_, hasKey, err := c.SetTenantKMSKey("alice", "")
	if err != nil {
		t.Fatalf("SetTenantKMSKey (clear): %v", err)
	}
	if hasKey {
		t.Error("expected hasTenantKey=false after clear")
	}
	if strings.Contains(gotBody, "kek_resource_name") {
		t.Errorf("empty key should omit the field entirely: %s", gotBody)
	}
}
