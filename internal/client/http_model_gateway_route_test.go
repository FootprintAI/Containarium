package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ModelGatewayService REST calls (#1726) — method + path must match the
// google.api.http mapping on ModelGatewayService in model_gateway.proto. This is
// the proto-drift pin for this service: change a path in the proto without
// changing it here (or vice versa) and these assertions fail, instead of the
// mismatch surfacing as a 404 at runtime.
//
// The paths asserted below are, verbatim from the proto:
//
//	PUT    /v1/model-gateway/keys/{key_owner}/{provider}
//	DELETE /v1/model-gateway/keys/{key_owner}/{provider}
//	GET    /v1/model-gateway/keys/{key_owner}/{provider}
//	POST   /v1/model-gateway/tokens
//	GET    /v1/model-gateway/{provider}/models
func TestModelGateway_HTTPPathsAndDecoding(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotBody string
	var respBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.EscapedPath(), r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	// The owner id carries a ':' by construction (`org:<id>`), so the escaping of
	// that segment is part of the contract, not an accident.
	const owner = "org:11111111-2222-3333-4444-555555555555"
	const escapedOwner = "org:11111111-2222-3333-4444-555555555555"
	const enumSeg = "GATEWAY_PROVIDER_KAFEIDO"

	t.Run("SetTenantProviderKey", func(t *testing.T) {
		respBody = `{"keyOwner":"` + owner + `","provider":"GATEWAY_PROVIDER_KAFEIDO","fingerprint":"0123456789abcdef","setAt":"2026-09-28T12:00:00Z"}`
		resp, err := c.SetTenantProviderKey(&pb.SetTenantProviderKeyRequest{
			KeyOwner: owner,
			Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
			ApiKey:   "sk-live",
		})
		if err != nil {
			t.Fatalf("SetTenantProviderKey: %v", err)
		}
		want := "/v1/model-gateway/keys/" + escapedOwner + "/" + enumSeg
		if gotMethod != http.MethodPut || gotPath != want {
			t.Errorf("%s %s, want PUT %s", gotMethod, gotPath, want)
		}
		if resp.GetFingerprint() != "0123456789abcdef" {
			t.Errorf("fingerprint = %q", resp.GetFingerprint())
		}
		// The key has to be in the BODY (body: "*"), not in the path.
		if !stringContains(gotBody, "sk-live") {
			t.Errorf("api_key did not travel in the request body: %s", gotBody)
		}
		if stringContains(gotPath, "sk-live") {
			t.Error("api_key leaked into the URL path")
		}
	})

	t.Run("GetTenantProviderKeyStatus", func(t *testing.T) {
		respBody = `{"keyOwner":"` + owner + `","provider":"GATEWAY_PROVIDER_KAFEIDO","set":true,"fingerprint":"0123456789abcdef"}`
		resp, err := c.GetTenantProviderKeyStatus(&pb.GetTenantProviderKeyStatusRequest{
			KeyOwner: owner, Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		})
		if err != nil {
			t.Fatalf("GetTenantProviderKeyStatus: %v", err)
		}
		want := "/v1/model-gateway/keys/" + escapedOwner + "/" + enumSeg
		if gotMethod != http.MethodGet || gotPath != want {
			t.Errorf("%s %s, want GET %s", gotMethod, gotPath, want)
		}
		if !resp.GetSet() {
			t.Error("set = false")
		}
	})

	t.Run("DeleteTenantProviderKey", func(t *testing.T) {
		respBody = `{"tokensRevoked":true}`
		resp, err := c.DeleteTenantProviderKey(&pb.DeleteTenantProviderKeyRequest{
			KeyOwner: owner, Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		})
		if err != nil {
			t.Fatalf("DeleteTenantProviderKey: %v", err)
		}
		want := "/v1/model-gateway/keys/" + escapedOwner + "/" + enumSeg
		if gotMethod != http.MethodDelete || gotPath != want {
			t.Errorf("%s %s, want DELETE %s", gotMethod, gotPath, want)
		}
		if !resp.GetTokensRevoked() {
			t.Error("tokens_revoked = false")
		}
	})

	t.Run("MintGatewayToken", func(t *testing.T) {
		respBody = `{"token":"eyJ.a.b","baseUrl":"http://10.0.0.1:8080/v1/model/kafeido","keyOwner":"` + owner + `","expiresAt":"2026-09-29T12:00:00Z","tokenId":"deadbeef"}`
		resp, err := c.MintGatewayToken(&pb.MintGatewayTokenRequest{
			Box:      "alice",
			Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
			RunId:    "run-1",
		})
		if err != nil {
			t.Fatalf("MintGatewayToken: %v", err)
		}
		if gotMethod != http.MethodPost || gotPath != "/v1/model-gateway/tokens" {
			t.Errorf("%s %s, want POST /v1/model-gateway/tokens", gotMethod, gotPath)
		}
		if !stringContains(gotBody, `"box":"alice"`) || !stringContains(gotBody, `"runId":"run-1"`) {
			t.Errorf("request body missing fields: %s", gotBody)
		}
		if resp.GetTokenId() != "deadbeef" || resp.GetBaseUrl() == "" {
			t.Errorf("decoded = %+v", resp)
		}
	})

	t.Run("ListGatewayModels", func(t *testing.T) {
		respBody = `{"models":[{"id":"m-small"},{"id":"m-large"}],"keyOwner":"` + owner + `"}`
		resp, err := c.ListGatewayModels(&pb.ListGatewayModelsRequest{
			Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		})
		if err != nil {
			t.Fatalf("ListGatewayModels: %v", err)
		}
		want := "/v1/model-gateway/" + enumSeg + "/models"
		if gotMethod != http.MethodGet || gotPath != want {
			t.Errorf("%s %s, want GET %s", gotMethod, gotPath, want)
		}
		if len(resp.GetModels()) != 2 || resp.GetModels()[0].GetId() != "m-small" {
			t.Errorf("models = %+v", resp.GetModels())
		}
	})

	t.Run("ListGatewayModels with a box rides as a query parameter", func(t *testing.T) {
		respBody = `{"models":[],"keyOwner":"user:alice"}`
		if _, err := c.ListGatewayModels(&pb.ListGatewayModelsRequest{
			Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
			Box:      "alice",
		}); err != nil {
			t.Fatalf("ListGatewayModels: %v", err)
		}
		want := "/v1/model-gateway/" + enumSeg + "/models"
		if gotPath != want {
			t.Errorf("path = %s, want %s (box is NOT a path segment in the mapping)", gotPath, want)
		}
		if gotQuery != "box=alice" {
			t.Errorf("query = %q, want box=alice", gotQuery)
		}
	})
}

// TestModelGatewayEnumPathSegment pins that the {provider} segment is the enum's
// own name. grpc-gateway parses an enum path parameter with runtime.Enum, which
// accepts the value's NAME (or its number) — a lowercase nickname would 400.
func TestModelGatewayEnumPathSegment(t *testing.T) {
	for _, p := range []pb.GatewayProvider{
		pb.GatewayProvider_GATEWAY_PROVIDER_ANTHROPIC,
		pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO,
		pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI_OPENAI,
	} {
		got := gatewayKeyPath("user:alice", p)
		want := "/v1/model-gateway/keys/user:alice/" + p.String()
		if got != want {
			t.Errorf("gatewayKeyPath(%v) = %q, want %q", p, got, want)
		}
	}
}

func stringContains(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
