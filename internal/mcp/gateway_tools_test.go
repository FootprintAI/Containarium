package mcp

import (
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

// The mint_gateway_token tool (#1726). Two things are worth testing here and
// nothing else: that the tool-facing arguments translate into the protojson
// shapes the generated REST gateway actually accepts, and that the tool is gated
// by gateway:mint while the key verbs have no tool at all.

func TestMintGatewayTokenBody_ToWire(t *testing.T) {
	tests := []struct {
		name         string
		in           MintGatewayTokenBody
		wantErr      bool
		wantProvider string
		wantTTL      string
	}{
		{
			name:         "provider becomes the enum value name",
			in:           MintGatewayTokenBody{Box: "alice", Provider: "kafeido"},
			wantProvider: "GATEWAY_PROVIDER_KAFEIDO",
		},
		{
			name:         "hyphenated provider name",
			in:           MintGatewayTokenBody{Box: "alice", Provider: "gemini-openai"},
			wantProvider: "GATEWAY_PROVIDER_GEMINI_OPENAI",
		},
		{
			// A Go duration string is NOT valid protojson for Duration; the wire
			// form is seconds with an "s" suffix. Getting this wrong fails at the
			// grpc-gateway, before any handler, so it has to be pinned.
			name:         "ttl becomes protojson seconds",
			in:           MintGatewayTokenBody{Box: "alice", Provider: "kafeido", TTL: "2h"},
			wantProvider: "GATEWAY_PROVIDER_KAFEIDO",
			wantTTL:      "7200s",
		},
		{
			name:         "sub-hour ttl",
			in:           MintGatewayTokenBody{Box: "alice", Provider: "kafeido", TTL: "90m"},
			wantProvider: "GATEWAY_PROVIDER_KAFEIDO",
			wantTTL:      "5400s",
		},
		{
			name:         "omitted ttl stays omitted so the server's default applies",
			in:           MintGatewayTokenBody{Box: "alice", Provider: "kafeido"},
			wantProvider: "GATEWAY_PROVIDER_KAFEIDO",
			wantTTL:      "",
		},
		{name: "unknown provider", in: MintGatewayTokenBody{Box: "alice", Provider: "nope"}, wantErr: true},
		{name: "missing provider", in: MintGatewayTokenBody{Box: "alice"}, wantErr: true},
		{name: "the enum spelling is not accepted as a provider name", in: MintGatewayTokenBody{Box: "alice", Provider: "GATEWAY_PROVIDER_KAFEIDO"}, wantErr: true},
		{name: "unparseable ttl", in: MintGatewayTokenBody{Box: "alice", Provider: "kafeido", TTL: "2 days"}, wantErr: true},
		{name: "zero ttl", in: MintGatewayTokenBody{Box: "alice", Provider: "kafeido", TTL: "0s"}, wantErr: true},
		{name: "negative ttl", in: MintGatewayTokenBody{Box: "alice", Provider: "kafeido", TTL: "-5m"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.toWire()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Provider != tt.wantProvider {
				t.Errorf("provider = %q, want %q", got.Provider, tt.wantProvider)
			}
			if got.TTL != tt.wantTTL {
				t.Errorf("ttl = %q, want %q", got.TTL, tt.wantTTL)
			}
			if got.Box != tt.in.Box {
				t.Errorf("box = %q, want %q", got.Box, tt.in.Box)
			}
		})
	}
}

// TestGatewayTools_MintIsScopedAndTheKeyVerbsHaveNoTool is the MCP-side half of
// the scope split: an agent may mint a scoped token, and there is no tool through
// which any agent token could write a REAL provider key.
func TestGatewayTools_MintIsScopedAndTheKeyVerbsHaveNoTool(t *testing.T) {
	srv := &Server{}
	srv.registerTools()

	var mint *Tool
	for i := range srv.tools {
		switch srv.tools[i].Name {
		case "mint_gateway_token":
			mint = &srv.tools[i]
		case "set_tenant_provider_key", "delete_tenant_provider_key", "get_tenant_provider_key_status",
			"gateway_key_set", "gateway_key_delete", "gateway_key_status":
			t.Errorf("tool %q exists; the gateway:admin key verbs must not be reachable over MCP", srv.tools[i].Name)
		}
	}
	if mint == nil {
		t.Fatal("mint_gateway_token is not registered")
	}
	if mint.RequiredScope != auth.ScopeGatewayMint {
		t.Errorf("mint_gateway_token RequiredScope = %q, want %q", mint.RequiredScope, auth.ScopeGatewayMint)
	}
	// A gateway:admin token must not reach the mint tool either — the scopes are
	// not a hierarchy.
	if toolAllowed([]string{auth.ScopeGatewayAdmin}, mint) {
		t.Error("a gateway:admin-only token was allowed to call mint_gateway_token")
	}
	if !toolAllowed([]string{auth.ScopeGatewayMint}, mint) {
		t.Error("a gateway:mint token was refused mint_gateway_token")
	}
	if mint.InputSchema == nil {
		t.Fatal("mint_gateway_token has no input schema")
	}
	required, _ := mint.InputSchema["required"].([]string)
	wantRequired := map[string]bool{"box": false, "provider": false}
	for _, r := range required {
		wantRequired[r] = true
	}
	for name, present := range wantRequired {
		if !present {
			t.Errorf("%q is not required by mint_gateway_token's schema", name)
		}
	}
}

// A dry run must not render a token field at all — the handler's formatting is
// the last place a credential could leak into an agent's transcript.
func TestHandleMintGatewayToken_DryRunOutputHasNoTokenField(t *testing.T) {
	fake := &mintOnlyAPI{resp: &MintGatewayTokenResponse{
		Token:    "eyJ.should.not.appear",
		BaseURL:  "http://10.0.0.1:8080/v1/model/kafeido",
		KeyOwner: "user:alice",
		TokenID:  "deadbeef",
	}}
	out, err := handleMintGatewayToken(fake, map[string]interface{}{
		"box": "alice", "provider": "kafeido", "dry_run": true,
	})
	if err != nil {
		t.Fatalf("handleMintGatewayToken: %v", err)
	}
	if mcpContains(out, "eyJ.should.not.appear") {
		t.Errorf("dry-run output contains the token:\n%s", out)
	}
	if !mcpContains(out, "dry run") {
		t.Errorf("dry-run output does not say it was a dry run:\n%s", out)
	}
	if !fake.called {
		t.Error("the handler did not call the API")
	}
	if !fake.req.DryRun {
		t.Error("dry_run did not reach the request")
	}
}

func TestHandleMintGatewayToken_RequiresBoxAndProvider(t *testing.T) {
	fake := &mintOnlyAPI{resp: &MintGatewayTokenResponse{}}
	if _, err := handleMintGatewayToken(fake, map[string]interface{}{"provider": "kafeido"}); err == nil {
		t.Error("want an error without box")
	}
	if _, err := handleMintGatewayToken(fake, map[string]interface{}{"box": "alice"}); err == nil {
		t.Error("want an error without provider")
	}
	if fake.called {
		t.Error("the handler called the API despite invalid arguments")
	}
}

// mintOnlyAPI implements just enough of API to drive handleMintGatewayToken.
// It embeds the interface so the rest of API's (large) surface panics rather than
// silently returning zero values if the handler ever reached for more.
type mintOnlyAPI struct {
	API
	resp   *MintGatewayTokenResponse
	req    MintGatewayTokenBody
	called bool
}

func (m *mintOnlyAPI) MintGatewayToken(req MintGatewayTokenBody) (*MintGatewayTokenResponse, error) {
	m.called = true
	m.req = req
	return m.resp, nil
}

func mcpContains(haystack, needle string) bool {
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
