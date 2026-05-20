package auth

import (
	"net/http/httptest"
	"testing"
)

// Phase 1.5 — tests for ExtractBearerForUpgrade + AckSubprotocol.

// validJWT is a structurally valid JWT (header.payload.signature
// dot-separated, base64url alphabet). Signature is bogus —
// ExtractBearerForUpgrade does not verify, it just extracts.
const validJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.AAAA-_BBBBccccDDDDeeeeFFFFgggg"

func TestExtractBearerForUpgrade_Subprotocol_MarkerThenToken(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.Header.Set("Sec-WebSocket-Protocol", "containarium.bearer, "+validJWT)
	tok, src := ExtractBearerForUpgrade(r)
	if src != TokenSourceSubprotocol {
		t.Fatalf("source: got %v want subprotocol", src)
	}
	if tok != validJWT {
		t.Fatalf("token: got %q want %q", tok, validJWT)
	}
}

func TestExtractBearerForUpgrade_Subprotocol_TokenWithoutMarker(t *testing.T) {
	// Some clients send the JWT alone — accepted as a fallback
	// because it still avoids the URL.
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.Header.Set("Sec-WebSocket-Protocol", validJWT)
	tok, src := ExtractBearerForUpgrade(r)
	if src != TokenSourceSubprotocol {
		t.Fatalf("source: got %v want subprotocol", src)
	}
	if tok != validJWT {
		t.Fatalf("token: got %q want %q", tok, validJWT)
	}
}

func TestExtractBearerForUpgrade_Subprotocol_IgnoresNonJWTFallback(t *testing.T) {
	// A subprotocol entry that's NOT a JWT and NOT preceded by
	// the marker should be ignored (e.g. a real subprotocol the
	// client wants for the application layer).
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.Header.Set("Sec-WebSocket-Protocol", "chat.v1, json")
	tok, src := ExtractBearerForUpgrade(r)
	if src != TokenSourceNone {
		t.Fatalf("source: got %v want none; tok=%q", src, tok)
	}
}

func TestExtractBearerForUpgrade_Subprotocol_PrefersOverHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.Header.Set("Sec-WebSocket-Protocol", "containarium.bearer, "+validJWT)
	r.Header.Set("Authorization", "Bearer header-token")
	tok, src := ExtractBearerForUpgrade(r)
	if src != TokenSourceSubprotocol {
		t.Fatalf("subprotocol must win over Authorization; got %v", src)
	}
	if tok != validJWT {
		t.Fatalf("token: got %q", tok)
	}
}

func TestExtractBearerForUpgrade_AuthorizationHeaderFallback(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.Header.Set("Authorization", "Bearer hdr-token")
	tok, src := ExtractBearerForUpgrade(r)
	if src != TokenSourceAuthorizationHeader {
		t.Fatalf("source: got %v", src)
	}
	if tok != "hdr-token" {
		t.Fatalf("token: got %q", tok)
	}
}

func TestExtractBearerForUpgrade_QueryParamLegacy(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x?token=query-token", nil)
	tok, src := ExtractBearerForUpgrade(r)
	if src != TokenSourceQueryParam {
		t.Fatalf("source: got %v", src)
	}
	if tok != "query-token" {
		t.Fatalf("token: got %q", tok)
	}
}

func TestExtractBearerForUpgrade_HeaderBeatsQuery(t *testing.T) {
	// Authorization header wins over ?token= when subprotocol
	// is absent.
	r := httptest.NewRequest("GET", "/v1/x?token=query-token", nil)
	r.Header.Set("Authorization", "Bearer hdr-token")
	tok, src := ExtractBearerForUpgrade(r)
	if src != TokenSourceAuthorizationHeader {
		t.Fatalf("source: got %v", src)
	}
	if tok != "hdr-token" {
		t.Fatalf("token: got %q", tok)
	}
}

func TestExtractBearerForUpgrade_NoToken(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	tok, src := ExtractBearerForUpgrade(r)
	if src != TokenSourceNone {
		t.Fatalf("source: got %v want none", src)
	}
	if tok != "" {
		t.Fatalf("token should be empty, got %q", tok)
	}
}

func TestExtractBearerForUpgrade_AuthorizationWithoutBearerPrefix(t *testing.T) {
	// "Basic XXX" must not be mistaken for a bearer token.
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	tok, src := ExtractBearerForUpgrade(r)
	if src != TokenSourceNone {
		t.Fatalf("source: got %v want none; tok=%q", src, tok)
	}
}

func TestAckSubprotocol_PresentReturnsMarker(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.Header.Set("Sec-WebSocket-Protocol", "containarium.bearer, "+validJWT)
	if got := AckSubprotocol(r); got != WSSubprotocolBearer {
		t.Fatalf("ack: got %q want %q", got, WSSubprotocolBearer)
	}
}

func TestAckSubprotocol_AbsentReturnsEmpty(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	if got := AckSubprotocol(r); got != "" {
		t.Fatalf("ack: got %q want empty", got)
	}
}

func TestAckSubprotocol_OnlyOtherSubprotocols(t *testing.T) {
	// If the client offered subprotocols but not the bearer
	// marker, we don't ack anything — the server didn't
	// recognize them. Gorilla will then omit the response
	// header entirely (the RFC allows this).
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.Header.Set("Sec-WebSocket-Protocol", "chat.v1, json")
	if got := AckSubprotocol(r); got != "" {
		t.Fatalf("ack: got %q want empty", got)
	}
}

func TestLooksLikeJWT(t *testing.T) {
	cases := map[string]bool{
		validJWT:                      true,
		"a.b.c":                       false, // total length below 16-char floor
		"":                            false,
		"only-two.segments-here":      false,
		"four.dot.segments.here":      false,
		"contains spaces.and.illegal": false,
		// Three valid base64url-charset segments, total length
		// above the floor → passes the heuristic. We're only
		// gating against the obviously-not-a-JWT case.
		"aaaaaaaaaaaaaaaaaaaa.bbbb.cccc": true,
	}
	for s, want := range cases {
		got := looksLikeJWT(s)
		if got != want {
			t.Errorf("looksLikeJWT(%q): got %v want %v", s, got, want)
		}
	}
}
