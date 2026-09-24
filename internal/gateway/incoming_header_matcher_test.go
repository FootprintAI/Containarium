package gateway

import "testing"

// A client must not be able to smuggle identity into gRPC metadata via
// Grpc-Metadata-* request headers; identity is written only by annotateContext.
func TestIncomingHeaderMatcher_DropsReservedIdentityKeys(t *testing.T) {
	for _, h := range []string{
		"Grpc-Metadata-Roles", "Grpc-Metadata-Username", "grpc-metadata-scopes",
		"Grpc-Metadata-Act", "Grpc-Metadata-Jti", "Grpc-Metadata-Run_id",
		"Grpc-Metadata-Tracker_conn", "Grpc-Metadata-X-Containarium-Gateway-Forward",
	} {
		if key, ok := incomingHeaderMatcher(h); ok {
			t.Errorf("%s was forwarded as metadata %q", h, key)
		}
	}
	// Ordinary client metadata still flows.
	if key, ok := incomingHeaderMatcher("Grpc-Metadata-X-Request-Id"); !ok || key != "X-Request-Id" {
		t.Errorf("non-reserved metadata header dropped or renamed: %q ok=%v", key, ok)
	}
}
