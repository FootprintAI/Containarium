package cmd

import (
	"github.com/footprintai/containarium/internal/client"
	"testing"
)

func TestTenantReviewNetworkPolicyHTTPDefaultTransport(t *testing.T) {
	oldServer, oldHTTP, oldInsecure := serverAddr, httpMode, insecure
	t.Cleanup(func() { serverAddr, httpMode, insecure = oldServer, oldHTTP, oldInsecure })
	serverAddr, httpMode, insecure = "http://127.0.0.1:12345", false, true
	c, err := newTenantAccessClient()
	if err != nil {
		t.Fatalf("HTTP address refused: %v", err)
	}
	if closer, ok := c.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}
	if _, ok := c.(*client.HTTPClient); !ok {
		t.Fatalf("network-policy documents HTTP API default but access selected %T", c)
	}
}
