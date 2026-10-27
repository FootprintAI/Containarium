package anondoor

import (
	"errors"
	"net/http"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
)

// TestAnonymousRouteRegistrationUsesEnsureAuthority fails closed before piping.
func TestAnonymousRouteRegistrationUsesEnsureAuthority(t *testing.T) {
	srv, _ := fakeDaemon(t, http.StatusOK, okBody, 0)
	keyPath, _ := writeUpstreamKey(t)
	wire, _, _ := testKey(t)
	meta := fakeConn{user: "client-chosen-name", remote: "192.0.2.2:1234", id: "transport"}
	calls := 0
	denied := errors.New("controller unavailable")
	p := newPlugin(t, srv.URL, keyPath, func(c *Config) {
		c.RegisterRoute = func(conn libplugin.ConnMetadata, res *pb.EnsureAnonymousBoxResponse) error {
			calls++
			if conn.UniqueID() != meta.id || res.BoxName != "anon-1a2b3c4d-container" || res.SshHost != "10.100.0.57" {
				t.Fatal("route registration lost transport or Ensure identity")
			}
			return denied
		}
	})
	if _, err := p.PluginConfig().PublicKeyCallback(meta, wire); !errors.Is(err, denied) || calls != 1 {
		t.Fatalf("unregistered anonymous route escaped: %v, calls=%d", err, calls)
	}
}
