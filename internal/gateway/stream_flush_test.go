package gateway

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
)

type noopAuditLogger struct{}

func (noopAuditLogger) Log(context.Context, *audit.AuditEntry) error { return nil }

const streamFlushTestSecret = "a-secret-that-is-at-least-32-bytes-long!!"

// #2773: a server-streaming grpc-gateway response served through the
// PRODUCTION chain (wrapHTTPHandler: cors → auth → audit → GuardSSHAuthzPath
// → mux, the same call Start makes) must deliver every chunk and never write
// the "unexpected type of web server" error into the body. The chain is built
// by the shared helper rather than assembled here, so a wrapper added to any
// layer later is covered.
func TestStreamingResponseThroughProductionChain(t *testing.T) {
	mux := runtime.NewServeMux()
	const events = 5
	err := mux.HandlePath(http.MethodGet, "/v1/security/exec-events", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		i := 0
		recv := func() (proto.Message, error) {
			if i == events {
				return nil, io.EOF
			}
			i++
			return wrapperspb.String("event"), nil
		}
		ctx := runtime.NewServerMetadataContext(r.Context(), runtime.ServerMetadata{})
		runtime.ForwardResponseStream(ctx, mux, &runtime.JSONPb{}, w, r, recv)
	})
	if err != nil {
		t.Fatal(err)
	}

	tm, err := auth.NewTokenManager(streamFlushTestSecret, "containarium")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	tok, err := tm.GenerateToken("alice", []string{"admin"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	handler, rest := wrapHTTPHandler(mux, auth.NewAuthMiddleware(tm).HTTPMiddleware, noopAuditLogger{})
	if rest == nil {
		t.Fatal("wrapHTTPHandler returned a nil rest handler")
	}

	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Proof this is the real chain: without a bearer the auth layer refuses.
	unauth, err := http.Get(srv.URL + "/v1/security/exec-events")
	if err != nil {
		t.Fatal(err)
	}
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401 (auth layer missing from chain?)", unauth.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/security/exec-events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var lines []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != events {
		t.Fatalf("got %d chunks, want %d: %q", len(lines), events, lines)
	}
	for _, l := range lines {
		if strings.Contains(l, "unexpected type of web server") || !strings.Contains(l, `"result"`) {
			t.Fatalf("bad chunk %q", l)
		}
	}
}
