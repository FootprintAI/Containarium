package gateway

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/metrics"
)

type noopAuditLogger struct{}

func (noopAuditLogger) Log(context.Context, *audit.AuditEntry) error { return nil }

// #2773: a server-streaming grpc-gateway response served through the real
// audit + metrics middleware must deliver every chunk and never write the
// "unexpected type of web server" error into the body.
func TestStreamingResponseThroughAuditAndMetricsMiddleware(t *testing.T) {
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

	mp := sdkmetric.NewMeterProvider()
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	handler := metrics.HTTPMetricsMiddleware(audit.HTTPAuditMiddleware(mux, noopAuditLogger{}), mp)

	srv := httptest.NewServer(handler)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/security/exec-events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

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
