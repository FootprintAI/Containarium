package cloud

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
)

func TestIsRESTControlPlane(t *testing.T) {
	cases := map[string]bool{
		"https://cloud.containarium.dev": true,
		"http://localhost:8080":          true,
		"cloud.containarium.dev:443":     false,
		"10.0.0.5:50051":                 false,
		"":                               false,
	}
	for cp, want := range cases {
		if got := isRESTControlPlane(cp); got != want {
			t.Errorf("isRESTControlPlane(%q) = %v, want %v", cp, got, want)
		}
	}
}

func TestRESTActuation_HeartbeatAndStatus(t *testing.T) {
	var gotPaths []string
	var gotBearer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		gotBearer = r.Header.Get("Grpc-Metadata-Host-Bearer")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	r := newRESTActuation(srv.URL, "host-bearer-tok")
	if _, err := r.Heartbeat(context.Background(), &cloudv1.HeartbeatRequest{}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if _, err := r.ReportHostStatus(context.Background(), &cloudv1.ReportHostStatusRequest{CpuCores: 24, TotalRamMb: 128000}); err != nil {
		t.Fatalf("ReportHostStatus: %v", err)
	}
	if len(gotPaths) != 2 || gotPaths[0] != "/v1/actuation/heartbeat" || gotPaths[1] != "/v1/actuation/status" {
		t.Errorf("paths = %v, want [/v1/actuation/heartbeat /v1/actuation/status]", gotPaths)
	}
	if gotBearer != "host-bearer-tok" {
		t.Errorf("host bearer header = %q, want it forwarded as Grpc-Metadata-Host-Bearer", gotBearer)
	}
}

func TestRESTActuation_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":16,"message":"bad bearer"}`))
	}))
	defer srv.Close()
	r := newRESTActuation(srv.URL, "x")
	if _, err := r.Heartbeat(context.Background(), &cloudv1.HeartbeatRequest{}); err == nil {
		t.Fatal("a 401 must surface as an error")
	}
}

func TestEnrollREST(t *testing.T) {
	var got cloudv1.EnrollHostRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/actuation/enroll" {
			t.Errorf("path = %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = protojson.Unmarshal(raw, &got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hostId":"host-123"}`))
	}))
	defer srv.Close()

	id, bearer, err := enrollREST(context.Background(), srv.URL, "host-123.secret",
		EnrollOptions{DriverToken: "admin.jwt", OSSBackendID: "tunnel-gpu-node-a"})
	if err != nil {
		t.Fatalf("enrollREST: %v", err)
	}
	if id != "host-123" {
		t.Errorf("host id = %q, want host-123", id)
	}
	if bearer != "host-123.secret" {
		t.Errorf("bearer = %q, want host-123.secret (first enroll: response id matches the token's own id)", bearer)
	}
	if got.GetJoinToken() != "host-123.secret" || got.GetDriverToken() != "admin.jwt" || got.GetOssBackendId() != "tunnel-gpu-node-a" {
		t.Errorf("server saw join=%q driver=%q backend=%q", got.GetJoinToken(), got.GetDriverToken(), got.GetOssBackendId())
	}
}

// TestEnrollREST_ReEnroll pins the cloud #572 re-enroll case: the cloud
// resolves the join token to an EXISTING host row (matched on oss_backend_id)
// whose id differs from the throwaway id embedded in the join token itself.
// The bearer persisted client-side must use the RETURNED host id, not the
// token's own id — otherwise every heartbeat after a re-enroll 401s forever
// (the throwaway id was never created as an actual host row).
func TestEnrollREST_ReEnroll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hostId":"existing-host-999"}`))
	}))
	defer srv.Close()

	id, bearer, err := enrollREST(context.Background(), srv.URL, "throwaway-host-123.secret", EnrollOptions{})
	if err != nil {
		t.Fatalf("enrollREST: %v", err)
	}
	if id != "existing-host-999" {
		t.Errorf("host id = %q, want existing-host-999", id)
	}
	if bearer != "existing-host-999.secret" {
		t.Errorf("bearer = %q, want existing-host-999.secret (rebuilt from the returned id, not the token's own throwaway id)", bearer)
	}
}

// connCountingServer replies with the next status from statuses (the last one
// repeats) and counts distinct TCP connections via ConnState.
func connCountingServer(t *testing.T, statuses ...int) (srv *httptest.Server, conns *atomic.Int32) {
	t.Helper()
	conns = new(atomic.Int32)
	var n atomic.Int32
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i := int(n.Add(1)) - 1
		if i >= len(statuses) {
			i = len(statuses) - 1
		}
		w.WriteHeader(statuses[i])
		_, _ = w.Write([]byte("{}"))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, conns
}

func TestRESTActuation_RecyclesConnectionAfterRepeated5xx(t *testing.T) {
	srv, conns := connCountingServer(t, 502, 502, 502, 200)
	r := newRESTActuation(srv.URL, "tok")
	ctx := context.Background()
	for i := 0; i < recycleAfter5xx; i++ {
		if _, err := r.Heartbeat(ctx, &cloudv1.HeartbeatRequest{}); err == nil {
			t.Fatalf("call %d: want 502 error", i)
		}
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("connections before recycle = %d, want 1 (pooled)", got)
	}
	if _, err := r.Heartbeat(ctx, &cloudv1.HeartbeatRequest{}); err != nil {
		t.Fatalf("heartbeat after recycle: %v", err)
	}
	if got := conns.Load(); got != 2 {
		t.Errorf("connections after recycle = %d, want 2 (fresh dial)", got)
	}
}

func TestRESTActuation_NoRecycleBelowThreshold(t *testing.T) {
	srv, conns := connCountingServer(t, 502, 502, 200, 502, 502, 200)
	r := newRESTActuation(srv.URL, "tok")
	for i := 0; i < 6; i++ {
		_, _ = r.Heartbeat(context.Background(), &cloudv1.HeartbeatRequest{})
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("connections = %d, want 1: a success must reset the 5xx count", got)
	}
}

func TestRESTActuation_4xxDoesNotRecycle(t *testing.T) {
	srv, conns := connCountingServer(t, 401)
	r := newRESTActuation(srv.URL, "tok")
	for i := 0; i < recycleAfter5xx*3; i++ {
		_, _ = r.Heartbeat(context.Background(), &cloudv1.HeartbeatRequest{})
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("connections = %d, want 1: 401 must not recycle", got)
	}
}

func TestRESTActuation_4xxBetween5xxDoesNotResetOrCount(t *testing.T) {
	// 502,502,401,502 is still 3 5xx in a row as far as the connection goes.
	srv, conns := connCountingServer(t, 502, 502, 401, 502, 200)
	r := newRESTActuation(srv.URL, "tok")
	for i := 0; i < 5; i++ {
		_, _ = r.Heartbeat(context.Background(), &cloudv1.HeartbeatRequest{})
	}
	if got := conns.Load(); got != 2 {
		t.Errorf("connections = %d, want 2", got)
	}
}

func TestRESTActuation_RecycleConcurrent(t *testing.T) {
	srv, _ := connCountingServer(t, 502)
	r := newRESTActuation(srv.URL, "tok")
	const workers, iters = 16, 5
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_, _ = r.Heartbeat(context.Background(), &cloudv1.HeartbeatRequest{})
				_, _ = r.ReportHostStatus(context.Background(), &cloudv1.ReportHostStatusRequest{})
			}
		}()
	}
	wg.Wait()
	// Every call is a 502, so the counter cycles 1,2,0,...: after N calls it
	// must be N mod K. A lost update (missing lock) breaks this.
	total := workers * iters * 2
	r.mu.Lock()
	got := r.consecutive5xx
	r.mu.Unlock()
	if want := total % recycleAfter5xx; got != want {
		t.Errorf("consecutive5xx after %d 502s = %d, want %d", total, got, want)
	}
}

func TestRESTActuation_RecyclesHTTP2Connection(t *testing.T) {
	var n, conns atomic.Int32
	var nonH2 atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.ProtoMajor != 2 {
			nonH2.Store(true)
		}
		if n.Add(1) <= recycleAfter5xx {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	r := newRESTActuation(srv.URL, "tok")
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	r.hc.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}

	ctx := context.Background()
	for i := 0; i < recycleAfter5xx; i++ {
		if _, err := r.Heartbeat(ctx, &cloudv1.HeartbeatRequest{}); err == nil {
			t.Fatalf("call %d: want 502 error", i)
		}
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("connections before recycle = %d, want 1", got)
	}
	// The h2 client releases a finished stream asynchronously; a real
	// heartbeat tick is 30s later, so give it a moment like the tick would.
	time.Sleep(50 * time.Millisecond)
	if _, err := r.Heartbeat(ctx, &cloudv1.HeartbeatRequest{}); err != nil {
		t.Fatalf("heartbeat after recycle: %v", err)
	}
	if got := conns.Load(); got != 2 {
		t.Errorf("connections after recycle = %d, want 2", got)
	}
	if nonH2.Load() {
		t.Error("a request was not HTTP/2; the test no longer pins the h2 path")
	}
}
