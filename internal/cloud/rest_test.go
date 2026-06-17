package cloud

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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

	id, err := enrollREST(context.Background(), srv.URL, "host-123.secret",
		EnrollOptions{DriverToken: "admin.jwt", OSSBackendID: "tunnel-fts-13700k"})
	if err != nil {
		t.Fatalf("enrollREST: %v", err)
	}
	if id != "host-123" {
		t.Errorf("host id = %q, want host-123", id)
	}
	if got.GetJoinToken() != "host-123.secret" || got.GetDriverToken() != "admin.jwt" || got.GetOssBackendId() != "tunnel-fts-13700k" {
		t.Errorf("server saw join=%q driver=%q backend=%q", got.GetJoinToken(), got.GetDriverToken(), got.GetOssBackendId())
	}
}
