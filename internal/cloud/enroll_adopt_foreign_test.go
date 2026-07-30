package cloud

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
)

// `cloud enroll --adopt-foreign` (cloud #1006).
//
// The cloud refuses to enroll a host that already runs other organizations'
// cloud-managed containers — the root cause of the cloud#1001 co-residency.
// This flag is the operator's explicit acknowledgement. The decision is made
// and audited control-plane-side; the host's only job is to transmit the flag
// faithfully on BOTH transports, so these tests pin exactly that.

func TestEnroll_CarriesAdoptForeign(t *testing.T) {
	tests := []struct {
		name string
		opts EnrollOptions
		want bool
	}{
		{
			name: "default is false — the guard stays armed unless asked",
			opts: EnrollOptions{DriverToken: "admin.jwt", OSSBackendID: "tunnel-1"},
			want: false,
		},
		{
			name: "explicit acknowledgement is transmitted",
			opts: EnrollOptions{DriverToken: "admin.jwt", OSSBackendID: "tunnel-1", AdoptForeign: true},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			srv := grpc.NewServer()
			fake := &fakeActuation{}
			cloudv1.RegisterActuationServiceServer(srv, fake)
			go func() { _ = srv.Serve(lis) }()
			t.Cleanup(srv.Stop)

			if _, _, err := Enroll(context.Background(), lis.Addr().String(), "host-uuid.secret", true, tc.opts); err != nil {
				t.Fatalf("Enroll: %v", err)
			}

			fake.mu.Lock()
			defer fake.mu.Unlock()
			if fake.enrollAdoptForeign != tc.want {
				t.Errorf("control plane saw adopt_foreign = %v, want %v", fake.enrollAdoptForeign, tc.want)
			}
		})
	}
}

func TestEnrollREST_CarriesAdoptForeign(t *testing.T) {
	tests := []struct {
		name string
		opts EnrollOptions
		want bool
	}{
		{
			name: "default is false",
			opts: EnrollOptions{DriverToken: "admin.jwt", OSSBackendID: "tunnel-1"},
			want: false,
		},
		{
			name: "explicit acknowledgement is transmitted",
			opts: EnrollOptions{DriverToken: "admin.jwt", OSSBackendID: "tunnel-1", AdoptForeign: true},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got cloudv1.EnrollHostRequest
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				_ = protojson.Unmarshal(raw, &got)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"hostId":"host-123"}`))
			}))
			defer srv.Close()

			if _, _, err := enrollREST(context.Background(), srv.URL, "host-123.secret", tc.opts); err != nil {
				t.Fatalf("enrollREST: %v", err)
			}
			if got.GetAdoptForeign() != tc.want {
				t.Errorf("control plane saw adopt_foreign = %v, want %v", got.GetAdoptForeign(), tc.want)
			}
		})
	}
}
