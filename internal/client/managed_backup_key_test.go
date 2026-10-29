package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// #3213: the HTTP client reads managed_backup_key_configured from the
// camelCase JSON grpc-gateway emits for SystemInfo; absent (an older daemon)
// reads as false.
func TestHTTPManagedBackupKeyConfigured(t *testing.T) {
	for name, tc := range map[string]struct {
		info *pb.SystemInfo
		want bool
	}{
		"managed key": {&pb.SystemInfo{Hostname: "h", ManagedBackupKeyConfigured: true}, true},
		"no key":      {&pb.SystemInfo{Hostname: "h"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			body, err := protojson.Marshal(&pb.GetSystemInfoResponse{Info: tc.info})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			c, err := NewHTTPClient(srv.URL, "tok")
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.ManagedBackupKeyConfigured()
			if err != nil || got != tc.want {
				t.Errorf("got (%v, %v), want (%v, nil)", got, err, tc.want)
			}
		})
	}
}
