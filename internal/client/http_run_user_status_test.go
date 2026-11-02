package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHTTPGetBoxRunUserStatus(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"runUser":"ctn-run","toolAccessRecorded":true,"runUserExists":true,"state":"CODE_CREDENTIAL_SOURCE_EXPIRED"}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.GetBoxRunUserStatus("alice")
	if err != nil {
		t.Fatalf("GetBoxRunUserStatus: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/containers/alice/run-user/status" {
		t.Errorf("request = %s %s", gotMethod, gotPath)
	}
	if got.GetRunUser() != "ctn-run" || !got.GetToolAccessRecorded() || !got.GetRunUserExists() ||
		got.GetState() != pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED {
		t.Errorf("decoded = %v", got)
	}
}

// A daemon without the route answers 404; callers must see Unimplemented, the
// same soft path the gRPC transport gives.
func TestHTTPGetBoxRunUserStatus_OldDaemonIsUnimplemented(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetBoxRunUserStatus("alice"); status.Code(err) != codes.Unimplemented {
		t.Fatalf("err = %v, want Unimplemented", err)
	}
}
