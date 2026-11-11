package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHTTPSweepBoxRunCheckouts(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"platformRuns":true,"maxAge":"604800s","checkouts":[{"user":"alice","name":"repo-run-0123abcd","sizeBytes":"4096","disposition":"BOX_RUN_CHECKOUT_DISPOSITION_WOULD_REMOVE","futureField":1}]}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.SweepBoxRunCheckouts(&pb.SweepBoxRunCheckoutsRequest{Username: "alice", DryRun: true})
	if err != nil {
		t.Fatalf("SweepBoxRunCheckouts: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/containers/alice/code-run-checkouts:sweep" || !strings.Contains(gotBody, `"dryRun":true`) {
		t.Errorf("request = %s %s %s", gotMethod, gotPath, gotBody)
	}
	if !got.GetPlatformRuns() || len(got.GetCheckouts()) != 1 || got.GetCheckouts()[0].GetSizeBytes() != 4096 ||
		got.GetCheckouts()[0].GetDisposition() != pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_WOULD_REMOVE {
		t.Errorf("decoded = %v", got)
	}
}

func TestHTTPSweepBoxRunCheckouts_NotFound(t *testing.T) {
	t.Run("old daemon without the route is Unimplemented", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		c, _ := NewHTTPClient(srv.URL, "tok")
		if _, err := c.SweepBoxRunCheckouts(&pb.SweepBoxRunCheckoutsRequest{Username: "alice"}); status.Code(err) != codes.Unimplemented {
			t.Fatalf("err = %v, want Unimplemented", err)
		}
	})
	t.Run("a gateway NOT_FOUND (no such box) is not Unimplemented", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"no box for \"alice\""}`))
		}))
		defer srv.Close()
		c, _ := NewHTTPClient(srv.URL, "tok")
		_, err := c.SweepBoxRunCheckouts(&pb.SweepBoxRunCheckoutsRequest{Username: "alice"})
		if err == nil || status.Code(err) == codes.Unimplemented {
			t.Fatalf("err = %v", err)
		}
	})
}
