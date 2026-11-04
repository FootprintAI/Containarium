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
	"google.golang.org/protobuf/encoding/protojson"
)

func TestHTTPApplyBoxSkillSets(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"skillSets":["qa","sdlc"],"installed":[{"skillSet":"qa","skills":["qa-sprint-verify"],"futureField":1}],"removed":[],"unchanged":false,"release":"v0.127.0"}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.ApplyBoxSkillSets(&pb.ApplyBoxSkillSetsRequest{Username: "alice", SkillSets: []string{"sdlc", "qa"}})
	if err != nil {
		t.Fatalf("ApplyBoxSkillSets: %v", err)
	}
	// protojson's whitespace is deliberately unstable, so the body is decoded
	// rather than matched as text.
	var sent pb.ApplyBoxSkillSetsRequest
	if err := protojson.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatalf("request body %q: %v", gotBody, err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/containers/alice/skill-sets:apply" || sent.GetUsername() != "alice" || strings.Join(sent.GetSkillSets(), ",") != "sdlc,qa" {
		t.Errorf("request = %s %s %s", gotMethod, gotPath, gotBody)
	}
	if len(got.GetSkillSets()) != 2 || len(got.GetInstalled()) != 1 || got.GetInstalled()[0].GetSkillSet() != "qa" ||
		got.GetInstalled()[0].GetSkills()[0] != "qa-sprint-verify" || got.GetUnchanged() || got.GetRelease() != "v0.127.0" {
		t.Errorf("decoded = %v", got)
	}
}

func TestHTTPApplyBoxSkillSets_NotFound(t *testing.T) {
	t.Run("old daemon without the route is Unimplemented", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		c, _ := NewHTTPClient(srv.URL, "tok")
		if _, err := c.ApplyBoxSkillSets(&pb.ApplyBoxSkillSetsRequest{Username: "alice"}); status.Code(err) != codes.Unimplemented {
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
		_, err := c.ApplyBoxSkillSets(&pb.ApplyBoxSkillSetsRequest{Username: "alice"})
		if err == nil || status.Code(err) == codes.Unimplemented {
			t.Fatalf("err = %v", err)
		}
	})
}
