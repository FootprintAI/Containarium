package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestHTTPWriteBoxFile(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"path":"/home/alice/a/b.txt","size":"3","sha256":"abc","futureField":1}`))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.WriteBoxFile(&pb.WriteBoxFileRequest{Username: "alice", Path: "a/b.txt", Content: []byte("hey")})
	if err != nil {
		t.Fatalf("WriteBoxFile: %v", err)
	}
	var sent pb.WriteBoxFileRequest
	if err := protojson.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatalf("request body %q: %v", gotBody, err)
	}
	if gotMethod != http.MethodPut || gotPath != "/v1/containers/alice/files" || sent.GetPath() != "a/b.txt" || string(sent.GetContent()) != "hey" {
		t.Errorf("request = %s %s %s", gotMethod, gotPath, gotBody)
	}
	if got.GetPath() != "/home/alice/a/b.txt" || got.GetSize() != 3 || got.GetSha256() != "abc" {
		t.Errorf("decoded = %v", got)
	}
}

func TestHTTPWriteBoxFile_Errors(t *testing.T) {
	t.Run("old daemon without the route is Unimplemented", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		c, _ := NewHTTPClient(srv.URL, "tok")
		if _, err := c.WriteBoxFile(&pb.WriteBoxFileRequest{Username: "alice", Path: "a"}); status.Code(err) != codes.Unimplemented {
			t.Fatalf("err = %v, want Unimplemented", err)
		}
	})
	t.Run("a typed refusal is not Unimplemented", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":3,"message":"path must be relative"}`))
		}))
		defer srv.Close()
		c, _ := NewHTTPClient(srv.URL, "tok")
		_, err := c.WriteBoxFile(&pb.WriteBoxFileRequest{Username: "alice", Path: "/x"})
		if err == nil || status.Code(err) == codes.Unimplemented {
			t.Fatalf("err = %v, want the refusal", err)
		}
	})
}
