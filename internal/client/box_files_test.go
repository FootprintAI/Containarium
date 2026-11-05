package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #3548: PutBoxFile is the shared half of `containarium code put-file` and the
// platform MCP tool put_file.

type fakeBoxFileWriter struct {
	calls int
	got   *pb.WriteBoxFileRequest
	resp  *pb.WriteBoxFileResponse
	err   error
}

func (f *fakeBoxFileWriter) WriteBoxFile(req *pb.WriteBoxFileRequest) (*pb.WriteBoxFileResponse, error) {
	f.calls++
	f.got = req
	return f.resp, f.err
}

// sha256("hello")
const helloSHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

func TestPutBoxFile_SendsTheRequest(t *testing.T) {
	t.Run("checksum computed when not given", func(t *testing.T) {
		f := &fakeBoxFileWriter{resp: &pb.WriteBoxFileResponse{Path: "/home/alice/in/a.txt", Size: 5, Sha256: helloSHA}}
		resp, err := PutBoxFile(f, BoxFileParams{Box: "alice", Path: "in/a.txt", Content: []byte("hello")})
		if err != nil {
			t.Fatalf("PutBoxFile: %v", err)
		}
		if f.got.GetUsername() != "alice" || f.got.GetPath() != "in/a.txt" || string(f.got.GetContent()) != "hello" || f.got.GetSha256() != helloSHA || f.got.GetMode() != "" {
			t.Errorf("request = %v", f.got)
		}
		if resp.GetPath() != "/home/alice/in/a.txt" {
			t.Errorf("resp = %v", resp)
		}
	})
	t.Run("caller's checksum and mode are sent as given", func(t *testing.T) {
		other := strings.Repeat("a", 64)
		f := &fakeBoxFileWriter{resp: &pb.WriteBoxFileResponse{}}
		if _, err := PutBoxFile(f, BoxFileParams{Box: "alice", Path: "a", Content: []byte("hello"), Mode: "0400", SHA256: other}); err != nil {
			t.Fatal(err)
		}
		if f.got.GetSha256() != other || f.got.GetMode() != "0400" {
			t.Errorf("request = %v", f.got)
		}
	})
	t.Run("an empty file is a file", func(t *testing.T) {
		f := &fakeBoxFileWriter{resp: &pb.WriteBoxFileResponse{}}
		if _, err := PutBoxFile(f, BoxFileParams{Box: "alice", Path: "empty"}); err != nil {
			t.Fatal(err)
		}
		if f.calls != 1 {
			t.Errorf("calls = %d", f.calls)
		}
	})
}

func TestPutBoxFile_InvalidInputSendsNoRequest(t *testing.T) {
	cases := map[string]BoxFileParams{
		"bad box":      {Box: "../etc", Path: "a"},
		"empty box":    {Path: "a"},
		"empty path":   {Box: "alice"},
		"over the cap": {Box: "alice", Path: "a", Content: make([]byte, coderun.MaxBoxFileBytes+1)},
		"bad mode":     {Box: "alice", Path: "a", Mode: "0644"},
		"short sha256": {Box: "alice", Path: "a", SHA256: "abc"},
		"upper sha256": {Box: "alice", Path: "a", SHA256: strings.Repeat("A", 64)},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeBoxFileWriter{}
			if _, err := PutBoxFile(f, p); err == nil {
				t.Fatal("accepted")
			}
			if f.calls != 0 {
				t.Errorf("%d requests sent", f.calls)
			}
		})
	}
}

func TestPutBoxFile_TypedRefusals(t *testing.T) {
	for _, c := range []codes.Code{codes.InvalidArgument, codes.DataLoss, codes.FailedPrecondition, codes.PermissionDenied, codes.NotFound, codes.ResourceExhausted} {
		t.Run(c.String(), func(t *testing.T) {
			f := &fakeBoxFileWriter{err: status.Error(c, "daemon words")}
			_, err := PutBoxFile(f, BoxFileParams{Box: "alice", Path: "a", Content: []byte("x")})
			var refused *BoxFileRefusedError
			if !errors.As(err, &refused) {
				t.Fatalf("err = %v, want *BoxFileRefusedError", err)
			}
			if refused.Code != c || refused.Message != "daemon words" || refused.Path != "a" {
				t.Errorf("refusal = %+v", refused)
			}
			if !strings.Contains(err.Error(), "refused ("+refused.ReasonName()+")") || !strings.Contains(err.Error(), "daemon words") {
				t.Errorf("message = %q", err.Error())
			}
		})
	}
	if got := (&BoxFileRefusedError{Code: codes.DataLoss}).ReasonName(); got != "DATA_LOSS" {
		t.Errorf("ReasonName = %q, want DATA_LOSS", got)
	}
}

func TestPutBoxFile_FailuresAreNotRefusals(t *testing.T) {
	t.Run("old daemon stays Unimplemented", func(t *testing.T) {
		f := &fakeBoxFileWriter{err: status.Error(codes.Unimplemented, "nope")}
		_, err := PutBoxFile(f, BoxFileParams{Box: "alice", Path: "a"})
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("err = %v, want Unimplemented", err)
		}
	})
	t.Run("transport failure", func(t *testing.T) {
		f := &fakeBoxFileWriter{err: status.Error(codes.Unavailable, "down")}
		_, err := PutBoxFile(f, BoxFileParams{Box: "alice", Path: "a"})
		var refused *BoxFileRefusedError
		if err == nil || errors.As(err, &refused) {
			t.Fatalf("err = %v, want a plain failure", err)
		}
	})
}

func TestRenderBoxFileWrite(t *testing.T) {
	got := RenderBoxFileWrite("alice", &pb.WriteBoxFileResponse{Path: "/home/alice/a", Size: 5, Sha256: helloSHA})
	want := "alice: wrote /home/alice/a (5 bytes, sha256 " + helloSHA + ")\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Over REST the gateway's status body keeps its code, so a refusal is typed on
// either transport.
func TestHTTPWriteBoxFile_RefusalKeepsItsCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":15,"message":"the bytes on the box do not match"}`))
	}))
	defer srv.Close()
	c, _ := NewHTTPClient(srv.URL, "tok")
	_, err := PutBoxFile(c, BoxFileParams{Box: "alice", Path: "a", Content: []byte("x")})
	var refused *BoxFileRefusedError
	if !errors.As(err, &refused) || refused.Code != codes.DataLoss {
		t.Fatalf("err = %v, want a DATA_LOSS refusal", err)
	}
}
