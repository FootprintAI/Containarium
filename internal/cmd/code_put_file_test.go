package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeBoxFileWriter struct {
	got  *pb.WriteBoxFileRequest
	resp *pb.WriteBoxFileResponse
	err  error
}

func (f *fakeBoxFileWriter) WriteBoxFile(req *pb.WriteBoxFileRequest) (*pb.WriteBoxFileResponse, error) {
	f.got = req
	return f.resp, f.err
}

func TestCodePutFile_SendsContentAndChecksum(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "brief.md")
	if err := os.WriteFile(local, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeBoxFileWriter{resp: &pb.WriteBoxFileResponse{Path: "/home/alice/in/brief.md", Size: 5, Sha256: "deadbeef"}}
	var out bytes.Buffer
	if err := codePutFile(f, "alice", local, "in/brief.md", &out); err != nil {
		t.Fatalf("codePutFile: %v", err)
	}
	// sha256("hello")
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if f.got.GetUsername() != "alice" || f.got.GetPath() != "in/brief.md" || string(f.got.GetContent()) != "hello" || f.got.GetSha256() != want {
		t.Errorf("request = %v", f.got)
	}
	if !strings.Contains(out.String(), "/home/alice/in/brief.md") || !strings.Contains(out.String(), "5 bytes") {
		t.Errorf("output = %q", out.String())
	}
}

func TestCodePutFile_DefaultsTheRemotePathToTheBaseName(t *testing.T) {
	local := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(local, []byte("a,b"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeBoxFileWriter{resp: &pb.WriteBoxFileResponse{}}
	if err := codePutFile(f, "alice", local, "", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if f.got.GetPath() != "data.csv" {
		t.Errorf("path = %q, want data.csv", f.got.GetPath())
	}
}

func TestCodePutFile_RefusesAnOversizedFileBeforeTheCall(t *testing.T) {
	local := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(local, make([]byte, coderun.MaxBoxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeBoxFileWriter{}
	if err := codePutFile(f, "alice", local, "big.bin", &bytes.Buffer{}); err == nil {
		t.Fatal("want an error for a file over the limit")
	}
	if f.got != nil {
		t.Error("the RPC was called for an oversized file")
	}
}

func TestCodePutFile_OldDaemonSaysSo(t *testing.T) {
	local := filepath.Join(t.TempDir(), "a.txt")
	_ = os.WriteFile(local, []byte("x"), 0o600)
	f := &fakeBoxFileWriter{err: status.Error(codes.Unimplemented, "nope")}
	err := codePutFile(f, "alice", local, "a.txt", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "WriteBoxFile") {
		t.Fatalf("err = %v, want a message naming WriteBoxFile", err)
	}
}
