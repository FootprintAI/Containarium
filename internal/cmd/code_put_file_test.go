package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
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

	// The streamed form (#3548).
	gotHeader  *pb.WriteBoxFileStreamHeader
	gotStream  []byte
	streamResp *pb.WriteBoxFileStreamResponse
	streamErr  error
}

func (f *fakeBoxFileWriter) WriteBoxFile(req *pb.WriteBoxFileRequest) (*pb.WriteBoxFileResponse, error) {
	f.got = req
	return f.resp, f.err
}

func (f *fakeBoxFileWriter) WriteBoxFileStream(h *pb.WriteBoxFileStreamHeader, content io.Reader) (*pb.WriteBoxFileStreamResponse, error) {
	f.gotHeader = h
	b, err := io.ReadAll(content)
	if err != nil {
		return nil, err
	}
	f.gotStream = b
	if f.streamResp == nil {
		f.streamResp = &pb.WriteBoxFileStreamResponse{}
	}
	return f.streamResp, f.streamErr
}

func TestCodePutFile_SendsContentAndChecksum(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "brief.md")
	if err := os.WriteFile(local, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeBoxFileWriter{resp: &pb.WriteBoxFileResponse{Path: "/home/alice/in/brief.md", Size: 5, Sha256: "deadbeef"}}
	var out bytes.Buffer
	if err := codePutFile(f, "alice", local, "in/brief.md", false, &out); err != nil {
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

func TestCodePutFile_ForRunReachesBothForms(t *testing.T) {
	dir := t.TempDir()
	small, big := filepath.Join(dir, "small"), filepath.Join(dir, "big")
	if err := os.WriteFile(small, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), coderun.MaxBoxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, forRun := range []bool{false, true} {
		f := &fakeBoxFileWriter{resp: &pb.WriteBoxFileResponse{}}
		if err := codePutFile(f, "alice", small, "a", forRun, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if f.got.GetForRun() != forRun {
			t.Errorf("unary: for_run = %v, want %v", f.got.GetForRun(), forRun)
		}
		if err := codePutFile(f, "alice", big, "b", forRun, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if f.gotHeader.GetForRun() != forRun {
			t.Errorf("stream: for_run = %v, want %v", f.gotHeader.GetForRun(), forRun)
		}
	}
}

func TestCodePutFile_DefaultsTheRemotePathToTheBaseName(t *testing.T) {
	local := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(local, []byte("a,b"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeBoxFileWriter{resp: &pb.WriteBoxFileResponse{}}
	if err := codePutFile(f, "alice", local, "", false, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if f.got.GetPath() != "data.csv" {
		t.Errorf("path = %q, want data.csv", f.got.GetPath())
	}
}

// Above the streamed form's cap nothing is sent. (Before #3548's stream the
// limit here was the unary 2 MiB; a file between the two caps now streams.)
func TestCodePutFile_RefusesAnOversizedFileBeforeTheCall(t *testing.T) {
	local := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(local, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(local, coderun.MaxBoxFileStreamBytes+1); err != nil { // sparse
		t.Fatal(err)
	}
	f := &fakeBoxFileWriter{}
	if err := codePutFile(f, "alice", local, "big.bin", false, &bytes.Buffer{}); err == nil {
		t.Fatal("want an error for a file over the limit")
	}
	if f.got != nil || f.gotHeader != nil {
		t.Error("an RPC was called for an oversized file")
	}
}

func TestCodePutFile_StreamsAFileAboveTheUnaryCap(t *testing.T) {
	local := filepath.Join(t.TempDir(), "big.bin")
	body := bytes.Repeat([]byte("abcdefg"), (coderun.MaxBoxFileBytes+100)/7)
	if err := os.WriteFile(local, body, 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeBoxFileWriter{streamResp: &pb.WriteBoxFileStreamResponse{Path: "/home/alice/in/big.bin", Size: int64(len(body)), Sha256: "s"}}
	var out bytes.Buffer
	if err := codePutFile(f, "alice", local, "in/big.bin", false, &out); err != nil {
		t.Fatalf("codePutFile: %v", err)
	}
	if f.got != nil {
		t.Error("the unary RPC was called for a file above its cap")
	}
	sum := sha256.Sum256(body)
	h := f.gotHeader
	if h.GetUsername() != "alice" || h.GetPath() != "in/big.bin" || h.GetSize() != int64(len(body)) || h.GetSha256() != hex.EncodeToString(sum[:]) {
		t.Errorf("header = %v", h)
	}
	if !bytes.Equal(f.gotStream, body) {
		t.Errorf("streamed %d bytes, want the file's %d", len(f.gotStream), len(body))
	}
	if !strings.Contains(out.String(), "/home/alice/in/big.bin") {
		t.Errorf("output = %q", out.String())
	}
}

func TestCodePutFile_AtTheUnaryCapStaysUnary(t *testing.T) {
	local := filepath.Join(t.TempDir(), "edge.bin")
	if err := os.WriteFile(local, make([]byte, coderun.MaxBoxFileBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeBoxFileWriter{resp: &pb.WriteBoxFileResponse{}}
	if err := codePutFile(f, "alice", local, "edge.bin", false, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if f.got == nil || f.gotHeader != nil {
		t.Errorf("unary called = %v, stream called = %v; want unary only", f.got != nil, f.gotHeader != nil)
	}
}

func TestCodePutFile_OldDaemonWithoutTheStreamSaysSo(t *testing.T) {
	local := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(local, make([]byte, coderun.MaxBoxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeBoxFileWriter{streamErr: status.Error(codes.Unimplemented, "unknown method")}
	err := codePutFile(f, "alice", local, "big.bin", false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "box_files_stream") || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("err = %v, want the old-daemon message naming box_files_stream", err)
	}
}

func TestCodePutFile_OldDaemonSaysSo(t *testing.T) {
	local := filepath.Join(t.TempDir(), "a.txt")
	_ = os.WriteFile(local, []byte("x"), 0o600)
	f := &fakeBoxFileWriter{err: status.Error(codes.Unimplemented, "nope")}
	err := codePutFile(f, "alice", local, "a.txt", false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "WriteBoxFile") {
		t.Fatalf("err = %v, want a message naming WriteBoxFile", err)
	}
}
