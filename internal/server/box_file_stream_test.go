//go:build !containarium_client

package server

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// WriteBoxFileStream (#3548): WriteBoxFile above 2 MiB. Same harness as the
// unary tests (the root half faked, the box-user script real against a temp
// home), with the stream seam writing the staging file as the bytes arrive.

// fakeBoxFileStream is the server side of one client stream: msgs in order,
// then end (io.EOF by default, or the error a broken stream gives).
type fakeBoxFileStream struct {
	grpc.ServerStream
	ctx  context.Context
	msgs []*pb.WriteBoxFileStreamRequest
	end  error
	resp *pb.WriteBoxFileStreamResponse
}

func (f *fakeBoxFileStream) Context() context.Context { return f.ctx }

func (f *fakeBoxFileStream) Recv() (*pb.WriteBoxFileStreamRequest, error) {
	if len(f.msgs) == 0 {
		if f.end != nil {
			return nil, f.end
		}
		return nil, io.EOF
	}
	m := f.msgs[0]
	f.msgs = f.msgs[1:]
	return m, nil
}

func (f *fakeBoxFileStream) SendAndClose(r *pb.WriteBoxFileStreamResponse) error {
	f.resp = r
	return nil
}

func streamHeader(h *pb.WriteBoxFileStreamHeader) *pb.WriteBoxFileStreamRequest {
	if h.Username == "" {
		h.Username = "alice"
	}
	return &pb.WriteBoxFileStreamRequest{Part: &pb.WriteBoxFileStreamRequest_Header{Header: h}}
}

func streamData(b []byte) *pb.WriteBoxFileStreamRequest {
	return &pb.WriteBoxFileStreamRequest{Part: &pb.WriteBoxFileStreamRequest_Data{Data: b}}
}

// chunked splits b into header + data messages of n bytes.
func chunked(h *pb.WriteBoxFileStreamHeader, b []byte, n int) []*pb.WriteBoxFileStreamRequest {
	msgs := []*pb.WriteBoxFileStreamRequest{streamHeader(h)}
	for len(b) > 0 {
		k := min(n, len(b))
		msgs = append(msgs, streamData(b[:k]))
		b = b[k:]
	}
	return msgs
}

func (h *boxFileHarness) stream(ctx context.Context, msgs []*pb.WriteBoxFileStreamRequest, end error) (*pb.WriteBoxFileStreamResponse, error) {
	f := &fakeBoxFileStream{ctx: ctx, msgs: msgs, end: end}
	err := h.s.WriteBoxFileStream(f)
	return f.resp, err
}

// nothingLeft fails if a file, a temp file beside it, or a staging file exists.
func (h *boxFileHarness) nothingLeft(t *testing.T, rel string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(h.home, rel)); !os.IsNotExist(err) {
		t.Errorf("%s exists: %v", rel, err)
	}
	if left, _ := os.ReadDir(h.stage); len(left) != 0 {
		t.Errorf("staging not cleaned: %v", left)
	}
	if left, _ := os.ReadDir(filepath.Dir(filepath.Join(h.home, rel))); len(left) != 0 {
		t.Errorf("left beside the target: %v", left)
	}
}

func TestWriteBoxFileStream_WritesAFileAboveTheUnaryCap(t *testing.T) {
	h := newBoxFileHarness(t)
	body := bytes.Repeat([]byte("0123456789abcdef"), (MaxBoxFileBytes+MaxBoxFileBytes/2)/16) // 3 MiB
	resp, err := h.stream(tenantCtx("alice"), chunked(&pb.WriteBoxFileStreamHeader{
		Path: "in/big.bin", Size: int64(len(body)), Sha256: sum(body),
	}, body, 1<<20), nil)
	if err != nil {
		t.Fatalf("WriteBoxFileStream: %v", err)
	}
	want := filepath.Join(h.home, "in/big.bin")
	if resp.GetPath() != want || resp.GetSize() != int64(len(body)) || resp.GetSha256() != sum(body) {
		t.Fatalf("resp = %+v", resp)
	}
	got, err := os.ReadFile(want)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("file differs (%d bytes, %v)", len(got), err)
	}
	if st, _ := os.Stat(want); st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
	if left, _ := os.ReadDir(h.stage); len(left) != 0 {
		t.Errorf("staging not cleaned: %v", left)
	}
	if len(h.rootCmds) != 1 || !strings.Contains(h.rootCmds[0], "chown") {
		t.Errorf("root commands = %v, want one chown of the staged file", h.rootCmds)
	}
}

func TestWriteBoxFileStream_ReadOnlyModeAndEmptyFile(t *testing.T) {
	h := newBoxFileHarness(t)
	if _, err := h.stream(tenantCtx("alice"), chunked(&pb.WriteBoxFileStreamHeader{Path: "e", Mode: "0400"}, nil, 1), nil); err != nil {
		t.Fatalf("WriteBoxFileStream: %v", err)
	}
	st, err := os.Stat(filepath.Join(h.home, "e"))
	if err != nil || st.Size() != 0 || st.Mode().Perm() != 0o400 {
		t.Fatalf("file = %v, %v", st, err)
	}
}

func TestWriteBoxFileStream_PartialStreamLeavesNothing(t *testing.T) {
	cases := map[string]struct {
		end  error
		want codes.Code
	}{
		"stream ends short of size": {nil, codes.InvalidArgument},
		"client cancels mid-stream": {status.Error(codes.Canceled, "context canceled"), codes.Canceled},
		"connection breaks":         {io.ErrUnexpectedEOF, codes.Unavailable},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newBoxFileHarness(t)
			body := []byte("0123456789")
			msgs := chunked(&pb.WriteBoxFileStreamHeader{Path: "p/part.bin", Size: 20, Sha256: sum(append(body, body...))}, body, 4)
			_, err := h.stream(tenantCtx("alice"), msgs, c.end)
			if status.Code(err) != c.want {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if len(h.pushed) != 1 {
				t.Fatalf("pushed = %v: the case must reach the staging write", h.pushed)
			}
			h.nothingLeft(t, "p/part.bin")
		})
	}
	// Without a checksum only the declared size tells a short stream apart.
	t.Run("short stream without a checksum", func(t *testing.T) {
		h := newBoxFileHarness(t)
		_, err := h.stream(tenantCtx("alice"), chunked(&pb.WriteBoxFileStreamHeader{Path: "p/part.bin", Size: 20}, []byte("0123456789"), 4), nil)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
		h.nothingLeft(t, "p/part.bin")
	})
}

func TestWriteBoxFileStream_OversizedStreamIsRefused(t *testing.T) {
	t.Run("declared above the cap: refused before the box is touched", func(t *testing.T) {
		h := newBoxFileHarness(t)
		_, err := h.stream(tenantCtx("alice"), []*pb.WriteBoxFileStreamRequest{
			streamHeader(&pb.WriteBoxFileStreamHeader{Path: "big", Size: MaxBoxFileStreamBytes + 1}),
		}, nil)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
		if len(h.pushed) != 0 || len(h.rootCmds) != 0 {
			t.Errorf("the box was touched: pushed %v, root %v", h.pushed, h.rootCmds)
		}
	})
	t.Run("more data than declared: nothing left", func(t *testing.T) {
		h := newBoxFileHarness(t)
		// The stream then breaks instead of closing cleanly, so only the
		// size check made while the data arrives can answer InvalidArgument
		// (a check left to EOF would see the break and answer Unavailable).
		_, err := h.stream(tenantCtx("alice"), chunked(&pb.WriteBoxFileStreamHeader{Path: "o/over.bin", Size: 5}, []byte("0123456789"), 4), io.ErrUnexpectedEOF)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
		h.nothingLeft(t, "o/over.bin")
	})
	t.Run("a data message after the last byte is over", func(t *testing.T) {
		h := newBoxFileHarness(t)
		msgs := chunked(&pb.WriteBoxFileStreamHeader{Path: "o/x", Size: 2}, []byte("ab"), 2)
		msgs = append(msgs, streamData([]byte("c")))
		_, err := h.stream(tenantCtx("alice"), msgs, nil)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("err = %v, want InvalidArgument", err)
		}
		h.nothingLeft(t, "o/x")
	})
}

func TestWriteBoxFileStream_ChecksumMismatchLeavesTheOldFile(t *testing.T) {
	h := newBoxFileHarness(t)
	if err := os.WriteFile(filepath.Join(h.home, "keep.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := []byte("new bytes")
	_, err := h.stream(tenantCtx("alice"), chunked(&pb.WriteBoxFileStreamHeader{Path: "keep.txt", Size: int64(len(body)), Sha256: sum([]byte("other"))}, body, 3), nil)
	if status.Code(err) != codes.DataLoss {
		t.Fatalf("err = %v, want DataLoss", err)
	}
	if got, _ := os.ReadFile(filepath.Join(h.home, "keep.txt")); string(got) != "old" {
		t.Errorf("file = %q, want the old content", got)
	}
	if left, _ := os.ReadDir(h.stage); len(left) != 0 {
		t.Errorf("staging not cleaned: %v", left)
	}
	if left, _ := os.ReadDir(h.home); len(left) != 1 {
		t.Errorf("temp file left beside the target: %v", left)
	}
}

func TestWriteBoxFileStream_RefusesBadHeadersBeforeTouchingTheBox(t *testing.T) {
	cases := map[string][]*pb.WriteBoxFileStreamRequest{
		"no messages":         nil,
		"data first":          {streamData([]byte("x"))},
		"dotdot":              {streamHeader(&pb.WriteBoxFileStreamHeader{Path: "../outside", Size: 1})},
		"dotdot inside":       {streamHeader(&pb.WriteBoxFileStreamHeader{Path: "a/../../outside", Size: 1})},
		"absolute":            {streamHeader(&pb.WriteBoxFileStreamHeader{Path: "/etc/passwd", Size: 1})},
		"ssh dir":             {streamHeader(&pb.WriteBoxFileStreamHeader{Path: ".ssh/authorized_keys", Size: 1})},
		"containarium dir":    {streamHeader(&pb.WriteBoxFileStreamHeader{Path: ".containarium/code.json", Size: 1})},
		"newline":             {streamHeader(&pb.WriteBoxFileStreamHeader{Path: "a\nb", Size: 1})},
		"negative size":       {streamHeader(&pb.WriteBoxFileStreamHeader{Path: "a", Size: -1})},
		"mode 0644":           {streamHeader(&pb.WriteBoxFileStreamHeader{Path: "a", Size: 1, Mode: "0644"})},
		"sha not hex":         {streamHeader(&pb.WriteBoxFileStreamHeader{Path: "a", Size: 1, Sha256: "zz"})},
		"bad username":        {streamHeader(&pb.WriteBoxFileStreamHeader{Username: "a b", Path: "a", Size: 1})},
		"second header later": {streamHeader(&pb.WriteBoxFileStreamHeader{Path: "a", Size: 1}), streamHeader(&pb.WriteBoxFileStreamHeader{Path: "b", Size: 1})},
	}
	for name, msgs := range cases {
		t.Run(name, func(t *testing.T) {
			h := newBoxFileHarness(t)
			if _, err := h.stream(tenantCtx("alice"), msgs, nil); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if name != "second header later" && (len(h.pushed) != 0 || len(h.rootCmds) != 0) {
				t.Errorf("the box was touched: pushed %v, root %v", h.pushed, h.rootCmds)
			}
			h.nothingLeft(t, "a")
		})
	}
}

func TestWriteBoxFileStream_RequiresBoxOwnerOrCollaborator(t *testing.T) {
	h := newBoxFileHarness(t)
	_, err := h.stream(tenantCtx("mallory"), chunked(&pb.WriteBoxFileStreamHeader{Path: "a", Size: 1}, []byte("x"), 1), nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if len(h.pushed) != 0 {
		t.Errorf("a refused caller reached the box")
	}
}

func TestWriteBoxFileStream_AdvertisedAsACapability(t *testing.T) {
	for _, c := range daemonCapabilities() {
		if c == DaemonCapBoxFilesStream {
			return
		}
	}
	t.Fatalf("daemonCapabilities() lacks %q", DaemonCapBoxFilesStream)
}
