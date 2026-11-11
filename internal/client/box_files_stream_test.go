package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #3548: PutBoxFileStream is the shared half of `code put-file` above 2 MiB.
// The transport tests run a real gRPC server, and for REST the real gateway
// streaming handler in front of it (RegisterContainerServiceHandlerFromEndpoint:
// the in-process handler cannot stream), so the chunking, the NDJSON body and
// the early-refusal path are exercised end to end.

type fakeBoxFileStreamServer struct {
	pb.UnimplementedContainerServiceServer
	refuseOnHeader error // returned as soon as the header arrives
	refuseAtEnd    error // returned after the whole stream

	mu       sync.Mutex
	header   *pb.WriteBoxFileStreamHeader
	data     []byte
	chunks   int
	cleanEnd bool  // the client closed the stream (io.EOF)
	endErr   error // what Recv ended with otherwise
}

func (f *fakeBoxFileStreamServer) WriteBoxFileStream(s pb.ContainerService_WriteBoxFileStreamServer) error {
	for {
		m, err := s.Recv()
		f.mu.Lock()
		switch {
		case errors.Is(err, io.EOF):
			f.cleanEnd = true
		case err != nil:
			f.endErr = err
		case m.GetHeader() != nil:
			f.header = m.GetHeader()
		default:
			f.data = append(f.data, m.GetData()...)
			f.chunks++
		}
		f.mu.Unlock()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			break
		}
		if m.GetHeader() != nil && f.refuseOnHeader != nil {
			return f.refuseOnHeader
		}
	}
	if f.refuseAtEnd != nil {
		return f.refuseAtEnd
	}
	sum := sha256.Sum256(f.data)
	return s.SendAndClose(&pb.WriteBoxFileStreamResponse{
		Path: "/home/" + f.header.GetUsername() + "/" + f.header.GetPath(), Size: int64(len(f.data)), Sha256: hex.EncodeToString(sum[:]),
	})
}

func (f *fakeBoxFileStreamServer) snapshot() (h *pb.WriteBoxFileStreamHeader, data []byte, chunks int, clean bool, endErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.header, append([]byte(nil), f.data...), f.chunks, f.cleanEnd, f.endErr
}

func boxFileStreamTransports(t *testing.T, newFake func() *fakeBoxFileStreamServer) map[string]struct {
	client BoxFileStreamWriter
	fake   *fakeBoxFileStreamServer
} {
	t.Helper()
	serve := func(f *fakeBoxFileStreamServer) string {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		gs := grpc.NewServer()
		pb.RegisterContainerServiceServer(gs, f)
		go func() { _ = gs.Serve(lis) }()
		t.Cleanup(gs.Stop)
		return lis.Addr().String()
	}
	grpcFake, restFake := newFake(), newFake()
	g, err := NewGRPCClient(serve(grpcFake), "", true)
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	mux := runtime.NewServeMux()
	if err := pb.RegisterContainerServiceHandlerFromEndpoint(context.Background(), mux, serve(restFake),
		[]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}); err != nil {
		t.Fatalf("register gateway: %v", err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	h, err := NewHTTPClient(hs.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return map[string]struct {
		client BoxFileStreamWriter
		fake   *fakeBoxFileStreamServer
	}{"grpc": {g, grpcFake}, "rest": {h, restFake}}
}

// bigBody is a little over 3 MiB with a non-repeating pattern, so a dropped,
// duplicated or reordered chunk changes the bytes.
func bigBody() []byte {
	b := make([]byte, 3<<20+17)
	for i := range b {
		b[i] = byte(i*7 + i/4096)
	}
	return b
}

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestPutBoxFileStream_TransportsDeliverEveryByte(t *testing.T) {
	body := bigBody()
	for name, tr := range boxFileStreamTransports(t, func() *fakeBoxFileStreamServer { return &fakeBoxFileStreamServer{} }) {
		t.Run(name, func(t *testing.T) {
			resp, err := PutBoxFileStream(tr.client, BoxFileStreamParams{
				Box: "alice", Path: "in/big.bin", Content: bytes.NewReader(body), Size: int64(len(body)), Mode: "0400", SHA256: hexSum(body),
			})
			if err != nil {
				t.Fatalf("PutBoxFileStream: %v", err)
			}
			h, data, chunks, clean, _ := tr.fake.snapshot()
			if h.GetUsername() != "alice" || h.GetPath() != "in/big.bin" || h.GetMode() != "0400" || h.GetSha256() != hexSum(body) || h.GetSize() != int64(len(body)) {
				t.Errorf("header = %v", h)
			}
			if !bytes.Equal(data, body) {
				t.Fatalf("server got %d bytes, want the %d sent, in order", len(data), len(body))
			}
			if chunks < 4 || !clean {
				t.Errorf("chunks = %d (want >= 4 at 1 MiB each), clean end = %v", chunks, clean)
			}
			if resp.GetPath() != "/home/alice/in/big.bin" || resp.GetSize() != int64(len(body)) || resp.GetSha256() != hexSum(body) {
				t.Errorf("resp = %v", resp)
			}
		})
	}
}

func TestPutBoxFileStream_RefusalIsTyped(t *testing.T) {
	cases := map[string]func() *fakeBoxFileStreamServer{
		// The daemon refuses on the header while the client is still sending.
		"refused on the header": func() *fakeBoxFileStreamServer {
			return &fakeBoxFileStreamServer{refuseOnHeader: status.Error(codes.InvalidArgument, "path must stay inside the home directory")}
		},
		"checksum mismatch at the end": func() *fakeBoxFileStreamServer {
			return &fakeBoxFileStreamServer{refuseAtEnd: status.Error(codes.DataLoss, "the bytes on the box do not match")}
		},
	}
	body := bigBody()
	for cname, newFake := range cases {
		for name, tr := range boxFileStreamTransports(t, newFake) {
			t.Run(cname+"/"+name, func(t *testing.T) {
				_, err := PutBoxFileStream(tr.client, BoxFileStreamParams{Box: "alice", Path: "a", Content: bytes.NewReader(body), Size: int64(len(body))})
				var refused *BoxFileRefusedError
				if !errors.As(err, &refused) {
					t.Fatalf("err = %v, want *BoxFileRefusedError", err)
				}
				want := status.Code(newFake().refuseOnHeader)
				if want == codes.OK {
					want = status.Code(newFake().refuseAtEnd)
				}
				if refused.Code != want {
					t.Errorf("code = %v, want %v", refused.Code, want)
				}
			})
		}
	}
}

// failingReader yields n bytes and then fails, like a local file that cannot
// be read to the end.
type failingReader struct{ n int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, errors.New("disk read failed")
	}
	k := min(len(p), r.n)
	for i := range p[:k] {
		p[i] = 'x'
	}
	r.n -= k
	return k, nil
}

// A local read error aborts the stream: the daemon never sees a clean end of a
// short stream, and the caller gets the read error.
func TestPutBoxFileStream_ALocalReadErrorAbortsTheStream(t *testing.T) {
	for name, tr := range boxFileStreamTransports(t, func() *fakeBoxFileStreamServer { return &fakeBoxFileStreamServer{} }) {
		t.Run(name, func(t *testing.T) {
			_, err := PutBoxFileStream(tr.client, BoxFileStreamParams{Box: "alice", Path: "a", Content: &failingReader{n: 3 << 19}, Size: 3 << 20})
			if err == nil {
				t.Fatal("want an error")
			}
			var refused *BoxFileRefusedError
			if errors.As(err, &refused) {
				t.Errorf("a local read error is not a refusal: %v", err)
			}
			waitFor(t, func() bool { _, _, _, clean, endErr := tr.fake.snapshot(); return clean || endErr != nil })
			if _, _, _, clean, _ := tr.fake.snapshot(); clean {
				t.Error("the server saw a clean end of a short stream")
			}
		})
	}
}

func TestPutBoxFileStream_InvalidInputSendsNothing(t *testing.T) {
	cases := map[string]BoxFileStreamParams{
		"bad box":      {Box: "../etc", Path: "a", Content: bytes.NewReader(nil)},
		"empty path":   {Box: "alice", Content: bytes.NewReader(nil)},
		"over the cap": {Box: "alice", Path: "a", Content: bytes.NewReader(nil), Size: coderun.MaxBoxFileStreamBytes + 1},
		"negative":     {Box: "alice", Path: "a", Content: bytes.NewReader(nil), Size: -1},
		"bad mode":     {Box: "alice", Path: "a", Content: bytes.NewReader(nil), Mode: "0644"},
		"bad sha256":   {Box: "alice", Path: "a", Content: bytes.NewReader(nil), SHA256: "abc"},
		"no content":   {Box: "alice", Path: "a"},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			f := &countingStreamWriter{}
			if _, err := PutBoxFileStream(f, p); err == nil {
				t.Fatal("accepted")
			}
			if f.calls != 0 {
				t.Errorf("%d calls", f.calls)
			}
		})
	}
}

func TestPutBoxFileStream_OldDaemonStaysUnimplemented(t *testing.T) {
	f := &countingStreamWriter{err: status.Error(codes.Unimplemented, "unknown method")}
	_, err := PutBoxFileStream(f, BoxFileStreamParams{Box: "alice", Path: "a", Content: bytes.NewReader(nil)})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("err = %v, want Unimplemented", err)
	}
}

type countingStreamWriter struct {
	calls int
	err   error
}

func (c *countingStreamWriter) WriteBoxFileStream(*pb.WriteBoxFileStreamHeader, io.Reader) (*pb.WriteBoxFileStreamResponse, error) {
	c.calls++
	return &pb.WriteBoxFileStreamResponse{}, c.err
}

// waitFor polls cond for up to 5s: the server side of an aborted stream ends
// asynchronously from the client's return.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the server to see the stream end")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
