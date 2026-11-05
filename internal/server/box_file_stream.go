package server

import (
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// WriteBoxFileStream (#3548): WriteBoxFile for a file above 2 MiB. The header
// is validated and the caller authorized exactly as for WriteBoxFile; the data
// messages are then piped straight into the same root-made staging file, never
// buffered whole in the daemon, and placeBoxFile does the rest (chown, the box
// user's script, the checksum on the box, the atomic rename). The final path is
// touched only by that script, after every byte has arrived, so a stream that
// breaks, ends early or runs long leaves the staging file at most, and the
// failure path removes it.

const (
	// MaxBoxFileStreamBytes is the largest file WriteBoxFileStream accepts.
	MaxBoxFileStreamBytes = coderun.MaxBoxFileStreamBytes
	// DaemonCapBoxFilesStream: the WriteBoxFileStream RPC (#3548).
	DaemonCapBoxFilesStream = "box_files_stream"
)

// boxFileStreamWriteFunc is the streaming file API seam: write everything r
// yields at path inside the box, failing with r's error if it fails.
type boxFileStreamWriteFunc func(box, path string, r io.Reader, mode string) error

func (s *ContainerServer) boxFileWriteStreamFn() boxFileStreamWriteFunc {
	if s.boxFileWriteStream != nil {
		return s.boxFileWriteStream
	}
	if s.manager == nil {
		return nil
	}
	return s.manager.WriteFileStream
}

// WriteBoxFileStream implements pb.ContainerServiceServer.
func (s *ContainerServer) WriteBoxFileStream(stream pb.ContainerService_WriteBoxFileStreamServer) error {
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "the stream carried no header")
		}
		return boxFileStreamError(err)
	}
	h := first.GetHeader()
	if h == nil {
		return status.Error(codes.InvalidArgument, "the first message must be the header")
	}
	f, err := validateBoxFileTarget(h.GetUsername(), h.GetPath(), h.GetMode(), h.GetSha256())
	if err != nil {
		return err
	}
	if h.GetSize() < 0 || h.GetSize() > MaxBoxFileStreamBytes {
		return status.Errorf(codes.InvalidArgument, "size must be between 0 and %d bytes, got %d", MaxBoxFileStreamBytes, h.GetSize())
	}
	if err := s.authorizeBoxRuns(stream.Context(), h.GetUsername()); err != nil {
		return err
	}
	write := s.boxFileWriteStreamFn()
	if write == nil {
		return status.Error(codes.Unavailable, "no container backend to write a file on")
	}
	r := &boxFileStreamReader{stream: stream, size: h.GetSize()}
	got, err := s.placeBoxFile(f, func(box, stage string) error {
		werr := write(box, stage, r, "0600")
		switch {
		case r.err != nil && !errors.Is(r.err, io.EOF):
			// The stream's own failure, whatever the file API wrapped it in.
			return r.err
		case werr != nil:
			return status.Errorf(codes.Unavailable, "write %s: %v", h.GetPath(), werr)
		case !r.done:
			return status.Errorf(codes.Internal, "the file API stopped reading %s after %d of %d bytes", h.GetPath(), r.read, h.GetSize())
		}
		return nil
	})
	if err != nil {
		return err
	}
	return stream.SendAndClose(&pb.WriteBoxFileStreamResponse{Path: f.dst, Size: h.GetSize(), Sha256: got})
}

// boxFileStreamReader yields the data messages of a stream as one io.Reader of
// exactly size bytes. It reports io.EOF only once size bytes have arrived AND
// the client has closed the stream, so a reader that sees io.EOF has the whole
// file; anything else (short, long, a second header, a broken stream) is a
// status error kept in err.
type boxFileStreamReader struct {
	stream pb.ContainerService_WriteBoxFileStreamServer
	size   int64
	read   int64
	buf    []byte
	err    error
	done   bool
}

func (r *boxFileStreamReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		msg, err := r.stream.Recv()
		switch {
		case errors.Is(err, io.EOF) && r.read == r.size:
			r.done, r.err = true, io.EOF
			continue
		case errors.Is(err, io.EOF):
			r.err = status.Errorf(codes.InvalidArgument, "the stream ended after %d of %d bytes; no file was written", r.read, r.size)
			continue
		case err != nil:
			r.err = boxFileStreamError(err)
			continue
		case msg.GetHeader() != nil:
			r.err = status.Error(codes.InvalidArgument, "only the first message may be a header; no file was written")
			continue
		}
		d := msg.GetData()
		if int64(len(d)) > r.size-r.read {
			r.err = status.Errorf(codes.InvalidArgument, "the stream carries more than the declared %d bytes; no file was written", r.size)
			continue
		}
		r.read += int64(len(d))
		r.buf = d
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// boxFileStreamError keeps a stream failure's status code (Canceled when the
// client gave up, DeadlineExceeded) and calls anything else Unavailable.
func boxFileStreamError(err error) error {
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return status.Errorf(st.Code(), "the stream failed: %s; no file was written", st.Message())
	}
	return status.Error(codes.Unavailable, fmt.Sprintf("the stream failed: %v; no file was written", err))
}
