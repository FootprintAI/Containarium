package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The streamed form of writing a file into a box (#3548): files above
// coderun.MaxBoxFileBytes, up to coderun.MaxBoxFileStreamBytes, go through
// WriteBoxFileStream as a header and 1 MiB data messages. `code put-file`
// switches to it on its own above 2 MiB.

// BoxFileStreamChunkBytes is the data carried by one stream message: well under
// gRPC's default 4 MiB message cap.
const BoxFileStreamChunkBytes = 1 << 20

// writeBoxFileStreamTimeout bounds one streamed write (64 MiB on a slow link).
const writeBoxFileStreamTimeout = 30 * time.Minute

// BoxFilesStreamUnsupportedMessage is what a caller says to a daemon without
// WriteBoxFileStream when the file is above the unary cap.
var BoxFilesStreamUnsupportedMessage = fmt.Sprintf(
	"this daemon cannot take files above %d bytes (no WriteBoxFileStream, capability box_files_stream); upgrade it, or keep each file at %d bytes or less",
	coderun.MaxBoxFileBytes, coderun.MaxBoxFileBytes)

// BoxFileStreamWriter is what PutBoxFileStream needs from a daemon client; both
// GRPCClient and HTTPClient satisfy it. content yields exactly h.Size bytes.
type BoxFileStreamWriter interface {
	WriteBoxFileStream(h *pb.WriteBoxFileStreamHeader, content io.Reader) (*pb.WriteBoxFileStreamResponse, error)
}

// BoxFileStreamParams is one file to stream. Content must yield exactly Size
// bytes. SHA256 is sent as given (the caller hashes the source; this side
// cannot without reading it twice); empty means the daemon checks the size
// only.
type BoxFileStreamParams struct {
	Box     string
	Path    string
	Content io.Reader
	Size    int64
	Mode    string
	SHA256  string
}

// PutBoxFileStream writes p through c. Errors are sorted as PutBoxFile sorts
// them: Unimplemented as is, a refusal as *BoxFileRefusedError.
func PutBoxFileStream(c BoxFileStreamWriter, p BoxFileStreamParams) (*pb.WriteBoxFileResponse, error) {
	if err := validateBoxFileParams(p.Box, p.Path, p.Mode, p.SHA256); err != nil {
		return nil, err
	}
	switch {
	case p.Content == nil:
		return nil, errors.New("no content to stream")
	case p.Size < 0 || p.Size > coderun.MaxBoxFileStreamBytes:
		return nil, fmt.Errorf("size must be between 0 and %d bytes, got %d", coderun.MaxBoxFileStreamBytes, p.Size)
	}
	resp, err := c.WriteBoxFileStream(&pb.WriteBoxFileStreamHeader{
		Username: p.Box, Path: p.Path, Mode: p.Mode, Sha256: p.SHA256, Size: p.Size,
	}, p.Content)
	if err != nil {
		var local *boxFileLocalReadError
		if errors.As(err, &local) {
			return nil, fmt.Errorf("put %s on %s: %w", p.Path, p.Box, local.err)
		}
		return nil, boxFileError(p.Box, p.Path, err)
	}
	return &pb.WriteBoxFileResponse{Path: resp.GetPath(), Size: resp.GetSize(), Sha256: resp.GetSha256()}, nil
}

// boxFileLocalReadError marks a failure reading the caller's content, so it is
// never taken for a refusal from the daemon.
type boxFileLocalReadError struct{ err error }

func (e *boxFileLocalReadError) Error() string { return "read the local file: " + e.err.Error() }
func (e *boxFileLocalReadError) Unwrap() error { return e.err }

// forEachChunk reads content in chunks and calls send with each; a read error
// is returned as *boxFileLocalReadError.
func forEachChunk(content io.Reader, send func([]byte) error) error {
	buf := make([]byte, BoxFileStreamChunkBytes)
	for {
		n, err := io.ReadFull(content, buf)
		if n > 0 {
			if serr := send(buf[:n]); serr != nil {
				return serr
			}
		}
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return nil
		case err != nil:
			return &boxFileLocalReadError{err: err}
		}
	}
}

// WriteBoxFileStream streams one file into a box user's home (#3548). A local
// read error cancels the stream, so the daemon sees an aborted call, never a
// short one closed cleanly. The daemon's error is returned UNWRAPPED so an
// older daemon surfaces as codes.Unimplemented.
func (c *GRPCClient) WriteBoxFileStream(h *pb.WriteBoxFileStreamHeader, content io.Reader) (*pb.WriteBoxFileStreamResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), writeBoxFileStreamTimeout)
	defer cancel()
	stream, err := c.client.WriteBoxFileStream(ctx)
	if err != nil {
		return nil, err
	}
	// Send returns io.EOF once the daemon has ended the call (a refusal);
	// CloseAndRecv then returns the daemon's real status.
	serverDone := errors.New("the daemon ended the stream")
	send := func(m *pb.WriteBoxFileStreamRequest) error {
		if err := stream.Send(m); err != nil {
			if errors.Is(err, io.EOF) {
				return serverDone
			}
			return err
		}
		return nil
	}
	err = send(&pb.WriteBoxFileStreamRequest{Part: &pb.WriteBoxFileStreamRequest_Header{Header: h}})
	if err == nil {
		err = forEachChunk(content, func(b []byte) error {
			return send(&pb.WriteBoxFileStreamRequest{Part: &pb.WriteBoxFileStreamRequest_Data{Data: b}})
		})
	}
	if err != nil && !errors.Is(err, serverDone) {
		cancel()
		return nil, err
	}
	return stream.CloseAndRecv()
}

// WriteBoxFileStream is the REST form (POST /v1/box-files:stream): the body is
// newline-delimited JSON, the header object and then data objects, written as
// content is read. A local read error aborts the request body, so the gateway
// cancels the call rather than closing it short.
func (c *HTTPClient) WriteBoxFileStream(h *pb.WriteBoxFileStreamHeader, content io.Reader) (*pb.WriteBoxFileStreamResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), writeBoxFileStreamTimeout)
	defer cancel()
	pr, pw := io.Pipe()
	written := make(chan error, 1)
	go func() {
		line := func(m *pb.WriteBoxFileStreamRequest) error {
			b, err := protojson.Marshal(m)
			if err != nil {
				return err
			}
			_, err = pw.Write(append(b, '\n'))
			return err
		}
		err := line(&pb.WriteBoxFileStreamRequest{Part: &pb.WriteBoxFileStreamRequest_Header{Header: h}})
		if err == nil {
			err = forEachChunk(content, func(b []byte) error {
				return line(&pb.WriteBoxFileStreamRequest{Part: &pb.WriteBoxFileStreamRequest_Data{Data: b}})
			})
		}
		_ = pw.CloseWithError(err) // nil closes the body cleanly
		written <- err
	}()
	// localReadErr stops the body writer (the daemon may have answered before
	// reading it all) and reports its local read error, if it had one.
	localReadErr := func() error {
		_ = pr.Close()
		var local *boxFileLocalReadError
		if err := <-written; errors.As(err, &local) {
			return local
		}
		return nil
	}
	resp, err := c.doRequestBody(ctx, http.MethodPost, "/v1/box-files:stream", pr)
	if err != nil {
		if lerr := localReadErr(); lerr != nil {
			return nil, lerr
		}
		return nil, fmt.Errorf("write box file stream: %w", err)
	}
	defer drainClose(resp)
	bodyBytes, _ := io.ReadAll(resp.Body)
	lerr := localReadErr()
	if resp.StatusCode >= 400 {
		if lerr != nil {
			return nil, lerr
		}
		return nil, boxFileHTTPError(resp.StatusCode, bodyBytes, "WriteBoxFileStream")
	}
	out := &pb.WriteBoxFileStreamResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(bytes.TrimSpace(bodyBytes), out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}
