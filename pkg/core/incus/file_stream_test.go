package incus

import (
	"errors"
	"io"
	"strings"
	"testing"

	incusclient "github.com/lxc/incus/v7/client"
)

type trackedFileStream struct {
	io.Reader
	reads  int
	closed bool
}

func (r *trackedFileStream) Read(p []byte) (int, error) { r.reads++; return r.Reader.Read(p) }
func (r *trackedFileStream) Close() error               { r.closed = true; return nil }

type streamFileServer struct {
	incusclient.InstanceServer
	body    *trackedFileStream
	replay  bool
	written int64
	mode    int
}

func (s *streamFileServer) GetInstanceFile(string, string) (io.ReadCloser, *incusclient.InstanceFileResponse, error) {
	return s.body, &incusclient.InstanceFileResponse{Type: "file"}, nil
}
func (s *streamFileServer) CreateInstanceFile(_, _ string, args incusclient.InstanceFileArgs) error {
	if s.replay {
		if _, err := args.Content.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	n, err := io.Copy(io.Discard, args.Content)
	s.written, s.mode = n, args.Mode
	return err
}

func TestReadFileStream_TransfersUnreadBodyOwnership(t *testing.T) {
	body := &trackedFileStream{Reader: strings.NewReader("dump bytes")}
	c := &Client{server: &streamFileServer{body: body}}
	r, err := c.ReadFileStream("tenant-container", "/tmp/dump")
	if err != nil {
		t.Fatal(err)
	}
	if body.reads != 0 || body.closed {
		t.Fatal("file was read or closed before caller consumed it")
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "dump bytes" {
		t.Fatalf("body=%q", b)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !body.closed {
		t.Fatal("caller did not receive ownership of response body")
	}
}

func TestReadFileStream_BoundsSymlinkTarget(t *testing.T) {
	s := &fakeFileServer{symlinks: map[string]string{"/link": strings.Repeat("x", 4097)}}
	_, err := (&Client{server: s}).ReadFileStream("tenant-container", "/link")
	if err == nil || !strings.Contains(err.Error(), "4096") {
		t.Fatalf("err=%v", err)
	}
}

func TestWriteFileStream_ReadFailuresAndReplay(t *testing.T) {
	for _, kind := range []string{"normal", "reader-error", "forward-replay", "seekable-replay"} {
		t.Run(kind, func(t *testing.T) {
			s := &streamFileServer{replay: strings.Contains(kind, "replay")}
			c := &Client{server: s}
			r := io.LimitReader(strings.NewReader("dump bytes"), 10)
			if kind == "reader-error" {
				r = io.MultiReader(r, streamReadError{})
			}
			if kind == "seekable-replay" {
				r = strings.NewReader("dump bytes")
			}
			err := c.WriteFileStream("tenant-container", "/tmp/dump", r, "0600")
			wantError := kind == "reader-error" || kind == "forward-replay"
			if (err != nil) != wantError {
				t.Fatalf("err=%v", err)
			}
			if !wantError && (s.written != 10 || s.mode != 0o600) {
				t.Fatalf("written=%d mode=%o", s.written, s.mode)
			}
		})
	}
}

type streamReadError struct{}

func (streamReadError) Read([]byte) (int, error) { return 0, errors.New("stream read failed") }
