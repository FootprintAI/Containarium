package incus

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/limitio"
	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
)

// #3469: command output and whole-file reads from a box are capped, so a box
// that prints without end or holds a huge file cannot grow the daemon's
// memory without bound.

// repeatReader yields n copies of b, then EOF, without holding n bytes.
func repeatReader(b byte, n int64) io.Reader {
	return io.LimitReader(byteSource(b), n)
}

type byteSource byte

func (s byteSource) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(s)
	}
	return len(p), nil
}

// fakeExecServer implements only ExecInstance: it writes stdoutN bytes of
// 'o' and stderrN bytes of 'e' to the exec args' writers, in chunks, the
// way the Incus client's websocket mirror does.
type fakeExecServer struct {
	incusclient.InstanceServer
	stdoutN, stderrN int64
	exitCode         float64
}

func (f *fakeExecServer) ExecInstance(_ string, _ api.InstanceExecPost, args *incusclient.InstanceExecArgs) (incusclient.Operation, error) {
	if args != nil {
		if _, err := io.Copy(args.Stdout, repeatReader('o', f.stdoutN)); err != nil {
			return nil, err
		}
		if _, err := io.Copy(args.Stderr, repeatReader('e', f.stderrN)); err != nil {
			return nil, err
		}
	}
	return &fakeExecOp{exitCode: f.exitCode}, nil
}

// fakeExecOp answers both Wait and WaitContext so the test does not depend
// on which one the exec helper calls.
type fakeExecOp struct {
	incusclient.Operation
	exitCode float64
}

func (*fakeExecOp) Wait() error                       { return nil }
func (*fakeExecOp) WaitContext(context.Context) error { return nil }
func (o *fakeExecOp) Get() api.Operation {
	return api.Operation{Metadata: map[string]any{"return": o.exitCode}}
}

func TestExecWithOutput_UnderCapUnchanged(t *testing.T) {
	c := &Client{server: &fakeExecServer{stdoutN: 5, stderrN: 3}}
	stdout, stderr, err := c.ExecWithOutput("box", []string{"true"})
	if err != nil {
		t.Fatalf("ExecWithOutput: %v", err)
	}
	if stdout != "ooooo" || stderr != "eee" {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestExecWithOutput_ExactCapIsNotTooLarge(t *testing.T) {
	c := &Client{server: &fakeExecServer{stdoutN: limitio.MaxExecOutputBytes}}
	stdout, _, err := c.ExecWithOutput("box", []string{"true"})
	if err != nil {
		t.Fatalf("ExecWithOutput at exactly the cap: %v", err)
	}
	if int64(len(stdout)) != limitio.MaxExecOutputBytes {
		t.Fatalf("len(stdout) = %d, want %d", len(stdout), limitio.MaxExecOutputBytes)
	}
}

func TestExecWithOutput_StdoutOverCapStopsAtCap(t *testing.T) {
	c := &Client{server: &fakeExecServer{stdoutN: limitio.MaxExecOutputBytes + 1, stderrN: 3}}
	stdout, stderr, err := c.ExecWithOutput("box", []string{"yes"})
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
	if int64(len(stdout)) != limitio.MaxExecOutputBytes {
		t.Fatalf("len(stdout) = %d, want the cap %d", len(stdout), limitio.MaxExecOutputBytes)
	}
	if stderr != "eee" {
		t.Fatalf("stderr = %q, want it unaffected", stderr)
	}
}

func TestExecWithOutput_StderrOverCapStopsAtCap(t *testing.T) {
	c := &Client{server: &fakeExecServer{stderrN: limitio.MaxExecOutputBytes + 1}}
	_, stderr, err := c.ExecWithOutput("box", []string{"yes"})
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
	if int64(len(stderr)) != limitio.MaxExecOutputBytes {
		t.Fatalf("len(stderr) = %d, want the cap %d", len(stderr), limitio.MaxExecOutputBytes)
	}
}

func TestExecWithOutput_NonZeroExitStillReportedWhenOverCap(t *testing.T) {
	c := &Client{server: &fakeExecServer{stdoutN: limitio.MaxExecOutputBytes + 1, exitCode: 2}}
	_, _, err := c.ExecWithOutput("box", []string{"false"})
	if !errors.Is(err, limitio.ErrTooLarge) || !strings.Contains(err.Error(), "exited with code 2") {
		t.Fatalf("err = %v, want both the exit code and limitio.ErrTooLarge", err)
	}
}

func TestExecWithExitCode_UnderCapUnchanged(t *testing.T) {
	c := &Client{server: &fakeExecServer{stdoutN: 4, stderrN: 2, exitCode: 3}}
	stdout, stderr, code, err := c.ExecWithExitCode("box", []string{"sh"})
	if err != nil {
		t.Fatalf("ExecWithExitCode: %v", err)
	}
	if stdout != "oooo" || stderr != "ee" || code != 3 {
		t.Fatalf("stdout=%q stderr=%q code=%d", stdout, stderr, code)
	}
}

func TestExecWithExitCode_OverCapStopsAtCap(t *testing.T) {
	c := &Client{server: &fakeExecServer{stdoutN: limitio.MaxExecOutputBytes + 1, stderrN: limitio.MaxExecOutputBytes + 1, exitCode: 1}}
	stdout, stderr, code, err := c.ExecWithExitCode("box", []string{"yes"})
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
	if int64(len(stdout)) != limitio.MaxExecOutputBytes || int64(len(stderr)) != limitio.MaxExecOutputBytes {
		t.Fatalf("len(stdout)=%d len(stderr)=%d, want both at the cap %d", len(stdout), len(stderr), limitio.MaxExecOutputBytes)
	}
	if code != 1 {
		t.Fatalf("exitCode = %d, want 1 (still reported)", code)
	}
}

// fakeBigFileServer answers every GetInstanceFile with a regular file of n
// bytes, generated on the fly.
type fakeBigFileServer struct {
	incusclient.InstanceServer
	n int64
}

func (f *fakeBigFileServer) GetInstanceFile(_, _ string) (io.ReadCloser, *incusclient.InstanceFileResponse, error) {
	return io.NopCloser(repeatReader('f', f.n)), &incusclient.InstanceFileResponse{Type: "file"}, nil
}

func TestReadFile_ExactCapIsNotTooLarge(t *testing.T) {
	c := &Client{server: &fakeBigFileServer{n: limitio.MaxFileReadBytes}}
	got, err := c.ReadFile("box", "/big")
	if err != nil {
		t.Fatalf("ReadFile at exactly the cap: %v", err)
	}
	if int64(len(got)) != limitio.MaxFileReadBytes {
		t.Fatalf("len = %d, want %d", len(got), limitio.MaxFileReadBytes)
	}
}

func TestReadFile_OverCapStopsAtCap(t *testing.T) {
	c := &Client{server: &fakeBigFileServer{n: limitio.MaxFileReadBytes + 1}}
	got, err := c.ReadFile("box", "/big")
	if !errors.Is(err, limitio.ErrTooLarge) {
		t.Fatalf("err = %v, want limitio.ErrTooLarge", err)
	}
	if !strings.Contains(err.Error(), "/big") {
		t.Fatalf("err = %v, want it to name the file", err)
	}
	if int64(len(got)) > limitio.MaxFileReadBytes {
		t.Fatalf("len = %d, read past the cap %d", len(got), limitio.MaxFileReadBytes)
	}
}

// ReadFileStream is the uncapped path for large transfers: it must keep
// handing back the whole file.
func TestReadFileStream_NotCapped(t *testing.T) {
	c := &Client{server: &fakeBigFileServer{n: limitio.MaxFileReadBytes + 1}}
	r, err := c.ReadFileStream("box", "/big")
	if err != nil {
		t.Fatalf("ReadFileStream: %v", err)
	}
	defer r.Close()
	n, err := io.Copy(io.Discard, r)
	if err != nil || n != limitio.MaxFileReadBytes+1 {
		t.Fatalf("streamed %d bytes, %v; want %d", n, err, limitio.MaxFileReadBytes+1)
	}
}

// Under the cap a command failure comes back exactly as before: the same
// error, not a joined wrapper around it.
func TestExecWithOutput_UnderCapErrorNotWrapped(t *testing.T) {
	c := &Client{server: &fakeExecServer{stdoutN: 5, exitCode: 2}}
	_, _, err := c.ExecWithOutput("box", []string{"false"})
	if err == nil || err.Error() != "command exited with code 2" {
		t.Fatalf("err = %v, want exactly %q", err, "command exited with code 2")
	}
	if _, joined := err.(interface{ Unwrap() []error }); joined {
		t.Fatalf("err = %#v is a joined error; under the cap it must be returned as is", err)
	}
}
