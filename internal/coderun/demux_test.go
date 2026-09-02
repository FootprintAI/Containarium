package coderun

import (
	"bytes"
	"testing"

	"github.com/footprintai/containarium/internal/logframe"
)

func TestDemuxWriter_RoutesEachStream(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := NewDemuxWriter(&stdout, &stderr)

	var framed bytes.Buffer
	framed.Write(logframe.EncodeFrame(logframe.Stdout, []byte("out-a")))
	framed.Write(logframe.EncodeFrame(logframe.Stderr, []byte("err-a")))
	framed.Write(logframe.EncodeFrame(logframe.Stdout, []byte("out-b")))

	if _, err := w.Write(framed.Bytes()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if stdout.String() != "out-aout-b" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "out-aout-b")
	}
	if stderr.String() != "err-a" {
		t.Errorf("stderr = %q, want %q", stderr.String(), "err-a")
	}
}

// TestDemuxWriter_SplitAcrossChunks mirrors how StreamOutput actually
// drives a Writer: whatever byte range tail_log returned, not
// frame-aligned by construction.
func TestDemuxWriter_SplitAcrossChunks(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := NewDemuxWriter(&stdout, &stderr)

	var framed bytes.Buffer
	framed.Write(logframe.EncodeFrame(logframe.Stdout, []byte("hello")))
	framed.Write(logframe.EncodeFrame(logframe.Stderr, []byte("world")))
	full := framed.Bytes()

	split := len(full) / 2
	if _, err := w.Write(full[:split]); err != nil {
		t.Fatalf("Write(first half): %v", err)
	}
	if _, err := w.Write(full[split:]); err != nil {
		t.Fatalf("Write(second half): %v", err)
	}
	if stdout.String() != "hello" || stderr.String() != "world" {
		t.Errorf("stdout=%q stderr=%q, want hello/world", stdout.String(), stderr.String())
	}
}
