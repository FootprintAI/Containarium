package coderun

import (
	"io"

	"github.com/footprintai/containarium/internal/logframe"
)

// DemuxWriter decodes a framed (CaptureFramed) byte stream and routes each
// frame's payload to the matching underlying writer, in arrival order — the
// bytes routed to stdout (or to stderr) concatenate back into that
// stream's original content exactly, regardless of how the framed bytes
// were chunked across separate Write calls. Pass it as StreamOutput's w
// when a run's capture_mode is "framed"; pass the plain stdout writer
// directly when it's "combined".
type DemuxWriter struct {
	stdout, stderr io.Writer
	d              logframe.Demuxer
}

// NewDemuxWriter returns a DemuxWriter routing decoded stdout frames to
// stdout and stderr frames to stderr.
func NewDemuxWriter(stdout, stderr io.Writer) *DemuxWriter {
	return &DemuxWriter{stdout: stdout, stderr: stderr}
}

func (w *DemuxWriter) Write(p []byte) (int, error) {
	frames, err := w.d.Write(p)
	for _, f := range frames {
		dst := w.stdout
		if f.Stream == logframe.Stderr {
			dst = w.stderr
		}
		if _, werr := dst.Write(f.Payload); werr != nil {
			return 0, werr
		}
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
