package transfer

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// buildChangedTar writes a gzipped tar of the named files (paths
// forward-slash-relative to root) to w. Returns the number of bytes
// written.
//
// Mode bits and timestamps are preserved — important for executables.
// Directories aren't written explicitly; tar's extract creates them as
// needed when files in them arrive (tar honors leading-path mkdir
// implicitly).
func buildChangedTar(root string, paths []string, w io.Writer) (int64, error) {
	cw := &countingWriter{w: w}
	gz := gzip.NewWriter(cw)
	tw := tar.NewWriter(gz)

	for _, rel := range paths {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(abs)
		if err != nil {
			return 0, fmt.Errorf("stat %s: %w", abs, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return 0, fmt.Errorf("tar header %s: %w", abs, err)
		}
		hdr.Name = rel // forward-slash relative path

		if err := tw.WriteHeader(hdr); err != nil {
			return 0, fmt.Errorf("write header %s: %w", abs, err)
		}

		f, err := os.Open(abs) // #nosec G304 -- abs is constructed from root + a path obtained from our manifest, which we ourselves walked.
		if err != nil {
			return 0, fmt.Errorf("open %s: %w", abs, err)
		}
		if _, err := io.Copy(tw, f); err != nil {
			_ = f.Close()
			return 0, fmt.Errorf("copy %s: %w", abs, err)
		}
		_ = f.Close()
	}

	if err := tw.Close(); err != nil {
		return 0, fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return 0, fmt.Errorf("close gzip: %w", err)
	}
	return cw.n, nil
}

// countingWriter wraps an io.Writer and counts bytes for the byte-shipped
// metric in SyncResult.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
