package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/age"
)

// DefaultMaxDumpBytes bounds both the stored archive and its plaintext.
// Streaming keeps memory independent of this limit; the limit also bounds
// transfer and staging work for unexpectedly large dumps.
const DefaultMaxDumpBytes int64 = 16 << 30

// WithMaxDumpBytes overrides the 16 GiB archive limit. Non-positive values
// retain the default; there is deliberately no unlimited mode.
func WithMaxDumpBytes(n int64) Option {
	return func(m *Manager) {
		if n > 0 {
			m.maxDumpBytes = n
		}
	}
}

var ErrDumpTooLarge = errors.New("backup dump exceeds size limit")

// boundedReader probes one extra byte at the boundary to distinguish a
// complete stream from a truncated one. In particular, LimitReader alone
// would turn an oversized dump into an apparently successful short dump.
type boundedReader struct {
	mu       sync.Mutex
	r        io.Reader
	limit, n int64
	err      error
	eof      bool
}

func (r *boundedReader) Read(p []byte) (int, error) {
	// HTTP transports may finish a response before their request-body
	// goroutine finishes reading. Keep the completion check race-free.
	r.mu.Lock()
	if len(p) == 0 {
		r.mu.Unlock()
		return 0, nil
	}
	if r.err != nil {
		err := r.err
		r.mu.Unlock()
		return 0, err
	}
	remaining := r.limit - r.n
	r.mu.Unlock()
	// Never hold the state lock across I/O: an early HTTP response must
	// be able to observe an incomplete upload even while Read is blocked.
	if remaining == 0 {
		var extra [1]byte
		n, err := r.r.Read(extra[:])
		if n > 0 {
			err = fmt.Errorf("%w (%d bytes)", ErrDumpTooLarge, r.limit)
		}
		r.mu.Lock()
		if err == io.EOF {
			r.eof = true
		} else if err != nil {
			r.err = err
		}
		r.mu.Unlock()
		return 0, err
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.r.Read(p)
	r.mu.Lock()
	r.n += int64(n)
	if err == io.EOF {
		r.eof = true
	} else if err != nil {
		r.err = err
	}
	r.mu.Unlock()
	return n, err
}

func (r *boundedReader) result() (int64, error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n, r.err, r.eof
}

type boundedWriter struct {
	w        io.Writer
	limit, n int64
	err      error
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.limit-w.n {
		w.err = fmt.Errorf("%w (%d bytes)", ErrDumpTooLarge, w.limit)
		return 0, w.err
	}
	n, err := w.w.Write(p)
	w.n += int64(n)
	if err != nil {
		w.err = err
	}
	return n, err
}

func (m *Manager) stageDump(src io.Reader, id, ext string, recipients []string) (string, int64, string, error) {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return "", 0, "", err
	}
	f, err := os.CreateTemp(m.dir, ".backup-*.tmp")
	if err != nil {
		return "", 0, "", err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	h := sha256.New()
	dst := &boundedWriter{w: io.MultiWriter(f, h), limit: m.maxDumpBytes}
	var out io.Writer = dst
	var encrypted io.WriteCloser
	if len(recipients) > 0 {
		rs := make([]age.Recipient, 0, len(recipients))
		for _, recipient := range recipients {
			r, err := parseRecipient(recipient)
			if err != nil {
				return "", 0, "", err
			}
			rs = append(rs, r)
		}
		encrypted, err = age.Encrypt(dst, rs...)
		if err != nil {
			return "", 0, "", fmt.Errorf("encrypt dump: %w", err)
		}
		out = encrypted
	}
	in := &boundedReader{r: src, limit: m.maxDumpBytes}
	n, err := io.Copy(out, in)
	if err != nil {
		return "", 0, "", fmt.Errorf("stage dump: %w", err)
	}
	if n == 0 {
		return "", 0, "", fmt.Errorf("dump produced an empty archive (backup hook produced no output)")
	}
	if encrypted != nil {
		if err := encrypted.Close(); err != nil {
			return "", 0, "", fmt.Errorf("encrypt dump: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return "", 0, "", err
	}
	name := filepath.Join(m.dir, id+ext)
	if err := os.Rename(f.Name(), name); err != nil {
		return "", 0, "", err
	}
	return name, dst.n, hex.EncodeToString(h.Sum(nil)), nil
}

type fetchedDump struct {
	*os.File
	size   int64
	remove bool
}

func (f *fetchedDump) Close() error {
	err := f.File.Close()
	if f.remove {
		_ = os.Remove(f.Name())
	}
	return err
}

// fetchDump hashes a bounded stream, then rewinds the same open file.
// No bytes reach the target until the entire stored checksum is verified.
// GCS uses a unique temporary file, removed on both success and failure.
func (m *Manager) fetchDump(r *Record) (*fetchedDump, error) {
	if r.SizeBytes < 0 || r.SizeBytes > m.maxDumpBytes {
		return nil, fmt.Errorf("%w: recorded size %d (limit %d)", ErrDumpTooLarge, r.SizeBytes, m.maxDumpBytes)
	}
	name := r.Location
	remove := false
	if r.Destination == DestGCS {
		if m.uploader == nil {
			return nil, fmt.Errorf("cannot read GCS backup: no object-store uploader configured")
		}
		tmp, err := os.CreateTemp(m.dir, ".restore-*.tmp")
		if err != nil {
			return nil, err
		}
		name = tmp.Name()
		dst := &boundedWriter{w: tmp, limit: m.maxDumpBytes}
		downloadErr := m.uploader.DownloadStream(r.Location, dst)
		closeErr := tmp.Close()
		if dst.err != nil {
			downloadErr = dst.err
		}
		if downloadErr == nil {
			downloadErr = closeErr
		}
		if downloadErr != nil {
			_ = os.Remove(name)
			return nil, fmt.Errorf("failed to download %s: %w", r.Location, downloadErr)
		}
		remove = true
	}
	f, err := os.Open(name) // #nosec G304 -- persisted backup location or private staging file
	if err != nil {
		if remove {
			_ = os.Remove(name)
		}
		return nil, fmt.Errorf("failed to read dump %s: %w", name, err)
	}
	dump := &fetchedDump{File: f, remove: remove}
	ok := false
	defer func() {
		if !ok {
			_ = dump.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("backup dump is not a regular file")
	}
	if info.Size() > m.maxDumpBytes {
		return nil, fmt.Errorf("%w (%d bytes)", ErrDumpTooLarge, m.maxDumpBytes)
	}
	h := sha256.New()
	n, err := io.Copy(h, &boundedReader{r: f, limit: m.maxDumpBytes})
	if err != nil {
		return nil, fmt.Errorf("read dump: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != r.SHA256 {
		return nil, fmt.Errorf("dump integrity check failed: sha256 %s != recorded %s (corruption or tampering)", got, r.SHA256)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	dump.size, ok = n, true
	return dump, nil
}

type decryptionError struct{ err error }

func (e *decryptionError) Error() string { return "age decrypt: " + e.err.Error() }
func (e *decryptionError) Unwrap() error { return e.err }

type decryptReader struct{ io.Reader }

func (r decryptReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && err != io.EOF {
		err = &decryptionError{err}
	}
	return n, err
}

// writeDump authenticates encrypted content through EOF before the caller
// runs pg_restore. Only the target container sees plaintext; host staging
// contains ciphertext exclusively. Failed uploads are removed here; the
// caller removes successful staging after use.
func (m *Manager) writeDump(container, path string, src io.Reader, encrypted bool, identity string) (int64, error) {
	if encrypted {
		id, err := age.ParseX25519Identity(strings.TrimSpace(identity))
		if err != nil {
			return 0, &decryptionError{err}
		}
		r, err := age.Decrypt(src, id)
		if err != nil {
			return 0, &decryptionError{err}
		}
		src = decryptReader{r}
	}
	in := &boundedReader{r: src, limit: m.maxDumpBytes}
	complete := false
	defer func() {
		if !complete {
			_ = m.ops.Exec(container, []string{"rm", "-f", path})
		}
	}()
	err := m.ops.WriteFileStream(container, path, in, "0600")
	n, readErr, eof := in.result()
	if readErr != nil {
		return n, readErr
	}
	if err != nil {
		return n, err
	}
	if !eof {
		return n, fmt.Errorf("container file upload did not consume the complete dump")
	}
	complete = true
	return n, nil
}
