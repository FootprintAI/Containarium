// Package httpx holds small net/http helpers shared by the daemon's HTTP
// middleware so the next interface gap (Flusher, Hijacker, ReaderFrom, ...)
// is fixed in one place.
package httpx

import "net/http"

// StatusWriter wraps http.ResponseWriter to capture the status code the
// handler wrote. It is the status-recording writer the audit and metrics
// middleware share.
type StatusWriter struct {
	http.ResponseWriter
	StatusCode int
}

// NewStatusWriter wraps w. StatusCode starts at 200, which is what the server
// sends when the handler never calls WriteHeader.
func NewStatusWriter(w http.ResponseWriter) *StatusWriter {
	return &StatusWriter{ResponseWriter: w, StatusCode: http.StatusOK}
}

// WriteHeader records the status and forwards it.
func (sw *StatusWriter) WriteHeader(code int) {
	sw.StatusCode = code
	sw.ResponseWriter.WriteHeader(code)
}

// Unwrap exposes the underlying writer so http.NewResponseController can
// reach its Flusher/Hijacker. Without it, server-streaming responses (which
// flush after every chunk) fail with http.ErrNotSupported (#2773).
func (sw *StatusWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }
