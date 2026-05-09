// ip-echo is a tiny HTTP server that echoes the requester's identity. It is
// used to verify the PROXY protocol path: when placed behind Caddy with the
// proxy_protocol listener wrapper, the response should show the real client
// IP, not the upstream proxy's IP.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// Plain key=value lines, written via io.WriteString so the response
		// has no format-string path that could be confused with HTML
		// rendering. Test fixture only — not a user-facing surface.
		writeKV(w, "remote_addr", r.RemoteAddr)
		writeKV(w, "x_forwarded_for", r.Header.Get("X-Forwarded-For"))
		writeKV(w, "x_real_ip", r.Header.Get("X-Real-IP"))
		writeKV(w, "host", r.Host)
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("[ip-echo] listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}

func writeKV(w io.Writer, key, value string) {
	_, _ = io.WriteString(w, key)
	_, _ = io.WriteString(w, "=")
	_, _ = io.WriteString(w, value)
	_, _ = io.WriteString(w, "\n")
}
