// ip-echo is a tiny HTTP server that echoes the requester's identity. It is
// used to verify the PROXY protocol path: when placed behind Caddy with the
// proxy_protocol listener wrapper, the response should show the real client
// IP, not the upstream proxy's IP.
package main

import (
	"flag"
	"fmt"
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
		// Echoed verbatim into a text/plain response — there is no HTML
		// rendering path, so the gosec G203 "XSS via taint" finding is a
		// false positive in this test-fixture context.
		fmt.Fprintf(w, "remote_addr=%s\n", r.RemoteAddr)                       // #nosec G203 -- text/plain, no XSS surface
		fmt.Fprintf(w, "x_forwarded_for=%s\n", r.Header.Get("X-Forwarded-For")) // #nosec G203 -- text/plain, no XSS surface
		fmt.Fprintf(w, "x_real_ip=%s\n", r.Header.Get("X-Real-IP"))            // #nosec G203 -- text/plain, no XSS surface
		fmt.Fprintf(w, "host=%s\n", r.Host)                                    // #nosec G203 -- text/plain, no XSS surface
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
