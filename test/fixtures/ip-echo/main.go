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
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "remote_addr=%s\n", r.RemoteAddr)
		fmt.Fprintf(w, "x_forwarded_for=%s\n", r.Header.Get("X-Forwarded-For"))
		fmt.Fprintf(w, "x_real_ip=%s\n", r.Header.Get("X-Real-IP"))
		fmt.Fprintf(w, "host=%s\n", r.Host)
	})

	log.Printf("[ip-echo] listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
