package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	s := newStore(time.Now)
	errs := make(chan error, 2)
	for addr, h := range map[string]http.Handler{mintAddr: mintHandler(s), proxyAddr: proxyHandler(s)} {
		srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		go func() { errs <- srv.ListenAndServe() }()
	}
	// No request logging: nothing here writes a token or a cookie anywhere.
	log.Fatalf("slides-wsauth: %v", <-errs)
}
