// proxyproto-relay is a test fixture that mimics the sentinel's HTTPS
// forwarding path: it accepts TCP connections, optionally prepends a PROXY v2
// header (using the same encoder the sentinel uses), and pipes bytes to a
// backend address. Used for layer-2 verification against a real Caddy with
// the proxy_protocol listener wrapper.
package main

import (
	"flag"
	"io"
	"log"
	"net"

	"github.com/footprintai/containarium/internal/sentinel"
)

func main() {
	listen := flag.String("listen", ":4443", "address to listen on")
	backend := flag.String("backend", "127.0.0.1:8443", "backend to forward to")
	proxyProto := flag.Bool("proxy-protocol", false, "prepend a PROXY v2 header before forwarding")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	log.Printf("[relay] listening on %s, forwarding to %s, proxy_protocol=%v", *listen, *backend, *proxyProto)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go handle(c, *backend, *proxyProto)
	}
}

func handle(client net.Conn, backendAddr string, proxyProto bool) {
	defer client.Close()
	upstream, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("dial backend: %v", err)
		return
	}
	defer upstream.Close()

	if proxyProto {
		src, _ := client.RemoteAddr().(*net.TCPAddr)
		dst, _ := client.LocalAddr().(*net.TCPAddr)
		if src != nil && dst != nil {
			n, err := sentinel.WriteProxyV2(upstream, src, dst)
			if err != nil {
				log.Printf("write PROXY header: %v", err)
				return
			}
			log.Printf("[relay] wrote %d-byte PROXY v2: src=%s dst=%s", n, src, dst)
		}
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}
