package cmd

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// requireSecureTransportForIdentity refuses to send an age identity — a
// private key — over a cleartext transport to a non-loopback host.
//
// The request body carries the key, so an on-path observer of a plain-HTTP
// (or gRPC --insecure) connection would read it (CWE-319). Cleartext is
// allowed only to loopback, where nothing crosses a network. An empty server
// is left to the client constructor, which reports "--server is required".
//
// Cleartext means: gRPC with --insecure, or --http with an http:// URL. A
// scheme-less --http server counts too, because NewHTTPClient prepends
// "http://" to it.
func requireSecureTransportForIdentity(server string, httpMode, insecureConn bool) error {
	if server == "" {
		return nil
	}
	cleartext := insecureConn
	if httpMode {
		cleartext = !strings.HasPrefix(server, "https://")
	}
	if !cleartext || isLoopbackServer(server) {
		return nil
	}
	return fmt.Errorf("refusing to send the age identity (a private key) to %q over a cleartext connection: "+
		"use an https:// server with --http, or gRPC with mTLS (omit --insecure)", server)
}

// isLoopbackServer reports whether a --server value (host, host:port, or a
// URL) points at the local machine. Only the literal name "localhost" and
// loopback IPs qualify; a lookalike such as "localhost.example.com" does not.
func isLoopbackServer(server string) bool {
	hostport := server
	if strings.Contains(server, "://") {
		u, err := url.Parse(server)
		if err != nil {
			return false
		}
		hostport = u.Host
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
