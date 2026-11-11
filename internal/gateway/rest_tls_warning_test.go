package gateway

import (
	"strings"
	"testing"
)

// #3522: the REST listener serves plain HTTP. A bind reachable from off the
// host with no declared TLS terminator in front of it must warn at startup;
// a loopback bind or a declared terminator must not.

func TestRESTTLSWarning_NonLoopbackWithoutTerminatorWarns(t *testing.T) {
	for _, addr := range []string{
		":8080",           // the daemon's default bind: all interfaces
		"0.0.0.0:8080",    // IPv4 unspecified
		"[::]:8080",       // IPv6 unspecified, as a bound listener reports ":8080"
		"192.0.2.10:8080", // a specific non-loopback address (TEST-NET-1)
		"example.com:8080",
	} {
		w := RESTTLSWarning(addr, false)
		if w == "" {
			t.Errorf("RESTTLSWarning(%q, false) = \"\", want a warning", addr)
			continue
		}
		if !strings.Contains(w, "--rest-tls-terminator") {
			t.Errorf("RESTTLSWarning(%q, false) = %q, want it to name --rest-tls-terminator", addr, w)
		}
		if !strings.Contains(w, addr) {
			t.Errorf("RESTTLSWarning(%q, false) = %q, want it to name the bound address", addr, w)
		}
	}
}

func TestRESTTLSWarning_LoopbackIsSilent(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "127.0.0.53:8080", "[::1]:8080", "localhost:8080"} {
		for _, declared := range []bool{false, true} {
			if w := RESTTLSWarning(addr, declared); w != "" {
				t.Errorf("RESTTLSWarning(%q, %v) = %q, want no warning for a loopback bind", addr, declared, w)
			}
		}
	}
}

func TestRESTTLSWarning_DeclaredTerminatorIsSilent(t *testing.T) {
	for _, addr := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "192.0.2.10:8080"} {
		if w := RESTTLSWarning(addr, true); w != "" {
			t.Errorf("RESTTLSWarning(%q, true) = %q, want no warning once a terminator is declared", addr, w)
		}
	}
}
