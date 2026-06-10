//go:build embed_bpf

package netbpf

import _ "embed"

// bpfObject is the compiled netpolicy BPF object, baked into the binary at build
// time. It is populated only when building with `-tags embed_bpf`, which the
// release pipeline enables after `make build-bpf` has compiled the object into
// internal/netbpf/netpolicy.bpf.o (the file is gitignored — built, never
// committed). A normal `go build` (no tag) compiles embed_stub.go instead, so
// developers don't need a BPF toolchain.
//
//go:embed netpolicy.bpf.o
var bpfObject []byte

// EmbeddedObject returns the BPF object compiled into this binary, or nil if
// this build did not embed one.
func EmbeddedObject() []byte { return bpfObject }
