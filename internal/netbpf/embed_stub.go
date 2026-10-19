//go:build !embed_bpf

package netbpf

// EmbeddedObject returns nil in builds that did not embed a BPF object. The
// release pipeline builds with `-tags embed_bpf` (after `make build-bpf`) to get
// the real object via embed_bpf.go; every other build uses this stub so no BPF
// toolchain or compiled object is required to `go build`.
func EmbeddedObject() []byte { return nil }

// EmbeddedExecObject returns nil in builds that did not embed the execwatch
// object (#2637); same stub rule as EmbeddedObject.
func EmbeddedExecObject() []byte { return nil }
