package netbpf

import (
	"strings"
	"testing"
)

// In the default (untagged) test build, embed_stub.go is compiled, so no object
// is baked in.
func TestEmbeddedObject_NilWithoutTag(t *testing.T) {
	if obj := EmbeddedObject(); obj != nil {
		t.Errorf("EmbeddedObject() = %d bytes, want nil in an untagged build", len(obj))
	}
}

// Resolve("embedded") must fail clearly (not panic / not attempt a load) when the
// binary has no embedded object — guiding the operator to a path or a tagged
// build. This is checked before any kernel/rlimit interaction, so it is safe on
// every platform.
func TestResolve_EmbeddedAbsentErrors(t *testing.T) {
	for _, mode := range []string{"embedded", "1", "TRUE", " on "} {
		_, err := Resolve(mode)
		if err == nil {
			t.Fatalf("Resolve(%q) = nil error, want a no-embedded-object error", mode)
		}
		if !strings.Contains(err.Error(), "no embedded BPF object") {
			t.Errorf("Resolve(%q) error = %q, want it to mention the missing embedded object", mode, err)
		}
	}
}

// A non-keyword value is treated as a filesystem path; a missing file surfaces a
// stat error naming the path rather than the embedded-object error.
func TestResolve_PathValueIsLoadedAsFile(t *testing.T) {
	_, err := Resolve("/no/such/netpolicy.bpf.o")
	if err == nil {
		t.Fatal("Resolve(path) = nil error, want a stat error for a missing file")
	}
	if strings.Contains(err.Error(), "no embedded BPF object") {
		t.Errorf("Resolve(path) took the embedded branch: %v", err)
	}
}
