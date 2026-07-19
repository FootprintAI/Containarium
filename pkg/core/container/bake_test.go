package container

import "testing"

// TestBakedImageAliasFor pins the alias derivation: deterministic, and free
// of ":" and "/" so the incus client resolves it as a LOCAL alias (a ":"
// would read as a remote prefix, a "/" as a simplestreams path — either
// would silently turn the fast path into a network pull).
func TestBakedImageAliasFor(t *testing.T) {
	cases := []struct {
		image string
		want  string
	}{
		{"images:ubuntu/24.04", "containarium-base-images-ubuntu-24-04"},
		{"ubuntu:24.04", "containarium-base-ubuntu-24-04"},
		{"ubuntu/24.04", "containarium-base-ubuntu-24-04"},
		{"UBUNTU/24.04", "containarium-base-ubuntu-24-04"},
	}
	for _, c := range cases {
		got := BakedImageAliasFor(c.image)
		if got != c.want {
			t.Errorf("BakedImageAliasFor(%q) = %q, want %q", c.image, got, c.want)
		}
		for _, forbidden := range []byte{':', '/'} {
			for i := 0; i < len(got); i++ {
				if got[i] == forbidden {
					t.Errorf("alias %q contains %q — would not resolve as a local alias", got, string(forbidden))
				}
			}
		}
	}
}

// TestBakedImageMatches pins the fast-path gate: only an image explicitly
// baked for this exact (source, podman) combination is substituted — a bake
// for a different source or podman setting, or an image merely carrying the
// alias without the marker property, must never be silently reused.
func TestBakedImageMatches(t *testing.T) {
	baked := map[string]string{
		bakedPropBaked:  "true",
		bakedPropSource: "images:ubuntu/24.04",
		bakedPropPodman: "true",
	}

	if !bakedImageMatches(baked, "images:ubuntu/24.04", true) {
		t.Error("exact match must be accepted")
	}
	if bakedImageMatches(baked, "images:ubuntu/22.04", true) {
		t.Error("different source image must be rejected")
	}
	if bakedImageMatches(baked, "images:ubuntu/24.04", false) {
		t.Error("different podman setting must be rejected")
	}
	if bakedImageMatches(map[string]string{
		bakedPropSource: "images:ubuntu/24.04",
		bakedPropPodman: "true",
	}, "images:ubuntu/24.04", true) {
		t.Error("missing baked marker must be rejected")
	}
	if bakedImageMatches(nil, "images:ubuntu/24.04", true) {
		t.Error("nil properties must be rejected")
	}
}
