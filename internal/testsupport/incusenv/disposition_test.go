package incusenv

import "testing"

// The lane's whole value rests on this switch. If DispositionFor ever
// answered Skip where the lane asked for Fail, the Incus job would go green
// on a runner with no Incus — the same shape of check-that-cannot-fail that
// #1234 was filed for, one layer up.
//
// Deliberately untagged, so it runs in the ordinary unit suite: the guarantee
// is worth nothing if it can only be verified on a machine that already has
// the environment it is guarding.
func TestDispositionFor(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  Disposition
	}{
		{"unset is a developer laptop", "", Skip},
		{"the lane sets 1", "1", Fail},
		{"true", "true", Fail},
		{"TRUE is the same answer", "TRUE", Fail},
		{"yes", "yes", Fail},
		{"on", "on", Fail},
		{"surrounding whitespace does not change the answer", " 1 ", Fail},
		// An explicit negative must not be read as "the variable is set,
		// therefore require it" — a lane opting out would otherwise get
		// exactly the opposite of what it asked for.
		{"0 means the operator said no", "0", Skip},
		{"false means the operator said no", "false", Skip},
		// Anything we do not recognise is not an opt-in. Requiring Incus is
		// the stricter behaviour, and guessing a caller into it on a typo
		// turns a laptop run red for no reason.
		{"an unrecognised value is not an opt-in", "maybe", Skip},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DispositionFor(tc.value); got != tc.want {
				t.Errorf("DispositionFor(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// BoxImage decides where every lane test fetches its image from, so it gets a
// test that runs in the ordinary suite — the lane itself cannot check its own
// default, and getting this wrong sends five image fetches per run back to a
// third-party mirror (#1375).
func TestBoxImage(t *testing.T) {
	t.Run("defaults to the public alias", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_LANE_IMAGE", "")
		if got := BoxImage(); got != "images:ubuntu/24.04" {
			t.Errorf("BoxImage() = %q, want the public alias — a developer's laptop has no "+
				"pre-pulled copy and must still work with no setup", got)
		}
	})

	t.Run("honours the override", func(t *testing.T) {
		t.Setenv("CONTAINARIUM_LANE_IMAGE", "lane-box")
		if got := BoxImage(); got != "lane-box" {
			t.Errorf("BoxImage() = %q, want the override — without it CI re-fetches from the "+
				"public mirror on every create, which is what #1375 was filed for", got)
		}
	})
}
