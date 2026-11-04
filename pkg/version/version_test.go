package version

import "testing"

// TestReleaseTag (#3542): the release tag a build reports is "v" + its
// version, but only when the version is one a release can carry
// (MAJOR.MINOR.PATCH[-prerelease], the shape scripts/ci/validate-release-version.sh
// accepts). Anything else is no tag at all, so nothing downstream composes a
// registry reference that was never published.
func TestReleaseTag(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	for _, tc := range []struct{ version, want string }{
		{"0.129.0", "v0.129.0"},
		{"1.2.3", "v1.2.3"},
		{"0.130.0-rc.1", "v0.130.0-rc.1"},
		{"", ""},
		{"dev", ""},
		{"v0.129.0", "v0.129.0"}, // idempotent: a v-prefixed build version is not prefixed twice
		{"vv0.129.0", ""},
		{"0.129", ""},
		{"01.2.3", ""},
		{"0.129.0-", ""},
		{"0.129.0\n", ""},
		{"0.129.0 extra", ""},
	} {
		Version = tc.version
		if got := ReleaseTag(); got != tc.want {
			t.Errorf("Version=%q: ReleaseTag() = %q, want %q", tc.version, got, tc.want)
		}
	}
}
