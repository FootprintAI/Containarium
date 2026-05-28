package containariumotel

import (
	"regexp"
	"testing"
)

// semverish accepts the relaxed versions Containarium tags use
// (0.20.0, 0.20.0-rc.1, 0.20.0+sha.abcd). Whatever the VERSION file
// says, the parsed `version` should look like a version.
var semverish = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-.+][\w.-]+)?$`)

func TestVersion_NonEmpty(t *testing.T) {
	if version == "" {
		t.Fatal("version is empty — VERSION file may not have been embedded")
	}
}

func TestVersion_LooksLikeVersion(t *testing.T) {
	if !semverish.MatchString(version) {
		t.Errorf("version %q doesn't look like a version string", version)
	}
}

func TestVersion_TrimmedOfTrailingNewline(t *testing.T) {
	// The embedded VERSION file ships with a trailing newline (POSIX
	// text-file convention). The trimming step in version.go should
	// produce a clean version with no whitespace.
	if version != trimTest(version) {
		t.Errorf("version %q has untrimmed whitespace", version)
	}
}

func trimTest(s string) string {
	// Mirror of strings.TrimSpace's behavior; deliberate to detect
	// regressions in version.go's trim logic without re-importing.
	for len(s) > 0 && isSpace(s[0]) {
		s = s[1:]
	}
	for len(s) > 0 && isSpace(s[len(s)-1]) {
		s = s[:len(s)-1]
	}
	return s
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
