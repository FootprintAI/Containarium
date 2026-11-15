package sdlcskills

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultBaseURL is where signed skills releases are published. Empty: the
// signed source is used only where an operator configures a base URL, and
// everything else takes the skills bundle from the Containarium release
// (docs/design/sdlc-skills-option-b.md).
const DefaultBaseURL = ""

// baseURLPattern is what a skills base URL may be. It is spliced into a
// double-quoted shell string, so the charset has no $, backtick, quote,
// backslash or whitespace.
var baseURLPattern = regexp.MustCompile(`^https?://[A-Za-z0-9][A-Za-z0-9._~:/%+@-]*$`)

// SkillsSource says where a box's skills come from: the signed skills
// releases under a base URL, and optionally which release to move the box
// to. The zero value is "no signed source": the Containarium release's own
// bundle. Build one with NewSkillsSource; its values are then safe to splice
// into InstallScriptFrom.
type SkillsSource struct {
	baseURL, version string
}

// NewSkillsSource validates a base URL and a requested version. version is
// "", a version name or "latest". Empty keeps a box on the skills release it
// has. A version without a base URL is an error: there is nowhere to take it
// from.
func NewSkillsSource(baseURL, version string) (SkillsSource, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	version = strings.TrimSpace(version)
	if baseURL != "" {
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			return SkillsSource{}, fmt.Errorf("skills base URL %q must be an http or https URL", baseURL)
		}
		if !baseURLPattern.MatchString(baseURL) {
			return SkillsSource{}, fmt.Errorf("skills base URL %q is not usable (letters, digits and ._~:/%%+@- only)", baseURL)
		}
	}
	if version != "" && version != LatestVersion && !ValidSkillsVersion(version) {
		return SkillsSource{}, fmt.Errorf("skills version %q is not a skills release version (letters, digits and ._-, or %q)", version, LatestVersion)
	}
	if version != "" && baseURL == "" {
		return SkillsSource{}, fmt.Errorf("skills version %q needs a skills base URL: nowhere to take a signed skills release from", version)
	}
	return SkillsSource{baseURL: baseURL, version: version}, nil
}

// BaseURL is where signed skills releases are read from, without a trailing
// slash, or "".
func (s SkillsSource) BaseURL() string { return s.baseURL }

// Version is the skills release asked for: a version name, "latest", or ""
// to keep a box where it is.
func (s SkillsSource) Version() string { return s.version }

// Signed reports whether a signed source is configured.
func (s SkillsSource) Signed() bool { return s.baseURL != "" }
