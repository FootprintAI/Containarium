// Package sdlcskills holds the pin for the SDLC role skills shipped in
// coding-agent boxes (#2065): which commit of FootprintAI/open-sdlc-skills,
// and the sha256 of the tarball built from it.
//
// The lock lives in this package so the daemon can embed it: a consumer that
// loads the sdlc-skills.tar.gz release asset (the hosted issue-implementer,
// #2488) verifies the asset against this digest before trusting its contents,
// so the host and the boxes provably run the same pinned set.
package sdlcskills

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

//go:embed sdlc-skills.lock
var lockText string

// Lock is the parsed pin.
type Lock struct {
	// Repo is the GitHub owner/name of the skills repository.
	Repo string
	// Ref is the full 40-hex commit SHA the bundle is built from.
	Ref string
	// SHA256 is the hex digest of the packaged sdlc-skills.tar.gz.
	SHA256 string
}

var (
	refPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Parse reads a lock in the key=value form the scripts consume. Comment and
// blank lines are ignored. A lock missing any field, or with a ref or digest
// of the wrong shape, is an error rather than a partially usable pin.
func Parse(text string) (Lock, error) {
	var l Lock
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return Lock{}, fmt.Errorf("sdlcskills: malformed lock line %q", line)
		}
		switch key {
		case "repo":
			l.Repo = val
		case "ref":
			l.Ref = val
		case "sha256":
			l.SHA256 = val
		}
	}
	if l.Repo == "" {
		return Lock{}, fmt.Errorf("sdlcskills: lock has no repo")
	}
	if !refPattern.MatchString(l.Ref) {
		return Lock{}, fmt.Errorf("sdlcskills: lock ref %q is not a full commit sha", l.Ref)
	}
	if !shaPattern.MatchString(l.SHA256) {
		return Lock{}, fmt.Errorf("sdlcskills: lock sha256 %q is not a hex digest", l.SHA256)
	}
	return l, nil
}

// Embedded returns the pin this binary was built with.
func Embedded() (Lock, error) { return Parse(lockText) }
