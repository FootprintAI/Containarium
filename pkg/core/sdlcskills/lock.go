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
	// Sets maps a skill-set id to the namespaces it selects, from the
	// `set.<id>=<ns>,<ns>` lines (#3048). A namespace belongs to one set. A lock
	// without such lines (the earlier format) has none.
	Sets map[string][]string
}

var (
	refPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// setIDPattern is the charset of set ids and namespaces; it is also what the
	// installer script enforces, so neither can carry shell syntax.
	setIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)
	shaPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Parse reads a lock in the key=value form the scripts consume. Comment and
// blank lines are ignored. A lock missing any field, or with a ref or digest
// of the wrong shape, is an error rather than a partially usable pin.
func Parse(text string) (Lock, error) {
	l := Lock{Sets: map[string][]string{}}
	owner := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return Lock{}, fmt.Errorf("sdlcskills: malformed lock line %q", line)
		}
		if id, isSet := strings.CutPrefix(key, "set."); isSet {
			if !setIDPattern.MatchString(id) {
				return Lock{}, fmt.Errorf("sdlcskills: lock set id %q must match [a-z0-9-]+", id)
			}
			if _, dup := l.Sets[id]; dup {
				return Lock{}, fmt.Errorf("sdlcskills: lock defines set %q twice", id)
			}
			if val == "" {
				return Lock{}, fmt.Errorf("sdlcskills: lock set %q has no namespaces", id)
			}
			for _, ns := range strings.Split(val, ",") {
				if !setIDPattern.MatchString(ns) {
					return Lock{}, fmt.Errorf("sdlcskills: lock set %q has bad namespace %q", id, ns)
				}
				if prev, taken := owner[ns]; taken {
					return Lock{}, fmt.Errorf("sdlcskills: namespace %q is in sets %q and %q; a namespace belongs to one set", ns, prev, id)
				}
				owner[ns] = id
				l.Sets[id] = append(l.Sets[id], ns)
			}
			continue
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

// SkillSets is a validated skill-set selection (#3048): "all", "none", or one
// or more set ids. Parse it once from the recipe parameter or CLI flag; the
// installer script receives only the String form, whose charset cannot carry
// shell syntax.
type SkillSets struct {
	all, none bool
	ids       []string
}

// ParseSkillSets parses "", "all", "none" or a comma-separated list of set ids
// ([a-z0-9-]+). Empty means all, the pre-#3048 behaviour. "none" and "all" are
// literals that cannot be combined with ids. Whether an id is known is the
// lock's business and is checked by the installer, which names the known ids.
func ParseSkillSets(s string) (SkillSets, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "", "all":
		return SkillSets{all: true}, nil
	case "none":
		return SkillSets{none: true}, nil
	}
	var out SkillSets
	seen := map[string]bool{}
	for _, id := range strings.Split(s, ",") {
		id = strings.TrimSpace(id)
		if id == "all" || id == "none" {
			return SkillSets{}, fmt.Errorf("skill sets: %q cannot be combined with other set ids", id)
		}
		if !setIDPattern.MatchString(id) {
			return SkillSets{}, fmt.Errorf("skill sets: %q is not a valid set id (want [a-z0-9-]+, comma-separated)", id)
		}
		if !seen[id] {
			seen[id] = true
			out.ids = append(out.ids, id)
		}
	}
	return out, nil
}

// None reports whether the selection installs nothing.
func (s SkillSets) None() bool { return s.none }

// String is the SKILL_SETS value for the installer: all, none, or a,b.
func (s SkillSets) String() string {
	switch {
	case s.none:
		return "none"
	case s.all || len(s.ids) == 0:
		return "all"
	}
	return strings.Join(s.ids, ",")
}
