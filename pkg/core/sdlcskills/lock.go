// Package sdlcskills holds the pins for skill sources shipped in coding-agent
// boxes (#2065, #3048): each repository commit and the sha256 of its
// deterministic tarball.
//
// The lock lives in this package so the daemon can embed it: a consumer that
// loads the sdlc-skills.tar.gz release asset (the hosted issue-implementer,
// #2488) verifies the asset against the sdlc source before trusting its
// contents, so the host and the boxes provably run the same pinned set.
package sdlcskills

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

//go:embed sdlc-skills.lock
var lockText string

// Source is one pinned skill repository and the deterministic release asset
// built from it.
type Source struct {
	ID     string
	Repo   string
	Ref    string
	SHA256 string
}

// Lock is the parsed collection of source pins.
type Lock struct {
	// Repo, Ref and SHA256 are compatibility aliases for the sdlc source (or
	// the only source when no sdlc source exists). Older callers constructed a
	// Lock directly with these fields, so LoadBundleBytes continues to accept
	// them.
	Repo   string
	Ref    string
	SHA256 string
	// Sources is ordered as the source sections appear in the lock. The legacy
	// flat repo/ref/sha256 format is represented as one source named sdlc.
	Sources []Source
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

// Parse reads the sectioned lock format the scripts consume:
//
//	set.sdlc=architect,engineer
//	[sdlc]
//	repo=owner/name
//	ref=<full commit sha>
//	sha256=<bundle digest>
//
// The earlier flat repo/ref/sha256 form remains valid and becomes an implicit
// source named sdlc. Sectioned and flat pins cannot be mixed.
func Parse(text string) (Lock, error) {
	l := Lock{Sets: map[string][]string{}}
	owner := map[string]string{}
	sections := map[string]int{}
	seenKeys := map[string]bool{}
	current := ""
	legacyPin := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			id := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if !setIDPattern.MatchString(id) {
				return Lock{}, fmt.Errorf("sdlcskills: lock source id %q must match [a-z0-9-]+", id)
			}
			if _, dup := sections[id]; dup {
				return Lock{}, fmt.Errorf("sdlcskills: lock defines source %q twice", id)
			}
			sections[id] = len(l.Sources)
			l.Sources = append(l.Sources, Source{ID: id})
			current = id
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
		if key != "repo" && key != "ref" && key != "sha256" {
			continue
		}
		where := current
		if where == "" {
			where = "(legacy)"
			legacyPin = true
		}
		seenKey := where + "." + key
		if seenKeys[seenKey] {
			return Lock{}, fmt.Errorf("sdlcskills: lock source %q defines %s twice", where, key)
		}
		seenKeys[seenKey] = true
		if current != "" {
			i := sections[current]
			switch key {
			case "repo":
				l.Sources[i].Repo = val
			case "ref":
				l.Sources[i].Ref = val
			case "sha256":
				l.Sources[i].SHA256 = val
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
	if legacyPin && len(l.Sources) > 0 {
		return Lock{}, fmt.Errorf("sdlcskills: lock mixes flat repo/ref/sha256 keys with source sections")
	}
	if len(l.Sources) == 0 {
		l.Sources = []Source{{ID: "sdlc", Repo: l.Repo, Ref: l.Ref, SHA256: l.SHA256}}
	}
	for _, source := range l.Sources {
		if source.Repo == "" {
			return Lock{}, fmt.Errorf("sdlcskills: lock source %q has no repo", source.ID)
		}
		if !refPattern.MatchString(source.Ref) {
			return Lock{}, fmt.Errorf("sdlcskills: lock source %q ref %q is not a full commit sha", source.ID, source.Ref)
		}
		if !shaPattern.MatchString(source.SHA256) {
			return Lock{}, fmt.Errorf("sdlcskills: lock source %q sha256 %q is not a hex digest", source.ID, source.SHA256)
		}
	}
	if !legacyPin {
		primary := l.Sources[0]
		if source, ok := l.Source("sdlc"); ok {
			primary = source
		}
		l.Repo, l.Ref, l.SHA256 = primary.Repo, primary.Ref, primary.SHA256
	}
	return l, nil
}

// Source returns one named source pin.
func (l Lock) Source(id string) (Source, bool) {
	for _, source := range l.Sources {
		if source.ID == id {
			return source, true
		}
	}
	return Source{}, false
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
