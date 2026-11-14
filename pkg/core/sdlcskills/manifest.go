package sdlcskills

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ManifestName and SignatureName are the files published beside
// sdlc-skills.tar.gz in a skills release: the manifest, and the detached
// signature over the manifest's exact bytes.
const (
	ManifestName  = "sdlc-skills.manifest"
	SignatureName = "sdlc-skills.manifest.sig"
)

// LatestVersion is the name of the pointer to the newest release. It is not a
// version a manifest may carry.
const LatestVersion = "latest"

// maxManifestBytes bounds a manifest: a real one is a few hundred bytes.
const maxManifestBytes = 64 << 10

// versionPattern is what a skills release version may be. It is spliced into
// URLs and shell, so the charset carries no syntax of either.
var versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]*$`)

// ValidSkillsVersion reports whether v can name one skills release.
func ValidSkillsVersion(v string) bool {
	return v != LatestVersion && len(v) <= 64 && versionPattern.MatchString(v)
}

// Manifest is the signed description of one skills release.
type Manifest struct {
	// Contract is the manifest contract the release was written for.
	Contract int
	// Version names the release.
	Version string
	// SHA256 is the digest of the release's sdlc-skills.tar.gz.
	SHA256 string
	// Sources are the repository commits the bundle was built from, in the
	// manifest's order. Their SHA256 is unused.
	Sources []Source
	// Sets maps a set id to the namespaces it selects.
	Sets map[string][]string
}

// ParseManifest reads a manifest:
//
//	contract=1
//	version=2026.11.0
//	sha256=<bundle digest>
//	source.sdlc=owner/name@<full commit sha>
//	set.sdlc=architect,engineer
//
// Blank lines and # comments are skipped. A key this reader does not know is
// ignored, so a later release of the same contract still parses; a key given
// twice is refused. The contract is checked first: a manifest for a later
// contract is a *ContractTooNewError whatever else it holds.
//
// The bytes are whatever a signature covered. Verify the signature before
// acting on the result.
func ParseManifest(data []byte) (Manifest, error) {
	if len(data) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("sdlcskills: manifest exceeds %d bytes", maxManifestBytes)
	}
	values := map[string]string{}
	var order []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return Manifest{}, fmt.Errorf("sdlcskills: malformed manifest line %q", line)
		}
		if _, dup := values[key]; dup {
			return Manifest{}, fmt.Errorf("sdlcskills: manifest defines %s twice", key)
		}
		values[key] = val
		order = append(order, key)
	}

	contract, err := strconv.Atoi(values["contract"])
	if err != nil {
		return Manifest{}, fmt.Errorf("sdlcskills: manifest contract %q is not a number", values["contract"])
	}
	if err := CheckContract(contract); err != nil {
		return Manifest{}, err
	}
	m := Manifest{Contract: contract, Version: values["version"], SHA256: values["sha256"], Sets: map[string][]string{}}
	if !ValidSkillsVersion(m.Version) {
		return Manifest{}, fmt.Errorf("sdlcskills: manifest version %q is not a skills release version", m.Version)
	}
	if !shaPattern.MatchString(m.SHA256) {
		return Manifest{}, fmt.Errorf("sdlcskills: manifest sha256 %q is not a hex digest", m.SHA256)
	}
	owner := map[string]string{}
	for _, key := range order {
		val := values[key]
		if id, ok := strings.CutPrefix(key, "source."); ok {
			repo, ref, hasRef := strings.Cut(val, "@")
			if !setIDPattern.MatchString(id) || !hasRef || repo == "" {
				return Manifest{}, fmt.Errorf("sdlcskills: manifest source %q must be source.<id>=<owner>/<repo>@<commit>", key+"="+val)
			}
			if !refPattern.MatchString(ref) {
				return Manifest{}, fmt.Errorf("sdlcskills: manifest source %q ref %q is not a full commit sha", id, ref)
			}
			m.Sources = append(m.Sources, Source{ID: id, Repo: repo, Ref: ref})
			continue
		}
		id, ok := strings.CutPrefix(key, "set.")
		if !ok {
			continue
		}
		if !setIDPattern.MatchString(id) {
			return Manifest{}, fmt.Errorf("sdlcskills: manifest set id %q must match [a-z0-9-]+", id)
		}
		if val == "" {
			return Manifest{}, fmt.Errorf("sdlcskills: manifest set %q has no namespaces", id)
		}
		for _, ns := range strings.Split(val, ",") {
			if !setIDPattern.MatchString(ns) {
				return Manifest{}, fmt.Errorf("sdlcskills: manifest set %q has bad namespace %q", id, ns)
			}
			if prev, taken := owner[ns]; taken {
				return Manifest{}, fmt.Errorf("sdlcskills: namespace %q is in sets %q and %q; a namespace belongs to one set", ns, prev, id)
			}
			owner[ns] = id
			m.Sets[id] = append(m.Sets[id], ns)
		}
	}
	if len(m.Sets) == 0 {
		return Manifest{}, fmt.Errorf("sdlcskills: manifest defines no skill sets")
	}
	return m, nil
}

// SetIDs returns the set ids this release defines, sorted.
func (m Manifest) SetIDs() []string {
	ids := make([]string, 0, len(m.Sets))
	for id := range m.Sets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// SetNotInReleaseError is a set id this release does not define.
type SetNotInReleaseError struct {
	ID      string
	Version string
	Has     []string
}

func (e *SetNotInReleaseError) Error() string {
	return fmt.Sprintf("skill set %q is not in skills release %s; it has: %s", e.ID, e.Version, strings.Join(e.Has, ", "))
}

// Namespaces returns the namespaces ids select in this release, sorted. An id
// the release does not define is a *SetNotInReleaseError naming what it has.
func (m Manifest) Namespaces(ids []string) ([]string, error) {
	var out []string
	for _, id := range ids {
		nss, ok := m.Sets[id]
		if !ok {
			return nil, &SetNotInReleaseError{ID: id, Version: m.Version, Has: m.SetIDs()}
		}
		out = append(out, nss...)
	}
	sort.Strings(out)
	return out, nil
}

// Pin names the content the release was built from, for stamping into
// whatever is derived from it: "<owner>/<repo>@<sha12>" of the sdlc source
// (or the first one), the same shape a lock gives, or "skills <version>"
// when the manifest records no source.
func (m Manifest) Pin() string {
	if len(m.Sources) == 0 {
		return "skills " + m.Version
	}
	src := m.Sources[0]
	for _, s := range m.Sources {
		if s.ID == "sdlc" {
			src = s
		}
	}
	return src.Repo + "@" + src.Ref[:12]
}
