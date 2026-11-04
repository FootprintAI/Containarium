package sdlcskills

import (
	"regexp"
	"sort"
)

// DefaultRepo is the repository whose releases carry the installer script
// and the skills bundle: the installer's own REPO default.
const DefaultRepo = "FootprintAI/Containarium"

// ReleaseTagPattern is what may be interpolated into the installer's URLs. The
// tag lands inside a double-quoted shell string, so it is validated rather
// than quoted: a charset with no $, backtick, quote, or backslash cannot be
// anything but a path segment there.
var ReleaseTagPattern = regexp.MustCompile(`^v?[0-9A-Za-z][0-9A-Za-z._-]*$`)

// ValidReleaseTag reports whether tag is safe to splice into InstallScript.
func ValidReleaseTag(tag string) bool { return ReleaseTagPattern.MatchString(tag) }

// SkillSetsFromIDs is the selection of exactly ids, already validated against
// a lock ([a-z0-9-]+ each). No ids is the "none" selection: an empty target
// list removes what the installer owns, it never widens to "all".
func SkillSetsFromIDs(ids []string) SkillSets {
	if len(ids) == 0 {
		return SkillSets{none: true}
	}
	out := SkillSets{}
	seen := map[string]bool{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out.ids = append(out.ids, id)
		}
	}
	sort.Strings(out.ids)
	return out
}

// InstallScript is the shell that fetches release's install-sdlc-skills.sh
// from repo and runs it AS THE BOX USER (#2065), landing the pinned
// open-sdlc-skills role skills in ~/.claude/skills. `code install` runs it
// over SSH as the box user; ApplyBoxSkillSets (#3374) runs it through the
// daemon's `su - <user>` exec. The release tag must already satisfy
// ValidReleaseTag, so it is safe inside the double-quoted URL; sets' String
// form cannot carry shell syntax by construction.
//
// Only a 404 means "this release predates the skills asset" and is skipped
// with a message; any other fetch failure fails the install, so a network
// blip never silently ships a box with no skills. A hash mismatch or unsafe
// archive is the installer's own failure and propagates. An installer that
// predates SKILL_SETS would ignore it and install everything, so a narrowed
// selection against one fails instead.
func InstallScript(repo, release string, sets SkillSets) string {
	return `set -e
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
code="$(curl -sSL -o "$tmp" -w '%{http_code}' "https://raw.githubusercontent.com/` + repo + `/` + release + `/scripts/install-sdlc-skills.sh" </dev/null)"
case "$code" in
  200)
    if ! grep -q '^# skill-sets: v1$' "$tmp"; then
      # An installer that predates skill sets would ignore SKILL_SETS and install everything.
      case "` + sets.String() + `" in
        all) ;;
        none) echo "release ` + release + `'s SDLC skills installer predates skill sets; nothing to remove, skipping" >&2; exit 0 ;;
        *) echo "release ` + release + `'s SDLC skills installer predates skill sets; cannot apply SKILL_SETS=` + sets.String() + `" >&2; exit 1 ;;
      esac
    fi
    SKILL_SETS="` + sets.String() + `" RELEASE="` + release + `" REPO="` + repo + `" bash "$tmp" ;;
  404)
    case "` + sets.String() + `" in
      all|none) echo "release ` + release + ` has no SDLC skills installer; skipping" >&2 ;;
      *) echo "release ` + release + ` has no SDLC skills installer; cannot apply SKILL_SETS=` + sets.String() + `" >&2; exit 1 ;;
    esac ;;
  *) echo "fetching the SDLC skills installer failed: HTTP $code" >&2; exit 1 ;;
esac`
}
