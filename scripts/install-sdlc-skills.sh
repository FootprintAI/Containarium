#!/usr/bin/env bash
# install-sdlc-skills.sh — install the pinned SDLC role skills for Claude Code (#2065).
#
# Run AS THE BOX USER (the recipe drops to box_user for it; `code install` runs
# it as the user). Fetches the release asset built by build-sdlc-skills-bundle.sh,
# verifies its sha256, and installs one directory per skill under SKILLS_DIR:
#   ~/.claude/skills/<ns>-<name>/SKILL.md     e.g. qa-sprint-verify/SKILL.md
#   ~/.claude/skills/_shared/*.md             read by the skills at runtime
# It records what it installed so an update removes only what it owns:
#   .sdlc-skills-version   release / sha256 / install time
#   .sdlc-skills-manifest  the directories this installer owns
# Nothing else under SKILLS_DIR is touched. A hash mismatch or an unsafe archive
# installs nothing.
#
# Env:
#   REPO               default FootprintAI/Containarium
#   RELEASE            the release tag carrying the asset (v-prefixed), or
#   ARTIFACT_BASE_URL  overrides <https://github.com/REPO/releases/download/RELEASE>
#   SKILLS_DIR         default $HOME/.claude/skills
#   SKILL_SETS         which skill sets to install (#3048): "all" (default, also when
#                      empty), "none", or a comma-separated list of set ids such as
#                      "sdlc,qa". Which namespaces a set covers is defined once, in the
#                      `set.<id>=<ns>,<ns>` lines of pkg/core/sdlcskills/sdlc-skills.lock
#                      at RELEASE. An unknown id fails and names the known ones;
#                      "none" installs nothing and removes what this installer owns.
#                      _shared/ is installed whenever at least one set is.
#   SDLC_SKILLS_LOCK_URL  where to read that lock (default: the lock at RELEASE on
#                      raw.githubusercontent.com); only fetched for an explicit list
#   SDLC_SKILLS_OVERLAY_DIR  optional: a directory of skill dirs copied OVER the
#                      public set after install (the second copy wins), so a team
#                      can layer its own overrides without forking the public skills
set -euo pipefail

REPO="${REPO:-FootprintAI/Containarium}"
RELEASE="${RELEASE:-}"
if [[ -z "${ARTIFACT_BASE_URL:-}" ]]; then
  [[ -n "$RELEASE" ]] || { echo "install-sdlc-skills: set RELEASE (the release tag) or ARTIFACT_BASE_URL" >&2; exit 2; }
  ARTIFACT_BASE_URL="https://github.com/${REPO}/releases/download/${RELEASE}"
fi
SKILLS_DIR="${SKILLS_DIR:-${HOME:?HOME is not set}/.claude/skills}"
OVERLAY="${SDLC_SKILLS_OVERLAY_DIR:-}"

# Set ids are untrusted input: validate the whole value before anything uses it.
SKILL_SETS="${SKILL_SETS:-all}"
sets=()
case "$SKILL_SETS" in
  all|none) ;;
  *)
    if ! [[ "$SKILL_SETS" =~ ^[a-z0-9,-]+$ && "$SKILL_SETS" != ,* && "$SKILL_SETS" != *, && "$SKILL_SETS" != *,,* ]]; then
      echo "install-sdlc-skills: SKILL_SETS must be 'all', 'none' or comma-separated set ids matching [a-z0-9-]+; nothing installed" >&2; exit 2
    fi
    IFS=',' read -r -a sets <<< "$SKILL_SETS"
    for s in "${sets[@]}"; do
      if [[ "$s" == all || "$s" == none ]]; then
        echo "install-sdlc-skills: '$s' cannot be combined with other set ids; nothing installed" >&2; exit 2
      fi
    done
    ;;
esac

mkdir -p "$SKILLS_DIR"
manifest="$SKILLS_DIR/.sdlc-skills-manifest"

# Drop directories a previous install owned that the new selection no longer has.
prune_dropped() {
  [[ -f "$manifest" ]] || return 0
  while IFS= read -r old; do
    [[ "$old" =~ ^[A-Za-z0-9_-]+$ ]] || continue
    keep=0
    for n in "${new[@]+"${new[@]}"}"; do [[ "$n" == "$old" ]] && keep=1; done
    [[ "$keep" == 1 ]] || rm -rf "${SKILLS_DIR:?}/$old"
  done < "$manifest"
}

if [[ "$SKILL_SETS" == none ]]; then
  new=()
  prune_dropped
  : > "$manifest"
  rm -f "$SKILLS_DIR/.sdlc-skills-version"
  echo "==> SKILL_SETS=none: no SDLC skills installed; removed what this installer owned from $SKILLS_DIR"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> fetching SDLC skills from ${ARTIFACT_BASE_URL}"
curl -fsSL "${ARTIFACT_BASE_URL}/sdlc-skills.tar.gz" -o "$tmp/sdlc-skills.tar.gz" </dev/null
curl -fsSL "${ARTIFACT_BASE_URL}/sdlc-skills.tar.gz.sha256" -o "$tmp/sdlc-skills.tar.gz.sha256" </dev/null

want="$(cut -d' ' -f1 "$tmp/sdlc-skills.tar.gz.sha256" | head -n1)"
[[ "$want" =~ ^[0-9a-f]{64}$ ]] || { echo "install-sdlc-skills: malformed .sha256 file" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$tmp/sdlc-skills.tar.gz" | cut -d' ' -f1)"
else got="$(shasum -a 256 "$tmp/sdlc-skills.tar.gz" | cut -d' ' -f1)"; fi
if [[ "$got" != "$want" ]]; then
  echo "install-sdlc-skills: sha256 mismatch (asset $got, expected $want); nothing installed" >&2
  exit 1
fi

# Refuse anything that could write outside SKILLS_DIR before extracting a byte.
while IFS= read -r entry; do
  case "$entry" in
    /*|*..*) echo "install-sdlc-skills: unsafe path in archive: $entry; nothing installed" >&2; exit 1 ;;
  esac
done < <(tar -tzf "$tmp/sdlc-skills.tar.gz")
mkdir -p "$tmp/x"

if [[ "${#sets[@]}" -eq 0 ]]; then
  tar -xzf "$tmp/sdlc-skills.tar.gz" -C "$tmp/x"
else
  # Resolve set ids to namespaces through the lock that pins THIS bundle, then
  # extract only those namespaces' entries (plus _shared/).
  lock_url="${SDLC_SKILLS_LOCK_URL:-}"
  if [[ -z "$lock_url" ]]; then
    [[ -n "$RELEASE" ]] || { echo "install-sdlc-skills: set SDLC_SKILLS_LOCK_URL to select skill sets without RELEASE; nothing installed" >&2; exit 2; }
    lock_url="https://raw.githubusercontent.com/${REPO}/${RELEASE}/pkg/core/sdlcskills/sdlc-skills.lock"
  fi
  if ! curl -fsSL "$lock_url" -o "$tmp/sdlc-skills.lock" </dev/null; then
    echo "install-sdlc-skills: cannot read the skill-set lock at $lock_url (a release that predates skill sets cannot honour SKILL_SETS=$SKILL_SETS); nothing installed" >&2
    exit 1
  fi
  lock_sha="$(sed -n 's/^sha256=//p' "$tmp/sdlc-skills.lock" | head -n1)"
  if [[ "$lock_sha" != "$got" ]]; then
    echo "install-sdlc-skills: the lock does not pin the downloaded bundle (lock ${lock_sha:-none}, bundle $got); nothing installed" >&2
    exit 1
  fi
  known="$(sed -n 's/^set\.\([a-z0-9-][a-z0-9-]*\)=.*/\1/p' "$tmp/sdlc-skills.lock" | paste -sd, - | sed 's/,/, /g')"
  nss=()
  for s in "${sets[@]}"; do
    line="$(sed -n "s/^set\.${s}=//p" "$tmp/sdlc-skills.lock" | head -n1)"
    if [[ -z "$line" ]]; then
      echo "install-sdlc-skills: unknown skill set '$s'; known skill sets: ${known:-(none defined)}; nothing installed" >&2
      exit 1
    fi
    IFS=',' read -r -a more <<< "$line"
    for ns in "${more[@]}"; do
      [[ "$ns" =~ ^[a-z0-9-]+$ ]] || { echo "install-sdlc-skills: bad namespace '$ns' in set '$s'; nothing installed" >&2; exit 1; }
      nss+=("$ns")
    done
  done
  : > "$tmp/members"
  while IFS= read -r entry; do
    top="${entry%%/*}"
    take=0
    [[ "$top" == _shared ]] && take=1
    for ns in "${nss[@]}"; do [[ "$top" == "$ns"-* ]] && take=1; done
    [[ "$take" == 1 ]] && printf '%s\n' "$entry" >> "$tmp/members"
  done < <(tar -tzf "$tmp/sdlc-skills.tar.gz")
  tar -xzf "$tmp/sdlc-skills.tar.gz" -C "$tmp/x" -T "$tmp/members"
fi

new=()
for d in "$tmp/x"/*/; do [[ -d "$d" ]] || continue; new+=("$(basename "$d")"); done
[[ "${#new[@]}" -gt 0 ]] || { echo "install-sdlc-skills: archive holds no skills for SKILL_SETS=$SKILL_SETS; nothing installed" >&2; exit 1; }

prune_dropped

for n in "${new[@]}"; do
  rm -rf "${SKILLS_DIR:?}/$n"
  cp -R "$tmp/x/$n" "$SKILLS_DIR/$n"
done
printf '%s\n' "${new[@]}" > "$manifest"
printf 'release=%s sha256=%s installed=%s\n' "${RELEASE:-custom}" "$want" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$SKILLS_DIR/.sdlc-skills-version"

if [[ -n "$OVERLAY" ]]; then
  if [[ -d "$OVERLAY" ]]; then
    for d in "$OVERLAY"/*/; do
      [[ -d "$d" ]] || continue
      n="$(basename "$d")"
      [[ "$n" =~ ^[A-Za-z0-9_-]+$ ]] || continue
      rm -rf "${SKILLS_DIR:?}/$n"
      cp -R "$d" "$SKILLS_DIR/$n"
    done
    echo "==> applied overlay from $OVERLAY"
  else
    echo "install-sdlc-skills: overlay dir not found, skipped: $OVERLAY" >&2
  fi
fi

echo "==> installed ${#new[@]} SDLC skill entries into $SKILLS_DIR"
