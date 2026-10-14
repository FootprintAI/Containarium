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
tar -xzf "$tmp/sdlc-skills.tar.gz" -C "$tmp/x"

mkdir -p "$SKILLS_DIR"
manifest="$SKILLS_DIR/.sdlc-skills-manifest"

new=()
for d in "$tmp/x"/*/; do new+=("$(basename "$d")"); done
[[ "${#new[@]}" -gt 0 ]] || { echo "install-sdlc-skills: archive holds no skills; nothing installed" >&2; exit 1; }

# Drop directories a previous install owned that the pinned set no longer has.
if [[ -f "$manifest" ]]; then
  while IFS= read -r old; do
    [[ "$old" =~ ^[A-Za-z0-9_-]+$ ]] || continue
    keep=0
    for n in "${new[@]}"; do [[ "$n" == "$old" ]] && keep=1; done
    [[ "$keep" == 1 ]] || rm -rf "${SKILLS_DIR:?}/$old"
  done < "$manifest"
fi

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
