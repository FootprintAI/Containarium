#!/usr/bin/env bash
# install-sdlc-skills.sh — install the pinned SDLC role skills for Claude Code (#2065).
#
# Run AS THE BOX USER (the recipe drops to box_user for it; `code install` runs
# it as the user). Fetches a skills bundle, verifies it, and installs one
# directory per skill under SKILLS_DIR:
#   ~/.claude/skills/<ns>-<name>/SKILL.md     e.g. qa-sprint-verify/SKILL.md
#   ~/.claude/skills/_shared/*.md             read by the skills at runtime
# It records what it installed so an update removes only what it owns:
#   .sdlc-skills-version   release / sha256 / install time, and for a signed
#                          skills release: skills=<version> contract=<n>
#   .sdlc-skills-manifest  the directories this installer owns
#   .sdlc-skills-sets      signed source only: "<set id><TAB><directory>" per
#                          installed skill, as the signed manifest assigns them
# Nothing else under SKILLS_DIR is touched. A failed verification or an unsafe
# archive installs nothing.
#
# Two sources (docs/design/sdlc-skills-option-b.md):
#
#   Signed skills release — used when SDLC_SKILLS_BASE_URL is set. The release is
#   <base>/<version>/{sdlc-skills.tar.gz,sdlc-skills.manifest,sdlc-skills.manifest.sig}.
#   The manifest's signature is checked against the trusted keys below (or
#   SDLC_SKILLS_TRUSTED_KEYS_FILE) with openssl, then the bundle's sha256 against
#   the signed manifest. Skill sets are read from the signed manifest.
#   A box keeps its skills release: with no SDLC_SKILLS_VERSION the recorded
#   version is installed again; a box whose skills came from a release asset
#   stays on that release's asset; a box with nothing recorded takes `latest`
#   once. Only SDLC_SKILLS_VERSION moves a box.
#
#   Release asset — used otherwise. sdlc-skills.tar.gz and its .sha256 from the
#   Containarium release RELEASE; skill sets from that release's lock.
#
# Env:
#   REPO               default FootprintAI/Containarium
#   RELEASE            the release tag carrying the asset (v-prefixed), or
#   ARTIFACT_BASE_URL  overrides <https://github.com/REPO/releases/download/RELEASE>
#   SKILLS_DIR         default $HOME/.claude/skills
#   SKILL_SETS         which skill sets to install (#3048): "all" (default, also when
#                      empty), "none", or a comma-separated list of set ids such as
#                      "sdlc,qa". Which namespaces a set covers is defined once: in
#                      the signed manifest of the skills release, or, for a release
#                      asset, in the `set.<id>=<ns>,<ns>` lines of
#                      pkg/core/sdlcskills/sdlc-skills.lock at RELEASE. An unknown id
#                      fails and names the known ones; "none" installs nothing and
#                      removes what this installer owns. _shared/ is installed
#                      whenever at least one set is.
#   SDLC_SKILLS_LOCK_URL  release asset only: where to read that lock (default: the
#                      lock at RELEASE on raw.githubusercontent.com); only fetched
#                      for an explicit list
#   SDLC_SKILLS_BASE_URL  the base URL of signed skills releases; selects the
#                      signed source
#   SDLC_SKILLS_VERSION   the skills release to install: a version, or "latest".
#                      Needs SDLC_SKILLS_BASE_URL. Empty keeps the box where it is
#                      (see above)
#   SDLC_SKILLS_TRUSTED_KEYS_FILE  PEM public keys to trust INSTEAD of the ones
#                      below, for an operator who signs their own skills releases
#   SDLC_SKILLS_OVERLAY_DIR  optional: a directory of skill dirs copied OVER the
#                      public set after install (the second copy wins), so a team
#                      can layer its own overrides without forking the public skills
# skill-sets: v1
# (marker read by the recipe and `code install` to tell an installer that honours
#  SKILL_SETS from an older one; do not remove or reword)
# skills-source: v1
# (marker for an installer that honours SDLC_SKILLS_BASE_URL and
#  SDLC_SKILLS_VERSION; a caller asking for a skills version checks for it,
#  because an older installer would ignore the request; do not remove or reword)
set -euo pipefail

# The manifest contract this installer reads (pkg/core/sdlcskills/contract.go).
SUPPORTED_CONTRACT=1

# Public keys trusted to sign a skills release: the PEM blocks of
# pkg/core/sdlcskills/trusted-keys.pem, kept identical by a test. None yet.
TRUSTED_KEYS="$(cat <<'KEYS'
# BEGIN TRUSTED KEYS
# END TRUSTED KEYS
KEYS
)"

# The default base URL of signed skills releases. Empty: the signed source is
# used only when SDLC_SKILLS_BASE_URL is given.
DEFAULT_SKILLS_BASE_URL=""

die() { echo "install-sdlc-skills: $*; nothing installed" >&2; exit 1; }

REPO="${REPO:-FootprintAI/Containarium}"
RELEASE="${RELEASE:-}"
SKILLS_BASE_URL="${SDLC_SKILLS_BASE_URL:-$DEFAULT_SKILLS_BASE_URL}"
SKILLS_BASE_URL="${SKILLS_BASE_URL%/}"
SKILLS_VERSION="${SDLC_SKILLS_VERSION:-}"
VERSION_RE='^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$'
# The version is untrusted input that ends up in a URL: validate it first.
if [[ -n "$SKILLS_VERSION" ]]; then
  if ! [[ "$SKILLS_VERSION" =~ $VERSION_RE ]]; then
    echo "install-sdlc-skills: SDLC_SKILLS_VERSION must be a skills release version ([0-9A-Za-z._-], starting with a letter or digit) or 'latest'; nothing installed" >&2; exit 2
  fi
  if [[ -z "$SKILLS_BASE_URL" ]]; then
    echo "install-sdlc-skills: SDLC_SKILLS_VERSION=$SKILLS_VERSION needs SDLC_SKILLS_BASE_URL (where signed skills releases are published); nothing installed" >&2; exit 2
  fi
fi
if [[ -z "$SKILLS_BASE_URL" && -z "${ARTIFACT_BASE_URL:-}" ]]; then
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
  rm -f "$SKILLS_DIR/.sdlc-skills-version" "$SKILLS_DIR/.sdlc-skills-sets"
  echo "==> SKILL_SETS=none: no SDLC skills installed; removed what this installer owned from $SKILLS_DIR"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# What a previous run recorded for this box.
rec_release=""; rec_skills=""
if [[ -f "$SKILLS_DIR/.sdlc-skills-version" ]]; then
  read -r -a rec < "$SKILLS_DIR/.sdlc-skills-version" || true
  for tok in "${rec[@]+"${rec[@]}"}"; do
    case "$tok" in
      release=*) rec_release="${tok#release=}" ;;
      skills=*) rec_skills="${tok#skills=}" ;;
    esac
  done
  # The record is a file in the box user's tree: use only values of the right shape.
  [[ "$rec_skills" =~ $VERSION_RE && "$rec_skills" != latest ]] || rec_skills=""
  [[ "$rec_release" =~ ^v?[0-9A-Za-z][0-9A-Za-z._-]*$ && "$rec_release" != custom ]] || rec_release=""
fi

# Which source, and for the signed one which version. A box does not move to
# another skills release unless SDLC_SKILLS_VERSION asks for it.
source_kind=asset
if [[ -n "$SKILLS_BASE_URL" ]]; then
  source_kind=signed
  if [[ -z "$SKILLS_VERSION" ]]; then
    if [[ -n "$rec_skills" ]]; then
      SKILLS_VERSION="$rec_skills"
    elif [[ -n "$rec_release" ]]; then
      source_kind=asset
      RELEASE="$rec_release"
      ARTIFACT_BASE_URL="${ARTIFACT_BASE_URL:-https://github.com/${REPO}/releases/download/${RELEASE}}"
      echo "==> this box's SDLC skills came from release ${RELEASE}; staying on that release's bundle (set SDLC_SKILLS_VERSION to move it to a signed skills release)"
    else
      SKILLS_VERSION=latest
    fi
  fi
fi

# verify_signature <file> <sig>: true when any trusted key verifies any line
# of <sig> (base64 of a DER ECDSA signature over SHA-256, as cosign sign-blob
# --key writes) over <file>.
verify_signature() {
  command -v openssl >/dev/null 2>&1 || die "openssl is needed to verify the signature of a skills release"
  local keys="$tmp/trusted-keys.pem" line k
  if [[ -n "${SDLC_SKILLS_TRUSTED_KEYS_FILE:-}" ]]; then
    [[ -f "$SDLC_SKILLS_TRUSTED_KEYS_FILE" ]] || die "SDLC_SKILLS_TRUSTED_KEYS_FILE not found: $SDLC_SKILLS_TRUSTED_KEYS_FILE"
    cp "$SDLC_SKILLS_TRUSTED_KEYS_FILE" "$keys"
  else
    printf '%s\n' "$TRUSTED_KEYS" > "$keys"
  fi
  mkdir -p "$tmp/keys"
  awk -v dir="$tmp/keys" '
    /^-----BEGIN PUBLIC KEY-----[[:space:]]*$/ { n++; on = 1 }
    on { print > (dir "/" n ".pem") }
    /^-----END PUBLIC KEY-----[[:space:]]*$/ { on = 0 }
  ' "$keys"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//[[:space:]]/}"
    [[ -n "$line" ]] || continue
    printf '%s' "$line" | base64 --decode > "$tmp/sig.der" 2>/dev/null || continue
    for k in "$tmp/keys"/*.pem; do
      [[ -f "$k" ]] || continue
      if openssl dgst -sha256 -verify "$k" -signature "$tmp/sig.der" "$1" >/dev/null 2>&1; then return 0; fi
    done
  done < "$2"
  return 1
}

# The file whose `set.<id>=<ns>,<ns>` lines define the skill sets of the bundle
# being installed: the signed manifest, or the release's lock.
setsfile=""

if [[ "$source_kind" == signed ]]; then
  from="${SKILLS_BASE_URL}/${SKILLS_VERSION}"
  echo "==> fetching SDLC skills release ${SKILLS_VERSION} from ${SKILLS_BASE_URL}"
  curl -fsSL "${from}/sdlc-skills.manifest" -o "$tmp/manifest.signed" </dev/null || die "cannot fetch ${from}/sdlc-skills.manifest"
  curl -fsSL "${from}/sdlc-skills.manifest.sig" -o "$tmp/manifest.sig" </dev/null || die "cannot fetch ${from}/sdlc-skills.manifest.sig"
  [[ "$(wc -c < "$tmp/manifest.signed")" -le 65536 ]] || die "the manifest of skills release ${SKILLS_VERSION} exceeds 65536 bytes"
  # Nothing in the manifest is read before its signature verifies.
  verify_signature "$tmp/manifest.signed" "$tmp/manifest.sig" \
    || die "no trusted key verifies the signature of skills release ${SKILLS_VERSION}"

  # key=value lines; blank lines and # comments skipped; keys this installer
  # does not know are ignored, so a later release of the same contract works.
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^$/d' -e '/^#/d' "$tmp/manifest.signed" > "$tmp/manifest"
  bad="$(grep -v -m1 '^[^=][^=]*=' "$tmp/manifest" || true)"
  [[ -z "$bad" ]] || die "malformed line in the skills manifest: $bad"
  dup="$(cut -d= -f1 "$tmp/manifest" | LC_ALL=C sort | uniq -d | head -n1)"
  [[ -z "$dup" ]] || die "the skills manifest defines $dup twice"
  mget() { sed -n "s/^$1=//p" "$tmp/manifest" | head -n1; }

  contract="$(mget contract)"
  [[ "$contract" =~ ^[1-9][0-9]{0,5}$ ]] || die "the skills manifest has no usable contract version ('$contract')"
  if (( contract > SUPPORTED_CONTRACT )); then
    die "skills release ${SKILLS_VERSION} uses contract $contract; this installer supports contract $SUPPORTED_CONTRACT (use a newer Containarium release, or an earlier skills release)"
  fi
  m_version="$(mget version)"
  [[ "$m_version" =~ $VERSION_RE && "$m_version" != latest ]] || die "the skills manifest has no usable version ('$m_version')"
  # A signed release served under another version's path is not what was asked for.
  if [[ "$SKILLS_VERSION" != latest && "$SKILLS_VERSION" != "$m_version" ]]; then
    die "asked for skills release ${SKILLS_VERSION}, but the manifest there is for ${m_version}"
  fi
  want="$(mget sha256)"
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "the skills manifest has no sha256 digest"
  owned=" "; nsets=0
  while IFS='=' read -r key val; do
    id="${key#set.}"
    [[ "$id" =~ ^[a-z0-9-]+$ ]] || die "bad set id '$id' in the skills manifest"
    [[ "$val" =~ ^[a-z0-9-]+(,[a-z0-9-]+)*$ ]] || die "bad namespace list for set '$id' in the skills manifest"
    IFS=',' read -r -a more <<< "$val"
    for ns in "${more[@]}"; do
      [[ "$owned" != *" $ns "* ]] || die "namespace '$ns' is in more than one set of the skills manifest"
      owned+="$ns "
    done
    nsets=$((nsets + 1))
  done < <(grep '^set\.' "$tmp/manifest" || true)
  [[ "$nsets" -gt 0 ]] || die "the skills manifest defines no skill sets"

  SKILLS_VERSION="$m_version"
  curl -fsSL "${SKILLS_BASE_URL}/${SKILLS_VERSION}/sdlc-skills.tar.gz" -o "$tmp/sdlc-skills.tar.gz" </dev/null \
    || die "cannot fetch ${SKILLS_BASE_URL}/${SKILLS_VERSION}/sdlc-skills.tar.gz"
  got="$(sha256_of "$tmp/sdlc-skills.tar.gz")"
  if [[ "$got" != "$want" ]]; then
    die "sha256 mismatch (bundle $got, signed manifest $want)"
  fi
  setsfile="$tmp/manifest"
else
  echo "==> fetching SDLC skills from ${ARTIFACT_BASE_URL}"
  curl -fsSL "${ARTIFACT_BASE_URL}/sdlc-skills.tar.gz" -o "$tmp/sdlc-skills.tar.gz" </dev/null
  curl -fsSL "${ARTIFACT_BASE_URL}/sdlc-skills.tar.gz.sha256" -o "$tmp/sdlc-skills.tar.gz.sha256" </dev/null

  want="$(cut -d' ' -f1 "$tmp/sdlc-skills.tar.gz.sha256" | head -n1)"
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || { echo "install-sdlc-skills: malformed .sha256 file" >&2; exit 1; }
  got="$(sha256_of "$tmp/sdlc-skills.tar.gz")"
  if [[ "$got" != "$want" ]]; then
    echo "install-sdlc-skills: sha256 mismatch (asset $got, expected $want); nothing installed" >&2
    exit 1
  fi
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
  # Resolve set ids to namespaces through what defines THIS bundle's sets (the
  # signed manifest, or the lock that pins a release asset), then extract only
  # those namespaces' entries (plus _shared/).
  if [[ -z "$setsfile" ]]; then
    lock_url="${SDLC_SKILLS_LOCK_URL:-}"
    if [[ -z "$lock_url" ]]; then
      [[ -n "$RELEASE" ]] || { echo "install-sdlc-skills: set SDLC_SKILLS_LOCK_URL to select skill sets without RELEASE; nothing installed" >&2; exit 2; }
      lock_url="https://raw.githubusercontent.com/${REPO}/${RELEASE}/pkg/core/sdlcskills/sdlc-skills.lock"
    fi
    if ! curl -fsSL "$lock_url" -o "$tmp/sdlc-skills.lock" </dev/null; then
      echo "install-sdlc-skills: cannot read the skill-set lock at $lock_url (a release that predates skill sets cannot honour SKILL_SETS=$SKILL_SETS); nothing installed" >&2
      exit 1
    fi
    # The current lock has one [source] section per release asset. Read the
    # digest for sdlc-skills.tar.gz from [sdlc], while accepting the earlier flat
    # lock during the compatibility window.
    lock_sha="$(awk -F= '
      /^\[/ { in_sdlc = ($0 == "[sdlc]"); saw_section = 1; next }
      $1 == "sha256" && in_sdlc { print $2; found = 1; exit }
      $1 == "sha256" && !saw_section && legacy == "" { legacy = $2 }
      END { if (!found && legacy != "") print legacy }
    ' "$tmp/sdlc-skills.lock")"
    if [[ "$lock_sha" != "$got" ]]; then
      echo "install-sdlc-skills: the lock does not pin the downloaded bundle (lock ${lock_sha:-none}, bundle $got); nothing installed" >&2
      exit 1
    fi
    setsfile="$tmp/sdlc-skills.lock"
  fi
  known="$(sed -n 's/^set\.\([a-z0-9-][a-z0-9-]*\)=.*/\1/p' "$setsfile" | paste -sd, - | sed 's/,/, /g')"
  nss=()
  for s in "${sets[@]}"; do
    line="$(sed -n "s/^set\.${s}=//p" "$setsfile" | head -n1)"
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
if [[ "$source_kind" == signed ]]; then
  # Which set each installed directory belongs to, from the signed manifest
  # (the longest matching namespace, so `qa-x-...` is not taken for `qa`).
  : > "$tmp/sets"
  for n in "${new[@]}"; do
    [[ "$n" == _shared ]] && continue
    best_id=""; best_ns=""
    while IFS='=' read -r key val; do
      IFS=',' read -r -a more <<< "$val"
      for ns in "${more[@]}"; do
        if [[ "$n" == "$ns"-* && "${#ns}" -gt "${#best_ns}" ]]; then best_ns="$ns"; best_id="${key#set.}"; fi
      done
    done < <(grep '^set\.' "$tmp/manifest")
    [[ -z "$best_id" ]] || printf '%s\t%s\n' "$best_id" "$n" >> "$tmp/sets"
  done
  LC_ALL=C sort "$tmp/sets" > "$SKILLS_DIR/.sdlc-skills-sets"
  if [[ -n "$rec_skills" && "$rec_skills" != "$SKILLS_VERSION" ]]; then
    echo "==> skills release ${rec_skills} -> ${SKILLS_VERSION}"
  fi
  printf 'release=%s sha256=%s installed=%s skills=%s contract=%s\n' "${RELEASE:-custom}" "$want" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$SKILLS_VERSION" "$contract" > "$SKILLS_DIR/.sdlc-skills-version"
else
  rm -f "$SKILLS_DIR/.sdlc-skills-sets"
  printf 'release=%s sha256=%s installed=%s\n' "${RELEASE:-custom}" "$want" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$SKILLS_DIR/.sdlc-skills-version"
fi

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
