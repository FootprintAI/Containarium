#!/usr/bin/env bash
# build-sdlc-skills-bundle.sh — package the pinned SDLC role skills (#2065).
#
# Reads pkg/core/sdlcskills/sdlc-skills.lock, fetches exactly that commit of
# open-sdlc-skills, and writes into <out-dir>:
#   sdlc-skills.tar.gz         <ns>-<name>/SKILL.md per role skill, plus _shared/
#   sdlc-skills.tar.gz.sha256  its sha256
# The tarball is deterministic (sorted entries, fixed owner/mtime, no gzip
# timestamp): the same ref always yields the same bytes, so the lock can carry
# the digest and CI can verify it by rebuilding.
#
# Usage: build-sdlc-skills-bundle.sh [--update-lock] <out-dir>
#   --update-lock   write the computed sha256 back into the lock (the bump step)
# Env:
#   SDLC_SKILLS_LOCK      lock path (default pkg/core/sdlcskills/sdlc-skills.lock)
#   SDLC_SKILLS_REPO_URL  clone URL override (tests); default https://github.com/<repo>.git
set -euo pipefail

UPDATE_LOCK=0
OUT=""
for arg in "$@"; do
  case "$arg" in
    --update-lock) UPDATE_LOCK=1 ;;
    -*) echo "build-sdlc-skills-bundle: unknown flag: $arg" >&2; exit 2 ;;
    *) OUT="$arg" ;;
  esac
done
[[ -n "$OUT" ]] || { echo "usage: build-sdlc-skills-bundle.sh [--update-lock] <out-dir>" >&2; exit 2; }

LOCK="${SDLC_SKILLS_LOCK:-pkg/core/sdlcskills/sdlc-skills.lock}"
[[ -f "$LOCK" ]] || { echo "build-sdlc-skills-bundle: no lock file: $LOCK" >&2; exit 2; }
lock_get() { sed -n "s/^$1=//p" "$LOCK" | head -n1; }
REPO="$(lock_get repo)"; REF="$(lock_get ref)"; WANT_SHA="$(lock_get sha256)"
[[ -n "$REPO" ]] || { echo "build-sdlc-skills-bundle: lock has no repo" >&2; exit 2; }
[[ "$REF" =~ ^[0-9a-f]{40}$ ]] || { echo "build-sdlc-skills-bundle: lock ref must be a full 40-hex commit sha, got '$REF'" >&2; exit 2; }
URL="${SDLC_SKILLS_REPO_URL:-https://github.com/${REPO}.git}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
src="$tmp/src"; stage="$tmp/stage"
mkdir -p "$src" "$stage" "$OUT"

git -C "$src" init -q
git -C "$src" fetch -q --depth 1 "$URL" "$REF"
git -C "$src" checkout -q --detach FETCH_HEAD
got="$(git -C "$src" rev-parse HEAD)"
[[ "$got" == "$REF" ]] || { echo "build-sdlc-skills-bundle: fetched $got, lock pins $REF" >&2; exit 1; }

# Role skills: <ns>/<name>.md -> <ns>-<name>/SKILL.md. Top-level files (README,
# CONTRIBUTING) and dot-dirs are not skills; _shared/ is read at runtime by the
# skills and is copied as-is.
count=0
namespaces=" "
for d in "$src"/*/; do
  ns="$(basename "$d")"
  [[ "$ns" == _shared ]] && continue
  namespaces+="$ns "
  for f in "$d"*.md; do
    [[ -f "$f" ]] || continue
    name="$(basename "$f" .md)"
    mkdir -p "$stage/${ns}-${name}"
    cp "$f" "$stage/${ns}-${name}/SKILL.md"
    count=$((count + 1))
  done
done
[[ "$count" -gt 0 ]] || { echo "build-sdlc-skills-bundle: no role skills found at $REF" >&2; exit 1; }
# Skill sets (#3048): the lock's `set.<id>=<ns>,<ns>` lines say which namespaces
# each set id selects (install-sdlc-skills.sh SKILL_SETS). Once a lock declares
# any, they must partition the namespaces in the archive: every namespace in
# exactly one set, no set naming a namespace that is not there. A new upstream
# namespace therefore fails the build until it is assigned, instead of being
# silently unselectable.
if grep -q '^set\.' "$LOCK"; then
  assigned=" "
  while IFS='=' read -r key val; do
    id="${key#set.}"
    [[ "$id" =~ ^[a-z0-9-]+$ ]] || { echo "build-sdlc-skills-bundle: bad set id '$id' in the lock (want [a-z0-9-]+)" >&2; exit 1; }
    IFS=',' read -r -a nss <<< "$val"
    [[ "${#nss[@]}" -gt 0 ]] || { echo "build-sdlc-skills-bundle: set '$id' has no namespaces" >&2; exit 1; }
    for ns in "${nss[@]}"; do
      [[ "$namespaces" == *" $ns "* ]] || { echo "build-sdlc-skills-bundle: set '$id' names namespace '$ns', which is not in $REF" >&2; exit 1; }
      [[ "$assigned" != *" $ns "* ]] || { echo "build-sdlc-skills-bundle: namespace '$ns' is in more than one set" >&2; exit 1; }
      assigned+="$ns "
    done
  done < <(grep '^set\.' "$LOCK")
  for ns in $namespaces; do
    [[ "$assigned" == *" $ns "* ]] || { echo "build-sdlc-skills-bundle: namespace '$ns' is in no set; add it to a set.<id> line in the lock" >&2; exit 1; }
  done
fi
if [[ -d "$src/_shared" ]]; then
  mkdir -p "$stage/_shared"
  cp "$src/_shared/"*.md "$stage/_shared/"
fi

python3 -I - "$stage" "$OUT/sdlc-skills.tar.gz" <<'PY'
import gzip, io, os, sys, tarfile
stage, out = sys.argv[1], sys.argv[2]
names = []
for root, dirs, files in os.walk(stage):
    dirs.sort()
    for n in sorted(files):
        names.append(os.path.relpath(os.path.join(root, n), stage))
names.sort()
raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
    for n in names:
        data = open(os.path.join(stage, n), "rb").read()
        ti = tarfile.TarInfo(n)
        ti.size, ti.mode, ti.mtime = len(data), 0o644, 0
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        tf.addfile(ti, io.BytesIO(data))
with open(out, "wb") as f:
    with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0) as gz:
        gz.write(raw.getvalue())
PY

if command -v sha256sum >/dev/null 2>&1; then SUM="$(sha256sum "$OUT/sdlc-skills.tar.gz" | cut -d' ' -f1)"
else SUM="$(shasum -a 256 "$OUT/sdlc-skills.tar.gz" | cut -d' ' -f1)"; fi
printf '%s  sdlc-skills.tar.gz\n' "$SUM" > "$OUT/sdlc-skills.tar.gz.sha256"

if [[ "$UPDATE_LOCK" == 1 ]]; then
  sed -i.bak "s/^sha256=.*/sha256=${SUM}/" "$LOCK" && rm -f "$LOCK.bak"
  echo "build-sdlc-skills-bundle: lock updated ($count skills, sha256 ${SUM})"
elif [[ -z "$WANT_SHA" ]]; then
  echo "build-sdlc-skills-bundle: lock has no sha256 yet; run with --update-lock" >&2
  exit 1
elif [[ "$WANT_SHA" != "$SUM" ]]; then
  echo "build-sdlc-skills-bundle: sha256 mismatch: lock $WANT_SHA, rebuilt $SUM" >&2
  exit 1
else
  echo "build-sdlc-skills-bundle: ok ($count skills at ${REF:0:12}, sha256 ${SUM})"
fi
