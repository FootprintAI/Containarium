#!/usr/bin/env bash
#
# slides-agent-smoke.sh <image> | --self-test
#
# Runs the slides-agent image the way a box does and proves the part CI used to
# only scan: the pinned framework builds a deck, and the headless Chromium on
# the image's base prints it to a real PDF. A change of base distro or Chromium
# build is exactly what can break this without tripping the vulnerability gate.
#
#   1. seed a bind-mounted workspace from the image's template
#   2. `open-slide build` into /workspace/dist
#   3. `slides-print-pdf /workspace/dist /workspace/smoke.pdf` (the starter deck)
#   4. check the PDF: header, size, at least one page, 1920x1080 CSS px pages
#      (1440x810 pt), embedded fonts
#
# The PDF check is also exercised on seeded bad files by --self-test, so a
# green run is evidence the check can fail. Runs against any image reference:
# the PR build (containarium-slides-agent:ci) and the pre-publish scan copy
# (localhost:5000/containarium-slides-agent:scan).
set -euo pipefail

MIN_PDF_BYTES=5000

# check_pdf <file>: prints why and returns 1 when the file is not a usable deck
# PDF. Chromium's PDF writer leaves page and font dictionaries uncompressed, so
# they can be matched on the raw bytes without a PDF library.
check_pdf() {
  local f=$1 size pages
  [ -s "$f" ] || { echo "pdf: missing or empty" >&2; return 1; }
  [ "$(head -c 5 "$f")" = "%PDF-" ] || { echo "pdf: no %PDF- header" >&2; return 1; }
  size=$(wc -c < "$f")
  [ "$size" -ge "$MIN_PDF_BYTES" ] || { echo "pdf: $size bytes, want >= $MIN_PDF_BYTES" >&2; return 1; }
  pages=$({ grep -a -o -E '/Type */Page([^s]|$)' "$f" || true; } | wc -l)
  [ "$pages" -ge 1 ] || { echo "pdf: no page objects" >&2; return 1; }
  grep -a -q -E '/MediaBox *\[ *0 +0 +1440(\.0+)? +810(\.0+)? *\]' "$f" \
    || { echo "pdf: no 1440x810 pt (1920x1080 px) page box" >&2; return 1; }
  grep -a -q '/FontFile' "$f" || { echo "pdf: no embedded font" >&2; return 1; }
  echo "pdf ok: $size bytes, $pages page object(s)"
}

self_test() {
  local d f
  d=$(mktemp -d)
  trap 'rm -rf "$d"' RETURN
  pad() { head -c 6000 /dev/zero | tr '\0' ' '; }
  good="$d/good.pdf"
  { printf '%%PDF-1.4\n<< /Type /Page /MediaBox [0 0 1440 810] >>\n<< /FontFile2 5 0 R >>\n'; pad; } > "$good"
  check_pdf "$good" >/dev/null || { echo "self-test: a good pdf was rejected" >&2; return 1; }
  : > "$d/empty.pdf"
  printf 'not a pdf' > "$d/nohdr.pdf"
  { printf '%%PDF-1.4\n<< /Type /Page /MediaBox [0 0 1440 810] >>\n'; pad; } > "$d/nofont.pdf"
  { printf '%%PDF-1.4\n<< /Type /Pages >>\n<< /MediaBox [0 0 1440 810] /FontFile2 5 0 R >>\n'; pad; } > "$d/nopage.pdf"
  { printf '%%PDF-1.4\n<< /Type /Page /MediaBox [0 0 612 792] >>\n<< /FontFile2 5 0 R >>\n'; pad; } > "$d/badbox.pdf"
  { printf '%%PDF-1.4\n<< /Type /Page /MediaBox [0 0 1440 810] /FontFile2 5 0 R >>\n'; } > "$d/tiny.pdf"
  for f in empty nohdr nofont nopage badbox tiny; do
    if check_pdf "$d/$f.pdf" >/dev/null 2>&1; then
      echo "self-test: bad pdf '$f' was accepted" >&2
      return 1
    fi
  done
  echo "self-test ok: good pdf accepted; empty, headerless, fontless, pageless, wrong-size and tiny pdfs rejected"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

image=${1:?usage: slides-agent-smoke.sh <image> | --self-test}
ws=$(mktemp -d)
# The container runs as uid 1000, not the runner's user: it must be able to write.
chmod 0777 "$ws"
trap 'rm -rf "$ws" 2>/dev/null || true' EXIT

echo "::group::seed the workspace"
# The entrypoint refuses to start without auth material, even to seed.
docker run --rm -v "$ws:/workspace" -e SLIDES_SEED_ONLY=1 \
  -e SLIDES_AUTH_USER=smoke -e SLIDES_AUTH_HASH=smoke "$image"
test -d "$ws/slides"
echo "::endgroup::"

echo "::group::chromium"
docker run --rm --entrypoint chromium "$image" --version
echo "::endgroup::"

echo "::group::open-slide build"
docker run --rm -v "$ws:/workspace" --entrypoint /usr/local/bin/open-slide "$image" build
test -f "$ws/dist/index.html"
echo "::endgroup::"

echo "::group::slides-print-pdf"
docker run --rm -v "$ws:/workspace" --entrypoint /usr/local/bin/slides-print-pdf \
  "$image" /workspace/dist /workspace/smoke.pdf
echo "::endgroup::"

check_pdf "$ws/smoke.pdf"
