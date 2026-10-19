#!/usr/bin/env bash
# Sign every file in a directory with cosign keyless (GitHub OIDC) and verify
# each signature straight away (#2561).
#
# Usage: scripts/release/sign-assets.sh <dir>
#
# Writes <file>.sigstore.json next to each file: a Sigstore bundle holding the
# signature, the short-lived Fulcio certificate and the Rekor log entry, so a
# verifier needs only the file and its bundle. Files that already end in
# .sigstore.json are skipped, so a rerun does not sign signatures.
#
# Environment:
#   COSIGN       path to cosign (default: cosign on PATH)
#   IDENTITY     the certificate identity every signature must carry
#                (default: this repository's release.yml at GITHUB_REF)
#   OIDC_ISSUER  the certificate issuer (default: GitHub Actions)
#
# The verify step uses the same identity a user is told to check, so a
# release that signs with the wrong identity fails here, not in a customer's
# security review.
set -euo pipefail

dir="${1:?usage: sign-assets.sh <dir>}"
cosign_bin="${COSIGN:-cosign}"
issuer="${OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
command -v "$cosign_bin" >/dev/null || { echo "cosign not found ($cosign_bin); set COSIGN or put it on PATH" >&2; exit 2; }
[ -d "$dir" ] || { echo "$dir is not a directory" >&2; exit 2; }
if [ -z "${IDENTITY:-}" ]; then
  : "${GITHUB_REPOSITORY:?set IDENTITY, or GITHUB_REPOSITORY and GITHUB_REF}"
  : "${GITHUB_REF:?set IDENTITY, or GITHUB_REPOSITORY and GITHUB_REF}"
  IDENTITY="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@${GITHUB_REF}"
fi

count=0
while IFS= read -r -d '' f; do
  case "$f" in *.sigstore.json) continue ;; esac
  "$cosign_bin" sign-blob --yes --bundle "$f.sigstore.json" "$f" >/dev/null
  "$cosign_bin" verify-blob --bundle "$f.sigstore.json" \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$issuer" "$f" >/dev/null
  echo "signed: $(basename "$f")"
  count=$((count + 1))
done < <(find "$dir" -maxdepth 1 -type f -print0 | sort -z)

# Signing nothing and calling it done would publish an unsigned release.
[ "$count" -gt 0 ] || { echo "::error::no files to sign in $dir" >&2; exit 1; }
echo "signed $count files"
