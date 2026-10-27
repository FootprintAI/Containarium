#!/usr/bin/env bash
# Sign one pushed container image by digest with cosign keyless (GitHub OIDC)
# and verify the signature straight away.
#
# Usage: scripts/release/sign-image.sh <image> <digest> <workflow-file> [evidence-dir]
#
#   image          repository without tag or digest, e.g. ghcr.io/<org>/<name>
#   digest         the digest the push produced (sha256:<64 hex>), normally
#                  docker/build-push-action's `digest` output. With provenance
#                  and SBOM attestations on, that is the image index digest.
#   workflow-file  the workflow file expected to be signing, e.g. sidecars.yml
#   evidence-dir   where to write <name>.json (what was signed) and
#                  <name>.verify.json (cosign verify output); default: ./image-signatures
#
# Signs <image>@<digest>, never a tag: a tag can be moved after signing, a
# digest cannot. The verify step pins the same identity a user is told to
# check (docs/security/VERIFYING-RELEASES.md), so an image signed with the
# wrong identity fails here.
#
# Environment:
#   COSIGN       path to cosign (default: cosign on PATH)
#   OIDC_ISSUER  the certificate issuer (default: GitHub Actions)
#   GITHUB_REPOSITORY, GITHUB_REF, GITHUB_WORKFLOW_REF  set by GitHub Actions
set -euo pipefail

image="${1:?usage: sign-image.sh <image> <digest> <workflow-file> [evidence-dir]}"
digest="${2:?usage: sign-image.sh <image> <digest> <workflow-file> [evidence-dir]}"
workflow_file="${3:?usage: sign-image.sh <image> <digest> <workflow-file> [evidence-dir]}"
evidence_dir="${4:-image-signatures}"
cosign_bin="${COSIGN:-cosign}"
issuer="${OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
: "${GITHUB_REF:?GITHUB_REF is not set}"
: "${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF is not set}"

command -v "$cosign_bin" >/dev/null || { echo "cosign not found ($cosign_bin); set COSIGN or put it on PATH" >&2; exit 2; }

# A signature is a permanent public Rekor entry: only a release tag signs.
case "$GITHUB_REF" in
  refs/tags/v*) ;;
  *) echo "::error::refusing to sign on $GITHUB_REF (release tags only)" >&2; exit 1 ;;
esac
case "$image" in
  *@*) echo "::error::image must be a repository without tag or digest: $image" >&2; exit 2 ;;
esac
# A registry port (host:5000/name) is fine; a trailing :tag is not.
case "${image##*/}" in
  *:*) echo "::error::image must not carry a tag: $image" >&2; exit 2 ;;
esac
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "::error::not a sha256 digest: '$digest'" >&2; exit 1; }

# The identity Fulcio puts in the certificate SAN is https://github.com/ +
# the job's workflow ref. Build the one we expect from the repository, the
# named workflow file and the tag, and refuse if the running workflow is a
# different one: verifying against GITHUB_WORKFLOW_REF alone would accept
# whatever workflow happened to run this script.
identity="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/${workflow_file}@${GITHUB_REF}"
running="https://github.com/${GITHUB_WORKFLOW_REF}"
if [ "$identity" != "$running" ]; then
  echo "::error::expected to run as $identity, running as $running" >&2
  exit 1
fi

ref="${image}@${digest}"
name="${image##*/}"
mkdir -p "$evidence_dir"

"$cosign_bin" sign --yes "$ref"
"$cosign_bin" verify \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$ref" > "$evidence_dir/$name.verify.json"

printf '{"image":"%s","digest":"%s","ref":"%s","certificate_identity":"%s","certificate_oidc_issuer":"%s"}\n' \
  "$image" "$digest" "$ref" "$identity" "$issuer" > "$evidence_dir/$name.json"
echo "signed and verified: $ref"
echo "identity: $identity"
