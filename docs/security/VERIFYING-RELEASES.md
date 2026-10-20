# Verifying a release

A signed Containarium GitHub Release has a signature beside each file:
`<file>.sigstore.json`. The release workflow makes it with
[cosign](https://github.com/sigstore/cosign) keyless signing, so there is no
project key to obtain, trust, or rotate. What a signature proves is that the
file was produced by this repository's `release.yml` workflow, running on that
release's tag, and was not changed after.

Older releases may have checksums and SBOMs without signature bundles. A
release without `.sigstore.json` assets cannot pass this signature procedure.

This covers the binaries, the SPDX SBOMs, the agent-runtime and SDLC skills
bundles, the air-gapped install bundle, the Helm chart, `SHA256SUMS.txt`, and
the `.sha256` files. Container images carry their own provenance and SBOM
attestations and are not covered here.

## Verify one file

Install cosign (the release workflow uses v3.1.3), download the file and its `.sigstore.json`,
then:

```bash
TAG=v0.0.0   # the release you downloaded
cosign verify-blob \
  --bundle containariumd-linux-amd64.sigstore.json \
  --certificate-identity "https://github.com/FootprintAI/Containarium/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  containariumd-linux-amd64
```

`Verified OK` means the signature is valid, is recorded in the public Rekor
transparency log, and was made by that workflow at that tag. Any other output
is a failure: do not run the file.

The identity is the exact workflow and tag. A copy of the workflow in a fork,
a different workflow in this repository, or a different tag does not match.
To accept any release of this repository rather than one tag, use
`--certificate-identity-regexp '^https://github\.com/FootprintAI/Containarium/\.github/workflows/release\.yml@refs/tags/v[0-9]'`.
The certificate identity is case-sensitive; preserve `FootprintAI/Containarium`
exactly. GitHub web URL redirects do not make a differently cased identity valid.

## Verify checksums too

A signature covers one file. `SHA256SUMS.txt` is signed like any other, so you
can verify it once and then check every binary and SBOM it lists:

```bash
cosign verify-blob --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity "https://github.com/FootprintAI/Containarium/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
```

The Helm chart is listed in `SHA256SUMS.txt` and has its own `.sha256`.
The air-gapped bundle has its own `.sha256`. Each artifact and its checksum
sidecar is signed.

## Verify the entire release / sprint RC

From a checkout containing `scripts/release/verify_assets.py`, with `gh`,
Python 3 and cosign v3.1.3 available:

```bash
set -euo pipefail
TAG=v0.110.0-rc.1  # replace with the agreed sprint RC; this does not publish it
gh release download "$TAG" --repo FootprintAI/Containarium --dir release-files --pattern '*'
gh api "repos/FootprintAI/Containarium/releases/tags/$TAG" > release-metadata.json
python3 scripts/release/verify_assets.py release-files \
  --metadata release-metadata.json --repository FootprintAI/Containarium --tag "$TAG" \
  | tee release-verification.json
```

Use a new download directory for each tag. The verifier requires the published
asset inventory to match the download, verifies every artifact's signature
against the exact workflow/tag identity, requires the offline bundle and four
nonempty Linux SPDX SBOMs, checks checksums and coverage, and checks the chart's
version/appVersion and the chart version in release notes. A missing signature,
omitted required artifact, invalid signature or mismatch fails the command.
Its JSON report is evidence of what was checked; retain it with the RC tag's
resolved commit and the Helm install/upgrade run on the sprint umbrella.

`release.yml` runs this check after uploading signatures, downloading those
bundles again rather than trusting the local signing output. The read-only
`Release asset verification` workflow can also be dispatched for an existing
tag. Neither command signs or publishes anything. These checks do not replace
the kind install/upgrade test or the licence gate.

## Air-gapped hosts

Verification needs the `.sigstore.json` bundle and the Sigstore trust root,
not network access to the project. Fetch the bundle with the release files,
and run `cosign initialize` on a connected machine to copy its trust root to
the air-gapped host (`cosign verify-blob --trusted-root <file>` points cosign
at it). Without the trust root the bundle cannot be checked offline.

## How this is built

`release.yml` job `sign-release` runs after the binaries, bundle and chart have
all been uploaded. It downloads the Release's files, signs each, verifies each
signature against the identity above before attaching it, and uploads the
bundles. If any job it depends on fails, nothing is signed and the Release has
no `.sigstore.json` files, which is a visible failure. Signing runs on tag
pushes only: a `workflow_dispatch` rehearsal builds everything but signs
nothing, because a signature is a permanent entry in a public log.

## What a signature does not prove

It identifies the build that produced the file, not that the source is free of
bugs or that the dependencies are safe. Dependency licences are checked in CI
([DEPENDENCY-LICENSES.md](DEPENDENCY-LICENSES.md)) and each Linux binary has an
SBOM listing what it contains.
