# Verifying a release

Every file on a Containarium GitHub Release has a signature next to it:
`<file>.sigstore.json`. The release workflow makes it with
[cosign](https://github.com/sigstore/cosign) keyless signing, so there is no
project key to obtain, trust, or rotate. What a signature proves is that the
file was produced by this repository's `release.yml` workflow, running on that
release's tag, and was not changed after.

This covers the binaries, the SPDX SBOMs, the agent-runtime and SDLC skills
bundles, the air-gapped install bundle, the Helm chart, `SHA256SUMS.txt`, and
the `.sha256` files. Container images carry their own provenance and SBOM
attestations and are not covered here.

## Verify one file

Install cosign (v2.x or later), download the file and its `.sigstore.json`,
then:

```bash
TAG=v0.0.0   # the release you downloaded
cosign verify-blob \
  --bundle containariumd-linux-amd64.sigstore.json \
  --certificate-identity "https://github.com/footprintai/containarium/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  containariumd-linux-amd64
```

`Verified OK` means the signature is valid, is recorded in the public Rekor
transparency log, and was made by that workflow at that tag. Any other output
is a failure: do not run the file.

The identity is the exact workflow and tag. A copy of the workflow in a fork,
a different workflow in this repository, or a different tag does not match.
To accept any release of this repository rather than one tag, use
`--certificate-identity-regexp '^https://github.com/footprintai/containarium/\.github/workflows/release\.yml@refs/tags/v[0-9]'`.

## Verify checksums too

A signature covers one file. `SHA256SUMS.txt` is signed like any other, so you
can verify it once and then check every binary and SBOM it lists:

```bash
cosign verify-blob --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity "https://github.com/footprintai/containarium/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
```

The air-gapped bundle and the Helm chart are not listed in `SHA256SUMS.txt`;
each has its own `.sha256`, and each file and its `.sha256` is signed.

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
