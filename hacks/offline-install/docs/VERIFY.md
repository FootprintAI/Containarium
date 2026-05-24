# Bundle Verification

Two layers of integrity protection ship with every air-gapped bundle:

1. **Outer SHA256** — `<bundle>.tar.gz.sha256` on the GitHub release
   page. Verifies that the tarball you downloaded matches what we
   uploaded.
2. **Inner CHECKSUMS.sha256** — included inside the tarball. Verifies
   that every file inside the bundle matches what we packaged.

Cosign signing (v0.1) adds a third layer; v0 ships unsigned but with
both SHA256 layers.

## Layer 1 — Outer checksum

On the sherpa host (where you downloaded the bundle):

```bash
sha256sum -c containarium-bundle-v0.19.0-linux-amd64.tar.gz.sha256
# Expected: containarium-bundle-v0.19.0-linux-amd64.tar.gz: OK
```

If the check fails, **do not transfer the bundle**. Re-download it.

## Layer 2 — Inner checksums

The offline installer runs this automatically as its first step,
but you can verify manually on the air-gapped host:

```bash
cd containarium-bundle-v0.19.0-linux-amd64/
sha256sum -c CHECKSUMS.sha256
```

Expected output: every file ending in `OK`. A single mismatch indicates
in-transit corruption (bit-flip on the USB stick, scanner-rewrite by a
file diode); re-transfer the bundle.

## Layer 3 (v0.1) — Cosign signature

v0.1 of the bundle ships a `CHECKSUMS.sha256.sig` file alongside, signed
via Sigstore keyless OIDC. Verify on the sherpa host:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/footprintai/containarium/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle CHECKSUMS.sha256.sig \
  CHECKSUMS.sha256
```

A successful verification proves the checksum file was signed by the
FootprintAI release workflow (not just any host that happens to have
network access to GHCR).

## What about the contents?

Each file in the bundle is whatever the upstream publisher produced —
the Go tarball is what `go.dev` served, the Node tarball is what
`nodejs.org` served, the Incus debs are what Zabbly built. We re-host
without re-signing. If your security review requires verification of
upstream signatures, the SBOM (shipped in v0.1 as `bundle.sbom.json`
via `syft`) gives you the input list to audit independently.
