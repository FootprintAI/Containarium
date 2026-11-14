# SDLC skills: the pin, the bundle build and delivery move out of this repo ("option B")

**Status:** proposed. Nothing is cut over until PR 4 below.

## Problem

Today a change to the role skills is a change to this repository: the pin
(`pkg/core/sdlcskills/sdlc-skills.lock`) is edited here, the bundle is built by
this repository's release workflow, and a box picks the new bundle up whenever
it is re-applied from a newer release. The installer trusts the bundle because
its digest matches a `.sha256` file and a lock fetched over the same kind of
channel that delivered the bundle.

## Decision

- Skill content stays in the public skills repository. Unchanged.
- The control-plane repository ("cloud") owns the pin, builds the bundle at the
  pinned commit, signs it and publishes it at a URL it controls. A skill change
  is a cloud release, not a PR here.
- This repository embeds a public key and verifies a signature before trusting
  a bundle. The digest comes from the signed manifest, never from an unsigned
  file next to the bundle.
- A box keeps the skills release it was installed with. Moving it is a
  per-box, explicit call.
- This repository keeps a versioned contract for skill-set ids.

## Release day, before and after

| | Before | After |
| --- | --- | --- |
| Bump the skills | PR here editing the lock; `sdlc-skills-lock` CI rebuilds and compares | PR in cloud editing its lock (`ref`, `sha256`, `version`); cloud CI rebuilds and compares |
| Build and publish | this repo's tag build attaches `sdlc-skills.tar.gz` + `.sha256` to the Release | cloud's tag build builds, signs and publishes `<base>/<version>/` and moves `<base>/latest/` |
| This repo's tag build | builds the bundle, lists it in `SHA256SUMS.txt` | no skills step; the air-gapped bundle build fetches and verifies the signed artifact |
| Reaching a box | any re-apply from a newer release | `containarium code skill-sets <box> --skills-version <v>` |

## Published artifact

```
<base>/<version>/sdlc-skills.tar.gz            same deterministic layout as today
<base>/<version>/sdlc-skills.manifest          signed text manifest
<base>/<version>/sdlc-skills.manifest.sig      detached signature(s), one base64 line each
<base>/latest/sdlc-skills.manifest{,.sig}      copy of the newest version's two files
```

Manifest (`key=value`, `#` comments, unknown keys ignored, duplicate keys refused):

```
contract=1
version=2026.11.0
sha256=<digest of sdlc-skills.tar.gz>
source.sdlc=<owner>/<repo>@<full commit sha>
set.sdlc=architect,engineer,...
set.qa=qa
set.security=security
```

A versioned directory is immutable: the cloud publish step refuses to
overwrite one whose manifest differs. When a version is asked for by name, the
verifier also checks that the manifest's `version` is that name, so a validly
signed release cannot be served under another version's path.

## Signing choice

A detached **cosign key-pair signature** over the manifest: ECDSA P-256 over
SHA-256, ASN.1 DER, base64 (`cosign sign-blob --key`).

- Cloud already pins and runs cosign for its images, and cosign can sign with a
  key held in a KMS, so no private key has to sit in a CI secret.
- The format verifies with the Go standard library (`crypto/ecdsa`) and with
  `openssl dgst -sha256 -verify`, which box images already carry. No new Go
  module here and no new binary in a box.
- minisign was the alternative. Its Ed25519-over-BLAKE2b signature needs the
  minisign binary in every box (the installer is bash), and it cannot use a
  KMS key.
- Keyless cosign (what cloud uses for images) was rejected for this artifact:
  verifying it needs the certificate and transparency-log trust roots, network
  access and a large dependency, which fits neither the box installer nor an
  air-gapped build.
- `pkg/core/catalogsig` already verifies detached signatures here, for
  operator-supplied catalogs: raw Ed25519 with keys the operator configures.
  It was not reused. Checking a raw Ed25519 signature in the bash installer
  needs OpenSSL 3 in every box image, and cosign key pairs are P-256. The two
  stay separate: that one is opt-in trust an operator sets up, this one is a
  key built into the release.

Trusted keys live in `pkg/core/sdlcskills/trusted-keys.pub` (embedded by the
daemon and CLI) and inline in `scripts/install-sdlc-skills.sh`; a test fails
if the two differ. The file may hold several keys and a `.sig` may hold
several lines: any trusted key verifying any line is enough. Rotation is "add
the new key here and release, then cloud signs with both, then drop the old
key". An operator who runs their own skills release points the installer at
their own key file.

Limits: a mirror can replay an older, validly signed `latest`; that affects
only a fresh install with no version asked for, never an existing box.

## Skill-set contract

`pkg/core/sdlcskills/contract.go` holds `ContractVersion` (1) and the set ids
of that contract: `sdlc`, `qa`, `security`.

- A requested id outside the contract is refused before anything is fetched,
  with a message naming the known ids.
- The manifest's `set.<id>=` lines decide which namespaces a set covers. A
  bundle may define sets this daemon does not know; they are installed by
  `all` and cannot be selected by id until the daemon's contract lists them.
- An id in the contract that a given skills release does not define fails in
  the installer, naming the ids that release has.
- A bundle may add manifest keys without a contract bump. A change an older
  reader cannot ignore bumps `contract`; a reader refuses a manifest whose
  contract is higher than its own and says which it supports.

## Compatibility

| Daemon / installer | Bundle | Result |
| --- | --- | --- |
| Before this change | any signed release | Not reached: an old installer only reads the Release assets of its own tag, which stay where they are. |
| With this change | older signed release, same contract | Installs. A contract id the release lacks fails naming the ids it has. |
| With this change | newer signed release, same contract | Installs. Extra manifest keys ignored; extra sets handled as above. |
| With this change | higher contract | Refused, nothing installed; the message names the supported contract. |
| With this change | box installed from a release asset (no recorded skills version) | Stays on that release's asset until a skills version is asked for. |
| Air-gapped | signed release pinned and fetched at bundle-build time | Verified when cached, again when the bundle is assembled, and again at install; no network at install. |

## Per-box upgrade

The installer records `skills=<version>` in `~/.claude/skills/.sdlc-skills-version`.

- No version asked for: reuse the recorded version. A box with only a
  release recorded stays on that release's asset. A box with nothing
  recorded takes `latest` once and records it.
- `containarium code skill-sets <box> --skill-sets <ids> --skills-version <v|latest>`
  (and `code install --skills-version`) moves one box. The daemon RPC, the
  MCP tool and the recipe parameters carry the same field. Nothing moves a
  fleet in one call.
- A request against an installer or daemon that predates the field fails. It
  is never reported as a move.
- Removing every set (`none`) removes the record with the skills. Adding sets
  back later is a fresh install: it takes `latest` unless a version is named.

## Rollback

- A bad skills release: re-apply the previous version to the affected boxes
  (`--skills-version <previous>`); cloud republishes `latest` from the previous
  version. Versioned directories are never rewritten.
- A bad cutover (PR 4): revert it. The lock, build script and release steps
  come back, and releases before the cutover still carry their assets.
- A compromised signing key: remove it from `trusted-keys.pub` and the
  installer in a patch release; cloud re-signs published versions with the
  new key.

## PRs, in order

| # | Repo | What | Depends on |
| --- | --- | --- | --- |
| 1 | this repo (#3729) | Verifier, manifest and contract in `pkg/core/sdlcskills`; installer signed-source mode, off unless a base URL is given. No behaviour change by default. | none |
| 2 | cloud | The lock, the bundle build, manifest, signing and publish steps, and the CI check that the lock matches a rebuild. Publishing is skipped until the signing key and destination are configured. | none (format agreed with 1) |
| 3 | this repo (#3730) | `skills_version` on `ApplyBoxSkillSets`, `--skills-version` on `code skill-sets` and `code install`, the MCP argument, the recipe parameters, the daemon's base-URL setting, signed loading for the hosted issue-implementer's standard. | 1 |
| 4 | this repo (#3731) | The air-gapped bundle build fetches a pinned skills release, verifies it and ships it with the installer (`--fetch-only`). | 1 |
| 5 | this repo | Cutover: commit the public key, default the base URL, delete the lock, build script, `sdlc-skills-lock` workflow and the Release steps; the daemon attributes skills to sets from what the installer recorded (`.sdlc-skills-sets`) instead of the embedded lock. | 1, 3, 4, a first signed cloud release, the key and URL |
| 6 | cloud | The control plane passes its pinned skills version when it creates or upgrades a box. | 2, and a release of this repo with 3 |

PRs 5 and 6 are not open. 5 waits for two things only an operator can supply
(the signing key's public half and the public base URL) and for one signed
release to exist. 6 waits for a release of this repository carrying 3.

## Not verified by CI

Anything that needs a running box: an install inside a real box image
(`openssl` present, the box user's home), `code skill-sets --skills-version`
end to end through a daemon, and the air-gapped install. They are verification
items on the PRs.
