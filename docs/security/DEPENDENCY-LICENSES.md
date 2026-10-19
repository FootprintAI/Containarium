# Dependency licences

Containarium is Apache-2.0. Anyone redistributing it (a reseller, an air-gapped
install) needs to know what else is inside the binaries and under what terms.
CI enforces the answer for Go dependencies.

## What is enforced

`scripts/ci/check-licenses.sh` (workflow `licenses`) runs `go-licenses check`
over the full transitive package graph of every program we ship: the daemon,
the platform MCP, `agent-box`, the model gateway, and the client CLI built with
`-tags containarium_client`. It fails on any module whose licence is not on the
allow-list, including indirect ones. It runs when `go.mod`, `go.sum`, the script
or the workflow change, and weekly.

Allowed: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Unlicense, MPL-2.0.

| Licence family | Policy | Why |
|---|---|---|
| Permissive (Apache, MIT, BSD, ISC, Unlicense) | allowed | no copyleft obligations beyond keeping notices |
| MPL-2.0 | allowed | weak, file-level copyleft: it only requires the covered files' source to stay available, which unmodified dependencies already satisfy. Two modules today: `github.com/hashicorp/yamux` and `github.com/cyphar/filepath-securejoin` (the latter dual-licensed with BSD) |
| GPL, AGPL, LGPL, SSPL, BUSL, anything unrecognised | **blocked** | copyleft that could reach the combined work, or terms that restrict redistribution; an unrecognised licence is a failure until someone looks at it |

## Exceptions

| Module | Why it is exempt |
|---|---|
| `github.com/footprintai/containarium` | this repository |
| `github.com/rootless-containers/proto/go-proto` | its module zip carries no licence file (the scanner finds none), but the upstream repository declares Apache-2.0 |

Add an exception only with a sentence here saying why and what was checked.

## Changing the list

Adding a licence to the allow-list is a product decision, not a CI fix: copyleft
obligations differ per binary and per distribution channel. Change
`scripts/ci/check-licenses.sh` and this page in the same PR and say who agreed.

## What this does not cover

- Node dependencies of `agent-runtime` and the web UI, and Python packages.
- Software built into container images that is not this module: the sshpiper gateway image compiles upstream sshpiper and its plugins, and the OTel sidecar assembles an upstream collector. Their licences are not scanned here. The daemon, agent-box, MCP and model-gateway images build programs from this module, which the check does cover.
- Transitive licences of base-image packages (the images carry their own SBOM).
- Generating the `NOTICE` file from these licences, tracked in #2561.
- Whether a dependency's licence text matches what it declares: the scanner
  classifies the licence file it finds.
