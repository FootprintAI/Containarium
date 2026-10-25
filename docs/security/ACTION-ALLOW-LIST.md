# GitHub Actions allow-list

The third-party action allow-list decided on #2649 (decision 3) is the inventory
of actions the workflows use. This is that inventory as of #2904, taken from
`uses:` in `.github/`; every entry is pinned to a full commit SHA
(`scripts/ci/check-action-pins.sh`). Local `./` actions are not listed.

| Owner | Actions (uses) |
| --- | --- |
| GitHub (`actions`, `github`) | `actions/checkout`, `actions/cache` (+ `/restore`), `actions/upload-artifact`, `actions/download-artifact`, `actions/setup-go`, `actions/setup-node`, `actions/setup-python`, `github/codeql-action/upload-sarif` |
| Docker | `docker/setup-buildx-action`, `docker/setup-qemu-action`, `docker/login-action`, `docker/build-push-action` |
| Scanners and signing | `aquasecurity/trivy-action`, `securego/gosec`, `ossf/scorecard-action`, `actions/dependency-review-action`, `sigstore/cosign-installer`, `anchore/sbom-action/download-syft` |
| Tooling | `azure/setup-helm`, `hashicorp/setup-terraform` |
| Publishing | `softprops/action-gh-release`, `pypa/gh-action-pypi-publish` |

`actions/dependency-review-action` was added by #2794 (the
`dependency-review` workflow). `golangci-lint-action`, named in the #2649
decision, is not in use at this commit; add it here when it lands.

Adding a new action: add it to the table in the same PR, pin it to a full SHA
with a version comment, and say why in the PR description.

**Not yet enforced on GitHub.** At #2904 the repository's Actions setting still
reads `allowed_actions: all` and `sha_pinning_required: false`. Turning on
"allow select actions" with this list, and "require full-length commit SHAs",
is a repository admin setting and is tracked with #2649 story 2.
