# GitHub Actions allow-list

The third-party action allow-list decided on #2649 (decision 3) is the inventory
of actions the workflows use. This is that inventory as of #2904, taken from
`uses:` in `.github/`; every entry is pinned to a full commit SHA
(`scripts/ci/check-action-pins.sh`). Local `./` actions are not listed.

| Owner | Actions (uses) |
| --- | --- |
| GitHub (`actions`, `github`) | `actions/checkout`, `actions/cache` (+ `/restore`), `actions/upload-artifact`, `actions/download-artifact`, `actions/setup-go`, `actions/setup-node`, `actions/setup-python`, `github/codeql-action/upload-sarif` |
| Docker | `docker/setup-buildx-action`, `docker/setup-qemu-action`, `docker/login-action`, `docker/build-push-action` |
| Scanners and signing | `aquasecurity/trivy-action`, `securego/gosec`, `ossf/scorecard-action`, `sigstore/cosign-installer`, `anchore/sbom-action/download-syft` |
| Tooling | `azure/setup-helm`, `hashicorp/setup-terraform` |
| Publishing | `softprops/action-gh-release`, `pypa/gh-action-pypi-publish` |

`dependency-review-action` and `golangci-lint-action`, named in the #2649
decision, are not in use at this commit; add them here when they land. `actions/dependency-review-action` (#2794) is GitHub-owned, so the allow-list's GitHub-owned rule already covers it.

Adding a new action: add it to the table in the same PR, pin it to a full SHA
with a version comment, and say why in the PR description.

**Not yet enforced on GitHub.** At #2904 the repository's Actions setting still
reads `allowed_actions: all` and `sha_pinning_required: false`. Turning on
"allow select actions" with this list, and "require full-length commit SHAs",
is a repository admin setting. `scripts/admin/apply-repo-settings.sh` applies it (dry run by default); see [REPO-SETTINGS-RUNBOOK.md](REPO-SETTINGS-RUNBOOK.md). CI fails if a workflow uses an action that script does not allow.
