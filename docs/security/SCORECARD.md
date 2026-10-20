# OpenSSF Scorecard

The [Scorecard workflow](../../.github/workflows/scorecard.yml) measures the
public upstream repository on every push to `main` and weekly on Monday.
It does not run against PR code, and the analysis job does not run on forks,
which the Scorecard Action does not support.

The workflow uses commit-pinned Actions, a read-only default token, and
job-scoped `security-events: write` for the SARIF upload. Checkout does not
persist the token. Analysis runs only the actions allowed by Scorecard's
publication policy; arbitrary shell steps do not belong in this job.

The analysis job also needs `id-token: write` to authenticate result
publication to the Scorecard API and update the README badge. This permits
requesting an OIDC identity token, not writing repository contents or PRs;
it is scoped to the analysis job. The
[official Scorecard publication requirements](https://github.com/ossf/scorecard-action/tree/fa7117db83c52d787ae5a89f350999701505d78e#publishing-results)
require it in addition to the SARIF upload permission. This clarifies the
PRD's read-only-token rule: repository data writes remain limited to
code-scanning results, and no long-lived credential is introduced.

Each run uploads SARIF to the repository's code-scanning dashboard and keeps
the same report as the public `scorecard-report` Actions artifact for 30 days.
The workflow uses the default GitHub token and requires no new PAT secret.
Classic branch protection may be only partially visible to that token;
an unavailable check is not evidence that the corresponding control is absent.

## Initial baseline and target

The [first per-check baseline on #2649](https://github.com/FootprintAI/Containarium/issues/2649#issuecomment-6282709630)
was measured on 2026-10-20 with the checksum-verified official Scorecard
v5.6.0 CLI against upstream commit
`d287d803155df82786f61814943e48e1a29e17ec`: **5.4 / 10**. This was a CLI
measurement, not a workflow publication; the first scheduled publication
requires merging the workflow to upstream `main`.

| Priority check | Initial score / 10 |
|---|---:|
| Branch-Protection | 3 |
| Pinned-Dependencies | 0 |
| Token-Permissions | 0 |
| Dangerous-Workflow | 10 |
| Dependency-Update-Tool | 10 |

The [agreed target](https://github.com/FootprintAI/Containarium/issues/2649#issuecomment-6260335692)
is **at least 7.0 within 30 days**, with no zero on those five checks.
This workflow measures progress; it does not reject the initial baseline
for failing the future target. The total is Scorecard's risk-weighted score,
not the arithmetic mean of the check scores. Live repository settings,
advisories, and review history can change scores independently of source code.

For comparisons, retain the scanned repository and commit, scan timestamp,
Scorecard version, and every per-check score. Keep CLI measurements distinct
from the workflow's published results. A green upload does not prove that
the repository meets the target or that every reported dependency advisory
is exploitable in a shipped binary.
