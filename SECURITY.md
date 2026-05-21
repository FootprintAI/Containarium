# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in Containarium,
please report it privately. **Do not open a public issue, discussion,
or pull request that describes the vulnerability.**

### How to report

- **Preferred:** GitHub's private vulnerability reporting at
  <https://github.com/FootprintAI/Containarium/security/advisories/new>.
- **Email:** `devops@footprint-ai.com` (use the subject prefix
  `[security]` and include `Containarium` so it's routed correctly).

In your report, please include:

1. A description of the issue and its potential impact.
2. Step-by-step instructions to reproduce, including affected
   commits / released versions if known.
3. A proof-of-concept if you have one. Suspected severity is helpful
   but not required — we will triage.

We will acknowledge receipt within **3 business days** and aim to
provide a substantive response (initial triage, severity assessment,
expected remediation timeline) within **10 business days**.

## Disclosure timeline

We follow coordinated disclosure:

- We will work with you to confirm and fix the issue.
- Once a fix is available, we will release a patched version and
  publish a GitHub Security Advisory crediting the reporter (or
  remaining anonymous on request).
- We ask that you give us **at least 90 days** from the initial
  report before public disclosure, unless a shorter window is
  necessary because the issue is being actively exploited.

## Supported versions

Containarium is pre-1.0; security fixes land on `main` and are
included in the next tagged release. There is no LTS branch.
Operators running prior releases should upgrade to the latest tag.

| Branch / version | Supported     |
| ---------------- | ------------- |
| `main`           | ✅ active     |
| Latest release   | ✅ active     |
| Older releases   | ❌ upgrade    |

## Out of scope

The following are explicitly out of scope for this policy. Please
report them as normal issues if you'd like to discuss them:

- Findings against forks or unofficial builds.
- Issues that require an attacker who already has shell access to a
  daemon host (`root` on the host owns everything; that's the trust
  boundary).
- Vulnerabilities in third-party dependencies that don't affect a
  Containarium use case. (We track Go advisories via
  `govulncheck` in CI; if you find one we missed, please report.)
- Denial-of-service via unbounded request volume against a single
  daemon (operators are expected to put rate-limiting in front of
  internet-facing endpoints).

## Automated scanning

The project's CI runs three security scanners on every push to
`main` and every pull request:

- **gosec** — Go static analysis (SAST). Findings upload to GitHub
  code scanning as SARIF.
- **govulncheck** — Go vulnerability database. Fails the build when
  a known-fixed vuln is detected; tolerates upstream-unfixable
  advisories with a documented exception.
- **Trivy** — dependency vulnerability scan (CRITICAL + HIGH).
  Findings upload to GitHub code scanning.

The workflow lives at
[`.github/workflows/security.yml`](.github/workflows/security.yml).

## Audit history

A point-in-time zero-trust security audit (May 2026) drove the
hardening tracked in
[`docs/security/ZERO-TRUST-TODO.md`](docs/security/ZERO-TRUST-TODO.md).
The findings are folded into PRs tagged `sec/zero-trust-*` in the
git history. Major shipped items at the time of writing:

- Per-RPC RBAC + OAuth2-style scope enforcement
  ([PRs #246](https://github.com/FootprintAI/Containarium/pull/246),
   [#247](https://github.com/FootprintAI/Containarium/pull/247),
   [#251](https://github.com/FootprintAI/Containarium/pull/251),
   [#253](https://github.com/FootprintAI/Containarium/pull/253)).
- Short-lived access tokens + refresh tokens with single-use rotation
  ([#254](https://github.com/FootprintAI/Containarium/pull/254),
   [#255](https://github.com/FootprintAI/Containarium/pull/255)).
- JWT revocation list with CLI / RPC kill-switch
  ([#248](https://github.com/FootprintAI/Containarium/pull/248),
   [#249](https://github.com/FootprintAI/Containarium/pull/249)).
- WebSocket subprotocol auth
  ([#245](https://github.com/FootprintAI/Containarium/pull/245)).
- Wake-handler source-IP lockdown
  ([#244](https://github.com/FootprintAI/Containarium/pull/244)).

For the full open / closed status, see the audit TODO doc. For
day-to-day operator procedures (token rotation, leak response,
least-privilege agent tokens, audit-chain verification), see the
[operator security runbook](docs/security/OPERATOR-SECURITY-RUNBOOK.md).

## Thank you

Security reports help keep Containarium operators safe. We're
grateful to everyone who takes the time to find and report
vulnerabilities responsibly.
