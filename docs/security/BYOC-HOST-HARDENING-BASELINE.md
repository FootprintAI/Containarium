# BYOC Host Hardening Baseline

This document names what a bring-your-own-compute (BYOC) host should
meet before you rely on it as a security boundary. It exists because of
a specific gap (#1103): enrollment proves a host **can** run
Containarium — root, `incus`, working `useradd`/`userdel` — but says
nothing about whether it's **safe** to run tenant workloads on. For a
platform-managed backend that's Containarium's own problem. For BYOC,
the machine is yours, in your own account, running an image we did not
build — so "dedicated to you" is a claim we can only make as strong as
the evidence we actually collect.

If a claim here turns out to be wrong or stale, please open an issue —
this doc is meant to be checked against, not just read.

## What this is not

This is **not** an enforcement gate today. Every check below is
advisory: `containarium doctor`, `cloud enroll`, and `pool join` will
print unmet items loudly, but none of them refuse to enroll or join a
host that fails. Whether a posture miss should eventually block
enrollment is an open product decision (#1103) — this baseline defines
*what* to measure, not *what happens* when a measurement comes back bad.

## The baseline

Each row is one check in `internal/hostcheck/posture.go`, run by
`containarium doctor`, at `cloud enroll` / `pool join` time, and again
every status-report cycle (so drift after enrollment is caught too, not
just the moment you joined). The wire name matches the check name
verbatim — grep for it if you want the exact logic.

| Check | What a pass means | What a miss means |
|---|---|---|
| `data volume encrypted (dm-crypt)` | The volume backing `/var/lib/incus` (tenant container data) is a guest-visible dm-crypt device | Either genuinely unencrypted, or encrypted at a layer this guest can't see (e.g. cloud-provider CMEK) — the check says which, don't read a miss here as "definitely plaintext" |
| `secure boot enabled` | UEFI Secure Boot is on | Off, or the machine boots legacy BIOS with no measured-boot capability at all |
| `auditd running` | A host-level audit trail exists | No audit trail — a post-incident investigation has nothing to work from |
| `sshd hardened (no root login, no password auth)` | `PermitRootLogin` is not `yes` AND `PasswordAuthentication` is `no` | The host is brute-forceable, or root is reachable without a key |
| `unattended security upgrades enabled` | APT's periodic unattended-upgrade is on (Debian-family only; other distros report unknown, not fail) | Security patches require someone to remember to `apt upgrade` |
| `cloud metadata endpoint blocked` | `169.254.169.254:80` is unreachable from the host | A workload that escapes its container can reach instance credentials — see the network-policy caveat below |
| `tunnel unit does not carry its token on ExecStart` | The pool-join bearer token lives in a root-only `EnvironmentFile=`, not on the (world-readable) `ExecStart=` line | Any local user can read a live bearer-equivalent credential via `systemctl show`, `ps`, or journald |

A check that cannot gather evidence reports **unmet**, never a silent
pass — an ordinary, unhardened host is expected to light up several
warnings on first enrollment. That's the finding, not a defect in the
check.

## The metadata-endpoint control, honestly

`cloud metadata endpoint blocked` is the one item on this list with a
real enforcement mechanism behind it — Containarium's network-policy
engine defaults `allow_metadata` to `false`. But that engine is **not
armed by default** on a freshly enrolled BYOC host; arming it means
turning on the daemon's eBPF network-policy stack at the systemd level,
which is a bigger, host-wide lever than a single-purpose IMDS block (and
one with its own capacity considerations on a small box — see #1103's
tracking notes before wiring this up unconditionally). Until that's
resolved, treat a "blocked" result here as "blocked because someone
configured it," not "blocked because it's default."

## How to check a host

```bash
containarium doctor
```

prints the capability checks (blocking, exit-code-gated) followed by a
"Host security posture" section (advisory, this baseline). `cloud
enroll` and `pool join` print the same posture section at the moment a
host joins, so you don't have to run `doctor` separately to see it —
though re-running `doctor` later is how you catch drift after
enrollment.

## What we don't check yet

CIS-benchmark-style coverage beyond the table above — kernel hardening
sysctls, mandatory access control (AppArmor/SELinux) enforcement mode,
disk-image provenance/measured boot attestation, log forwarding off-box.
If your posture requirements go beyond this list, that's a real gap in
this baseline, not a reason to distrust the checks that do exist —
please open an issue naming what's missing.

## Related

- #1103 — the issue that created this baseline; tracks the two items
  still open (arming the metadata-block network policy by default, and
  the blocking-vs-warning product decision).
- [`SECURITY-FAQ.md`](SECURITY-FAQ.md) — the broader isolation-model
  answer this baseline is a special case of: "dedicated" is a claim
  scoped to what we've verified, not what the customer's word says.
