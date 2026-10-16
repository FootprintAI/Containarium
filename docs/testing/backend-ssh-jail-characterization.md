# Backend SSH jail characterization (#1138)

This bounded increment tests real OpenSSH sshd messages against the installed
fail2ban SSH filter and a real isolated fail2ban server. It does not implement
retry pacing, enable the opt-in transport adapter, or close #1138.

## Reproduced conditions

The fixture uses synthetic keys, ephemeral loopback ports and the runner's own
valid Unix account. A correct-key baseline must authenticate before rejected-key
cases run. Seven independent SSH connections then offer an unauthorized key.
The refusal case stops sshd first and verifies that seven TCP failures leave its
raw log unchanged. These are direct backend connections, not a reproduction of
SSHPiper's seven-attempt authentication exchange.

The Ubuntu 24.04 lane records installed package versions. The first local run
used OpenSSH `1:9.6p1-3ubuntu13.19` and fail2ban `1.0.2-3ubuntu0.1`:

| Seven attempts from 127.0.0.1 | Filter | Counted failures | Jail ban |
| --- | --- | ---: | --- |
| TCP refusal | `sshd` | 0 | No |
| Valid account, rejected public key | `sshd` (default `publickey=nofail`) | 0 | No |
| Valid account, rejected public key | `sshd[publickey=any]` | 7 | Yes |
| Invalid account | `sshd` | 7 | Yes |
| Valid account, rejected key, source explicitly exempt | `sshd[publickey=any]` | 0 | No |

All jails use `maxretry=3`, `findtime=600`, `bantime=3600`, matching the values in
[backend provisioning](../../terraform/modules/containarium/scripts/startup-spot.sh).
The test explicitly selects either an empty ignore list or `127.0.0.1/32` and
disables `ignoreself`, so the local fixture can exercise both outcomes. Production
whitelists remain unchanged. The fixture is not evidence that a production
sentinel's actual backend-visible address falls outside its effective whitelist.

Each case includes one additional real invalid-user failure from `127.0.0.2`.
This unexempt control must be counted, proving the daemon read the input even
when the tested source contributes zero. Raw `status.log` totals therefore have
**one extra failure** beyond the table. The control must never be banned.
The status snapshot is taken after the ban decision/action and before explicit
unban, so positive cases show the banned source as well as the recorded actions.

## Evidence and boundaries

Foreground sshd writes message bodies without a syslog envelope. The fixture
preserves `sshd-raw.log`, then replays every body with a current timestamp and
`fixture sshd:` prefix into `auth.log`. It does not recreate per-connection syslog
PIDs or deployed journal ingestion. The stock `sshd.conf` filter is copied
unchanged; only its documented `publickey=any` option varies. The assertion uses
the regex tool's **matched lines**, not its `Failregex` total, which also includes
`F-NOFAIL` bookkeeping matches.

The real jail's configured action records `ban <ip>` / `unban <ip>` in a private
file. Positive cases must appear in the real ban list, execute the ban action,
and execute unban when explicitly requested. No host firewall rule is changed.
**A jail decision is not proof that network packets were blocked.** This replay
fixture does not prove production #1138, multi-minute outage behavior, live
automatic recovery, or any safe number of dials per jail failure.

The [Sentinel SSH bans workflow](../../.github/workflows/ssh-ban.yml) adds a
separate race-enabled job and uploads a `backend-jail-characterization` artifact:
package versions, per-case raw/replayed logs, filter output, jail settings,
status and recorded actions. An explicit file allowlist excludes private keys.
Missing prerequisites fail the test rather than skipping it. Each test owns and
reaps its process groups, closes its private server/socket and removes its keys.

Negative-control evidence: temporarily rendering the live jail with `filter =
sshd` while retaining the strict-publickey test produced `expected 8 failures`,
actual `Total failed: 1`, and no ban. Restoring the selected filter made all five
cases pass. This catches a real filter/configuration mismatch; it is not merely
a test that succeeds when the daemon has not read the log.

Run on Ubuntu with `openssh-server` and `fail2ban` installed:

```bash
BACKEND_JAIL_EVIDENCE=/tmp/backend-jail-evidence \
  go test -race -tags integration -count=1 -timeout 2m -v \
  ./internal/sentinel/backendjail
```

`BACKEND_JAIL_BIN` may point to a directory containing the test executables;
`BACKEND_JAIL_CONFIG` may select an extracted upstream configuration tree.

## Consequence for the next increment

A TCP attempt is not a fail2ban failure. A blanket three-dial budget over ten
minutes is not justified by these results. Obtain the effective deployed jail
version, filter options, exemptions, source address and matching records before
claiming the backend-ban premise. Keep transport backoff separate from deliberate
credential-failure pacing and source-client attribution. Next, join this evidence
with the PR #2578 transport hook, then test shared admission and recovery against
live SSH plus an isolated firewall action; do not remove production exemptions
or treat this characterization as a fix.
