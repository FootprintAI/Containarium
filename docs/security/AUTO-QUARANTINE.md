# Auto-quarantine — scanner → virtual-patch

> Status: **Implemented, off by default.** The honest realization of the
> "scanner → virtual-patch" capstone from the virtual-patching epic (#659). Uses
> the merged Tier 1 deny rules ([`VIRTUAL-PATCHING-DESIGN.md`](./VIRTUAL-PATCHING-DESIGN.md)).

## What it does

When the ClamAV scanner finds malware in a container, the daemon adds a
**deny-all-egress** rule to that container's tenant — a network quarantine that
stops a compromised container exfiltrating or calling out — and **releases it
automatically** when the container next scans clean.

```
ClamAV scan → "infected"  →  deny 0.0.0.0/0 for the tenant (note: auto-quarantine)
ClamAV scan → "clean"     →  remove that rule
```

Enable with `CONTAINARIUM_SECURITY_AUTO_QUARANTINE=1`. Off by default.

## Why only ClamAV — and deliberately NOT Trivy CVEs

The epic's design docs framed a generic "a CVE finding emits a virtual-patch
rule." Wiring it for real surfaced an **impedance mismatch** worth stating
plainly:

- **Trivy / pentest findings** describe a vulnerable *package inside* a container
  (e.g. an outdated `libxml2`). There is **no network endpoint to block** — a
  deny rule (which blocks the tenant's *egress to a CIDR/port*) can't "patch" an
  internal package vuln. Forcing that mapping would ship a rule that looks like a
  fix but isn't. So Trivy CVEs are **deliberately not wired** to deny rules.
- **ClamAV findings** carry a clean verdict — `infected` / `clean` on a named
  container — that maps *correctly* onto the one action the merged
  infrastructure supports: **network-quarantine the tenant, release on clean.**
  That is a real virtual patch (contain the threat at the network until
  remediated), so it's what this ships.

Where Trivy/ZAP findings *do* have a sound virtual-patch path is the WAF (Tier 3,
#662) — a detected web exploit → a Coraza rule — and Tier 2 signatures for CVEs
with a known cleartext exploit pattern. Those hooks are future work and need a
CVE→signature/rule source; they are not this PR.

## Mechanics

- Hook point: `internal/security/scanner.go` invokes an optional
  `onScanResult(container, tenant, status)` callback after each scan saves its
  report. `internal/server/auto_quarantine.go` implements it over the
  network-policy deny-rule **store** directly (`MutateDenyRules`) — an in-process,
  atomic mutation, no RPC/auth round-trip.
- **Safe against operator rules.** The quarantine rule is marked with a
  reserved note. Release removes *only* that rule — an operator's own `0.0.0.0/0`
  deny (different note) is never clobbered, and if one already exists, quarantine
  relies on it rather than overwriting it.
- **Self-healing backstop.** Each infected scan refreshes a 24h expiry on the
  rule, so if scanning stops entirely a stale quarantine self-expires rather than
  blackholing a tenant forever. A clean scan releases immediately.

## Caveats (documented, not hidden)

- **Per-tenant, not per-container.** Deny rules are keyed by tenant, so
  quarantining one infected container blocks egress for *all* that tenant's
  containers. Containment over availability — acceptable for a malware response,
  and opt-in. (Per-container network policy would lift this; not available today.)
- **Only as strong as enforcement.** The deny rule is *stored* regardless, but it
  only *drops* traffic when the network-policy BPF enforcer is enabled and armed
  (`CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` + `CONTAINARIUM_NETWORK_POLICY_ENFORCE`).
  Without those, the quarantine is recorded (and visible via `network-policy
  get`) but not enforced.
- **Egress only.** A deny rule blocks the container's *outbound* — it stops
  exfiltration / C2, not inbound exploitation (that's the WAF/signature tiers).

## Validation

Pure logic (`applyQuarantine` / `releaseQuarantine` / `OnScanResult`) is
unit-tested, including the don't-clobber-operator-rules and no-duplicate-on-
reinfection cases. End to end needs a backend with ClamAV scanning + the network
enforcer armed: drop EICAR into a container, trigger a scan, confirm the tenant
gets a `0.0.0.0/0` deny (note `auto-quarantine`) and that egress is blocked under
enforce; remove EICAR, re-scan, confirm release.
