# Q32: public-IP hairpin on a GCP NAT primary

The operator ran #2732's Verify-on-dev steps for #2727 Q32 on a real,
single-host GCP primary on 2026-10-29. The container-to-public-IP HTTP and
HTTPS paths passed. This records HTTP hairpin behavior, rather than marking
every Q32 acceptance step verified or deploying #2735. Deployment
identifiers are omitted.

## Version and environment

- Release: **v0.121.0**, commit
  `c70bfee6534eaec45ce894ac5d5f7ca92cd77010`.
- Installed daemon SHA256:
  `17950e8945748e96cf6577bfcbb498c9a16027d7adb3b179e2cde318c6505a7e`,
  matching the release artifact. The installer was pinned to that commit.
- Ubuntu 24.04.5 LTS, Incus 7.5.1, Caddy 2.11.4; app hosting with a base
  domain, platform core services, and a separate Incus application container.
- GCP maps the public IP to the primary's private IP. The public IP does
  **not** appear in `ip -4 -br addr`, satisfying the NAT'd-host definition.
- The app's public A record resolves to that public IP, including from
  inside the application container. Bridge `raw.dnsmasq` is empty.
- A minimal HTTP fixture returns a unique proof marker, release, commit
  and request path. It does not add a Server or Via header.
- The daemon uses the native app-hosting configuration and `expose-port`
  route. Unrelated security/pentest/ZAP scanners are disabled.

Slice C, #3162 (`ba16e5e2ba336164c8eb13777e7db50b211ae6f0`), shipped in
v0.120.0. v0.121.0 is already published, so the compatibility release
required by #2735 has elapsed. That issue's tagged-release dependency and
CI gate are separate from the Q32 header check recorded below.

## Results

The initial pass ran at 12:01:28–12:01:31 UTC. Every response below returned
HTTP 200 and the expected fixture content; HTTPS certificate verification
passed using the system trust store, without `-k` or a custom CA.

| Client | Address selection | Ports | Result |
|---|---|---|---|
| Application container | `--resolve` to the primary's private IP | 80, 443 | pass |
| Application container | `--resolve` to the primary's public IP | 80, 443 | pass; Q32 NAT case |
| Application container | Normal DNS to the public IP | 80, 443 | pass |
| Primary host | `--resolve` to its public IP | 80, 443 | pass |
| External workstation | `--resolve` to the public IP | 80, 443 | pass |
| External workstation | Normal DNS | 443 | pass |

There were 10 VM-side and 4 external request cases, including repeated HTTP
checks with `-L`. HTTP directly returned 200 in this configuration; there
was no redirect to follow. These counts include controls and repetitions.

Both PREROUTING DNAT rules match `-m addrtype --dst-type LOCAL`, for ports
80 and 443, with no `! -s <bridge-subnet>` exclusion. The existing Caddy
destination MASQUERADE rule remains. Across the initial pass, DNAT packet
counters rose from 54 to 60 for HTTP and 101 to 106 for HTTPS; the Caddy
MASQUERADE counter rose from 198 to 210.

The TLS peer certificate matched the app hostname, with issuer
`Let's Encrypt / YE2`, valid from 2026-10-29 11:00:28 through
2027-01-27 11:00:27 GMT. Verbose curl output reported
`SSL certificate verify ok.` and the app's proof marker.

**Header difference from the old verification text:** the response has
`Via: 1.0 Caddy`, rather than `Server: Caddy`. The literal Server-header
expectation was not met. The successful path is evidenced by Caddy's Via
header, valid TLS, the origin fixture's content and the NAT rules/counters.
The service was not modified to manufacture the older header. No amendment
to the published acceptance text is recorded here, so this report does not
mark that Q32 header step passed.

This matches [Caddy v2.11.4's reverse-proxy implementation](https://github.com/caddyserver/caddy/blob/v2.11.4/modules/caddyhttp/reverseproxy/reverseproxy.go#L1139-L1145),
which explicitly deletes its Server header and adds Via when forwarding a
response. The missing Server header is expected proxy behavior; the Q32
acceptance wording still needs maintainer reconciliation.

## Restart and legacy-rule cleanup

At 12:03:52–12:04:07 UTC, two old-style `! -s <bridge-subnet>` DNAT rules
were appended behind the existing correct rules, targeting the same Caddy.
After `systemctl restart containarium`, the daemon removed both legacy
rules itself, leaving exactly two LOCAL rules. The fixture's fallback
cleanup did not remove anything. The API returned `healthy` and the
registered application route remained `active`.

During the restart, the application container repeatedly used public-IP
`--resolve`: HTTP **17/17** and HTTPS **17/17** requests succeeded with the
correct content. No failed requests were observed in these samples. This
tests reconciliation with old and new rules coexisting; it is not a full
downgrade-and-upgrade of an older release.

## Reproduce the decisive requests

On the primary, set `BOX`, `APP_DOMAIN` and `HOST_PUBLIC_IP` to the deployed
fixture's values, then run:

```bash
sudo incus exec "$BOX" -- curl -4 -sv --noproxy '*' \
  --resolve "${APP_DOMAIN}:443:${HOST_PUBLIC_IP}" "https://${APP_DOMAIN}/"
sudo incus exec "$BOX" -- curl -4 -sv --noproxy '*' \
  --resolve "${APP_DOMAIN}:80:${HOST_PUBLIC_IP}" "http://${APP_DOMAIN}/"
```

Check the fixture content, successful certificate verification for HTTPS,
and the `Server: Caddy` header required by #2732. Record the Server check as
unmet when it is absent, as in this pass; the observed `Via: 1.0 Caddy` is
additional path evidence, not an amendment of that acceptance check.
Also inspect `ip -4 -br addr`,
`iptables -t nat -S PREROUTING`, `iptables -t nat -S POSTROUTING` and
`incus network get incusbr0 raw.dnsmasq` for the conditions above.

The operator retains raw curl/TLS logs, NAT snapshots, restart traffic,
scripts and a SHA256 manifest outside this public repository. The complete
archive SHA256 is
`ffaef188530df6ff55a947f74ebc03d5d04fa0b048943d1b2ad402171b407128`.
Initial test assertions expected the older Server header and an HTTP
redirect; those assertion failures and the corrected results are both
retained. No secrets or live deployment addresses are included here.

This pass establishes HTTP hairpin behavior on the named v0.121.0 commit on
one GCP NAT primary. The private-IP checks are controls on that same host, not a
separate physical-host deployment. It does not retroactively certify the
original v0.116.0 binary. The #2735 flag-removal change is covered by its
CLI parsing tests and CI, without deploying its branch to this environment.
