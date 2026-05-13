# PROXY protocol — preserving the real client IP

## What this solves

Before this work, containers behind the sentinel saw `X-Forwarded-For: ::1`
(IPv6 loopback) regardless of who originated the request. The Containarium
data path is TLS-passthrough at every hop: the sentinel does SNI peeking and
forwards raw TCP, the backend's caddy-l4 does another SNI hop, and only at
the daemon's HTTP server (`srv0`) does TLS terminate. None of those hops
preserved the original client IP, because each one was opening a fresh TCP
connection downstream.

The PROXY protocol (HAProxy v2, binary) is the standard solution: every hop
prepends a tiny header carrying the original source/destination addresses,
and the receiver parses it before doing anything else. With the implementation
in this codebase, a curl from `203.0.113.42` lands in the WordPress nginx
access log as:

```
10.0.3.111 - - [...] "GET / HTTP/1.1" 200 ... "User-Agent" "203.0.113.42"
                                                            ^^^^^^^^^^^^^^
                                                X-Forwarded-For = real IP
```

## Architecture

```
                                          PROXY v2          PROXY v2
                                        (sentinel emits)   (caddy-l4 emits)
                                              │                   │
client ──TLS──▶ sentinel ──TCP+PROXY──▶ caddy-l4 ──TCP+PROXY──▶ srv0 ──HTTP──▶ container
              (SNI router)             (:443)                  (:8443)        (nginx)
                                       parses PROXY            parses PROXY
                                       routes by SNI           sets RemoteAddr
                                       on post-strip bytes     reverse_proxy with XFF
```

Three hops, each protected by a different layer of caddy-l4 / Caddy
configuration:

1. **Sentinel** (`internal/sentinel/`)
   - The SNI router (`buildSNIRoutingHandler` in `manager.go`) peeks the TLS
     ClientHello, looks up the destination primary, and forwards raw TCP.
   - When `--proxy-protocol` is enabled, it prepends a 28-byte (IPv4) PROXY v2
     header before the first TLS byte. The header is encoded by
     `WriteProxyV2` in `internal/sentinel/proxyproto.go`.

2. **caddy-l4 server** (`tls_passthrough` on `:443`, configured by
   `internal/app/l4_proxy.go`)
   - When the daemon is started with `--proxy-protocol`, the L4 server is
     produced in **pattern B** wrapped form: a single outer route whose
     handlers are `(layer4.handlers.proxy_protocol, layer4.handlers.subroute)`.
   - The `proxy_protocol` handler consumes the PROXY v2 bytes (lenient if
     absent — passes through unchanged for deploy-gap safety), then the
     `subroute` does SNI matching on the now-clean TLS bytes.
   - SNI passthrough routes (e.g. `passthrough-a.example`) forward raw TLS to
     their gRPC backends untouched.
   - The catchall route (no `match`) re-emits a PROXY v2 header to
     `localhost:8443` (`srv0`) using `proxy_protocol: "v2"` on its proxy
     handler, so srv0 can recover the real client IP.

3. **HTTP server `srv0`** (Caddy, configured by `internal/app/proxy.go`)
   - When the daemon is started with `--proxy-protocol`,
     `EnableProxyProtocol` installs a `[proxy_protocol, tls]`
     `listener_wrappers` chain on srv0 plus `trusted_proxies` for the same
     CIDRs. The wrapper consumes the PROXY header from caddy-l4 and updates
     `conn.RemoteAddr`. The trusted_proxies setting then makes Caddy's
     `reverse_proxy` use that as the source when emitting `X-Forwarded-For`.

## Deploy state matrix

The wrapper handlers are designed to be lenient on missing PROXY headers,
so the system stays correct in every combination of deploy state:

| Sentinel `--proxy-protocol` | Daemon `--proxy-protocol` | Wordpress XFF | gRPC | Notes |
|---|---|---|---|---|
| off | off | (n/a — Caddy doesn't add XFF on TLS-passthrough catchall path) | works | pre-rollout baseline |
| off | on | `::1` (caddy-l4's loopback to srv0) | works | "armed" state — daemon ready but sentinel not flipped |
| on | off | n/a — sentinel emits PROXY but srv0 has no wrapper, so Caddy treats PROXY bytes as part of the HTTP body and breaks | broken | **never deploy in this order** |
| on | on | real client IP | works | end state |

The two safe transitions are `off,off → off,on → on,on`. **Always deploy
the daemon side first**, verify, then flip the sentinel.

## Trust model

The `--proxy-protocol-trusted` flag lists the CIDRs allowed to send PROXY
headers. The same list is shared by both wrappers; extra entries on either
side are harmless because each wrapper only sees its own kind of upstream
peer.

| Wrapper | Sees connections from | Allow CIDRs (prod) |
|---|---|---|
| caddy-l4 `proxy_protocol` handler | sentinel (via host iptables DNAT, source preserved) | `<sentinel-VPC-IP>/32` (sentinel VPC IP) |
| srv0 `proxy_protocol` listener_wrapper | caddy-l4 (loopback dial to `localhost:8443`) | `127.0.0.0/8`, `::1/128` |

Concretely the daemon is started with:
```
--proxy-protocol --proxy-protocol-trusted=<sentinel-VPC-IP>/32,127.0.0.0/8,::1/128
```
and the sentinel with:
```
--proxy-protocol
```
(the sentinel itself doesn't validate; it just emits.)

`EnableProxyProtocol` and `EnableL4ProxyProtocol` both refuse empty or
wildcard (`0.0.0.0/0`, `::/0`) CIDR lists at construction time. An
unrestricted allow list lets any direct VPC peer spoof its source IP via a
forged PROXY header.

## Recommended rollout

1. **Deploy daemon** (backend VM) with `--proxy-protocol` flags. The daemon
   calls `EnableProxyProtocol` (srv0) and `EnableL4ProxyProtocol` (L4) at
   startup; the L4 server is reshaped into pattern B and the listener
   wrappers are armed. Both wrappers are lenient on missing PROXY, so
   in-flight non-PROXY traffic still flows.
2. **Verify** Caddy admin shows the wrapped L4 server and the srv0
   listener_wrappers, and that all subdomains still serve traffic.
3. **Restart sentinel** with `--proxy-protocol`. From now on every forwarded
   HTTPS connection carries a PROXY v2 header.
4. **Verify** with a known-IP curl + the destination container's access
   log. For wordpress: `curl https://wordpress.kafeido.app/?ip-test=<marker>`,
   then `ssh wordpress 'docker logs --tail 20 wordpress-nginx | grep <marker>'`
   — the rightmost `"..."` field is the parsed source IP.

## Rollback

Either side can be reverted in isolation thanks to the lenient wrappers:

- **Sentinel rollback**: remove the `--proxy-protocol` flag and restart.
  The daemon-side wrappers see no PROXY header and pass through unchanged;
  XFF reverts to `::1`. gRPC routes are unaffected.
- **Daemon rollback**: restart the daemon without `--proxy-protocol` flags.
  EnableProxyProtocol/EnableL4ProxyProtocol won't run; existing wrapping
  stays in the running Caddy until something explicitly removes it. To
  fully unwind, manually `DELETE /config/apps/http/servers/srv0` and the
  L4 server, then restart the daemon to let it rebuild the legacy flat
  shape.

## Tests

| Layer | File | What it validates |
|---|---|---|
| Encoder unit tests | `internal/sentinel/proxyproto_test.go` | byte-exact PROXY v2 IPv4/IPv6 header, payload preservation |
| Sentinel SNI-router e2e | `internal/sentinel/proxyproto_e2e_test.go` | real TCP+TLS through `buildSNIRoutingHandler`; client source port reaches backend with flag on, doesn't with it off |
| Sentinel real-Caddy e2e | `internal/sentinel/proxyproto_caddy_e2e_test.go` (build tag `proxyproto_real_caddy`) | spawns real Caddy 2.7+, drives TLS from 127.0.0.42, asserts X-Forwarded-For at backend |
| HTTP-side regression | `internal/app/proxy_test.go::TestProxyManager_EnableProxyProtocol_PreservesOtherFields` | `EnableProxyProtocol` doesn't clobber listen/routes/automatic_https on srv0 (the bug from incident #2) |
| L4 lifecycle regression | `internal/app/l4_proxy_test.go::TestL4ProxyManager_Lifecycle_WrappingSurvivesRouteSyncJob` | wrapping survives 3 RouteSyncJob-style add/remove cycles (the bug from incident #3) |
| Tier-2 driver | `test/fixtures/tier2-l4-lifecycle/main.go` | full lifecycle against a real caddy-l4 binary; sandbox-validated |

## Reference: pattern B caddy-l4 config

The wrapped shape produced by `EnableL4ProxyProtocol`:

```json
{
  "listen": [":443"],
  "routes": [{
    "handle": [
      {
        "handler": "proxy_protocol",
        "allow":   ["<sentinel-VPC-IP>/32", "127.0.0.0/8", "::1/128"],
        "timeout": "5s"
      },
      {
        "handler": "subroute",
        "routes": [
          {"match": [{"tls": {"sni": ["passthrough-a.example"]}}],
           "handle": [{"handler": "proxy", "upstreams": [{"dial": ["203.0.113.1:50051"]}]}]},
          {"match": [{"tls": {"sni": ["passthrough-b.example"]}}],
           "handle": [{"handler": "proxy", "upstreams": [{"dial": ["203.0.113.2:50052"]}]}]},
          {"handle": [{"handler": "proxy",
                       "upstreams": [{"dial": ["localhost:8443"]}],
                       "proxy_protocol": "v2"}]}
        ]
      }
    ]
  }]
}
```

Things to know about this shape that aren't obvious:

- **Single outer route, no `match`.** caddy-l4 evaluates routes top-to-bottom;
  the outer route always matches.
- **The `proxy_protocol` handler runs before any matcher in the subroute.**
  This is why pattern B works where the `proxy_protocol` matcher form
  doesn't — handlers run after route selection, so a matcher would have to
  consume bytes during the SNI-matching phase, and caddy-l4 silently drops
  malformed matcher chains.
- **Only the catchall has `proxy_protocol: "v2"` on its proxy handler.**
  gRPC routes leave it off because gRPC backends don't speak PROXY and
  expect raw TLS.
- **`allow` is required on the handler.** Without it, the handler errors
  with `"unknown field"` (the matcher form has no `allow`).

## Reference: srv0 (HTTP server) config

Added by `ProxyManager.EnableProxyProtocol`:

```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":80", ":8443"],
          "listener_wrappers": [
            {"wrapper": "proxy_protocol", "allow": ["<sentinel-VPC-IP>/32", "127.0.0.0/8", "::1/128"], "timeout": "5s"},
            {"wrapper": "tls"}
          ],
          "trusted_proxies": {"source": "static", "ranges": ["<sentinel-VPC-IP>/32", "127.0.0.0/8", "::1/128"]},
          "routes": [...preserved verbatim...],
          ...
        }
      }
    }
  }
}
```

The wrapper chain order is **`[proxy_protocol, tls]`** — proxy_protocol must
run first to consume the leading PROXY bytes, then the TLS terminator sees
the underlying ClientHello at byte 0.

The `trusted_proxies` setting is what makes Caddy's `reverse_proxy` populate
`X-Forwarded-For` from the parsed source IP rather than ignoring it. Without
this, the wrapper would correctly set `RemoteAddr` but `reverse_proxy` would
fall back to the raw TCP peer (loopback) for the XFF value.

## Troubleshooting

### TLS handshake fails silently for a tunnel-promoted pool primary

**Symptom.** A new pool primary (`containarium daemon --pool X --app-hosting --base-domain X.example.com` paired with a `containarium tunnel ... --pool X --public-hostname X.example.com --public-port 443` on the same box) registers cleanly — `/v1/backends` lists it healthy, `/sentinel/primaries` has the right hostname — but `curl https://X.example.com/` fails the TLS handshake:

```
curl: (35) LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to X.example.com:443
```

Probing the primary's Caddy directly *on the primary's box* succeeds and serves the right Let's Encrypt cert:

```
$ echo | openssl s_client -servername X.example.com -connect 127.0.0.1:443
...
subject=CN=X.example.com
issuer=C=US, O=Let's Encrypt, CN=...
Verify return code: 0 (ok)
```

So the cert and Caddy are fine — the failure is between sentinel and primary's Caddy.

**Cause.** When the sentinel runs with `--proxy-protocol` (which the prod sentinel does), the SNI router writes a PROXY v2 frame before forwarding the TLS bytes (`internal/sentinel/manager.go`, `buildSNIRoutingHandler` → `writeProxyHeader`). The tunnel client on the primary side forwards the bytes verbatim to `localhost:443`, including the PROXY frame. If the primary's daemon is **not** started with `--proxy-protocol`, its Caddy has no `proxy_protocol` listener_wrapper, interprets the PROXY framing as TLS bytes, and closes the connection. Neither side logs anything useful: the sentinel sees `read 1566 bytes, wrote 0`; the primary's Caddy never logs because TLS handshake never starts.

**Fix.** Start the primary's daemon with `--proxy-protocol --proxy-protocol-trusted=127.0.0.0/8`. The tunnel client's local connection is on loopback, so trusting `127.0.0.0/8` is correct and tight. In systemd:

```ini
# /etc/systemd/system/containarium.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/local/bin/containarium daemon --pool X --rest --jwt-secret-file /etc/containarium/jwt.secret \
  --app-hosting --base-domain X.example.com \
  --proxy-protocol --proxy-protocol-trusted=127.0.0.0/8
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart containarium.service
```

Successful startup logs:

```
Caddy listener_wrappers: PROXY v2 enabled, trusted=[127.0.0.0/8]
[L4ProxyManager] PROXY protocol configured (allow=[127.0.0.0/8]); ...
Management route ensured: X.example.com -> <primary-ip>:8080
```

After restart, `curl https://X.example.com/` should return HTTP 404 (daemon's "no app for /" passthrough) within a second, served with the real Let's Encrypt cert.

**Why this trap exists.** The sentinel-side PROXY flag is per-deployment policy; the primary-side flag is per-primary configuration. There is no handshake between them that detects mismatch, so the first request silently fails. Until that's fixed in code, every tunnel-promoted primary stood up against a PROXY-enabled sentinel needs the matching flag.

### `Failed to ensure Caddy server config: ... 409 key already exists: http` on every daemon startup

**Symptom.** `journalctl -u containarium.service` shows this warning every time the daemon starts; subsequent daemon-driven Caddy updates appear to do nothing.

**Cause.** Bug in `ProxyManager.ensureHTTPApp` before v0.16.6 — strict-decoded the Caddy config into a typed struct that transitively held an interface slice. `encoding/json` cannot decode into interfaces, so the decode failed, the code fell through to a PUT that 409'd because the http app already existed, and `EnsureServerConfig` returned an error. The daemon kept running, but updates that assumed `EnsureServerConfig` had succeeded were silently lost.

**Fix.** Upgrade to v0.16.6 or later. The fix is in [#157](https://github.com/FootprintAI/Containarium/pull/157).

## History

| PR | Summary |
|---|---|
| [#105](https://github.com/FootprintAI/Containarium/pull/105) | Sentinel side: `WriteProxyV2` encoder, `--proxy-protocol` flag, header injected in `buildSNIRoutingHandler`. Includes the Go-level e2e and the real-Caddy e2e gated by build tag. |
| [#106](https://github.com/FootprintAI/Containarium/pull/106) | Daemon side, srv0 only: `--proxy-protocol` and `--proxy-protocol-trusted` flags; `ProxyManager.EnableProxyProtocol` rewritten to use the atomic `getFullConfig`+`loadConfig` pattern (the previous PATCH-on-server form would clobber `listen`/`routes`). |
| [#107](https://github.com/FootprintAI/Containarium/pull/107) | Daemon side, L4: pattern B wrapping; `L4ProxyManager` becomes wrapping-aware so `RouteSyncJob`'s CRUD operations on the inner route list don't undo the wrapper. Closes the gRPC-outage gap from #106. |
