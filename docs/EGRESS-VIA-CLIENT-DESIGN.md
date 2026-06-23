# Egress via client — design

**Status: proposal (needs approval).** Tracks [#808](https://github.com/FootprintAI/Containarium/issues/808).

Route a box's outbound traffic (e.g. a headless browser) through the operator's
workstation, so the box egresses with the operator's IP/network — safely, with
one command, and **without** exposing a container sshd or punching shared holes.

## Why the obvious approaches don't work

Verified live (#808):

1. **`ssh -R` from the client → box.** The sentinel terminates SSH on the
   *host* (sshpiper → host sshd → `containarium-shell` → `incus exec` into the
   box). Forwarded sockets live in the **host** netns; the box is a separate
   netns. A host-loopback `-R` listener is `ConnectionRefused` from inside the
   box. (`GatewayPorts no` also forces loopback.)
2. **`ssh -L` from inside the box → client (workaround #1).** Requires the box
   to *reach* the client. Operator laptops are NAT'd — confirmed: the Mac is
   tailnet-only (`100.124.9.5`), no public sshd; the cloud box is not on the
   tailnet and cannot dial it. So "box dials client" is unavailable for the
   common case.
3. **Daemon dials the client's SOCKS directly.** Works only if the *host* can
   reach the client (e.g. a tailnet host like a BYOC node). The cloud workhorse
   is not on the tailnet → unavailable for cloud boxes.

The one party that can always reach both ends is: the **client reaches the
control plane** (it already does — that's how it drives the platform), and the
**daemon can enter the box netns** (`incus exec`). The design pivots on those
two facts.

## Architecture — daemon-mediated reverse egress proxy

```
 box app (Chrome)                     daemon (host)                cloud CP            client (Mac)
   │ socks5 127.0.0.1:P  ── incus-exec'd in-box forwarder ──▶ │                          │
   │                                   │  box→daemon (bridge gw, already reachable)      │
   │                                   ├── egress stream ─────▶ CP ◀── egress channel ──┤ (client dials CP)
   │                                   │                        │                        ├─▶ local SOCKS ─▶ internet
```

- **Listener lives in the box netns.** The daemon `incus exec`s a small
  forwarder bound to `127.0.0.1:P` *inside the box* — so the box's apps get a
  normal localhost SOCKS, and the listener is correctly namespaced (the thing
  every other approach gets wrong).
- **Box → daemon** uses the bridge gateway the box already reaches (it talks to
  the daemon/model-gateway there today).
- **Daemon → client** rides a **client-initiated egress channel** to the cloud
  control plane (the client always reaches the CP; the CP reaches the daemon via
  the existing sentinel peer-proxy / actuation path). yamux (already a dep, used
  by the BYOC tunnel) multiplexes per-connection streams over it.
- **Client** terminates each stream into a local SOCKS server it runs (or one
  the CLI starts), which egresses with the operator's IP.

No `GatewayPorts`, no shared-bridge listener, no container sshd, no requirement
that the box or host can reach the client.

## CLI / MCP (CLI-first per repo convention)

```
containarium egress-via-client <box> [--socks-port 1080] [--show]
```
- Runs on the operator's machine. Starts a local SOCKS (or `--socks host:port`
  to reuse one), opens the egress channel to the CP, and prints the in-box proxy
  address to point apps at (`socks5://127.0.0.1:P`).
- `--show` reveals the live stream count; Ctrl-C tears everything down.
- MCP `egress_via_client` wraps the same Go function (thin).

## Security

- **Scoped to the caller's own box.** The egress channel is authenticated with
  the caller's token; the daemon only sets up a forwarder for a box the caller
  owns.
- **Opt-in + ephemeral.** Nothing is created until invoked; the in-box forwarder
  and the channel are torn down on disconnect / box stop. Audit-logged.
- **Respects eBPF egress policy.** The box→daemon hop is an egress connection
  from the box; it must be permitted by the box's egress allowlist (or a
  dedicated, audited exemption), so this cannot silently bypass egress controls.
- **Never exposes a container sshd** (preserves the property in #808).
- The client's SOCKS is bound to the client's own loopback; only the
  authenticated channel reaches it.

## Phased implementation

- **2a — in-box forwarder + daemon relay (OSS).** `containarium egress-forward`
  (a minimal, well-tested TCP forwarder) that the daemon `incus exec`s into the
  box; daemon-side relay that bridges box→upstream with source-IP restriction.
  Directly usable on a **tailnet host** (`--socks` = a host-reachable SOCKS),
  which is the live-demoable slice (fts-13700k reaches the Mac's tailnet SOCKS).
- **2b — daemon-bridged `ssh -R` (OSS, IMPLEMENTED).** Refined during live
  validation: the from-scratch client→CP yamux channel proved unnecessary. The
  client always *can* SSH to the box, and `ssh -R 127.0.0.1:<p>:localhost:<socks>`
  lands a listener in the **host** netns — useless to the box directly, but the
  **daemon bridges it into the box** with the Phase-2a relay (`upstream` = that
  host-loopback port, source-restricted to the box IP). Works for the
  **NAT'd-client + box** case with no new cloud protocol. Shipped: proto RPCs
  `StartEgressProxy`/`StopEgressProxy` on `NetworkService`, daemon impl +
  `egressproxy.Manager`, gRPC client, and `containarium egress-via-client`
  (starts a local SOCKS, opens the `ssh -R`, calls the RPC, tears down on exit).
  Validated live (fts→Mac): box egress `211.75.165.177` → `36.230.33.117`.
  Remaining for the **cloud** box specifically: extend the cloud ossshim to
  forward `/v1/network/egress-proxy` (today unserved cloud paths 404) so the
  operator's CLI reaches the box's daemon through the CP.
- **2c — UX.** `--show`, auto-teardown, audit entries, docs + a Chrome
  `--proxy-server` recipe.

## Rejected alternatives

- Host `GatewayPorts clientspecified` + bridge-IP `-R`: cross-tenant exposure on
  the shared bridge.
- Direct container sshd exposure: breaks the no-direct-container-sshd model.
- Requiring every box on the tailnet: heavyweight, and tenant boxes joining the
  operator tailnet is its own trust problem.
