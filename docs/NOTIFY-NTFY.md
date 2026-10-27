# Push a waiting permission request to your phone (ntfy)

A `containarium code run <box> --approvals ask` run pauses when the agent
needs a permission (#2183). With a notification channel set, the daemon
pushes that request to your phone through [ntfy](https://ntfy.sh), so you
don't have to poll `code status` (#2185, PRD `docs/product/phone-approval.md`
Story 3).

## Set it up

```bash
# a topic that needs a token (recommended)
containarium --server <daemon> notify set ntfy \
  --ntfy-server https://ntfy.example.com --topic my-runs --token-file ~/.ntfy-token

# or pipe the token in
pass show ntfy | containarium --server <daemon> notify set ntfy \
  --ntfy-server https://ntfy.example.com --topic my-runs --token-stdin

containarium --server <daemon> notify test     # one test push
containarium --server <daemon> notify show     # never prints the token
containarium --server <daemon> notify delete   # channel and token removed
```

- `--ntfy-server` is the ntfy server's base URL. It is not called `--server`
  because the global `--server` names the daemon.
- The token comes from `--token-file` or stdin, never from a flag, so it does
  not land in shell history. With a token the server must be `https`.
- Running `set` again without a token keeps the stored one; `--clear-token`
  removes it.
- One channel per user. `--user <name>` acts on another user's channel and
  needs the admin role. Writes need the `secrets:write` scope, reads and
  `test` need `secrets:read`.

Then subscribe to the same topic in the ntfy app on your phone.

### Self-hosted ntfy on a private network

The daemon sends from the host's network, so by default it reaches only
public addresses: a tenant must not be able to point it at the box bridge or
the host's LAN. To use a self-hosted ntfy server on a private address, the
operator lists its network in the daemon's environment and restarts the
daemon:

```bash
CONTAINARIUM_NOTIFY_ALLOWED_CIDRS=192.0.2.0/28        # comma-separated CIDRs
```

Keep the list narrow (the ntfy server's own address or subnet). A malformed
value is logged and the daemon then reaches public servers only. Loopback,
link-local and cloud-metadata addresses stay refused whatever the list says.
`notify test` reports only that the push failed; the reason is in the daemon
log.

## ntfy.sh topics are public by name

On the public ntfy.sh server, anyone who knows or guesses a topic name can
subscribe to it and read every push, and can publish to it too. A push names
your box, your run, and for Bash the command the agent wants to run. Use one
of these instead of an open topic:

- an **access-controlled topic** (ntfy.sh account with a reserved topic, or
  any ntfy server with access control) and its token, or
- a **self-hosted ntfy server**, reachable from the daemon, with access
  control on.

An unguessable topic name with no token is better than nothing, but anyone
who sees the name once (a screenshot, a shared config) can read the pushes.

## What a push contains

- Title: `<box>/<run> needs approval`, or `<box>/<run>: N requests need
  approval` when several are waiting.
- The tool name.
- For `Bash` only: the command, with control characters escaped, cut to 200
  characters. With `--redact-command` on the channel it is left out.
- When the request expires (it is then denied), and the request id.

A push never carries file contents, environment values, secrets, or any other
tool's input. For every tool other than `Bash` only the name is sent, because
its input can hold a file's contents, a path, or arbitrary JSON.

## How it is sent

The daemon sends the push, not the box: the agent runs as the box's user, so
a token on the box would be the agent's to read. The token is stored as a
broker-only tenant secret named `CONTAINARIUM_NOTIFY_NTFY_TOKEN_<random>`:
never delivered to a box by any delivery mode, and never returned by
`secrets get` or any notify RPC.

Each new token gets a new secret. `notify set` writes it, then switches the
channel to it in one write, then removes the old one. If anything fails
before that switch, the previous server and token stay in effect; a token is
never sent to a server it was not set for. `notify delete` removes the token
first and the channel last, so a failed delete can simply be retried.
Only the exact secrets this service wrote are ever removed; another secret
whose name merely starts with the same prefix is left alone.

Every 5 seconds the daemon reads the input journal of every running run on
the box of each user with a channel, read-only, through the same guarded root
read `code runs` uses. Users without a channel cost nothing.

- **Timing.** The first request of a run is pushed on the poll that finds it:
  within one poll interval (5 seconds) plus the read of the box and the time
  the ntfy server takes to accept the push. With a server that answers
  promptly that is well under 10 seconds; a slow or unreachable server can
  delay it (each attempt gives up after 10 seconds and is retried on the
  next poll).
- **Bursts.** Further requests within 30 seconds of a run's last delivered
  push wait, then go out as one push with a count. No request is dropped,
  within the read limit below. A request that is answered or expires before
  its push is due is not sent. A later journal line the agent writes with the
  same request id is ignored: the box's own first line for the id is pushed.
- **Delivery is at least once.** After a daemon restart, requests still open
  are pushed again. A failed push is retried on the next poll.
- **Isolation.** Each user is polled separately, so one slow box or ntfy
  server does not delay anyone else's pushes.
- **Network.** The daemon never follows a redirect from the ntfy server (that
  would hand the token to another host), and refuses loopback, link-local
  (where most clouds serve instance metadata) and the cloud-metadata
  addresses outside it (AWS and GCP over IPv6, Alibaba Cloud over IPv4; listed
  in `internal/notify/ntfy.go`). Private, CGNAT and IPv6 ULA addresses (the
  daemon's own LAN and the box bridge) are refused too, unless the operator
  lists the network; see "Self-hosted ntfy on a private network" below.

## Limits

- ntfy only. The push has no Allow / Deny buttons yet; answer with the CLI.
- The journal on the box is writable by the box's user, so an agent can make
  the daemon push text of its choosing to your topic, at most three pushes
  per poll and one per run per 30 seconds. It cannot read the token or
  answer a request this way.
- The daemon reads the last 256 KiB of a run's request and response lines
  (about 300 requests and their responses at the largest prompt size). A
  request still open behind more than that much later traffic is not pushed;
  a request expires after `--approval-timeout`, 30 minutes by default.
- If removing a replaced token's secret fails, that secret stays behind
  (broker-only, never delivered to a box); the daemon logs it.
- Needs Postgres on the daemon; without it `NotifyService` is not registered.
