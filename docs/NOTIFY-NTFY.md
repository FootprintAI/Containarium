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
a token on the box would be the agent's to read. The token is stored as the
broker-only tenant secret `CONTAINARIUM_NOTIFY_NTFY_TOKEN`: never delivered
to a box by any delivery mode, and never returned by `secrets get` or any
notify RPC. If you already have a secret by that name in a delivered mode,
`notify set` refuses to overwrite it; delete it first.

Every 5 seconds the daemon reads the input journal of every running run on
the box of each user with a channel, read-only, through the same guarded root
read `code runs` uses. Users without a channel cost nothing.

- **Timing.** The first request of a run is pushed on the poll that finds it,
  normally within 5 seconds (one poll interval plus the read of the box).
- **Bursts.** Further requests within 30 seconds of a run's last push wait,
  then go out as one push with a count. No request is dropped. A request that
  is answered or expires before its push is due is not sent.
- **Delivery is at least once.** After a daemon restart, requests still open
  are pushed again. A failed push is retried on the next poll.
- **Network.** The daemon never follows a redirect from the ntfy server (that
  would hand the token to another host), and refuses loopback, link-local and
  cloud-metadata addresses. Private LAN addresses are allowed, for a
  self-hosted server on the same network.

## Limits

- ntfy only. The push has no Allow / Deny buttons yet; answer with the CLI.
- The journal on the box is writable by the box's user, so an agent can make
  the daemon push text of its choosing to your topic, at most three pushes
  per poll and one per run per 30 seconds. It cannot read the token or
  answer a request this way.
- Needs Postgres on the daemon; without it `NotifyService` is not registered.
