# Box logs (`TailBoxLogs`, `containarium logs`)

`TailBoxLogs` (`GET /v1/containers/{username}/logs`, see
`proto/containarium/v1/box_logs.proto`) reads a box's systemd journal and the
logs of the docker containers running inside it, merged into one stream in
receipt-time order. `containarium logs <box>` and the MCP `box_logs` tool are
thin wrappers over it. No SSH access is needed: the caller needs a token that
may connect to the box (the box's owner or a collaborator, with the
`ssh:write` scope), the same rule as `TailBoxRunLog`.

## Reading

```bash
containarium logs alice --server <host>                       # last 100 lines
containarium logs alice --since 15m --server <host>           # everything from 15 minutes ago
containarium logs alice --unit nginx --container web -f --server <host>
```

Each line is printed as `<time> <label> <text>`, where the label is
`journal/<unit>` (or the syslog identifier when the entry has no unit) or
`container/<name>`.

| Flag | API field | Meaning |
|------|-----------|---------|
| `--since` | `since` | Start at this time: a duration back from now (`15m`) or an RFC 3339 time |
| `--tail` | `tail` | Start with only the last N lines (0–1000). Without `--since`, 100 |
| `--unit` (repeatable) | `units` | Only these systemd units; `nginx` means `nginx.service` |
| `--container` (repeatable) | `containers` | Only these containers, by name |
| `--max-lines` | `max_lines` | Most lines per window (default 200, at most 1000) |
| `--follow`, `-f` | `follow_seconds` | Keep reading; each request waits up to 10 s for a line |

With only `--unit`, no container is read; with only `--container`, the
journal is not read. A unit or container the box does not have is
`INVALID_ARGUMENT`, and the message lists the valid names.

## Resuming: the cursor

Each response carries an opaque `cursor`. Passing it back as `cursor` reads
the lines after that window, with no line repeated and none skipped, as long
as the filters stay the same. `more` is set when lines were already waiting
past the window: read again at once. `containarium logs` does this for you.

The daemon merges the sources up to one second behind the box's clock, so a
line a slower source delivers late is still placed in order rather than
skipped.

## When nothing is read

| `status` | Meaning |
|----------|---------|
| `BOX_LOGS_STATUS_BOX_STOPPED` | The box is not running. It is not started and its disk is not read; the cursor comes back unchanged. |
| `BOX_LOGS_STATUS_RUNTIME_UNSUPPORTED` | The box runs its containers on podman or a rootless docker. This version reads docker-backed boxes only, and returns no lines rather than a window that leaves those containers out. `runtime` says which runtime was found. |

A box with no container runtime is read as journal only (`runtime` is
`BOX_CONTAINER_RUNTIME_NONE`).

## Limits and safety

- Collection is one fixed script the daemon runs in the box. Only integers,
  a validated journal cursor and unit names matching
  `[A-Za-z0-9][A-Za-z0-9@_.:-]*` are passed into it; container names are only
  compared, never run.
- The script times its readers out after a few seconds and caps its output
  at 8 MiB.
- Everything the box prints is treated as untrusted. Invalid UTF-8 and
  control characters (other than tab) become U+FFFD, a line's text is capped
  at 8 KiB (`truncated` is set), and a window holds at most `max_lines` lines
  and 1 MiB of text. Output frames that do not parse are skipped and counted
  in `dropped_frames`.
- journald prints a field longer than 4 KiB as null; such a line arrives
  with empty text and `truncated` set.
- Container logs are read with `docker logs`, which works with docker's
  default `json-file` log driver (the platform's docker setup does not change
  it) and the `local` and `journald` drivers.
