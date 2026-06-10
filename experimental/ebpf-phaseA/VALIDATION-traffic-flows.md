# Backend validation runbook — bidirectional flow accounting + history

On-backend acceptance for the two eBPF traffic-flow changes that ship together
on this branch:

- **#631** — reply-direction bytes via a 2nd program on the veth `TC_EGRESS`
  hook (`bytes_received` populated, not just `bytes_sent`).
- **#632** — persist closed eBPF flows to `traffic_history` so the historical
  view + aggregates light up on backends where conntrack attribution fails.

Both are gated on this runbook because the compiled BPF object is never
committed (built on the backend / in CI), so the kernel verifier only exercises
the new `netpolicy_egress` program and the wider `flow_stat` at first load.

> Anonymise before pasting results anywhere public: use `<backend>`, `<tenant>`,
> `$DAEMON`, `$JWT` — never real hostnames / IPs / tenant names.

## Prerequisites

- A Linux backend, **kernel ≥ 6.6** (TCX attach), Incus, `clang`/`llvm` +
  kernel UAPI headers (`libbpf-dev linux-libc-dev`).
- The daemon built from **this branch** (`feat/traffic-history-persist`, which
  includes #631). `make build-linux`.
- **Postgres reachable by the daemon** (`--postgres` / the usual connstring) —
  #632 writes history there; without it the live view still works but history
  won't persist.
- A throwaway tenant container you can generate traffic from.

## Phase 0 — build the object and start the daemon

```sh
# On the backend, from experimental/ebpf-phaseA:
clang -O2 -g -target bpfel -I/usr/include/$(uname -m)-linux-gnu \
    -c netpolicy.bpf.c -o /etc/containarium/netpolicy.bpf.o

# Sanity: the object must carry BOTH programs + the flows map.
llvm-objdump -h /etc/containarium/netpolicy.bpf.o | grep -E 'netpolicy(_egress)?|flows' || true
# Expect sections for classifier/netpolicy AND classifier/netpolicy_egress.
```

Point the daemon at it and (re)start. Enforcement is NOT needed for accounting,
so leave `CONTAINARIUM_NETWORK_POLICY_ENFORCE` unset:

```sh
export CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT=/etc/containarium/netpolicy.bpf.o
# restart the daemon (systemd unit / however this backend runs it)
```

Give the container a policy so the enforcer attaches to its veth (any
log_only policy is enough to make it a managed veth):

```sh
containarium network-policy set <tenant> --mode log_only --egress-cidr 0.0.0.0/0
```

## Phase 1 — verifier acceptance (#631)

The new egress program + 48-byte `flow_stat` must load without a verifier
rejection, and both hooks must attach.

```sh
journalctl -u containarium --since "2 min ago" | grep -iE '\[netpolicy\]'
```

**Pass criteria:**
- `enforcer started` and `traffic-flow accounting enabled (poll=…)` appear.
- **No** verifier / load error (`load collection`, `attach TCX egress …`).
- Both programs are attached to the container's host veth:
  ```sh
  VETH=$(incus config get <container> volatile.eth0.host_name)
  tc filter show dev "$VETH" ingress      # netpolicy
  tc filter show dev "$VETH" egress       # netpolicy_egress  ← the #631 add
  # (or: bpftool net show dev "$VETH")
  ```

If the egress program is missing from the object, the daemon logs that
reply-byte accounting is unavailable and continues — that means the object
wasn't rebuilt from this branch.

## Phase 2 — reply bytes are non-zero (#631)

Generate a request/response flow with a real response payload (HTTPS download
gives an obvious receive side):

```sh
incus exec <container> -- sh -c 'curl -s https://1.1.1.1 -o /dev/null'
# or a sized download: curl -s https://<host>/100mb.bin -o /dev/null
```

Read the live view (wait one poll interval, ~15s):

```sh
curl -s -H "Authorization: Bearer $JWT" \
  "$DAEMON/v1/containers/<tenant>-container/connections" | jq '.connections[]
  | {destIp, destPort, bytesSent, bytesReceived}'
# or, if the traffic CLI is present on this build:
containarium traffic connections <tenant>-container
```

**Pass criteria:** the flow shows **both** `bytesSent > 0` **and**
`bytesReceived > 0` (pre-#631 this was always 0), attributed to the right
container, with the correct dest IP/port.

## Phase 3 — history persistence (#632)

A flow is persisted when it disappears from the BPF LRU map (closed / idle /
evicted) between polls. Generate a flow, let it finish, then wait past a couple
of poll intervals:

```sh
incus exec <container> -- sh -c 'curl -s https://1.1.1.1 -o /dev/null'
sleep 60   # let the flow go idle and the poll observe it disappear
```

Query history:

```sh
curl -s -H "Authorization: Bearer $JWT" \
  "$DAEMON/v1/containers/<tenant>-container/traffic/history" | jq '.connections[]
  | {sourceIp, destIp, destPort, bytesSent, bytesReceived, endedAt}'
# or: containarium traffic history <tenant>-container
```

**Pass criteria:** the closed flow appears in history with the correct
5-tuple + byte counts. (Requires Postgres configured.)

**The docker-in-LXC payoff** (optional but the point of #632): run a
docker-compose workload *inside* the LXC and confirm history populates for it —
this is the case where the conntrack collector attributed nothing and history
was previously empty.

## Phase 4 — no regression

Confirm the existing Phase A behaviour is intact:

- `seen` counter still increments as the container sends traffic (the
  ingress-hook accounting / policy path is unchanged).
- A would-deny flow still logs (`[netpolicy] deny …`) and, if you separately arm
  `CONTAINARIUM_NETWORK_POLICY_ENFORCE=1` with a `--mode enforce` policy, still
  drops — the egress program is accounting-only and must not affect enforcement.
- A neighbour container with no policy is unaffected.

## Rollback

Unset `CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT` and restart — the daemon reverts
to the conntrack-only collector exactly as before. No persisted data is removed.

## Recording the result

Post the outcome (pass/fail per phase, with the relevant `journalctl` / `jq`
output, **anonymised**) on **PR #642**, and note Phase 1–2 on **PR #641**. On a
clean pass:

1. Mark **#641** ready → merge to `main`.
2. **#642** retargets to `main` → mark ready → merge.
3. **#644** (cross-source dedup, #643) retargets to `main` → merge.

Do not reorder — each depends on the one below it.
