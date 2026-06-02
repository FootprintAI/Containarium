# Repro / validation harnesses

Self-contained scripts for reproducing and validating specific issues on a
throwaway VM, where the relevant daemons can't run on a dev host (e.g. macOS).

## #301 — sshpiper reload drops live SSH sessions

`sshpiper-reload-301.sh` answers the one runtime question the fix hinges on:
does the `sshpiperd` YAML plugin pick up `config.yaml` changes for **new**
connections **without** a restart, while leaving **existing** sessions alive?

> **Resolved — Option A, confirmed from upstream source.** The `sshpiperd`
> `yaml` plugin's `listPipe` calls `loadConfig()` (an `os.ReadFile` + parse of
> `config.yaml`) on **every** incoming connection — there is no in-memory cache
> and no restart/SIGHUP needed to pick up new routes, while in-flight
> TCP-proxied sessions are untouched. See `plugin/yaml/skel.go`
> (`listPipe` → `loadConfig`) and `plugin/yaml/yaml.go` in
> `github.com/tg123/sshpiper`. The fix — delete the `RestartSSHPiper()` calls
> and just write `config.yaml` — shipped accordingly. This harness now serves as
> an empirical re-confirmation against the fleet's exact `sshpiperd` build.

It stands up a hermetic sshpiper + a throwaway upstream sshd, holds a live
session, rewrites the config to add a route, and checks Option A (hot-reload,
no restart) then Option B (SIGHUP) — with a CONTROL that does a real restart and
asserts the held session **drops**, so a "survived" result can't be a false
negative. See the script header and the #301 design note for the full rationale.

### Quick start (macOS / Linux via Multipass)

```bash
# from this directory:
./multipass-up.sh --run
```

That launches an Ubuntu 24.04 VM (`cloud-init.yaml` installs the SSH tooling),
copies the harness in, and runs it as root. The verdict maps directly to the
design-note options:

- **OPTION A CONFIRMED** → delete the three `RestartSSHPiper()` calls; the
  YAML plugin hot-reloads. Few-line fix.
- **OPTION B CONFIRMED** → replace `systemctl restart` with reload/SIGHUP.
- **NEITHER** → coalesce restarts (Option C) now; plan a custom upstream
  plugin (Option E).

### Faithful run (production's exact sshpiperd)

The hot-reload behavior is a property of the specific `sshpiperd` build, so the
meaningful run is against the binary the fleet uses. Get production's invocation
from `systemctl cat sshpiper` on a real sentinel, install that binary in the VM,
and run:

```bash
multipass exec sp301 -- sudo \
  SSHPIPERD_BIN=/usr/local/bin/sshpiperd \
  SSHPIPERD_LAUNCH='/usr/local/bin/sshpiperd <prod args>' \
  /home/ubuntu/sshpiper-reload-301.sh
```

### Other Multipass commands

```bash
./multipass-up.sh           # launch/reuse VM + copy harness (prints next steps)
./multipass-up.sh --shell   # drop into a shell on the VM
./multipass-up.sh --down    # delete + purge the VM
```

Prereq: `brew install --cask multipass` (macOS) or https://multipass.run.

## Extending toward a multi-node dev cluster (not built yet)

A single VM is enough for #301. The broader SSH/routing/control-plane/metrics
validation (e.g. end-to-end sentinel↔daemon HMAC for #341/#345, the OTLP ingest
path) wants two VMs — a sentinel and a backend daemon — provisioned via the
existing `hacks/install.sh` (single-node) + `scripts/install-lab-tunnel.sh`
(tunnel client → sentinel registry) + Phase B (Incus + daemon + core
containers). That multi-node automation is **not** scripted here yet, and note
the hard limits of a VM cluster: **no GPU passthrough (#316)** and **no nested
Windows VMs (#318)** — those need real hardware.
