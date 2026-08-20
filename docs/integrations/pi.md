# pi on Containarium

[pi](https://pi.dev) (`@earendil-works/pi-coding-agent`) is a local-first
coding agent CLI: sessions on local disk, no SaaS backend, no account. Its own
docs are blunt about the trade-off that comes with that — there are no
permission popups, so *"run in a container, or build your own confirmation
flow."*

A Containarium box is that container. pi installs into the box and runs there,
with the box's filesystem as its working tree, the box's network as its egress
path, and the box's lifecycle as its blast radius.

```bash
containarium create alice --ssh-key ~/.ssh/id_ed25519.pub
containarium ssh-config sync
ssh alice 'curl -fsSL https://pi.dev/install.sh | sh'
containarium sync alice                  # your code -> ~/work in the box
ssh alice -t 'cd ~/work && pi'
```

## Why pi runs *inside* the box

[README step 4](../../README.md) wires an agent to a box over MCP — the agent
stays on your laptop and drives `agent-box` inside the container as a tool
server. **pi has no MCP client**, by design: *"No MCP. Build CLI tools with
READMEs (see Skills), or build an extension that adds MCP support."* So that
wiring has nothing to attach to.

Running pi in the box gets to the same place from the other direction:

```
  Claude Code / Cursor / codex          pi
  ────────────────────────────          ──
  brain   on the laptop                 brain   in the box
  hands   in the box (agent-box, MCP)   hands   in the box (pi's own
  API key on the laptop                         read/write/edit/bash)
                                        API key in the box (tenant secret)
```

`agent-box` exists to give a *remote* brain hands inside the container. When
the brain is already in the container, pi's native `read` / `write` / `edit` /
`bash` tools act on exactly the same filesystem, so agent-box is redundant on
this path — you are not giving anything up by skipping it.

What the box still buys you, unchanged:

| | |
|---|---|
| **Isolation** | pi's `bash` tool runs in an LXC container, not on your laptop |
| **Blast radius** | the box holds an SSH key, not a kube-apiserver token — no host, no control plane, no other tenant |
| **Egress control** | eBPF egress policy applies to everything pi shells out to |
| **Persistence** | `~/.pi/agent/sessions/` survives restarts, so `pi -c` resumes yesterday's session |
| **Reachability** | `expose-port` puts what pi built on a public HTTPS hostname |
| **Key custody** | the provider key is a daemon-managed tenant secret, not a line in your laptop's shell profile |

## Prerequisites

- A Containarium daemon and a box you can reach (`ssh <box>` after
  `containarium ssh-config sync`, or `containarium connect <box>`).
- A provider API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …). pi supports
  20+ providers.
- Outbound egress from the box to the provider's API. Plain boxes have normal
  outbound access; if your operator has armed eBPF egress enforcement, the
  provider domain has to be allowed (see [Limitations](#limitations)).
- The stock `images:ubuntu/24.04` box has `curl` and `git` but no `tmux` and no
  Node; step 2 covers what to add.

## 1. Create the box

```bash
containarium create alice --ssh-key ~/.ssh/id_ed25519.pub --server <backend>
containarium ssh-config sync
# then, once, in ~/.ssh/config:  Include ~/.containarium/ssh_config
ssh alice
```

You land in `/home/alice` as the box's own user, with passwordless `sudo`.

If you pass `--idle-stop 30m`, the box auto-stops after 30 minutes idle and
wakes on access. An active SSH/exec session counts as activity, so an attached
pi session is never stopped mid-run — but a detached, backgrounded `pi -p` with
no live session can be. Size the threshold for the longest unattended run you
expect, or leave `--idle-stop` off for agent boxes.

## 2. Install pi in the box

```bash
ssh alice 'curl -fsSL https://pi.dev/install.sh | sh'
ssh alice 'pi --version'
ssh alice 'sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -qq tmux'      # only needed for `connect --session`
```

The stock `images:ubuntu/24.04` box ships `curl` and `git`, so the installer
runs as-is. It has no `tmux` and no Node — install tmux if you want detachable
sessions (step 5), and Node ≥ 20 if you prefer `npm i -g --ignore-scripts
@earendil-works/pi-coding-agent` over the installer.

pi keeps everything under `/home/alice/.pi/` — config, `models.json`,
extensions, skills, and session files. That's on the box's persistent disk, so
it survives stop/start and auto-sleep wake. Install once per box, not once per
task.

## 3. Give pi its key as a tenant secret

Don't paste the key into an SSH command — it lands in your laptop's shell
history and the box's process table. Use the secrets store, with **file-based
delivery**:

```bash
containarium secrets set alice ANTHROPIC_API_KEY sk-ant-... --delivery compose
containarium secrets refresh alice
ssh alice "grep -q containarium/secrets.env ~/.profile || \
    echo 'set -a; . /run/containarium/secrets.env; set +a' >> ~/.profile"
ssh alice 'bash -lc "printenv ANTHROPIC_API_KEY >/dev/null && echo present"'
```

`secrets set` encrypts at rest on the daemon (AES-256-GCM) and `secrets
refresh` pushes the current store to a running box without a restart.
`--delivery compose` writes a shared dotenv file at
`/run/containarium/secrets.env` (tmpfs); `--delivery file` writes one file per
secret at `/run/secrets/<NAME>` if you'd rather read them individually.

### Why not the default `env` delivery

The default (`--delivery env`) stamps `environment.<NAME>=<value>` on the LXC.
That reaches container-start processes and nested docker/compose apps — but
**not an SSH shell session**, which is where pi runs. The login path rebuilds
the environment from scratch (`sshd` → the box's login wrapper → `su -` →
`bash`), and `su -` drops inherited variables by design. Measured on a stock
Ubuntu 24.04 box: a variable present in the container's systemd manager
environment is visible to a `systemd-run` unit and absent from every SSH
session, interactive or not.

So `printenv ANTHROPIC_API_KEY` over SSH is not a good check for `env`
delivery — it will read as failure even when the stamp is correctly applied.
Use `compose`/`file` delivery for anything a *shell* has to see.

pi's own `/login` flow also works if you'd rather authenticate interactively
inside the box; the credential then lives in `~/.pi/` on the box's disk instead
of in the daemon's encrypted store.

See [SECRETS-MANAGEMENT-DESIGN.md](../SECRETS-MANAGEMENT-DESIGN.md) and
[security/SECRETS-ENV-VAR-RISK.md](../security/SECRETS-ENV-VAR-RISK.md) for
what env-var delivery does and does not protect against.

## 4. Get your code into the box

```bash
containarium push alice          # committed history only, via real `git push`
containarium sync alice          # mirror cwd, uncommitted + untracked included
```

Both land in `~/work` inside the box by default (`--remote-path` to change it).
`push` is the git-native path — it sets up a bare repo at `~/work.git` with a
post-receive hook that checks out the tree. `sync` is "make the remote look
like local right now".

For work that starts in the box, skip both and let pi `git clone` — it has
network access and a shell.

## 5. Run pi

**Interactive**, the common case:

```bash
ssh alice -t 'cd ~/work && pi'
```

**Long-lived and detachable** — `connect --session` hosts the session in a
named tmux session *on the box*, so you can close your laptop and reattach:

```bash
containarium connect alice --session pi --exec 'cd ~/work'
containarium connect alice --session pi          # attach your terminal
```

**Headless**, for scripts and CI:

```bash
ssh alice 'cd ~/work && pi -p "fix the failing test in ./api" --mode json'
```

`-p` prints the response and exits; `--mode json` emits events as JSON lines
(`--mode rpc` gives LF-delimited JSONL for process integration). Sessions
auto-save under `~/.pi/agent/sessions/`, keyed by working directory — `pi -c`
resumes the most recent one, `--session <id>` picks a specific one.

## 6. Serve what pi built

```bash
containarium expose-port alice --container-port 8080 --domain blog.example.com
curl https://blog.example.com
```

Caddy on the sentinel terminates TLS and forwards to `alice-container:8080`.
This is the loop that makes an agent box worth more than a local sandbox: pi
builds it, the box serves it, the URL is real.

## Teaching pi the platform

pi's substitute for MCP is "CLI tools with READMEs." The `containarium` CLI is
already that, so a skill in `~/.pi/agent/skills/containarium/SKILL.md` — in the
box or on your laptop — is enough for pi to drive the platform itself:

```markdown
# containarium
Use when the user asks to create, expose, or clean up a sandbox box.

- create:  containarium create <name> --ssh-key ~/.ssh/id_ed25519.pub
- wire:    containarium ssh-config sync
- expose:  containarium expose-port <name> --container-port <p> --domain <d>
- delete:  containarium delete <name>
```

Package it (`pi install git:...`) if you want it on every box you create.

## Limitations

- **No MCP client, so no `agent-box` tools or resources.** pi cannot read
  `containarium://ci-context`. On a box kept alive by the
  [containarium-run](https://github.com/FootprintAI/containarium-run) GitHub
  Action, the same data is a plain file — `cat
  /workspace/.containarium/ci-context.json` — so a CI-debugging skill can point
  pi at it directly. Adding a real MCP client means writing a pi extension
  (`~/.pi/agent/extensions/`, TypeScript, may spawn subprocesses); it is not
  needed for anything on this page.
- **No approval prompts.** pi does not confirm writes or shell commands. The
  box *is* the confirmation boundary — treat every box running pi as
  fully-consented-to-be-modified, and don't mount host paths into it.
- **Egress enforcement.** If the daemon serves the model gateway and eBPF
  enforcement is armed, skill boxes are pinned to the gateway and direct
  provider domains are dropped. A plain box created with `containarium create`
  is not pinned; if your operator has armed a deny-by-default allowlist, add
  the provider domain. Routing pi through the gateway itself
  (`~/.pi/agent/models.json` accepts custom providers speaking the
  Anthropic/OpenAI/Google API shapes) is possible in principle, but the gateway
  mints tokens for skill boxes today — see
  [AGENT-MODEL-GATEWAY-DESIGN.md](../AGENT-MODEL-GATEWAY-DESIGN.md).
- **`connect --session` needs tmux on the box** (step 2 installs it);
  without it, use plain `--exec` or `ssh`.
- **One box, one agent identity.** Secrets are per-tenant, so two people
  sharing a box share the key. Give each human their own box.

## Cleanup

```bash
containarium delete alice --server <backend>
```

Deletes the box, its filesystem, and with it every pi session, extension, and
credential that lived inside it.
