# Doc map

One row per page (or per section of a long page). `Sources` are the paths,
routes, commands and config keys the section makes claims about — globs
allowed. `Verified` is the commit the section was last checked against;
`/writer-docs audit` diffs the sources since then
(`git diff --stat <verified>..HEAD -- <sources>`), re-runs the section's
commands, and checks every flag against `--help`.

Status: 🟢 verified on `Verified` · 🟡 verified statically only (flags,
links, code) — the commands need a fresh VM to run · 🔴 stale (issue
linked) · 🔴 unverified (no commit on record) · ✎ editorial (prose with
no code to diff; checked for links only).

| Page | Section | Sources | Figures | Verified | Status |
|------|---------|---------|---------|----------|--------|
| README.md | Header, badges | `go.mod`, `LICENSE`, `docs/images/quickstart.gif` | — | `106a18b3` | 🟢 |
| README.md | Choose your path · Why an agent runtime? | — | — | `106a18b3` | ✎ |
| README.md | Quick start (steps 1–3) | `hacks/install.sh`, `hacks/install-cli.sh`, `internal/cmd/quickstart.go`, `internal/cmd/ssh_config.go`, `internal/cmd/code.go`, `internal/cmd/list.go`, `internal/agentbox/**`, `cmd/agent-box/**` | — | `106a18b3` | 🟡 |
| README.md | After your first box | `internal/cmd/code*.go`, `internal/cmd/expose_port.go`, `internal/cmd/quickstart.go`, `docs/integrations/pi.md` | — | `106a18b3` | 🟡 |
| README.md | The four primitives | `internal/agentbox/**`, `internal/mcp/**`, `cmd/mcp-server/**`, `internal/cmd/*.go`, `docs/SENTINEL-DESIGN.md` | — | `106a18b3` | 🟢 |
| README.md | Architecture (diagram, env-var table) | `internal/gateway/**`, `internal/server/**`, `internal/secrets/**`, `internal/audit/**`, `docs/MULTI-POOL.md`, `docs/security/OPERATOR-SECURITY-RUNBOOK.md`, env `CONTAINARIUM_REQUIRE_IMAGE_DIGEST` `CONTAINARIUM_VERIFY_IMAGE_DIGEST` `CONTAINARIUM_ALLOWED_IMAGE_REGISTRIES` `CONTAINARIUM_KMS_BACKEND` `CONTAINARIUM_REQUIRE_ENVELOPE` `CONTAINARIUM_POSTGRES_URL_FILE` `CONTAINARIUM_POSTGRES_PASSWORD_FILE` `CONTAINARIUM_WAKE_TRUSTED_PROXIES` | — | `106a18b3` | 🟢 |
| README.md | How it's different · Comparison FAQ · Use cases · In the wild | — | — | `106a18b3` | ✎ |
| README.md | What's in the box | `internal/cmd/daemon.go` (`--runtime`), `internal/gateway/webui.go`, `docs/KIND-QUICKSTART.md`, `docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md`, `docs/WINDOWS-VM-SETUP.md`, `terraform/modules/containarium/**` | — | `106a18b3` | 🟢 |
| README.md | CLI reference (essentials) | `internal/cmd/create.go`, `internal/cmd/list.go`, `internal/cmd/info.go`, `internal/cmd/delete.go`, `internal/cmd/expose_port.go`, `internal/cmd/route*.go`, `internal/cmd/passthrough*.go`, `internal/cmd/ssh_config.go`, `internal/cmd/token*.go` | — | `106a18b3` | 🟢 |
| README.md | Deployment · System requirements | `hacks/install.sh`, `hacks/README.md`, `terraform/gce/**`, `cmd/containariumd/**` | — | `106a18b3` | 🟡 |
| README.md | API | `internal/gateway/gateway.go`, `internal/cmd/daemon.go`, `api/swagger/containarium.swagger.json` | — | `106a18b3` | 🟢 |
| README.md | Hardening notes | `internal/agentbox/sandbox.go`, `terraform/gce/**` | — | `106a18b3` | 🟢 |
| README.md | Status · Roadmap · Contributing · License · Acknowledgments · Support | `CLAUDE.md`, `LICENSE`, `CONTRIBUTING.md` | — | `106a18b3` | ✎ |
| docs/architecture/deployment-modes.md | Components, three deployment-mode diagrams (hosted, BYOC, air-gapped), trust boundaries, host prerequisites, sizing (TBD) | `internal/cmd/daemon.go`, `internal/server/dual_server.go`, `internal/cmd/sentinel.go`, `internal/sentinel/**`, `internal/cloud/**`, `internal/auth/**`, `internal/secrets/**`, `internal/hostcheck/**`, `hacks/install.sh`, `hacks/install-cli.sh`, `hacks/offline-install/install.sh`, `pkg/core/incus/**`, `pkg/core/network/portforward.go`, `internal/app/caddy_types.go`, `internal/config/byoc.go`, `internal/config/k8s.go`, `charts/containarium-k8s/Chart.yaml`, `docs/TUNNEL-REVERSE-PROXY.md`, `docs/BYOC-BACKEND-BRINGUP.md` | 3 Mermaid diagrams, parsed with `mermaid@11.4.1` | `2a69ebbb` | 🟡 |
| docs/security/CLAIMS.md | Claim → evidence table | `internal/audit/**`, `internal/modelgateway/**`, `internal/server/privileged_policy.go`, `internal/server/image_digest.go`, `internal/server/network_policy_enforcer.go`, `docs/security/multi-tenant-isolation.md` | — | `f78fa547` | 🟡 |
| docs/security/DATA-FLOW-AND-RETENTION.md | Retention classes, legal holds, the dry-run report, audit trail, known limits, store inventory | `proto/containarium/v1/retention.proto`, `internal/retention/**`, `internal/server/retention_server.go`, `internal/cmd/retention.go`, `internal/server/agent_task_store.go`, `internal/server/crew_run_store.go`, `internal/server/run_journal_reaper.go`, `internal/traffic/**`, `internal/audit/**`, `docs/PROOF-PACK.md` | — | — | 🔴 unverified (new page, #2875) |
| docs/UPGRADE-AND-ROLLBACK.md | Mechanisms, who can do what, upgrade, checks, rollback, RTO/RPO, supported-release policy | `internal/cmd/backends_upgrade.go`, `internal/cmd/backends_versions.go`, `internal/cmd/upgrade_watchdog.go`, `internal/server/autoupdate.go`, `internal/server/github_upgrade.go`, `internal/server/container_rollback.go`, `internal/server/container_snapshot.go`, `internal/server/backup_server.go`, `internal/cmd/backup_restore.go`, `scripts/deploy-binary.sh`, `scripts/containarium-backup.timer`, `scripts/ci/helm-install-upgrade.sh`, `SECURITY.md` | — | — | 🔴 unverified (new page, #2563; flags and links CI-checked, no drill run) |
| docs/DRILL-RECORD-TEMPLATE.md | Drill record template | `docs/UPGRADE-AND-ROLLBACK.md` | — | — | ✎ |

## Run evidence

Executed (not just `--help`-checked) on a fresh Ubuntu 24.04 box on the
hosted cloud, 2026-10-15, against the released **v0.103.3** binary. The box
was deleted afterwards.

| Command | Result |
|---------|--------|
| `curl -fsSL …/hacks/install-cli.sh \| sudo bash` (README step 2, variant B) | ✅ installed `containarium-linux-amd64`, reported `Installed: Containarium v0.103.3` |
| `containarium version` | ✅ `Containarium v0.103.3` |
| `containarium {passthrough,audit,daemon,doctor} --help` | ✅ each reports it lives in `containariumd` on the host |
| every verb and flag the README uses (`quickstart`, `ssh-config sync`, `code run/install`, `token refresh/generate`, `passthrough-route add`, …) | ✅ present on the released binary |

Sections marked 🟡 above have every flag, link and config key checked but
not every command run.
