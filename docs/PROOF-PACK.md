# Proof Pack

A Proof Pack shows that a repository's test commands were run. It records what each command returned and printed. The platform runs the commands in a box and builds the pack itself; nothing in it comes from the coding agent. The coding agent's `tests_run: true` is still only the agent's claim. A pack records what actually happened.

This page covers the pack format and how it is generated (#2797, slice 1 of #2366). Later slices build on it:

- #2798 seals the pack into the audit hash chain and attaches it to the PR.
- #2799 makes a box other than the coder's produce the pack.

The message is `ProofPack` in [`proto/containarium/v1/proof_pack.proto`](../proto/containarium/v1/proof_pack.proto). The code is in `internal/proofpack`.

## Declaring the commands

A repository declares its test commands under the `test:` key of `.github/containarium.yml`. The value is either one command:

```yaml
test: make check
```

or a list of named steps:

```yaml
test:
  - name: unit
    kind: unit
    run: go test ./...
  - name: lint
    kind: static_analysis
    run: golangci-lint run
  - name: deps
    kind: security_scan
    run: govulncheck ./...
```

Rules for the list form:

- `kind` is one of `unit`, `integration`, `e2e`, `static_analysis`, `security_scan` or `test`. It defaults to `test`.
- `name` must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` and be unique within the list.
- A step has only these three fields.
- A list may hold at most 32 steps.
- The file may be at most 64 KiB.
- Other top-level keys in the file are ignored.

A one-command declaration becomes a single step named `test` with kind `test`.

When there is no `test:` key, the pack falls back:

| The repository has | What runs | `command_source` |
|---|---|---|
| a `test:` key | the declared steps, in order | `DECLARED` |
| no `test:` key, but a `Makefile` at its root | `make test`, as step `make-test` | `FALLBACK_MAKE_TEST` |
| neither | nothing; the status is `NO_COMMANDS` | `NONE` |

A declaration that cannot be read or parsed is an error, and no pack is produced. That includes a `test:` key with no value, and anything at that path that is not a readable file, such as a dangling symlink or a directory. It never falls back to `make test`; the fallback applies only when the key is absent.

## Generating a pack

`proof-pack generate` is a server-side command: it ships in `containariumd` and not in the client binary. It runs on the host that owns the box and reaches the box through the local Incus backend, the same backend the daemon uses:

```bash
containariumd proof-pack generate <tenant>-container --dir /workspace --out pack.json
```

- `--dir` is the repository directory inside the box. The default is `/workspace`, where a box's git source is checked out.
- `--step-timeout` limits each step. The default is `10m`.
- `--out` is where the pack JSON is written. It defaults to stdout, and the file is created with mode 0600.

stderr gets a one-line summary with the pack's SHA-256.

Exit status:

- `0` when the pack's status is `PASSED`.
- `1` when the status is `FAILED` or `NO_COMMANDS`. The pack is written either way.
- Non-zero with no pack when the commands could not be run at all. Causes include an unreachable box, a missing `--dir`, a box without coreutils `timeout` when at least one step has to run (a repository with nothing to run still yields a `NO_COMMANDS` pack), or a declaration that cannot be read or does not parse.

## How a step runs

Each step runs as root in the box. It runs from `--dir`, with stdin closed, under `timeout`. The step gets SIGTERM at the limit and SIGKILL 10 s later.

Combined stdout and stderr go to a temporary file in the box that is unlinked before the step starts, so a step that deletes files cannot lose its own outcome, and only the last 256 KiB of it leave the box. Keeping the end of the output keeps the summary and failures of a test run. The pack records:

| Field | Meaning |
|---|---|
| `name`, `kind` | the declared name and kind; never the command line |
| `exit_code` | the step's exit status |
| `timed_out` | the step hit the limit: exit 124 or 137, and the wall clock reached the limit |
| `duration_ms` | wall time of the exec, measured by the host |
| `log` | the last 256 KiB of combined output, as bytes |
| `log_sha256` | SHA-256 (lowercase hex) of `log` as stored |
| `log_truncated`, `log_original_bytes` | whether output was cut, and its full size |

Pack-level fields:

| Field | Meaning |
|---|---|
| `producer` | the box the commands ran in |
| `repo_dir` | the directory they ran from |
| `git_commit` | `HEAD` of `repo_dir`, or empty when it is not a git checkout |
| `declaration_sha256` | SHA-256 of the `.github/containarium.yml` that was read |
| `counts` | steps passed and failed per kind |
| `status` | the overall outcome, described below |
| `started_at`, `finished_at` | when generation started and finished |
| `log_limit_bytes`, `step_timeout_seconds` | the bounds the steps ran under |

`status` is set as follows:

- `PASSED`: every step exited 0 within its limit.
- `FAILED`: at least one step did not.
- `NO_COMMANDS`: nothing ran.

Counts are of steps by exit status. The pack does not parse any test framework's output, so it does not count individual test cases.

## What a pack does not record

The pack has no field for a step's command line or for the environment. Generation forwards none of the host's environment into the box: a step sees the box's default exec environment. A step is identified only by the name the repository declared for it.

A command's own output can still echo what it runs. `make`, for example, prints each recipe line. That text is log content and is kept as printed. A repository whose test output prints secrets should fix that output; the pack will not redact it.

## Who produces the pack in a crew

In a crew, the pack comes from a member whose role is `pack_producer`, never from the coder (#2799). Roles are declared per member in `crews.yaml`:

```yaml
- id: engineer-crew
  topology: pipeline
  skill_ids: [issue-implementer, diff-reviewer, test-runner]
  roles: [coder, reviewer, pack_producer]
```

`RunCrew` rejects a crew whose `pack_producer` is the same skill as its `coder`, or would run in the same box. It also rejects a producer that is not the last member of a `pipeline` crew, and a producer with no coder.

The producer is not an agent and is sent no A2A task. Its run goes like this:

1. Its box is provisioned with the run's git checkout. It gets no platform token and no model gateway token.
2. The pipeline's last agent (the reviewer) returns the final files.
3. The daemon writes the whole content of each file into the producer's checkout. If any path is outside the checkout, no file is written.
4. The daemon runs the repository's test commands in the producer's box, as `proof-pack generate` does.

The run result carries the outcome as `CrewRun.proof_pack`:

| Field | Meaning |
|---|---|
| `status` | the pack's status; unset when no pack was produced |
| `producer_box`, `coder_box` | where the commands ran, and the coder's box; never equal |
| `pack_sha256` | `proofpack.PackDigest` of the pack |
| `git_commit` | the commit the final files were written onto |
| `applied_files` | the files written before the commands ran |
| `error` | why no pack was produced |

A failed or missing pack does not fail the crew run. The pack's `status` is what should gate opening a pull request; the coder's `tests_run` should not. The pull request is opened by the managed control plane, outside this repository.

## Digests

- **`log_sha256`** covers the stored log bytes, after truncation. This lets a verifier recompute it from the pack alone. `proofpack.CheckPartDigests` does this and names the first step that does not match.
- **`proofpack.PackDigest`** is the SHA-256 of the pack's deterministic proto encoding. It is the digest `generate` prints. Like the guardrail attestation's policy hash, it is computed over the binary encoding, not the JSON file.

## Sealing

Sealing (#2798) writes the pack's digests into the audit hash chain as one ordinary `audit_logs` row. It goes through the same append path as every other audit row, so the chain's own row hash covers it. No new hashing scheme is involved. The row has:

- action `proof_pack.seal`, resource type `proof_pack`, and resource id the pack digest;
- the username and run id the pack was sealed for;
- as its detail, a `ProofPackSeal` (JSON) holding:
  - `pack_sha256`: `PackDigest` of the whole pack;
  - `header_sha256`: `PackDigest` of the pack with its steps removed, so it covers every field that is not a step;
  - `parts`: for each step, its name and the SHA-256 of its deterministic proto encoding.

`proofpack.Seal` writes the row and returns a `SealedProofPack`: the pack plus its seal, which also carries `audit_row_id`, the id of that row. That is the file attached to the PR. A pack whose stored log digests are already wrong is refused, not sealed.

## Attaching it to the PR

When a tracker-dispatched run submits its change (`SubmitTrackerChange`, see [the tracker broker design](architecture/agent-tracker-broker.md)), the daemon does the following before anything is pushed:

1. It generates the pack in the run's box, from the run's workspace.
2. It checks that the pack ran at the commit being submitted.
3. It seals the pack.

The pushed branch then gets one more commit on top of the agent's commits. That commit adds the sealed pack as `.containarium/proof-pack.json`. A file the agent put at that path is replaced. The PR description carries the pack digest (`sha256:…`), its status, its step count and the seal's audit row.

The change is not opened without its pack. If the pack cannot be generated, the workspace moved while it ran, or the daemon has no audit store to seal into, the submit fails and nothing is pushed. A pack whose status is `FAILED` or `NO_COMMANDS` is still attached: the pack is the evidence, not a gate.

The pack is generated while the submit call is in progress, so the submit takes as long as the repository's tests, up to the default step timeout of 10 minutes per step. For now the pack is produced in the run's own box; #2799 moves it to a box other than the coder's.

## Verifying a sealed pack

```bash
containarium proof-pack verify proof-pack.json
```

Like `audit verify`, this is a server-side command that reads the audit chain straight from Postgres, configured the same way. It checks, in order:

1. each step's `log_sha256` against its log;
2. that `audit_row_id` is this pack's seal row (action, resource type and pack digest);
3. the hash chain from that row to the tip, as `audit verify` does;
4. each step's digest and the header digest against the seal **in the chain row**, not the copy in the file.

The first part that does not match is named, for example `step 1 ("lint"): digest ... does not match sealed ...`, or `pack header: ...` for a field that is not a step. A step that was dropped or added is named too. Exit status is 0 when everything matches and non-zero otherwise.

The chain walk proves the chain is internally consistent. To rule out someone with database write access rewriting the chain and recomputing every hash after the edit, also run `audit verify-anchor`.

### Verifying from another machine

```bash
containarium proof-pack verify proof-pack.json --server <daemon-address>
```

With `--server` on the command line, the pack is sent to the daemon's `VerifyProofPack` API (`POST /v1/proof-packs/verify` over REST) and no Postgres is read, so it works from any machine. The caller needs the `audit:read` scope. The daemon runs the same check as above. A pack that does not verify exits non-zero, naming the first differing step or the header, and a seal row purged by retention is reported as its own state. The pack is bounded at 32 steps and 4 MiB. Only `--server` itself switches modes: a server address that comes from the environment or config does not, so scripts that run the local command keep running it.

A daemon's "ok" is weaker than verifying offline: you are trusting the daemon that holds the chain. On success the daemon returns the chain tip id and its row hash; compare that hash with the external anchor. This version does not return the anchor reference itself.

### After a retention purge

The audit log is one chain, and retention in enforce mode purges its oldest rows as a prefix ([data flow and retention](security/DATA-FLOW-AND-RETENTION.md)). A seal row is an ordinary row of the gateway-logs class (90 days by default). The 365-day evidence-bundles window does not apply to it.

- **Rows below the seal row purged:** the pack still verifies. The chain walk starts from the stored chain base, as `audit verify` does.
- **The seal row itself purged:** this happens once the row is past the gateway-logs window, below the latest anchor, and not kept by a legal hold or by an unexpired row ahead of it. From then on the pack cannot be checked against the chain, and `verify` says the seal row was purged by retention. That is a different message from a seal row that is missing without a purge, which is reported as tampering.
