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
- Non-zero with no pack when the commands could not be run at all. Causes include an unreachable box, a missing `--dir`, a box without coreutils `timeout`, or a declaration that cannot be read or does not parse.

## How a step runs

Each step runs as root in the box. It runs from `--dir`, with stdin closed, under `timeout`. The step gets SIGTERM at the limit and SIGKILL 10 s later.

Combined stdout and stderr go to a temporary file in the box, and only the last 256 KiB of it leave the box. Keeping the end of the output keeps the summary and failures of a test run. The pack records:

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

## Digests

- **`log_sha256`** covers the stored log bytes, after truncation. This lets a verifier recompute it from the pack alone. `proofpack.CheckPartDigests` does this and names the first step that does not match.
- **`proofpack.PackDigest`** is the SHA-256 of the pack's deterministic proto encoding. It is the digest `generate` prints. Like the guardrail attestation's policy hash, it is computed over the binary encoding, not the JSON file.

Sealing the pack into the audit chain, and `proof-pack verify`, are #2798.
