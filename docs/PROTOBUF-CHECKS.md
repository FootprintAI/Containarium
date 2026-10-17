# Protobuf checks

`scripts/buf-version.env` is the shared Buf CLI version and checksum pin.
Local Makefile commands, release/proto CI, and the offline bundle use it.
Update that file deliberately when upgrading Buf; do not install `@latest`
in CI. The remote code-generation plugins have separate pins in
`buf.gen.yaml`.

## Local use

Install the pinned, checksum-verified binary (Linux/macOS, amd64/arm64):

```bash
./scripts/install-buf.sh ./bin/buf
export BUF="$PWD/bin/buf"
make proto-lint
make proto-breaking
make proto
./scripts/test-proto-gates.sh
```

If `buf` is already on PATH at the pinned version, `BUF` is optional.
The Makefile refuses a missing or mismatched version before generation,
lint, or breaking checks. This prevents older tools from rejecting the
`STANDARD` category in the v2 configuration.

`make proto-breaking` compares against the local `main` by default.
To check another base, pass Buf's input through `PROTO_AGAINST`:

```bash
PROTO_AGAINST='.git#ref=<base-commit>' make proto-breaking
```

The base must be available locally. CI checks out full history and compares
the PR against its target branch's base commit, including fork PRs.

## CI and legacy contracts

`.github/workflows/proto.yml` runs lint and the gate regression tests on
every PR and push to `main`; PRs also run the `FILE` breaking rules against
their base. A lint or compatibility failure fails the job.

`scripts/test-proto-gates.sh` checks that the repository passes lint, a
mismatched CLI is refused, a non-PascalCase message fails lint, an unchanged
schema passes breaking, and deleting a field fails breaking. Mutations run
in a temporary copy, leaving the checkout intact.

Keep `STANDARD` enabled. Existing published RPC type names, shared response
types, and `ACCESS_TYPE_SSH = 0` use rule- and file-scoped `lint.ignore_only`
entries in `buf.yaml` for compatibility reasons (in-source `buf:lint:ignore`
comments are not used: they leak into the generated swagger and Go docs). A
waiver applies to the listed file, not to one declaration. These waivers
preserve existing SDK interfaces and enum JSON names. New declarations still
have to satisfy the rules; do not add entries for new RPCs or blanket
exclusions to make a new API pass.

The root workspace checks the project's `proto` module. Vendored upstream
definitions under `third_party/proto` are a separate generation-only
module, whose lint/breaking policy belongs to their upstream.
