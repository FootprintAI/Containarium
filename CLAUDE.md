# Containarium — guidance for Claude / AI assistants

This file is a small set of durable conventions for AI assistants working
on this repository. Keep it short — only rules whose violation we'd
actually want to catch in review.

## CLI-first, MCP wraps it

When adding a new platform action (anything that mutates Containarium
state — create, expose, route, deploy, etc.):

1. Land it as a `containarium <verb>` cobra subcommand under
   `internal/cmd/<verb>.go` first.
2. The MCP tool in `internal/mcp/tools.go` is a **thin wrapper** over the
   same underlying Go function used by the CLI handler. Don't have the
   MCP tool call an HTTP endpoint that the CLI doesn't.

**Why:** The CLI is the canonical interface. Humans, shell scripts, CI,
and demo recordings all consume it; MCP is one specific consumer (AI
agents). Building CLI-first means:

- Anything an agent can do, a human can do via shell — symmetric surface
  with no agent-only escape hatches.
- Demo recordings are reproducible `bash` scripts, not "spin up an
  agent + JWT token" rituals.
- Tests focus on the CLI handler / shared client function; MCP correctness
  follows for free.
- The OSS community gets value from the CLI even without running an agent.

**Anti-pattern:** an MCP tool that talks to an HTTP endpoint with no
matching `containarium <verb>` subcommand. If you spot one, file a
follow-up to add the CLI counterpart.

## API: protobuf contract first, grpc-gateway for REST

The API is defined in `proto/containarium/v1/*.proto` *first*. Everything
else — gRPC server stubs, the HTTP/REST shim, the OpenAPI swagger doc,
the typed client — is **generated** from those protos via `make proto`
(which runs `buf generate`).

When adding a new endpoint:

1. Add the RPC + request/response messages in `.proto`.
2. Annotate the RPC with `(google.api.http)` for the REST verb+path
   mapping and `(grpc.gateway.protoc_gen_openapiv2.options.openapiv2_operation)`
   for the swagger description.
3. `make proto` to regenerate `pkg/pb/`, the `.pb.gw.go` gateway shim,
   and `api/swagger/containarium.swagger.json`.
4. Implement the gRPC method in `internal/server/`.
5. Wire the typed client method in `internal/client/{grpc.go, http.go}`.

**Why:** one contract drives three consumers (gRPC clients, REST/HTTP
clients via grpc-gateway, and the OpenAPI viewer) — they cannot drift
because they all regenerate from the same source. The MCP server
(which speaks REST through grpc-gateway) gets every new endpoint for
free. The CLI adds a thin cobra subcommand that calls the generated
client.

**Anti-pattern:** writing a hand-rolled `net/http` handler under
`internal/gateway/` for a new customer-facing endpoint. A handful of
legacy or internal-only endpoints (e.g. `/healthz`,
`/authorized-keys/sentinel`) live in the gateway directly — those
predate the convention or are infrastructure plumbing not in the
product contract. For anything an external caller, the CLI, or the
MCP server should hit, go through proto.

## Strong typing — use the type system, not strings

A corollary of proto-first: when proto already gives us typed
primitives, use them.

- **Protobuf enums over magic strings.** If a field's value is "must
  be one of X, Y, Z," it's an enum. Define the enum in `.proto`,
  regenerate, and let the Go code use typed constants. Example: an
  `os_type` field that accepts `ubuntu | rocky9 | rhel9` becomes a
  `OSType` enum on the proto and `pb.OSType_*` constants in Go —
  not a `string` parameter with a comment listing the allowed values.

- **Well-defined Go structs over `map[string]interface{}`.** Every
  wire payload deserves a named struct with explicit fields. The only
  legitimate uses of `map[string]interface{}` are at the type-erasing
  boundary — the MCP JSON-RPC tool-arguments shape, generic gRPC
  `google.protobuf.Any` codecs, configuration files with truly unknown
  schemas. Convenience to avoid writing a 5-line struct is not a
  legitimate use.

**Why:** dynamic typing pushes correctness checks to runtime, where
they show up as `expected string, got float64` inside a test (best
case) or in a customer's log (worst case). Static typing pushes them
to the compiler, which catches them before code review. The cost is
the struct definition; the saving is the bug-hunt months later.

**Anti-pattern signs:**
- A string field with a comment listing the allowed values.
- A function that takes `map[string]interface{}` and pulls fields out
  by name with type assertions.
- Tests that assert on `result["foo"].(string)` instead of `result.Foo`.

When you spot one on the way past, fix it. The cost is small; the debt
compounds.

## Two MCP servers, distinct surfaces

- `cmd/mcp-server/` — **platform** MCP. Outside-the-box admin
  operations: create container, list containers, expose port, etc.
  Talks to the platform's REST/gRPC API.
- `cmd/agent-box/` — **in-the-box** MCP. Linux-native operations
  (shell, files) running *inside* a single Containarium box. Reached
  over stdio, typically wrapped by SSH on the client side.

Don't mix them. Tools that operate on a single box's filesystem belong
in `agent-box`; tools that operate across boxes belong in the platform
MCP.
