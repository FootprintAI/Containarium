# Structured host posture reports

`ReportHostStatusRequest.posture` (field 13, `HostSecurityPosture`) carries
one host hardening measurement. It is additive to the existing actuation
contract; fields 1–12 and the status endpoint are unchanged.

- `checks`: named `HostCapabilityCheck` results with `name`, `ok` and `detail`.
  Names are the original posture probe names, without the legacy `posture: `
  prefix. `ok=false` includes an unknown/unmeasurable check; `detail` retains
  the probe's explanation.
- `measured_at`: host-clock timestamp at the start of the posture probe, not
  at serialization or transmission. A slow probe does not freshen old evidence.

The daemon uses the same `hostcheck.RunPosture()` invocation for the new field
and the legacy `checks` list on every capability report. Legacy posture names,
order, details and pass/fail values remain unchanged. `self_check_ok` still
comes only from required capability checks; posture and readiness remain
advisory. This change adds evidence, not a placement/enrollment policy.

## Receiver semantics and rollout

A non-nil posture with measured named checks is different from an absent
posture. Absence means **not reported**, never a passing posture. Old senders
and platforms without a posture probe omit the field. An empty check list or
missing timestamp is not evidence of a fresh passing measurement either.
Consumers must verify that their required checks are present and passing and
that the host-clock measurement is fresh under their clock-skew policy.

Driver-token refresh uses the same RPC but intentionally sends only
`driver_token`; it does not run a capability probe. An absent posture on such
an update must not erase a receiver's last stored measurement or freshen it.
Freshness continues to be assessed from that measurement's timestamp.

The vendored actuation contract originates in the cloud repository. Sync this
additive message and field number to that repository before consuming/storing
the structured field there. Older protobuf receivers safely ignore field 13;
the default grpc-gateway JSON decoder also discards unknown fields. Custom
JSON receivers configured to reject unknown fields must be updated or enable
unknown-field discarding before new hosts report to them. The daemon does not
silently strip posture or retry an unauthenticated/failed report.

## Validation boundaries

Regression tests cover passing, failing, mixed and absent measurements,
unchanged legacy behavior, real-probe snapshot consistency, successive gRPC
reports, JSON payload preservation, and old-schema protobuf/default-gateway
receivers. An old sender also decodes with posture absent on the new schema.
These tests require no cloud account or production credentials. They do not
verify a deployed private cloud receiver, its persistence, or placement policy.
