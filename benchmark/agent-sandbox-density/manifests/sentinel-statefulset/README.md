# sentinel-statefulset manifests

Raw k8s manifests (not Helm-templated) for the benchmark-only topology
documented in `../../README.md`'s "The experiment group's k8s footprint":
`Service → Deployment (containarium-bench-sentinel) → StatefulSet
(containarium-bench-daemon)`, in front of the same daemon container spec
`charts/containarium-k8s/` produces.

**This does not replace `charts/containarium-k8s/` and is not a proposed
production architecture.** The real chart's daemon is stateless (no PVCs,
all durable state lives in the k8s API/etcd via CRDs) — a StatefulSet buys
it nothing. This exists purely to measure, live, what this specific
topology shape actually costs, since "conceptually intended architecture"
in prose isn't a number. See `scripts/07-provision-containarium-sentinel.sh`
for how these get applied, and `RESULTS.md` for what the measurement found.

## Why these files have no `__PLACEHOLDER__` values

Every other manifest in this benchmark (`../sandbox-template.yaml`) is a
static template with `sed`-substituted placeholders. These can't be: the
daemon's actual container spec (image tag, JWT secret name, gateway env
vars) is entirely Helm-computed and would have to be re-derived by hand
here, which drifts the moment the chart changes. Instead,
`07-provision-containarium-sentinel.sh` `helm install`s the real chart
with `daemon.replicaCount=0` (so nothing double-runs), reads back the
resulting (0-replica but fully-specced) Deployment object with `kubectl
get -o json`, and uses `jq` to reshape that exact `spec.template.spec`
into a StatefulSet — the container spec is guaranteed identical to what
the chart would have run, because it's not re-typed, it's extracted.

Only the sentinel (a stock `nginx:1.27-alpine` reverse proxy — there is no
Containarium-specific "sentinel" component that fronts the daemon's own
API today, see `README.md`) and the headless Service are static files
here, since neither depends on chart-computed values.
