# KIND Quickstart — K8s Agent-Box Backend

Run a Containarium daemon against a local [kind](https://kind.sigs.k8s.io/)
cluster. No cloud account required. The daemon creates per-tenant pods instead
of LXC containers; everything else (CLI, MCP server, proto API) is identical.

**Time to first agent box: ~5 minutes.**

## Prerequisites

| Tool | Install |
|---|---|
| Docker | https://docs.docker.com/get-docker/ |
| kind | `brew install kind` / https://kind.sigs.k8s.io/docs/user/quick-start/ |
| kubectl | `brew install kubectl` |
| Helm 3 | `brew install helm` / https://helm.sh/docs/intro/install/ |
| Go 1.23+ (binary path only) | https://go.dev/dl/ |

---

## Helm quickstart (recommended)

If you already have a kind cluster, the Helm chart installs everything in
one command.

```sh
# 1. Create the cluster
kind create cluster --name containarium

# 2. Install the agent-sandbox controller (kubernetes-sigs/agent-sandbox).
#    The daemon declares one Sandbox CR per box; the controller owns the
#    pod + headless Service under it. Note: the v0.5.1 release asset is
#    manifest.yaml (upstream's README still references
#    sandbox-with-extensions.yaml, which 404s).
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.5.1/manifest.yaml
kubectl -n agent-sandbox-system wait --for=condition=available \
  deployment/agent-sandbox-controller --timeout=180s

# 3. Generate sshpiper's TWO keypairs and their Secrets — both are required
#    before installing the chart, for different reasons:
#    - server key: sshpiper's identity to CLIENTS. The chart never creates
#      this Secret for you; skip it and the sshpiper pod sits in
#      ContainerCreating forever on a FailedMount event for
#      "sshpiper-server-key" — no daemon error, no helm install failure,
#      just a silently stuck pod. Easy to miss.
#    - upstream key: sshpiper's identity to each BOX (sshpiper -> box hop).
#      REQUIRED or the daemon refuses to start (#1496) — with no upstream
#      credential, sshpiper falls back to password auth, which every box
#      refuses, so every gateway connection would fail silently otherwise.
kubectl create namespace agent-gateway
ssh-keygen -t ed25519 -N '' -f ./sshpiper_server -C sshpiper-server
kubectl -n agent-gateway create secret generic sshpiper-server-key \
  --from-file=server_key=./sshpiper_server
ssh-keygen -t ed25519 -N '' -f ./sshpiper_upstream -C sshpiper-upstream
kubectl -n agent-gateway create secret generic sshpiper-upstream-key \
  --from-file=ssh-privatekey=./sshpiper_upstream

# 4. Install the chart from the repo
cd Containarium
go build -o containarium ./cmd/containarium   # needed for the CLI calls below
helm install containarium ./charts/containarium-k8s \
  --set daemon.jwtSecret="$(openssl rand -hex 32)" \
  --set storageClass=standard \
  --set gateway.upstreamKeySecret=sshpiper-upstream-key \
  --set-file gateway.upstreamPublicKey=./sshpiper_upstream.pub \
  --wait

# 5. Create a box
export CTN_URL="http://localhost:8080"
JWT_SECRET="$(kubectl get secret containarium-containarium-k8s-daemon \
  -o jsonpath='{.data.jwt-secret}' | base64 -d)"

# The API expects a signed JWT, not the raw daemon secret — mint one with
# `token generate` (it must be signed with the SAME secret the daemon holds).
export CTN_JWT="$(./containarium token generate --username admin --roles admin \
  --secret "$JWT_SECRET" --raw)"

kubectl port-forward svc/containarium-containarium-k8s-daemon 8080:8080 &
./containarium create mybox \
  --server "$CTN_URL" --http --token "$CTN_JWT"

# 6. Verify isolation: no SA token in the box pod
kubectl exec -n tenant-mybox box -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1
# cat: can't open '...token': No such file or directory  ← expected
```

> **SSH access** requires the full agent-box image and sshpiper (installed by
> the chart). The chart exposes the gateway as a real `NodePort` (32022 by
> default) — kind maps that straight through to the host, so
> `ssh -p 32022 mybox@localhost` reaches sshpiper directly, no
> `kubectl port-forward` involved. Keep it that way if you set
> `runtimeClass: runsc` (below): `kubectl port-forward`/`kubectl exec`
> straight to a gVisor-scheduled box pod does not work (a gVisor
> characteristic, not a Containarium bug — see #1489), but the NodePort →
> sshpiper → box path is real pod networking the whole way and is unaffected
> — **as long as the upstream keypair from step 3 is actually configured**;
> without it, the connection fails at auth before gVisor ever matters (#1496).

---

## 1. Create the cluster

```sh
kind create cluster --name containarium
```

kind's default CNI (kindnet) does **not** enforce NetworkPolicy. For the
isolation demo (egress deny-by-default) install Calico instead:

```sh
# Optional: NetworkPolicy-enforcing cluster
cat <<'EOF' > /tmp/kind-calico.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
EOF
kind create cluster --name containarium --config /tmp/kind-calico.yaml
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n kube-system --timeout=120s
```

## 2. Build containarium

```sh
git clone https://github.com/FootprintAI/Containarium.git
cd Containarium
go build -o containarium ./cmd/containarium
```

## 3. Install the agent-sandbox controller

The daemon's K8s backend declares one `Sandbox` CR (agents.x-k8s.io/v1beta1)
per box; the [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
controller creates the pod and headless Service under it. Without the CRD +
controller installed, `create` fails on the Sandbox create.

```sh
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.5.1/manifest.yaml
kubectl -n agent-sandbox-system wait --for=condition=available \
  deployment/agent-sandbox-controller --timeout=180s
```

## 4. Set up SSH gateway routing (namespace + Pipe CRD)

The daemon programs SSH routing via the sshpiper `Pipe` CRD, and this is **on
by default** — `CONTAINARIUM_K8S_GATEWAY_NAMESPACE` defaults to
`agent-gateway`, not something you opt into. `create` fails hard with
`the server could not find the requested resource` if the `Pipe` CRD isn't
installed, even once the `agent-gateway` namespace exists — the namespace
alone is not enough.

For a local quickstart without a full sshpiper deployment, create the
namespace and apply the minimal `Pipe` CRD this repo ships for exactly this
purpose:

```sh
kubectl create namespace agent-gateway
kubectl apply -f deploy/k8s/sshpiper/10-pipe-crd.yaml

# The daemon also refuses to start with gateway routing enabled and no
# upstream keypair configured (#1496) — even with no sshpiper actually
# running yet, so generate one now and pass it to step 5 below:
ssh-keygen -t ed25519 -N '' -f ./sshpiper_upstream -C sshpiper-upstream
kubectl -n agent-gateway create secret generic sshpiper-upstream-key \
  --from-file=ssh-privatekey=./sshpiper_upstream
```

This lets the daemon program `Pipe` objects (so `create` succeeds) without
requiring a running sshpiper deployment — nothing is watching the Pipe yet,
so the Secret above isn't actually authenticating anything until you stand
up sshpiper for real. See
[`deploy/k8s/sshpiper/README.md`](../deploy/k8s/sshpiper/README.md) to turn
this into an actual SSH-reachable gateway.

> The Helm quickstart above doesn't need this step: the chart's
> `charts/containarium-k8s/crds/` directory (including `pipe.yaml`) is
> auto-installed by `helm install`, and `templates/namespace.yaml` creates
> `agent-gateway` too.
>
> Alternative: if you don't need gateway routing for this quickstart at all,
> set `CONTAINARIUM_K8S_GATEWAY_NAMESPACE=""` on the daemon (step 5) instead
> of creating the namespace/CRD/keypair above — `create` then skips the Pipe
> step entirely, and the daemon no longer requires an upstream keypair
> either (#1496 only fires when gateway routing is enabled). **Don't do
> this if boxes run under a gVisor `RuntimeClass`**
> (`CONTAINARIUM_K8S_RUNTIME_CLASS=runsc` / chart `runtimeClass: runsc`):
> without the gateway, the only way left to reach the box is
> `kubectl port-forward`/`kubectl exec` straight to its pod, and that
> doesn't work under gVisor (#1489) — the gateway is then your only working
> access path, so it needs the upstream keypair configured for real (see
> [`deploy/k8s/sshpiper/README.md`](../deploy/k8s/sshpiper/README.md)).

## 5. Start the daemon

```sh
export KUBECONFIG="$(kind get kubeconfig --name containarium 2>/dev/null || echo ~/.kube/config)"

# JWT secret must be >= 32 bytes (auth.MinSecretKeyLen) — the daemon refuses
# to start REST auth on anything shorter. The literal below is 33 bytes;
# for anything beyond a throwaway local cluster, generate one instead:
#   JWT_SECRET="$(openssl rand -base64 32)"
export JWT_SECRET="dev-secret-at-least-32-bytes-long"

CONTAINARIUM_RUNTIME=k8s \
CONTAINARIUM_K8S_KUBECONFIG="$KUBECONFIG" \
CONTAINARIUM_K8S_BOX_IMAGE="registry.k8s.io/pause:3.9" \
CONTAINARIUM_K8S_GATEWAY_HOST="localhost" \
CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET="sshpiper-upstream-key" \
CONTAINARIUM_K8S_GATEWAY_UPSTREAM_PUBLIC_KEY="$(cat ./sshpiper_upstream.pub)" \
./containarium daemon \
  --skip-infra-init \
  --standalone \
  --jwt-secret "$JWT_SECRET" \
  --port 50051 \
  --http-port 8080 \
  --rest
```

> `daemon` has no `start` subcommand — the daemon runs directly under
> `containarium daemon` (foreground; Ctrl+C to stop).
>
> The two `GATEWAY_UPSTREAM_*` vars are only required when gateway routing
> is enabled (the default — step 4); using the "skip gateway routing"
> alternative above drops both.

> `registry.k8s.io/pause:3.9` is a minimal placeholder image that satisfies the
> StatefulSet — it boots instantly and verifies object creation without needing
> the real agent-box image. Replace with
> `ghcr.io/footprintai/containarium-agent-box:latest` once you are ready for a
> real SSH session.

The daemon logs `Box runtime: k8s` on startup.

## 6. Create a box

In a second terminal:

```sh
export CTN_URL="http://localhost:8080"
export JWT_SECRET="dev-secret-at-least-32-bytes-long"  # same value as --jwt-secret in step 5

# The API expects a signed JWT, not the raw secret — `export CTN_JWT="$JWT_SECRET"`
# and passing that as --token no longer works. Mint a real token instead:
export CTN_JWT="$(./containarium token generate --username admin --roles admin \
  --secret "$JWT_SECRET" --raw)"

./containarium create mybox \
  --server "$CTN_URL" \
  --http \
  --token "$CTN_JWT"
```

Verify the pod is scheduled:

```sh
kubectl get pods -n tenant-mybox
# NAME   READY   STATUS    RESTARTS   AGE
# box    1/1     Running   0          10s
```

And the per-tenant objects (the Sandbox is the daemon's object; the pod and
Service under it are the agent-sandbox controller's):

```sh
kubectl get ns,sandbox,netpol -l containarium.dev/tenant=mybox
kubectl get pods,svc -n tenant-mybox
```

## 7. Persistent storage (optional)

kind ships a `standard` StorageClass backed by the local-path provisioner.
Pass `CONTAINARIUM_K8S_STORAGE_CLASS=standard` to enable PVC-per-box:

```sh
CONTAINARIUM_RUNTIME=k8s \
CONTAINARIUM_K8S_KUBECONFIG="$KUBECONFIG" \
CONTAINARIUM_K8S_BOX_IMAGE="registry.k8s.io/pause:3.9" \
CONTAINARIUM_K8S_GATEWAY_HOST="localhost" \
CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET="sshpiper-upstream-key" \
CONTAINARIUM_K8S_GATEWAY_UPSTREAM_PUBLIC_KEY="$(cat ./sshpiper_upstream.pub)" \
CONTAINARIUM_K8S_STORAGE_CLASS="standard" \
./containarium daemon \
  --skip-infra-init --standalone \
  --jwt-secret "$JWT_SECRET" \
  --port 50051 --http-port 8080 --rest
```

After creating a box, inspect the PVC:

```sh
kubectl get pvc -n tenant-mybox
# NAME   STATUS   VOLUME   CAPACITY   ACCESS MODES   STORAGECLASS   AGE
# data   Pending  …        …          RWO            standard       5s
```

The PVC stays Pending until a pod with `AutoStart=true` schedules (the
local-path provisioner binds on pod assignment, not on PVC creation).

## 8. Verify isolation

```sh
# No service-account token is mounted in the box pod.
kubectl exec -n tenant-mybox box -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1
# cat: can't open '/var/run/secrets/kubernetes.io/serviceaccount/token': No such file or directory

# Default-deny NetworkPolicy is in place.
kubectl get netpol -n tenant-mybox
# NAME           POD-SELECTOR   AGE
# default-deny   …              …
```

## 9. Teardown

```sh
# Delete the box (retains PVC when StorageClass is set).
./containarium delete mybox --server "$CTN_URL" --http --token "$CTN_JWT"

# Destroy the kind cluster.
kind delete cluster --name containarium
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Box runtime: lxc` in logs | env var not set | Check `CONTAINARIUM_RUNTIME=k8s` is exported |
| `failed to select box backend: k8s: build rest config` | Kubeconfig missing | Set `CONTAINARIUM_K8S_KUBECONFIG` |
| Pod stays `Pending` forever | No schedulable node | `kubectl describe pod -n tenant-mybox box` for events |
| `ensure gateway pipe: ... namespaces "agent-gateway" not found` | Gateway namespace missing | `kubectl create namespace agent-gateway` (step 4) |
| `ensure gateway pipe: ... the server could not find the requested resource` | `Pipe` CRD not installed (namespace existing is not enough) | `kubectl apply -f deploy/k8s/sshpiper/10-pipe-crd.yaml` (step 4) |
| `ensure sandbox: ... no matches for kind "Sandbox"` | agent-sandbox controller/CRD not installed | Step 3: apply the agent-sandbox `manifest.yaml` |
| Pod never appears for a created box | Controller not running | `kubectl get pods -n agent-sandbox-system` |
| `k8s config: ... gateway routing enabled ... upstream credential ...` at daemon startup | Gateway routing on (default) with no upstream keypair configured (#1496) | Generate one and set `CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET`/`_PUBLIC_KEY` (step 4), or clear `CONTAINARIUM_K8S_GATEWAY_NAMESPACE` to disable gateway routing |
| SSH through the gateway always fails `Permission denied (publickey)` even with the right key | Same #1496 root cause, but caught at connection time instead of daemon startup — usually means the upstream keypair Secret exists but wasn't actually wired to the daemon's env | Confirm `CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET`/`_PUBLIC_KEY` are set on the *running* daemon, not just created as a Secret |
| sshpiper pod stuck `ContainerCreating` forever, `kubectl describe` shows `FailedMount ... secret "sshpiper-server-key" not found` | The chart's sshpiper Deployment mounts `gateway.sshpiper.serverKeySecret` (default `sshpiper-server-key`) but never creates it — no daemon error, no `helm install` failure, just a silently stuck pod | Create it before `helm install` (step 3): `ssh-keygen -t ed25519 -N '' -f ./sshpiper_server -C sshpiper-server` then `kubectl -n agent-gateway create secret generic sshpiper-server-key --from-file=server_key=./sshpiper_server` |
| `create` succeeds but the box still runs the OLD `--image` after a fix | A prior partial `create` (e.g. failed at the Pipe step) already created the Sandbox; re-running `create` treats an existing Sandbox as success and does **not** update its spec (image included) | Delete first, then re-create: `./containarium delete mybox --server "$CTN_URL" --http --token "$CTN_JWT"`, or pass `--force` to `create` to delete+recreate in one step |

## CI / automated testing

The k8s-e2e workflow (`.github/workflows/k8s-e2e.yml`) spins a throwaway kind
cluster and runs the reconciler's integration suite against it:

```sh
# Run locally (requires kind + Docker)
bash scripts/k8s-e2e.sh
```

See [K8S-AGENT-BOX-RUNTIME-DESIGN.md](K8S-AGENT-BOX-RUNTIME-DESIGN.md) for
the full architecture reference.
