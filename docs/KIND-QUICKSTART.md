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

# 3. Install the chart from the repo
cd Containarium
helm install containarium ./charts/containarium-k8s \
  --set daemon.jwtSecret="$(openssl rand -hex 32)" \
  --set storageClass=standard \
  --wait

# 4. Create a box
export CTN_URL="http://localhost:8080"
export CTN_JWT="$(kubectl get secret containarium-containarium-k8s-daemon \
  -o jsonpath='{.data.jwt-secret}' | base64 -d)"

kubectl port-forward svc/containarium-containarium-k8s-daemon 8080:8080 &
./containarium container create myorg/mybox \
  --url "$CTN_URL" --token "$CTN_JWT"

# 5. Verify isolation: no SA token in the box pod
kubectl exec -n tenant-mybox box -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1
# cat: can't open '...token': No such file or directory  ← expected
```

> **SSH access** requires the full agent-box image and sshpiper (installed by
> the chart). Forward port 32022 from the kind node to reach the SSH gateway:
> `ssh -p 32022 mybox@localhost`

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
controller installed, `container create` fails on the Sandbox create.

```sh
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.5.1/manifest.yaml
kubectl -n agent-sandbox-system wait --for=condition=available \
  deployment/agent-sandbox-controller --timeout=180s
```

## 4. Create the gateway namespace

The daemon programs SSH routing via the sshpiper `Pipe` CRD. For a local
quickstart without a real sshpiper deployment, create the namespace so the
daemon doesn't error on Pipe operations:

```sh
kubectl create namespace agent-gateway
```

## 5. Start the daemon

```sh
export KUBECONFIG="$(kind get kubeconfig --name containarium 2>/dev/null || echo ~/.kube/config)"

CONTAINARIUM_RUNTIME=k8s \
CONTAINARIUM_K8S_KUBECONFIG="$KUBECONFIG" \
CONTAINARIUM_K8S_BOX_IMAGE="registry.k8s.io/pause:3.9" \
CONTAINARIUM_K8S_GATEWAY_HOST="localhost" \
./containarium daemon start \
  --skip-infra-init \
  --standalone \
  --jwt-secret dev-secret-min32chars-padding \
  --port 50051 \
  --http-port 8080 \
  --rest
```

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
export CTN_JWT="dev-secret-min32chars-padding"  # same value as --jwt-secret

./containarium container create myorg/mybox \
  --url "$CTN_URL" \
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
CONTAINARIUM_K8S_STORAGE_CLASS="standard" \
./containarium daemon start \
  --skip-infra-init --standalone \
  --jwt-secret dev-secret-min32chars-padding \
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
./containarium container delete myorg/mybox --url "$CTN_URL" --token "$CTN_JWT"

# Destroy the kind cluster.
kind delete cluster --name containarium
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Box runtime: lxc` in logs | env var not set | Check `CONTAINARIUM_RUNTIME=k8s` is exported |
| `failed to select box backend: k8s: build rest config` | Kubeconfig missing | Set `CONTAINARIUM_K8S_KUBECONFIG` |
| Pod stays `Pending` forever | No schedulable node | `kubectl describe pod -n tenant-mybox box` for events |
| `Pipe` errors in daemon log | Gateway namespace missing | `kubectl create namespace agent-gateway` |
| `ensure sandbox: ... no matches for kind "Sandbox"` | agent-sandbox controller/CRD not installed | Step 3: apply the agent-sandbox `manifest.yaml` |
| Pod never appears for a created box | Controller not running | `kubectl get pods -n agent-sandbox-system` |

## CI / automated testing

The k8s-e2e workflow (`.github/workflows/k8s-e2e.yml`) spins a throwaway kind
cluster and runs the reconciler's integration suite against it:

```sh
# Run locally (requires kind + Docker)
bash scripts/k8s-e2e.sh
```

See [K8S-AGENT-BOX-RUNTIME-DESIGN.md](K8S-AGENT-BOX-RUNTIME-DESIGN.md) for
the full architecture reference.
