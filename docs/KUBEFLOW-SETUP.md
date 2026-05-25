# Kind + Kubeflow AI Reference Platform on Containarium

Run the **full Kubeflow AI Reference Platform** (release `26.03`) inside a Containarium container using Kind as the Kubernetes backend. This is the complete platform: Istio + Dex auth, Pipelines, Notebooks, KServe, Katib, Trainer, Model Registry, Spark Operator, Central Dashboard, and supporting services.

## Architecture

```
Incus LXC container (security.nesting=true)
  └── Docker (required by Kind)
      └── Kind cluster (K8s 1.34, 3 nodes: 1 control-plane + 2 workers)
          ├── istio-system (service mesh, auth, ingress)
          ├── kubeflow (Pipelines, Notebooks, KServe, Katib, Trainer, …)
          ├── cert-manager
          ├── auth (Dex OIDC)
          ├── knative-serving (KServe runtime)
          └── user namespaces (per Profile)
```

Three layers of containerization (LXC → Docker → K8s pods) enabled by Incus `security.nesting=true`. Multi-node Kind cluster lets KServe + Knative spread workloads across worker nodes.

## What You Get

The stack installs the full **Kubeflow AI Reference Platform 26.03** from [`kubeflow/manifests`](https://github.com/kubeflow/manifests):

| Component | Version | Resource (idle) |
|-----------|---------|-----------------|
| Kubeflow Pipelines | 2.16.0 | 970m CPU, 3.5GB mem, 35GB PVC |
| KServe (model serving) | 0.16.0 | 600m CPU, 1.2GB mem |
| Model Registry | 0.3.8 | 510m CPU, 2GB mem, 20GB PVC |
| Istio | 1.29.1 | 750m CPU, 2.4GB mem |
| Knative (serving + eventing) | 1.21.x | 1.45 CPU, 1GB mem |
| Katib (HPO) | 0.19.0 | 13m CPU, 476MB mem, 10GB PVC |
| Trainer | 2.2.0 | 8m CPU, 143MB mem |
| Notebook Controller v1 | 1.11.0-rc.1 | 5m CPU, 93MB mem |
| Central Dashboard | 2.0.0-rc.1 | 2m CPU, 159MB mem |
| Dex / OAuth2-Proxy | 2.45 / 7.14.3 | minimal |
| Cert-Manager | 1.19.4 | minimal |
| Spark Operator | 2.5.0 | minimal |
| **Total at idle** | | **~4.4 CPU, ~12GB memory, ~65GB PVC** |

## Prerequisites

- **Memory**: 16GB minimum, 32GB+ recommended (for actual workloads)
- **CPU**: 8+ cores recommended
- **Disk**: 100GB+ (PVCs alone need 65GB)
- **Nested containers**: `--podman` flag required (sets `security.nesting=true`)
- **Peer node**: Only a peer node with sufficient RAM have the RAM; the primary VM is too small

## Quick Start

### 1. Create the container

```bash
containarium create mldev \
  --ssh-key ~/.ssh/id_ed25519.pub \
  --cpu 8 --memory 32GB --disk 150GB \
  --podman \
  --stack kind-kubeflow \
  --backend-id tunnel-<peer-id>-gpu
```

The stack installs Docker CE, clones `kubeflow/manifests` at tag `26.03` to `/opt/kubeflow-manifests`, and writes a `setup-kubeflow` helper script.

> **Note**: We don't pre-install Kind/kubectl/kustomize. The Kubeflow manifests repo ships its own install script (`tests/install_KinD_create_KinD_cluster_install_kustomize.sh`) that pins the right versions. We delegate to it at setup time so version upgrades are just a `git pull` of the manifests repo.

### 2. SSH in and run the installer

```bash
ssh mldev

# Interactive — will prompt for email and password
setup-kubeflow

# Or non-interactive with custom credentials
KUBEFLOW_USER=me@example.com KUBEFLOW_PASSWORD='s3cret!' setup-kubeflow

# Or accept defaults (user@example.com / 12341234) — press Enter at prompts
```

The script:
1. Reads `KUBEFLOW_USER` and `KUBEFLOW_PASSWORD` env vars (or prompts interactively)
2. Generates a bcrypt hash via `passlib` and patches `common/dex/base/dex-passwords.yaml` before install
3. Tunes `fs.inotify.*` for many controllers
4. Installs Kind v0.30.0, kubectl (latest stable), Kustomize v5.8.1 to `~/.local/bin`
5. Creates a 3-node Kind cluster running Kubernetes 1.34
6. Saves kubeconfig to `~/.kube/config`
7. Runs Kubeflow's install loop:
   ```bash
   while ! kustomize build example | kubectl apply --server-side --force-conflicts -f -; do
       sleep 20
   done
   ```
8. Waits for all pods to become ready

Total time: **~20-30 minutes**.

### 3. Access the Central Dashboard

```bash
kubectl port-forward -n istio-system svc/istio-ingressgateway 8080:80 --address 0.0.0.0 &
```

Open `http://<container-ip>:8080/` and log in with the credentials you set. If you accepted defaults:
- **Username**: `user@example.com`
- **Password**: `12341234`

### Changing the Password Later

The stack ships a `kubeflow-set-password` helper:

```bash
# Interactive prompt
kubeflow-set-password

# Or inline
kubeflow-set-password 'new-password'
```

This generates a new bcrypt hash, patches the `dex-passwords` Secret, and restarts Dex. New password works in ~30s.

## Slimming Down

The full platform uses ~12GB at idle. To fit Kubeflow into 4-8GB, edit `/opt/kubeflow-manifests/example/kustomization.yaml` **before** running `setup-kubeflow` and remove components you don't need (e.g. KServe, Spark, Katib).

To remove components after install:
```bash
# Disable KServe if not serving models
kubectl delete ns kserve

# Disable Katib if not tuning hyperparameters
kubectl delete ns katib-system

# Scale down individual deployments
kubectl scale deployment -n kubeflow <name> --replicas=0
```

## GPU Support

Pass GPU at create time and install the NVIDIA device plugin:

```bash
# When creating the container:
containarium create mldev --gpu 0 --stack kind-kubeflow --podman ...

# After setup-kubeflow completes — install NVIDIA device plugin:
kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.17.0/deployments/static/nvidia-device-plugin.yml

# Verify
kubectl describe node | grep nvidia.com/gpu
```

Then request GPUs in Notebooks (via the UI) or Pipelines:
```python
from kfp import dsl

@dsl.component(packages_to_install=['torch'])
def train():
    import torch
    assert torch.cuda.is_available()

@dsl.pipeline(name='gpu-training')
def gpu_pipeline():
    t = train()
    t.set_accelerator_type('nvidia.com/gpu').set_accelerator_limit(1)
```

## Running Your First Notebook

1. Open the Central Dashboard
2. Select/create your **Profile** namespace (top-right)
3. **Notebooks** → **New Notebook**
4. Pick an image (default Jupyter, or TensorFlow/PyTorch pre-built)
5. Set CPU/memory/GPU resources
6. **Launch** → **Connect** once ready

## Running Your First Pipeline

From the dashboard → **Pipelines** → `[Tutorial]` examples → **Create experiment** → **Start run**.

Or via Python SDK:
```python
# pip install kfp==2.16.0
import kfp
from kfp import dsl

@dsl.component
def add(a: int, b: int) -> int:
    return a + b

@dsl.pipeline(name='add-numbers')
def my_pipeline():
    add(a=1, b=2)

client = kfp.Client(host='http://<container-ip>:8080/pipeline')
client.create_run_from_pipeline_func(my_pipeline)
```

## Persistence

The Kind cluster's data lives in `/var/lib/docker/volumes/kind/` inside the container, which sits on ZFS-backed persistent storage. The cluster survives container stop/start.

To back up:
```bash
kind get kubeconfig --name kubeflow > ~/kubeflow-kubeconfig
kubectl get all -A -o yaml > cluster-dump.yaml
```

To wipe and reinstall:
```bash
kind delete cluster --name kubeflow
setup-kubeflow
```

## Upgrading Kubeflow

The manifests are pinned to release `26.03`. Two future releases are planned per year (e.g., `26.10`). To upgrade:

```bash
# On the container
cd /opt/kubeflow-manifests
git fetch --tags
git checkout 26.10  # or whichever release
# Re-run the install loop:
while ! kustomize build example | kubectl apply --server-side --force-conflicts -f -; do sleep 20; done
```

See [Upgrading and Extending](https://github.com/kubeflow/manifests?tab=readme-ov-file#upgrading-and-extending) in the manifests README.

## Troubleshooting

### Install loop never finishes
The first 5-15 iterations always show errors — that's expected (CRDs being created, webhooks warming up). If it's still failing after 20+ iterations:
```bash
cd /opt/kubeflow-manifests
kustomize build example | kubectl apply --server-side --force-conflicts -f - 2>&1 | tail -30
```
Common causes:
- Insufficient memory (`free -h`)
- Webhook pods not ready (`kubectl get pods -A | grep -v Running`)
- Network policies blocking webhook callbacks (rare)

### Pods stuck in `Pending` / `ContainerCreating`
```bash
kubectl describe pod <name> -n <ns>
```
Usually insufficient memory or PVC provisioning. Kind uses `local-path-provisioner` by default — check it's running:
```bash
kubectl get pods -n local-path-storage
```

### Login fails
- Default credentials: `user@example.com` / `12341234`
- If changed, check `common/dex/base/config-map.yaml`
- Reset Dex: `kubectl delete pod -n auth -l app=dex`

### Central Dashboard 404
- Check Istio ingress: `kubectl get pods -n istio-system`
- Port-forward dropped — restart it
- Direct Pipelines access: `kubectl port-forward -n kubeflow svc/ml-pipeline-ui 8888:80`

### inotify watch limit exceeded
The `setup-kubeflow` script bumps this. If you still see errors:
```bash
sudo sysctl -w fs.inotify.max_user_watches=2097152
sudo sysctl -w fs.inotify.max_user_instances=4096
```

### High memory pressure
Full Kubeflow uses ~12GB idle. See [Slimming Down](#slimming-down) above.

## References

- [kubeflow/manifests 26.03 release notes](https://github.com/kubeflow/manifests/releases/tag/26.03)
- [Kubeflow manifests README](https://github.com/kubeflow/manifests)
- [Kubeflow user docs](https://www.kubeflow.org/docs/)
- [Kind docs](https://kind.sigs.k8s.io/)
