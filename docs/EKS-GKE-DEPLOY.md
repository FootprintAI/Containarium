# Running agent boxes on managed Kubernetes (EKS / GKE)

This guide runs the whole agent-box stack — SSH-reachable, MCP-native boxes —
on a **managed Kubernetes cluster** (Amazon EKS or Google GKE), fronted by a
**cloud LoadBalancer**. No sentinel, no bare-metal, no LXC.

The point is leverage: the cloud's managed control plane, node autoscaling, and
disk provisioning are shared infrastructure you don't operate. Containarium is
the thin layer on top that the cloud doesn't give you — credential-scoped
SSH/MCP access, the gateway key choreography, per-tenant isolation, and box
lifecycle (start / stop / suspend / TTL).

## Prerequisites

Common:

- A managed cluster: **EKS** (any supported version) or **GKE** (Standard or
  Autopilot).
- [Helm](https://helm.sh/) 3.x and `kubectl` pointed at the cluster.
- OpenSSH (`ssh-keygen`) and OpenSSL available on your workstation for creating
  the gateway keys and JWT secret.
- The [Containarium CLI](https://github.com/FootprintAI/Containarium/releases)
  installed if you plan to create boxes with `containarium create`; it is not
  needed when using the operator path in [Declarative boxes](#declarative-boxes-the-box-crd).
- The **agent-sandbox controller** installed
  ([install guide](https://agent-sandbox.sigs.k8s.io/docs/getting_started/)).
- An SSH host key for the gateway (created below).

EKS-only:

- The [AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/)
  — it turns the Service annotations into a real NLB.
- The [EBS CSI driver](https://github.com/kubernetes-sigs/aws-ebs-csi-driver)
  and a `gp3` StorageClass. EKS doesn't ship one by default; apply:

  ```yaml
  apiVersion: storage.k8s.io/v1
  kind: StorageClass
  metadata:
    name: gp3
  provisioner: ebs.csi.aws.com
  volumeBindingMode: WaitForFirstConsumer
  parameters:
    type: gp3
  ```

GKE-only:

- Nothing extra — the L4 LoadBalancer and the `standard-rwo` StorageClass are
  built in.

## Prepare the gateway upstream key

Gateway routing is enabled by default and requires a dedicated upstream key.
Create the key pair and store its private key in the gateway namespace before
running any chart install command. The chart renders this namespace by
default, and Helm will not adopt a hand-made one, so every install command
below passes `--set gateway.createNamespace=false`. Do not flip an existing
release from `true` to `false`: Helm would delete the namespace, and its
Secrets, on upgrade.

```bash
kubectl create namespace agent-gateway
ssh-keygen -t ed25519 -N '' -f ./sshpiper_upstream -C sshpiper-upstream
kubectl -n agent-gateway create secret generic sshpiper-upstream-key \
  --from-file=ssh-privatekey=./sshpiper_upstream
```

`ssh-keygen` also creates `./sshpiper_upstream.pub`; the install examples use
that matching public key. Keep the private key file secure.

## Prepare the gateway host-key Secret

The gateway namespace was created in the upstream-key setup above. The gateway
presents a stable SSH host key so clients can pin it; generate one and store it
in that namespace before installing the chart:

```bash
ssh-keygen -t ed25519 -f gateway_host_key -N ""
kubectl -n agent-gateway create secret generic sshpiper-server-key \
  --from-file=server_key=gateway_host_key
```

## Install a released chart

Each release publishes the Helm chart as an OCI artifact next to the binaries.
The chart version is the release version without its leading `v`; the chart
pins the daemon image of its own release (`ghcr.io/footprintai/containarium:v<release>`),
so a given `--version` always installs the same daemon.

> **Standalone example:** If you are following the numbered walkthrough below,
> skip this install command and use one of the cloud-preset commands in step 1
> instead. Do not run both installs with the same `containarium` release name.

```bash
helm install containarium oci://ghcr.io/footprintai/charts/containarium-k8s \
  --version <release-without-v> \
  --set daemon.jwtSecret="$(openssl rand -hex 24)" \
  --set gateway.upstreamKeySecret=sshpiper-upstream-key \
  --set gateway.createNamespace=false \
  --set-file gateway.upstreamPublicKey=./sshpiper_upstream.pub
```

`gateway.upstreamKeySecret` is required because gateway routing is on by
default and the daemon refuses to start without an upstream credential, so a
bare `helm template` / `helm install` with no values fails fast by design.
To disable gateway routing, set both
`gateway.enabled=false` and `gateway.namespace=""`:
`--set gateway.enabled=false --set gateway.namespace=""`.

The cloud presets (`values-gke.yaml`, `values-eks.yaml`) live in the repository
at the release tag; pass the one you need with `-f`. The release notes for each
tag print the exact chart version. The chart in the repository
(`charts/containarium-k8s`) carries development placeholders (`0.0.0-dev`,
image tag `latest`); only the packaged chart attached to a release is stamped,
so install from a release, not from a checkout, when you need a reproducible
deployment.

The gateway image (`containarium-sshpiper`) is pinned to the same release tag as
the daemon. The box image (`containarium-agent-box`) is still referenced by a
moving tag in `values.yaml`; pin it with `--set agentBox.image=...` if you need
that pinned as well.

### What is tested

| Target | Status |
|---|---|
| Kubernetes 1.31.0, kind v0.24.0 (`kindest/node:v1.31.0`) | published-chart install/upgrade CI on chart/release workflow changes and after each tag's OCI publish |
| kind (`k8s-e2e`: throwaway kind v0.24.0 cluster, default node image) | backend lifecycle exercised in CI on every change to the reconciler |
| `helm lint` and template rendering (default, gateway disabled, release-stamped) | exercised in CI on every change under `charts/` |
| EKS (`values-eks.yaml`) and GKE (`values-gke.yaml`) presets | configuration examples; **not** installed in CI, so no provider/version combination is certified |

Kubernetes 1.31.0 is the chart's CI compatibility baseline. Other Kubernetes
versions, including provider-specific EKS/GKE versions, need validation in
your environment; the chart does not enforce a version range (`kubeVersion`
is unset). The agent-sandbox controller has its own version requirements.

`Helm install and upgrade` installs published chart `0.108.0`, upgrades it
to the target release, and performs a clean install of that target from
`oci://ghcr.io/footprintai/charts/containarium-k8s`. It waits for the daemon
to become ready and checks that its pod actually pulled
`ghcr.io/footprintai/containarium:v<version>` without an image override.
On PRs it also upgrades to the current checkout's packaged chart using the
published `0.109.0` daemon image. The test provisions the gateway's host and
upstream keys and waits for both Deployments; SSH sessions, tenant isolation
and box lifecycle belong to the backend e2e lane. The cluster and kubeconfig
are created per run and always removed.

To repeat the published-chart test locally (Docker, kind v0.24.0, kubectl,
Helm 3.16.2, Python 3, OpenSSH and OpenSSL required):

```bash
bash scripts/ci/helm-install-upgrade.sh 0.108.0 <target-release-without-v>
```

## Architecture

```
                         one public SSH endpoint
                    (cloud LoadBalancer: NLB / GCP L4)
                                  │
                          ┌───────▼────────┐
                          │  sshpiper      │  routes by SSH username,
                          │  (gateway)     │  reads Pipe CRs
                          └───────┬────────┘
              ┌───────────────────┼───────────────────┐
        ┌─────▼─────┐       ┌─────▼─────┐       ┌─────▼─────┐
        │ box (pod) │       │ box (pod) │       │ box (pod) │   Sandbox CRs,
        │ agent-box │       │ agent-box │       │ agent-box │   one per tenant
        │  :2222    │       │  :2222    │       │  :2222    │   (managed nodes)
        └───────────┘       └───────────┘       └───────────┘
              persistent workspace = cloud disk (EBS / PD)

   Containarium daemon (in-cluster) programs the Pipes + key Secrets and owns
   box lifecycle. The agent-sandbox controller turns each Sandbox CR into a pod
   + headless Service. Everything is ordinary Kubernetes — it runs the same on
   EKS, GKE, or kind.
```

**What is the cloud's job vs. Containarium's job**

| Layer | Provided by |
| --- | --- |
| Control plane, node autoscaling, upgrades | EKS / GKE (managed) |
| The one public SSH endpoint | Cloud LoadBalancer (NLB / GCP L4) |
| Per-box persistent workspace | Cloud block storage (EBS gp3 / PD) |
| Pod lifecycle (create/suspend/resume/TTL) | agent-sandbox `Sandbox` CRD |
| Credential-scoped SSH → MCP access | Containarium `agent-box` + sshpiper gateway |
| Username→box routing, key choreography | Containarium daemon (programs `Pipe` CRs) |

The sentinel and yamux tunnel are **not** used here — they're the
*multi-cluster federation* path (one address across several clusters/clouds),
covered at the end. A single EKS or GKE cluster needs only its own cloud LB.

## 1. Install the chart with the cloud preset

Pick the preset for your cloud — it sets the gateway Service to `LoadBalancer`
with the right annotations and selects a cloud StorageClass for box workspaces.

```bash
# GKE
helm install containarium ./charts/containarium-k8s \
  -f charts/containarium-k8s/values-gke.yaml \
  --set daemon.jwtSecret="$(openssl rand -hex 24)" \
  --set gateway.upstreamKeySecret=sshpiper-upstream-key \
  --set gateway.createNamespace=false \
  --set-file gateway.upstreamPublicKey=./sshpiper_upstream.pub

# EKS
helm install containarium ./charts/containarium-k8s \
  -f charts/containarium-k8s/values-eks.yaml \
  --set daemon.jwtSecret="$(openssl rand -hex 24)" \
  --set gateway.upstreamKeySecret=sshpiper-upstream-key \
  --set gateway.createNamespace=false \
  --set-file gateway.upstreamPublicKey=./sshpiper_upstream.pub
```

This deploys the Containarium daemon (`--runtime=k8s`), the sshpiper gateway,
RBAC, and the `Pipe` CRD. For a VPC-internal gateway instead of a public one,
see the commented annotations in the preset file.

> **Developer boxes?** Add `-f charts/containarium-k8s/values-devbox.yaml` to
> the install to give every box an interactive shell instead of the MCP
> endpoint — see [Developer-box mode](#developer-box-mode-interactive-shell).

## 2. Get the public endpoint

The cloud provisions the LoadBalancer asynchronously; wait for its address:

```bash
kubectl -n agent-gateway get svc containarium-containarium-k8s-sshpiper \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}'
```

Call that `<gateway>` below (an IP on GKE, an NLB hostname on EKS).

## 3. Create a box and connect

Boxes are created through the daemon (which programs the gateway Pipe and key
Secrets for you). Reach the daemon API — for admin use, port-forward it:

```bash
kubectl port-forward svc/containarium-containarium-k8s-daemon 8080:8080 &
export CONTAINARIUM_SERVER=http://localhost:8080

# create a box named <box>, registering the agent's public key (a file path)
containarium create <box> --ssh-key ~/.ssh/id_ed25519.pub
```

Then connect over the public gateway — the username selects the box, the agent
holds only its SSH key, and every session is the forced-command MCP server:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0.0.1"}}}' \
  | ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=accept-new \
      -p 22 <box>@<gateway>
# -> {"result":{...,"serverInfo":{"name":"containarium-agent-box",...}}}
```

Point any MCP client at `ssh -i ~/.ssh/id_ed25519 -p 22 <box>@<gateway>` and it
speaks to the box with zero cluster credentials in its path.

## Developer-box mode (interactive shell)

By default every box is an MCP endpoint: `ssh <box>@<gateway>` runs the
forced-command `agent-box` server and nothing else. To make boxes **interactive
developer machines** instead — where `ssh <box>@<gateway>` lands in a real
`/bin/bash` — install with the `values-devbox.yaml` preset composed onto the
cloud preset. This is an alternative to the standard GKE/EKS install above;
choose this command instead of running another `helm install containarium`
with the same release name:

```bash
# developer boxes on GKE (compose with values-eks.yaml on EKS)
helm install containarium ./charts/containarium-k8s \
  -f charts/containarium-k8s/values-gke.yaml \
  -f charts/containarium-k8s/values-devbox.yaml \
  --set daemon.jwtSecret="$(openssl rand -hex 24)" \
  --set gateway.upstreamKeySecret=sshpiper-upstream-key \
  --set gateway.createNamespace=false \
  --set-file gateway.upstreamPublicKey=./sshpiper_upstream.pub
```

The preset sets `agentBox.mode=shell` (the box image's `AGENTBOX_MODE`), so a
box created exactly as in step 3 gives you a shell instead of the MCP loop:

```bash
ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=accept-new -p 22 <box>@<gateway>
# -> lands in /bin/bash inside the box
```

**Tradeoff.** Shell mode drops the forced-command guarantee — anyone who can
authenticate gets a general shell in the box, not just its MCP surface. Pair it
with the default-deny NetworkPolicy from [Production notes](#production-notes)
so the shell can't reach the cluster network, and scope who may create boxes. To
run MCP and developer boxes side by side, deploy two daemon releases (one with
the preset, one without). See
[K8S-AGENT-BOX-RUNTIME-DESIGN.md](K8S-AGENT-BOX-RUNTIME-DESIGN.md) for the
image-level detail.

## Declarative boxes (the Box CRD)

Everything above creates boxes imperatively (`containarium create`). With the
**operator** enabled, a box is also a custom resource — create it with
`kubectl apply` or GitOps, and a controller reconciles it into the same bundle.
This is another alternative installation; choose it instead of the standard or
developer-box `helm install containarium` command above. Do not run these
install examples sequentially with the same release name.

```bash
# install with the operator on (composes with any cloud preset)
helm install containarium ./charts/containarium-k8s \
  -f charts/containarium-k8s/values-gke.yaml \
  --set operator.enabled=true \
  --set daemon.jwtSecret="$(openssl rand -hex 24)" \
  --set gateway.upstreamKeySecret=sshpiper-upstream-key \
  --set gateway.createNamespace=false \
  --set-file gateway.upstreamPublicKey=./sshpiper_upstream.pub
```

```yaml
# box.yaml
apiVersion: containarium.dev/v1alpha1
kind: Box
metadata:
  name: alice
spec:
  mode: shell            # or "mcp" (default)
  sshKeys:
    - ssh-ed25519 AAAA... alice
  resources:
    cpu: "2"
    memory: 4GB
```

```bash
kubectl apply -f box.yaml
kubectl get boxes          # NAME  TENANT  MODE  PHASE  ENDPOINT  AGE
ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=accept-new -p 22 alice@<gateway>
```

`containarium create` and `kubectl apply` converge on the same `Box` resource,
so the CLI and GitOps drive one reconcile loop. The operator is opt-in
(`operator.enabled`); with it off, only the imperative path runs. See
[issue #995](https://github.com/FootprintAI/Containarium/issues/995) for the design.

## Production notes

- **Pin the gateway host key.** The chart defaults to
  `CONTAINARIUM_K8S_INSECURE_IGNORE_HOST_KEY=1` for out-of-the-box dev. In
  production, unset it and distribute the gateway host key so clients use
  `StrictHostKeyChecking=yes` against a known `known_hosts` entry.
- **Default-deny NetworkPolicy — a box with no egress policy has _no_
  outbound network.** You don't add this: the daemon already creates a
  `default-deny` NetworkPolicy in each box namespace. On its own it permits
  exactly one thing — DNS (UDP/TCP 53) to `kube-system`. Nothing else. So a
  box with no policy set can resolve names and **connect to nothing**: no
  `pip install`, no `apt-get`, no outbound HTTP, no control-plane API.

  This is measured, not inferred — `TestE2E_BoxEgressPosture` observes it on a
  Calico cluster in CI, with a DNS positive control to prove the probe itself
  works.

  That floor is the *starting* posture, not the ceiling. A per-tenant egress
  **allowlist** driven by `NetworkPolicyService` shipped in [#1188]: a
  reconciler converges each tenant's namespace NetworkPolicy with the stored
  policy, so an allowlist appears as egress rules alongside the DNS
  allowance, and removing a policy reverts to this floor rather than to
  allow-all. `TestE2E_TenantEgressAllowlistIsEnforced` proves it with packets
  on Calico — a destination inside the allowlist is reachable, one outside it
  is not.

  Two practical consequences:

  - If your agents need to install packages or reach the internet, set an
    egress policy for that tenant. Until you do, the floor above is what they
    get — which is the point, but it surprises people who expected the LXC
    backend's open-by-default posture.
  - Enforcement is the CNI's job (Calico on EKS, Dataplane V2 / Cilium on
    GKE). On a CNI that ignores NetworkPolicy the object is inert and boxes
    have *unrestricted* egress — the opposite posture, silently. Verify which
    you have rather than assuming.

  [#1188]: https://github.com/FootprintAI/Containarium/issues/1188
- **Elastic capacity.** Because boxes are ordinary pods, the cluster autoscaler
  (managed node groups / Karpenter on EKS, node auto-provisioning / Autopilot
  on GKE) scales nodes to fit them. Combine with the Sandbox CRD's
  suspend/`shutdownTime` to release idle boxes and their nodes.
- **Internal gateways.** Flip the preset's LB annotations to the internal
  variant for a VPC-private endpoint reached over a bastion or VPN.

## Multi-cluster / multi-cloud (optional)

Everything above is single-cluster. When you want **one address across several
clusters or clouds** (GKE *and* EKS behind a single SSH endpoint), that's where
the Containarium sentinel comes in: it fronts many in-cluster gateways over a
tunnel and routes by username across all of them. Start each cluster's daemon
with `--ssh-host <sentinel>` and run `containarium tunnel`; see
[SENTINEL-DESIGN.md](SENTINEL-DESIGN.md) and the three-hop chain in
[K8S-AGENT-BOX-RUNTIME-DESIGN.md](K8S-AGENT-BOX-RUNTIME-DESIGN.md). For a single
managed cluster you don't need it — the cloud LoadBalancer is the endpoint.
