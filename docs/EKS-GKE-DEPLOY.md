# Running agent boxes on managed Kubernetes (EKS / GKE)

This guide runs the whole agent-box stack — SSH-reachable, MCP-native boxes —
on a **managed Kubernetes cluster** (Amazon EKS or Google GKE), fronted by a
**cloud LoadBalancer**. No sentinel, no bare-metal, no LXC.

The point is leverage: the cloud's managed control plane, node autoscaling, and
disk provisioning are shared infrastructure you don't operate. Containarium is
the thin layer on top that the cloud doesn't give you — credential-scoped
SSH/MCP access, the gateway key choreography, per-tenant isolation, and box
lifecycle (start / stop / suspend / TTL).

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

## Prerequisites

Common:

- A managed cluster: **EKS** (any supported version) or **GKE** (Standard or
  Autopilot).
- [Helm](https://helm.sh/) 3.x and `kubectl` pointed at the cluster.
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

## 1. Create the gateway host-key Secret

The gateway presents a stable SSH host key so clients can pin it. Generate one
and store it in the gateway namespace:

```bash
kubectl create namespace agent-gateway
ssh-keygen -t ed25519 -f gateway_host_key -N ""
kubectl -n agent-gateway create secret generic sshpiper-server-key \
  --from-file=server_key=gateway_host_key
```

## 2. Install the chart with the cloud preset

Pick the preset for your cloud — it sets the gateway Service to `LoadBalancer`
with the right annotations and selects a cloud StorageClass for box workspaces.

```bash
# GKE
helm install containarium ./charts/containarium-k8s \
  -f charts/containarium-k8s/values-gke.yaml \
  --set daemon.jwtSecret="$(openssl rand -hex 24)"

# EKS
helm install containarium ./charts/containarium-k8s \
  -f charts/containarium-k8s/values-eks.yaml \
  --set daemon.jwtSecret="$(openssl rand -hex 24)"
```

This deploys the Containarium daemon (`--runtime=k8s`), the sshpiper gateway,
RBAC, and the `Pipe` CRD. For a VPC-internal gateway instead of a public one,
see the commented annotations in the preset file.

## 3. Get the public endpoint

The cloud provisions the LoadBalancer asynchronously; wait for its address:

```bash
kubectl -n agent-gateway get svc containarium-containarium-k8s-sshpiper \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}'
```

Call that `<gateway>` below (an IP on GKE, an NLB hostname on EKS).

## 4. Create a box and connect

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

> For a developer-style **interactive shell** instead of the MCP endpoint, the
> box image supports `AGENTBOX_MODE=shell` (opt-in; drops the forced command).
> See [K8S-AGENT-BOX-RUNTIME-DESIGN.md](K8S-AGENT-BOX-RUNTIME-DESIGN.md).

## Production notes

- **Pin the gateway host key.** The chart defaults to
  `CONTAINARIUM_K8S_INSECURE_IGNORE_HOST_KEY=1` for out-of-the-box dev. In
  production, unset it and distribute the gateway host key so clients use
  `StrictHostKeyChecking=yes` against a known `known_hosts` entry.
- **Default-deny NetworkPolicy.** Pair each box namespace with a default-deny
  egress policy (enforced by the CNI — Calico on EKS, Dataplane V2 / Cilium on
  GKE) so a box can't reach the cluster network even under shell mode.
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
