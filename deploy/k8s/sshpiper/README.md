# sshpiper gateway for the Kubernetes agent-box backend

Deploys the SSH gateway that fronts Containarium's Kubernetes boxes. An agent
connects once to this gateway; sshpiper routes by SSH username to the right
per-tenant box pod. Design + topology: [`docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md`](../../../docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md).

```
agent ──ssh <tenant>@<gateway> :22──▶ sshpiper ──:2222──▶ box-0 (agent-box)
        auth: Pipe spec.from                auth: Pipe spec.to.private_key_secret
        (the agent's key)                   (sshpiper's upstream key, authorized on the box)
```

The Containarium daemon (k8s build) programs one `Pipe` per box automatically;
these manifests stand up sshpiper itself. Two keypairs are involved:

| Key | Presented by | Verified by | Lives in |
| --- | --- | --- | --- |
| **server key** | sshpiper → client | the agent's `known_hosts` | `sshpiper-server-key` Secret |
| **upstream key** | sshpiper → box | the box's `authorized_keys` | `sshpiper-upstream-key` Secret (private) + daemon config (public) |

## Prerequisites

- A cluster with a NetworkPolicy-enforcing CNI (Calico/Cilium) for the box
  default-deny policy to bite. The gateway itself works on any CNI.
- The Containarium daemon running the `k8s` build variant.

## 1. Generate the two keypairs

```bash
# Server key — sshpiper's identity to clients.
ssh-keygen -t ed25519 -N '' -f ./sshpiper_server -C sshpiper-server
# Upstream key — sshpiper's identity to boxes.
ssh-keygen -t ed25519 -N '' -f ./sshpiper_upstream -C sshpiper-upstream
```

## 2. Create the Secrets (in the gateway namespace)

```bash
kubectl apply -f 00-namespace.yaml
kubectl -n agent-gateway create secret generic sshpiper-server-key \
  --from-file=server_key=./sshpiper_server
# The data key MUST be `ssh-privatekey` — sshpiper's kubernetes plugin reads
# spec.to.private_key_secret from that key (verified live).
kubectl -n agent-gateway create secret generic sshpiper-upstream-key \
  --from-file=ssh-privatekey=./sshpiper_upstream
```

## 3. Point the daemon at the gateway

Set these on the `containarium-k8s` daemon so it programs Pipes that route
through sshpiper and so boxes authorize the upstream key:

```bash
CONTAINARIUM_K8S_GATEWAY_NAMESPACE=agent-gateway
CONTAINARIUM_K8S_GATEWAY_HOST=<gateway public host>      # surfaced to clients
CONTAINARIUM_K8S_GATEWAY_UPSTREAM_KEY_SECRET=sshpiper-upstream-key
CONTAINARIUM_K8S_GATEWAY_UPSTREAM_PUBLIC_KEY="$(cat ./sshpiper_upstream.pub)"
```

## 4. Deploy sshpiper

```bash
kubectl apply -f 10-pipe-crd.yaml -f 20-rbac.yaml -f 30-deployment.yaml -f 40-service.yaml
kubectl -n agent-gateway rollout status deploy/sshpiper
```

## 5. Create a box and watch the route appear

```bash
# via the daemon (CLI/MCP); then:
kubectl -n agent-gateway get pipes
```

## 6. Acceptance — SSH through the gateway

```bash
GW=$(kubectl -n agent-gateway get svc sshpiper -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
ssh -i <agent-private-key> <tenant>@"$GW"
# Lands directly in the box's agent-box stdio MCP (ForceCommand-pinned) —
# no shell. Point an MCP client at this exact ssh command.
```

## Dev / kind notes

- **No LoadBalancer** (kind, bare-metal): change `40-service.yaml` to
  `type: NodePort`, or `kubectl -n agent-gateway port-forward svc/sshpiper 2222:22`
  and `ssh -p 2222 <tenant>@127.0.0.1`.
- **kindnet doesn't enforce NetworkPolicy** — the box default-deny policy is a
  no-op there; use a Calico-backed kind config to exercise enforcement.

## Security notes

- `automountServiceAccountToken: false` on boxes; the gateway SA is least
  privilege (read Pipes + Secrets in this namespace only — no `pods/exec`).
- The box authorizes only sshpiper's upstream key, never the agent's — the
  agent can never reach a box except through the gateway's per-tenant Pipe.
- Pin the `farmer1992/sshpiperd` image to a release tag in production.
- Host-key pinning (replacing the Pipe's `ignore_hostkey`) is a planned
  follow-up.
