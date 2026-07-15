#!/usr/bin/env bash
#
# k8s-sentinel-e2e.sh — prove the sentinel→K8s-node SSH chain end to end:
#
#   agent ──agent key──▶ sentinel sshpiper ──sentinel upstream key──▶
#     node in-cluster sshpiper (NodePort) ──node upstream key──▶ box pod → MCP
#
# A kind cluster stands in for the K8s node (its in-cluster sshpiper is the
# node gateway); a second sshpiperd, run directly on the runner with a
# generated yaml config, stands in for the fleet sentinel. Both hops are
# real sshpiperd; only the daemon is faked (we program the node gateway's
# Pipe + the box Secret directly rather than running the Containarium daemon,
# which would need Postgres etc.).
#
# Status: manual/local verification tool. Not yet wired into a required CI
# gate — the stand-in sentinel's exact sshpiperd yaml-plugin invocation needs
# a live shakeout on a real runner before it becomes a gate. The unit tests
# (tunnel Forward map, ResolveGatewayDialTarget) and the existing k8s-e2e
# cover the code paths; this script proves the full two-hop chain end to end.
#
# Local use:    bash scripts/k8s-sentinel-e2e.sh
# Keep cluster: E2E_KEEP=1 bash scripts/k8s-sentinel-e2e.sh
#
# Requirements: kind, kubectl, docker, ssh, ssh-keygen, base64 (all on the
# GitHub ubuntu-latest runner). The node gateway image is
# ghcr.io/footprintai/containarium-sshpiper (published per release); the box
# image is ghcr.io/footprintai/containarium-agent-box. Override with
# AGENT_BOX_IMAGE / SSHPIPER_IMAGE.
set -euo pipefail

CLUSTER="${KIND_CLUSTER:-containarium-sentinel-e2e}"
AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v0.5.1}"
AGENT_BOX_IMAGE="${AGENT_BOX_IMAGE:-ghcr.io/footprintai/containarium-agent-box:latest-stable}"
SSHPIPER_IMAGE="${SSHPIPER_IMAGE:-ghcr.io/footprintai/containarium-sshpiper:latest-stable}"
KEYDIR="$(mktemp -d)"
SENTINEL_PORT=32222 # host port the "sentinel" sshpiperd listens on
NODE_NODEPORT=32022 # kind NodePort for the node gateway

cleanup() {
  [ -n "${SENTINEL_PID:-}" ] && kill "${SENTINEL_PID}" 2>/dev/null || true
  if [ "${E2E_KEEP:-}" != "1" ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
  rm -rf "$KEYDIR"
}
trap cleanup EXIT

echo "==> keys: agent, sentinel-upstream, node-upstream, host keys"
ssh-keygen -t ed25519 -f "$KEYDIR/agent" -N "" -q
ssh-keygen -t ed25519 -f "$KEYDIR/sentinel_upstream" -N "" -q # sentinel → node gateway
ssh-keygen -t ed25519 -f "$KEYDIR/node_upstream" -N "" -q     # node gateway → box
ssh-keygen -t ed25519 -f "$KEYDIR/sentinel_host" -N "" -q
ssh-keygen -t ed25519 -f "$KEYDIR/node_host" -N "" -q

echo "==> kind cluster + agent-sandbox controller + Pipe CRD"
kind create cluster --name "$CLUSTER" --config - >/dev/null <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: ${NODE_NODEPORT}
        hostPort: ${NODE_NODEPORT}
EOF
kubectl apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/manifest.yaml" >/dev/null
kubectl -n agent-sandbox-system wait --for=condition=available deployment/agent-sandbox-controller --timeout=180s
kubectl apply -f "https://raw.githubusercontent.com/tg123/sshpiper/master/plugin/kubernetes/crd.yaml" >/dev/null
kubectl create namespace agent-gateway >/dev/null

echo "==> node gateway (in-cluster sshpiper) on NodePort ${NODE_NODEPORT}"
kubectl -n agent-gateway create secret generic sshpiper-server-key --from-file=server_key="$KEYDIR/node_host" >/dev/null
kubectl -n agent-gateway create secret generic node-upstream-key --type=kubernetes.io/ssh-auth \
  --from-file=ssh-privatekey="$KEYDIR/node_upstream" >/dev/null
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ServiceAccount
metadata: {name: sshpiper, namespace: agent-gateway}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: sshpiper, namespace: agent-gateway}
rules:
  - {apiGroups: [sshpiper.com], resources: [pipes], verbs: [get, list, watch]}
  - {apiGroups: [""], resources: [secrets], verbs: [get, list, watch]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: sshpiper, namespace: agent-gateway}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: sshpiper}
subjects: [{kind: ServiceAccount, name: sshpiper, namespace: agent-gateway}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: sshpiper, namespace: agent-gateway}
spec:
  replicas: 1
  selector: {matchLabels: {app: sshpiper}}
  template:
    metadata: {labels: {app: sshpiper}}
    spec:
      serviceAccountName: sshpiper
      containers:
        - name: sshpiper
          image: ${SSHPIPER_IMAGE}
          env:
            - {name: PLUGIN, value: kubernetes}
            - {name: SSHPIPERD_SERVER_KEY, value: /serverkey/ssh_host_ed25519_key}
          ports: [{name: ssh, containerPort: 2222}]
          volumeMounts: [{name: server-key, mountPath: /serverkey/, readOnly: true}]
      volumes:
        - name: server-key
          secret:
            secretName: sshpiper-server-key
            items: [{key: server_key, path: ssh_host_ed25519_key}]
---
apiVersion: v1
kind: Service
metadata: {name: sshpiper, namespace: agent-gateway}
spec:
  type: NodePort
  selector: {app: sshpiper}
  ports: [{name: ssh, port: 22, targetPort: 2222, nodePort: ${NODE_NODEPORT}}]
EOF
kubectl -n agent-gateway rollout status deployment/sshpiper --timeout=180s

echo "==> box: agent-box Sandbox + authorized_keys Secret (node upstream key) + host key"
kubectl create namespace tenant-mybox >/dev/null
# The box authorizes the NODE gateway's upstream key (hop 3).
kubectl -n tenant-mybox create secret generic mybox-authorized-keys \
  --from-file=authorized_keys="$KEYDIR/node_upstream.pub" >/dev/null
# Stable box host key so the node gateway can dial it (ignore_hostkey in the Pipe below).
kubectl -n tenant-mybox create secret generic mybox-host-key \
  --from-file=host_key="$KEYDIR/node_host" >/dev/null
docker pull -q "$AGENT_BOX_IMAGE" >/dev/null
kind load docker-image "$AGENT_BOX_IMAGE" --name "$CLUSTER" >/dev/null 2>&1 || true
kubectl apply -f - >/dev/null <<EOF
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata: {name: box, namespace: tenant-mybox, labels: {app.kubernetes.io/managed-by: containarium, containarium.dev/tenant: mybox}}
spec:
  service: true
  operatingMode: Running
  podTemplate:
    metadata: {labels: {app.kubernetes.io/managed-by: containarium, containarium.dev/tenant: mybox}}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: agent-box
          image: ${AGENT_BOX_IMAGE}
          ports: [{name: ssh, containerPort: 2222}]
          volumeMounts:
            - {name: authorized-keys, mountPath: /etc/agent-box, readOnly: true}
      volumes:
        - {name: authorized-keys, secret: {secretName: mybox-authorized-keys}}
EOF
kubectl -n tenant-mybox wait --for=create pod --selector=containarium.dev/tenant=mybox --timeout=60s
kubectl -n tenant-mybox wait --for=condition=ready pod --selector=containarium.dev/tenant=mybox --timeout=180s

echo "==> node gateway Pipe: username mybox → box pod, from-keys = agent + sentinel-upstream"
FROM_B64=$(cat "$KEYDIR/agent.pub" "$KEYDIR/sentinel_upstream.pub" | base64 -w0)
kubectl apply -f - >/dev/null <<EOF
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata: {name: box-mybox, namespace: agent-gateway}
spec:
  from:
    - {username: mybox, authorized_keys_data: ${FROM_B64}}
  to:
    host: box.tenant-mybox.svc.cluster.local:2222
    username: agent
    ignore_hostkey: true
    private_key_secret: {name: node-upstream-key}
EOF

echo "==> sentinel: a second sshpiperd on the runner routing mybox → the kind NodePort"
mkdir -p "$KEYDIR/sentinel/users/mybox"
cp "$KEYDIR/agent.pub" "$KEYDIR/sentinel/users/mybox/authorized_keys"
# Paths in the config are the CONTAINER paths (see the volume mounts below):
# the sentinel config dir mounts at /sentinel, the upstream key at
# /sentinel_upstream. The yaml plugin refuses a world-readable config, so
# chmod 600 (the real sentinel does the same — startup-sentinel.sh).
cat > "$KEYDIR/sentinel/config.yaml" <<EOF
version: "1.0"
pipes:
  - from:
      - username: "mybox"
        authorized_keys:
          - /sentinel/users/mybox/authorized_keys
    to:
      host: 127.0.0.1:${NODE_NODEPORT}
      username: "mybox"
      ignore_hostkey: true
      private_key: /sentinel_upstream
EOF
chmod 600 "$KEYDIR/sentinel/config.yaml"
# sshpiperd CLI: global flags, then the plugin (by full path — the plugins
# aren't on PATH in this image), then plugin flags. Matches the sentinel's
# own unit (terraform/.../sshpiper.service.tmpl). Override the image
# entrypoint, which otherwise hardcodes the kubernetes plugin.
docker run -d --rm --name sentinel-sshpiper --network host \
  --entrypoint /sshpiperd/sshpiperd \
  -v "$KEYDIR/sentinel:/sentinel:ro" \
  -v "$KEYDIR/sentinel_host:/host_key:ro" \
  -v "$KEYDIR/sentinel_upstream:/sentinel_upstream:ro" \
  "$SSHPIPER_IMAGE" \
  -i /host_key -p "${SENTINEL_PORT}" --log-level info \
  /sshpiperd/plugins/yaml --config /sentinel/config.yaml >/dev/null
SENTINEL_PID=1 # sentinel runs as a docker container; cleanup kills it below
trap 'docker rm -f sentinel-sshpiper >/dev/null 2>&1 || true; [ "${E2E_KEEP:-}" != "1" ] && kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; rm -rf "$KEYDIR"' EXIT
sleep 4

echo "==> MCP initialize through BOTH hops (agent key only, ssh mybox@sentinel)"
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sentinel-e2e","version":"0.0.1"}}}'
RESP=$(printf '%s\n' "$INIT" | timeout 25 ssh -i "$KEYDIR/agent" -p "$SENTINEL_PORT" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
  mybox@127.0.0.1)
if ! printf '%s' "$RESP" | grep -q '"containarium-agent-box"'; then
  echo "FAIL: no MCP initialize response through the sentinel→node→box chain" >&2
  echo "Got: $RESP" >&2
  docker logs sentinel-sshpiper 2>&1 | tail -20 >&2 || true
  kubectl -n agent-gateway logs deployment/sshpiper --tail=20 >&2 || true
  exit 1
fi
echo "OK: agent-box answered MCP through sentinel → node gateway → box (agent held only its SSH key)."
echo "Test finished."
