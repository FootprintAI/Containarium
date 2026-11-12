#!/usr/bin/env bash
# Install and upgrade published OCI charts in a disposable kind cluster (#2574).
# Usage: bash scripts/ci/helm-install-upgrade.sh BASE_VERSION VERSION [CANDIDATE_TGZ]
# The optional candidate is stamped with VERSION's appVersion and tested after
# the published upgrade, so PRs also exercise their own chart changes.
set -euo pipefail

base="${1:?usage: helm-install-upgrade.sh BASE_VERSION VERSION [CANDIDATE_TGZ]}"
version="${2:?missing target version}"
candidate="${3:-}"
base="${base#v}"
version="${version#v}"
chart=oci://ghcr.io/footprintai/charts/containarium-k8s
work="$(mktemp -d)"
cluster="helm-release-$(basename "$work" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')"
export KUBECONFIG="$work/kubeconfig"
release=helm-release
namespace=helm-release
gateway=helm-release-gateway
timeout="${HELM_TEST_TIMEOUT:-20m}"

# EXIT handler: preserve the test status, emit diagnostics on failure, then
# remove this invocation's disposable kind cluster and temporary kubeconfig.
cleanup() {
  result=$?
  if [ "$result" -ne 0 ]; then
    kubectl get pods -A -o wide || true
    for ns in "$namespace" "$gateway"; do
      kubectl -n "$ns" describe pods || true
      kubectl -n "$ns" logs -l "app.kubernetes.io/instance=$release" --all-containers --tail=100 || true
    done
  fi
  kind delete cluster --name "$cluster" || true
  rm -rf "$work"
  exit "$result"
}
trap cleanup EXIT

# Never use the contributor's current context or a shared dev cluster.
kind create cluster --name "$cluster" --image kindest/node:v1.31.0 --wait 180s

ssh-keygen -q -t ed25519 -N '' -f "$work/server"
ssh-keygen -q -t ed25519 -N '' -f "$work/upstream"
# Create the gateway namespace with Helm ownership and install its host and
# upstream key Secrets. Call before each clean install; failures stop the test.
prepare_gateway() {
  # Secrets must predate installation. The chart manages this Namespace, so
  # give the precreated namespace the same ownership as the Helm release.
  kubectl create namespace "$gateway"
  kubectl label namespace "$gateway" app.kubernetes.io/managed-by=Helm
  kubectl annotate namespace "$gateway" \
    "meta.helm.sh/release-name=$release" "meta.helm.sh/release-namespace=$namespace"
  kubectl -n "$gateway" create secret generic sshpiper-server-key --from-file="server_key=$work/server"
  kubectl -n "$gateway" create secret generic sshpiper-upstream-key --from-file="ssh-privatekey=$work/upstream"
}
prepare_gateway

values=(
  --namespace "$namespace" --create-namespace
  --set fullnameOverride=helm-release
  --set-string "daemon.jwtSecret=$(openssl rand -hex 32)"
  --set-string "gateway.namespace=$gateway"
  --set gateway.upstreamKeySecret=sshpiper-upstream-key
  --set-file "gateway.upstreamPublicKey=$work/upstream.pub"
  --wait --timeout "$timeout"
)

# Require ready daemon and gateway pods with the expected images and pulled
# image IDs. $1 is the daemon version without v; optional $2 overrides only
# the gateway tag for the historical baseline that predates release pinning.
assert_running_release() {
  expected="$1"
  gateway_tag="${2:-v$expected}"
  kubectl -n "$namespace" rollout status deployment/helm-release-daemon --timeout="$timeout"
  kubectl -n "$gateway" rollout status deployment/helm-release-sshpiper --timeout="$timeout"
  kubectl -n "$namespace" get pods -l "app.kubernetes.io/instance=$release" -o json > "$work/pods.json"
  kubectl -n "$gateway" get pods -l "app.kubernetes.io/instance=$release,app.kubernetes.io/name=sshpiper" -o json > "$work/gateway-pods.json"
  python3 - "$work/pods.json" "$work/gateway-pods.json" "$expected" "$gateway_tag" <<'PY'
import json
import sys

images = (
    (sys.argv[1], "daemon", "ghcr.io/footprintai/containarium:v" + sys.argv[3]),
    (sys.argv[2], "sshpiper", "ghcr.io/footprintai/containarium-sshpiper:" + sys.argv[4]),
)
for path, name, expected in images:
    pods = json.load(open(path))["items"]
    running = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
    assert running, f"no current {name} pods"
    for pod in running:
        container = next(c for c in pod["spec"]["containers"] if c["name"] == name)
        assert container["image"] == expected, (container["image"], expected)
        status = next(c for c in pod["status"]["containerStatuses"] if c["name"] == name)
        assert status["ready"] and status.get("imageID"), status
    print("ready, pulled image:", expected)
PY
}

# No image overrides: the image must come from the published chart appVersion.
helm install "$release" "$chart" --version "$base" "${values[@]}"
# This fixed baseline predates gateway pinning (#2703); all target/candidate
# assertions below require the gateway's exact release tag as well.
assert_running_release "$base" latest-stable

# SSH through the gateway to a stand-in box after an upgrade (#3628). The box
# is an sshd pod with a stable host key; the Pipe pins that key via
# known_hosts_data (the form the daemon programs), with no host-key override.
# A client logging in as the tenant must reach the box through sshpiper.
ssh-keygen -q -t ed25519 -N '' -f "$work/client"
ssh-keygen -q -t ed25519 -N '' -f "$work/boxhost"
box_ns=helm-release-box
box_tenant=gwcheck
setup_gateway_box() {
  kubectl create namespace "$box_ns"
  kubectl -n "$box_ns" create secret generic box-hostkey --from-file="ssh_host_ed25519_key=$work/boxhost"
  # The gateway authenticates to the box with the chart's upstream key.
  kubectl -n "$box_ns" create configmap box-authorized --from-file="authorized_keys=$work/upstream.pub"
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata: {name: box, namespace: $box_ns, labels: {app: box}}
spec:
  containers:
    - name: sshd
      image: alpine:3.20
      command: ["/bin/sh", "-c"]
      args:
        - |
          apk add --no-cache openssh >/dev/null
          adduser -D agent && echo "agent:\$(head -c16 /dev/urandom | base64)" | chpasswd
          cp /hk/ssh_host_ed25519_key /etc/ssh/hk && chmod 600 /etc/ssh/hk
          exec /usr/sbin/sshd -D -e -p 2222 -h /etc/ssh/hk \
            -o AuthorizedKeysFile=/ak/authorized_keys -o StrictModes=no
      ports: [{containerPort: 2222}]
      readinessProbe: {tcpSocket: {port: 2222}, periodSeconds: 3}
      volumeMounts:
        - {name: hk, mountPath: /hk}
        - {name: ak, mountPath: /ak}
  volumes:
    - {name: hk, secret: {secretName: box-hostkey}}
    - {name: ak, configMap: {name: box-authorized}}
---
apiVersion: v1
kind: Service
metadata: {name: box, namespace: $box_ns}
spec:
  selector: {app: box}
  ports: [{port: 2222, targetPort: 2222}]
EOF
  kubectl -n "$box_ns" wait --for=condition=Ready pod/box --timeout="$timeout"
  pin="$(printf '[box.%s.svc.cluster.local]:2222 %s\n' "$box_ns" "$(cut -d' ' -f1,2 "$work/boxhost.pub")" | base64 -w0)"
  from="$(base64 -w0 "$work/client.pub")"
  kubectl apply -f - <<EOF
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata: {name: $box_tenant, namespace: $gateway}
spec:
  from:
    - username: $box_tenant
      authorized_keys_data: $from
  to:
    host: box.$box_ns.svc.cluster.local:2222
    username: agent
    known_hosts_data: $pin
    private_key_secret: {name: sshpiper-upstream-key}
EOF
}
assert_ssh_through_gateway() {
  svc_port="$(kubectl -n "$gateway" get svc helm-release-sshpiper -o jsonpath='{.spec.ports[0].port}')"
  kubectl -n "$gateway" port-forward svc/helm-release-sshpiper "12222:$svc_port" >"$work/pf.log" 2>&1 &
  pf=$!
  trap 'kill $pf 2>/dev/null || true' RETURN
  for _ in $(seq 1 30); do (echo > /dev/tcp/127.0.0.1/12222) 2>/dev/null && break; sleep 1; done
  out="$(ssh -p 12222 -i "$work/client" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 \
    "$box_tenant@127.0.0.1" 'echo gateway-ssh-ok')"
  [ "$out" = gateway-ssh-ok ] || { echo "::error::ssh through the gateway returned: $out"; exit 1; }
  echo "ssh through the gateway reached the box"
}
# The upgraded daemon must carry no host-key override unless the value is set.
assert_no_host_key_override() {
  if kubectl -n "$namespace" get deployment helm-release-daemon -o yaml |
    grep -q CONTAINARIUM_K8S_INSECURE_IGNORE_HOST_KEY; then
    echo "::error::daemon sets CONTAINARIUM_K8S_INSECURE_IGNORE_HOST_KEY after upgrade"
    exit 1
  fi
}

helm upgrade "$release" "$chart" --version "$version" "${values[@]}"
assert_running_release "$version"
setup_gateway_box
assert_ssh_through_gateway

if [ -n "$candidate" ]; then
  helm upgrade "$release" "$candidate" "${values[@]}"
  assert_running_release "$version"
  assert_no_host_key_override
  assert_ssh_through_gateway
fi

# Roll back to revision 1, the published baseline, and require it to serve
# again (#3060). Revision 1 differs from the upgraded revisions in daemon and
# gateway image, so assert_running_release proves the old pods came back, not
# merely that the command succeeded.
latest="$(helm history "$release" --namespace "$namespace" -o json |
  python3 -c 'import json,sys; print(max(r["revision"] for r in json.load(sys.stdin)))')"
helm rollback "$release" 1 --namespace "$namespace" --wait --timeout "$timeout"
assert_running_release "$base" latest-stable
# Rollback is a new revision, not a rewind: it must be latest+1 and deployed.
helm history "$release" --namespace "$namespace" -o json |
  python3 -c '
import json, sys
latest = int(sys.argv[1])
rows = json.load(sys.stdin)
last = max(rows, key=lambda r: r["revision"])
assert last["revision"] == latest + 1, (last, latest)
assert last["status"] == "deployed", last
assert "Rollback to 1" in last["description"], last
print("rollback recorded as revision", last["revision"])
' "$latest"

# A second clean install proves the target also works without an old release.
helm uninstall "$release" --namespace "$namespace" --wait --timeout "$timeout"
prepare_gateway
helm install "$release" "$chart" --version "$version" "${values[@]}"
assert_running_release "$version"
helm history "$release" --namespace "$namespace"
