#!/usr/bin/env bash
# Dedicated, disposable kind lane. No ambient kubeconfig or existing cluster is used.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
TASK_DIR="$(mktemp -d)"
CLUSTER="containarium-snapshot-$(basename "$TASK_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
export KUBECONFIG="$TASK_DIR/kubeconfig"
CREATED=0
cleanup() {
  if [[ "$CREATED" == 1 ]]; then kind delete cluster --name "$CLUSTER"; fi
  # Do not recursively delete downloaded upstream sources; mktemp data can be inspected.
}
trap cleanup EXIT
CREATED=1
kind create cluster --name "$CLUSTER" --wait 180s
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v1.0.8/sandbox.yaml
kubectl -n agent-sandbox-system rollout status deployment/agent-sandbox-controller --timeout=240s
SNAPSHOTTER=https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v8.7.0
for crd in volumesnapshotclasses volumesnapshotcontents volumesnapshots; do
  kubectl apply -f "$SNAPSHOTTER/client/config/crd/snapshot.storage.k8s.io_${crd}.yaml"
done
kubectl apply -f "$SNAPSHOTTER/deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml"
kubectl apply -f "$SNAPSHOTTER/deploy/kubernetes/snapshot-controller/setup-snapshot-controller.yaml"
kubectl -n kube-system rollout status deployment/snapshot-controller --timeout=240s
# Official CSI hostpath manifests, pinned to release v1.19.0. Install only the
# driver components, not upstream's test service exposing the CSI socket.
curl -fsSL https://api.github.com/repos/kubernetes-csi/csi-driver-host-path/tarball/v1.19.0 -o "$TASK_DIR/hostpath.tar.gz"
echo "1642265f0970392e8d8e1183e64a98fe0533541e2adfa70b019ac11faa5d6cdb  $TASK_DIR/hostpath.tar.gz" | sha256sum -c -
mkdir "$TASK_DIR/hostpath"
tar -xzf "$TASK_DIR/hostpath.tar.gz" -C "$TASK_DIR/hostpath" --strip-components=1
for component in external-provisioner/v6.4.0 external-attacher/v4.13.0 external-resizer/v2.3.0; do
  kubectl apply -f "https://raw.githubusercontent.com/kubernetes-csi/$component/deploy/kubernetes/rbac.yaml"
done
kubectl apply -f "$SNAPSHOTTER/deploy/kubernetes/csi-snapshotter/rbac-csi-snapshotter.yaml"
for manifest in csi-hostpath-driverinfo csi-hostpath-plugin csi-hostpath-snapshotclass; do
  kubectl apply -f "$TASK_DIR/hostpath/deploy/kubernetes-1.35/hostpath/$manifest.yaml"
done
kubectl rollout status statefulset/csi-hostpathplugin --timeout=300s
kubectl apply -f - <<'YAML'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: snapshot-e2e
provisioner: hostpath.csi.k8s.io
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
YAML
CONTAINARIUM_K8S_SNAPSHOT_E2E=1 go test -tags k8s -run '^TestE2E_CSISnapshot$' -timeout 10m -v ./pkg/core/box/k8s
