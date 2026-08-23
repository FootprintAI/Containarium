#!/bin/bash
#
# Provision the control-group VM: vanilla kubeadm single-node cluster, CNI,
# kubelet --max-pods raised past the stock 110 default (see README.md
# "Kubelet max-pods"), and the upstream kubernetes-sigs/agent-sandbox
# controller + CRDs.
#
# Runs everything inside the guest over SSH (see lib.sh ssh_or_local) —
# targets whatever config.env's REMOTE_HOST/REMOTE_SSH_PORT/REMOTE_SSH_USER
# point at. --name is accepted for symmetry with the other scripts and
# logged, but this script's actions are entirely inside the guest.
#
# Usage:
#   scripts/01-provision-k8s-control.sh --name <vm-name>
#
# Assumes the guest is Ubuntu Server 24.04 (matches VM_BASE_ISO guidance in
# config.env.example) with passwordless sudo for REMOTE_SSH_USER.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib.sh
source ./lib.sh

VM_NAME=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	--name)
		VM_NAME="$2"
		shift 2
		;;
	-h | --help)
		grep '^#' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		die "unknown argument: $1"
		;;
	esac
done
[[ -n "$VM_NAME" ]] || die "usage: $0 --name <vm-name>"

load_config
require_vars K8S_MAX_PODS AGENT_SANDBOX_VERSION REMOTE_SSH_USER

log "provisioning k8s control group on '${VM_NAME}' (max-pods=${K8S_MAX_PODS}, agent-sandbox=${AGENT_SANDBOX_VERSION})"

log "installing containerd + kubeadm/kubelet/kubectl"
ssh_or_local "sudo bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq apt-transport-https ca-certificates curl gpg containerd

mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl restart containerd

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key |
	gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' |
	tee /etc/apt/sources.list.d/kubernetes.list >/dev/null
apt-get update -qq
apt-get install -y -qq kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

swapoff -a
sed -i '/ swap /s/^/#/' /etc/fstab

cat <<EOF >/etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

cat <<EOF >/etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
sysctl --system >/dev/null
REMOTE

log "kubeadm init with maxPods=${K8S_MAX_PODS}"
ssh_or_local "sudo bash -s" <<REMOTE
set -euo pipefail
cat <<KUBEADM_CFG >/tmp/kubeadm-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
networking:
  podSubnet: "192.168.0.0/16"
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
maxPods: ${K8S_MAX_PODS}
KUBEADM_CFG

kubeadm init --config /tmp/kubeadm-config.yaml

mkdir -p /root/.kube
cp -f /etc/kubernetes/admin.conf /root/.kube/config
mkdir -p /home/${REMOTE_SSH_USER}/.kube
cp -f /etc/kubernetes/admin.conf /home/${REMOTE_SSH_USER}/.kube/config
chown -R ${REMOTE_SSH_USER}:${REMOTE_SSH_USER} /home/${REMOTE_SSH_USER}/.kube

# Single-node cluster — the control-plane taint would otherwise prevent
# any Sandbox pod from scheduling at all.
kubectl --kubeconfig=/root/.kube/config taint nodes --all node-role.kubernetes.io/control-plane- || true
REMOTE

log "installing Calico CNI"
ssh_or_local "kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml"
ssh_or_local "kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n kube-system --timeout=180s"

log "installing agent-sandbox controller ${AGENT_SANDBOX_VERSION}"
ssh_or_local "kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/manifest.yaml"
ssh_or_local "kubectl -n agent-sandbox-system wait --for=condition=available deployment/agent-sandbox-controller --timeout=180s"

log "creating benchmark namespace"
ssh_or_local "kubectl create namespace sandbox-density-bench --dry-run=client -o yaml | kubectl apply -f -"

log "provisioning complete. Verify: kubectl get nodes -o wide; kubectl -n agent-sandbox-system get pods"
