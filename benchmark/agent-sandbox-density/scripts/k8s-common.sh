#!/bin/bash
#
# Shared kubeadm + CNI + agent-sandbox-controller provisioning. Both sides
# of this benchmark run on Kubernetes now — the control group creates
# `Sandbox` CRs directly, the experiment group creates them indirectly via
# the Containarium daemon (see README.md "Experiment group") — so both
# need the identical base cluster. This is that shared base: any drift
# between the two sides here would confound the comparison (see README.md
# "Fairness notes"). Sourced by 01-provision-k8s-control.sh and
# 03-provision-containarium.sh, not executed directly.

set -euo pipefail

provision_base_k8s() {
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
# any pod (Sandbox-controller-owned or Containarium-owned) from
# scheduling at all.
kubectl --kubeconfig=/root/.kube/config taint nodes --all node-role.kubernetes.io/control-plane- || true
REMOTE

	log "installing Calico CNI"
	ssh_or_local "kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml"
	ssh_or_local "kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n kube-system --timeout=180s"

	log "installing agent-sandbox controller ${AGENT_SANDBOX_VERSION}"
	ssh_or_local "kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/manifest.yaml"
	ssh_or_local "kubectl -n agent-sandbox-system wait --for=condition=available deployment/agent-sandbox-controller --timeout=180s"
}
