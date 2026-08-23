#!/bin/bash
#
# Shared kubeadm + CNI + gVisor + agent-sandbox-controller provisioning.
# Both sides of this benchmark run on Kubernetes, with gVisor installed and
# every Sandbox pod scheduled under it — the control group creates `Sandbox`
# CRs directly (kubectl), the experiment group creates them indirectly via
# the Containarium daemon (see README.md "What's actually under test").
# gVisor being present on BOTH sides is deliberate: it removes gVisor
# itself as a variable, so what the benchmark actually isolates is
# Containarium's own orchestration cost (the extra daemon hop, and the
# request==limit CLI behavior — see README.md "Fairness notes"), not
# "does gVisor cost density" mixed in with it. Any drift between the two
# sides in this shared setup would confound that. Sourced by
# 01-provision-k8s-control.sh and 03-provision-containarium.sh, not
# executed directly.

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
	# `kubectl wait` on a label selector errors immediately with "no
	# matching resources found" if zero pods currently match — it does not
	# wait for the DaemonSet controller to create them. Hit this live: the
	# calico-node DaemonSet object exists right after apply, but its pods
	# take a few seconds to appear. Poll for at least one to exist first.
	ssh_or_local "until [ \"\$(kubectl get pods -l k8s-app=calico-node -n kube-system --no-headers 2>/dev/null | wc -l)\" -gt 0 ]; do sleep 2; done"
	ssh_or_local "kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n kube-system --timeout=180s"

	log "installing agent-sandbox controller ${AGENT_SANDBOX_VERSION}"
	ssh_or_local "kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/manifest.yaml"
	ssh_or_local "kubectl -n agent-sandbox-system wait --for=condition=available deployment/agent-sandbox-controller --timeout=180s"
}

# install_gvisor installs runsc + the containerd shim, registers it as a
# containerd runtime handler, and creates the matching k8s RuntimeClass.
# Called on BOTH sides (see the file header) so gVisor itself isn't a
# variable between the two runs — only who's doing the scheduling is.
install_gvisor() {
	log "installing gVisor (${GVISOR_RUNTIME_CLASS})"
	ssh_or_local "sudo bash -s" <<REMOTE
set -euo pipefail
ARCH=\$(uname -m)
URL="https://storage.googleapis.com/gvisor/releases/release/latest/\${ARCH}"
cd /tmp
curl -fsSLO "\${URL}/runsc" -O "\${URL}/runsc.sha512" \
	-O "\${URL}/containerd-shim-runsc-v1" -O "\${URL}/containerd-shim-runsc-v1.sha512"
sha512sum -c runsc.sha512 -c containerd-shim-runsc-v1.sha512
chmod a+rx runsc containerd-shim-runsc-v1
mv runsc containerd-shim-runsc-v1 /usr/local/bin/

cat <<TOML >>/etc/containerd/config.toml

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.${GVISOR_RUNTIME_CLASS}]
  runtime_type = "io.containerd.${GVISOR_RUNTIME_CLASS}.v1"
TOML
systemctl restart containerd
sleep 2
# Confirm the CRI plugin actually picked up the new runtime handler before
# moving on — found live that the wrong plugin ID (an older containerd
# v1-era path, io.containerd.grpc.v1.cri) silently creates an inert config
# tree on containerd v2.x: no error, no warning, just "no runtime for
# \"${GVISOR_RUNTIME_CLASS}\" is configured" at first pod creation, several
# steps later. containerd 2.x's actual CRI plugin id is
# io.containerd.cri.v1.runtime (see the existing runc entry
# \`containerd config default\` already generates, in the same file).
crictl info 2>/dev/null | grep -q "\"${GVISOR_RUNTIME_CLASS}\"" ||
	{ echo "containerd did not pick up the ${GVISOR_RUNTIME_CLASS} runtime handler after restart" >&2; exit 1; }

cat <<EOF | kubectl apply -f -
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: ${GVISOR_RUNTIME_CLASS}
handler: ${GVISOR_RUNTIME_CLASS}
EOF
REMOTE
}
