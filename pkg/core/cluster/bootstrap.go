package cluster

import (
	"fmt"
	"sort"
	"strings"
)

// Bootstrap renderers — pure functions producing the shell that runs
// inside a freshly created VM over `incus exec`. Rendered output is
// golden-tested (testdata/*.golden): a change to what executes inside
// a tenant's cluster VM must show up as a reviewable golden diff.
//
// Both scripts assume the pinned k3s binary was already pushed to
// K3sBinaryPath by the manager — bootstrap never downloads anything.

const (
	// K3sBinaryPath is where the manager pushes the pinned binary.
	K3sBinaryPath = "/usr/local/bin/k3s"
	// AgentTokenPath is where the manager pushes the join token (0600).
	AgentTokenPath = "/etc/containarium/k3s-agent-token"
	// KubeconfigPath is where k3s server writes the admin kubeconfig.
	KubeconfigPath = "/etc/rancher/k3s/k3s.yaml"
	// NodeTokenPath is where k3s server writes the agent join token.
	NodeTokenPath = "/var/lib/rancher/k3s/server/node-token"
)

// ServerBootstrap parameterizes the control-plane script.
type ServerBootstrap struct {
	// TLSSANs are extra subject-alt-names for the API server cert —
	// the external endpoint and the VM IP, so the rewritten
	// kubeconfig verifies.
	TLSSANs []string
}

// RenderServerScript renders the control-plane first-boot script: a
// systemd unit for `k3s server`, tainted so tenant pods never schedule
// onto the platform-owned VM, traefik disabled (ingress is a later
// phase riding the platform's own routing).
func RenderServerScript(b ServerBootstrap) string {
	sans := append([]string(nil), b.TLSSANs...)
	sort.Strings(sans)
	var sanFlags strings.Builder
	for _, s := range sans {
		fmt.Fprintf(&sanFlags, " --tls-san %s", s)
	}
	return fmt.Sprintf(`#!/bin/sh
# containarium managed-cluster control-plane bootstrap (#1414).
# The k3s binary is pre-pushed; this script only wires and starts it.
set -eu

chmod 0755 %[1]s

cat > /etc/systemd/system/k3s.service <<'UNIT'
[Unit]
Description=containarium managed k3s server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=%[1]s server --disable traefik --node-taint node-role.kubernetes.io/control-plane=:NoSchedule --write-kubeconfig-mode 0600%[2]s
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now k3s.service

# Bootstrap is done when the admin kubeconfig and the join token exist.
i=0
until [ -s %[3]s ] && [ -s %[4]s ]; do
  i=$((i+1))
  [ "$i" -gt 120 ] && { echo "k3s server did not come up" >&2; exit 1; }
  sleep 2
done
`, K3sBinaryPath, sanFlags.String(), KubeconfigPath, NodeTokenPath)
}

// AgentBootstrap parameterizes a worker script.
type AgentBootstrap struct {
	// ServerURL is the control-plane's in-host API URL
	// (https://<cp-ip>:6443) — workers join over the private bridge,
	// not the published endpoint.
	ServerURL string
}

// RenderAgentScript renders a worker first-boot script: a systemd unit
// for `k3s agent` joining via the pre-pushed token file.
func RenderAgentScript(b AgentBootstrap) string {
	return fmt.Sprintf(`#!/bin/sh
# containarium managed-cluster worker bootstrap (#1414).
# The k3s binary and the join token are pre-pushed.
set -eu

chmod 0755 %[1]s
chmod 0600 %[2]s

cat > /etc/systemd/system/k3s-agent.service <<'UNIT'
[Unit]
Description=containarium managed k3s agent
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=%[1]s agent --server %[3]s --token-file %[2]s
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now k3s-agent.service
`, K3sBinaryPath, AgentTokenPath, b.ServerURL)
}

// RewriteKubeconfigServer replaces the server URL in a k3s admin
// kubeconfig with the published external endpoint. Pure string surgery
// on the one line k3s emits (`server: https://127.0.0.1:6443`), so it
// needs no YAML dependency.
func RewriteKubeconfigServer(kubeconfig, endpoint string) string {
	lines := strings.Split(kubeconfig, "\n")
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "server:") {
			indent := l[:len(l)-len(strings.TrimLeft(l, " \t"))]
			lines[i] = indent + "server: https://" + endpoint
		}
	}
	return strings.Join(lines, "\n")
}

// CA (cluster-autoscaler) deployment paths on the control-plane VM.
// Everything lives outside the tenant-visible Kubernetes API: the CA
// runs as a containerd task under systemd, and its mTLS client
// credential is a file on the platform-owned VM.
const (
	CACredDir         = "/etc/containarium/ca"
	CAClientCertPath  = CACredDir + "/client.crt"
	CAClientKeyPath   = CACredDir + "/client.key"
	CACACertPath      = CACredDir + "/ca.crt"
	CACloudConfigPath = CACredDir + "/cloud-config.yaml"
)

// CADeploy parameterizes the autoscaler unit on the control plane.
type CADeploy struct {
	// ProviderAddr is the daemon's CA-provider mTLS listener as
	// reachable from the VM (host bridge IP:port).
	ProviderAddr string
}

// RenderCACloudConfig renders the stock externalgrpc cloud-config: the
// provider address plus the mTLS client credential paths (the client's
// only supported auth mechanism).
func RenderCACloudConfig(d CADeploy) string {
	return fmt.Sprintf("address: %q\nkey: %q\ncert: %q\ncacert: %q\n",
		d.ProviderAddr, CAClientKeyPath, CAClientCertPath, CACACertPath)
}

// RenderCAUnitScript renders the script that installs and starts the
// cluster-autoscaler systemd unit: the digest-pinned stock image run
// as a plain containerd task via `k3s ctr` — never a Pod, so no
// tenant with cluster-admin can exec into it or read its credential.
func RenderCAUnitScript(d CADeploy) string {
	return fmt.Sprintf(`#!/bin/sh
# containarium managed-cluster autoscaler bootstrap (#1415).
# Stock cluster-autoscaler, digest-pinned, as a containerd task —
# outside the tenant-visible Kubernetes API surface.
set -eu

cat > /etc/systemd/system/k3s-cluster-autoscaler.service <<'UNIT'
[Unit]
Description=containarium managed-cluster autoscaler (externalgrpc)
After=k3s.service
Requires=k3s.service

[Service]
ExecStartPre=%[1]s ctr images pull %[2]s
ExecStartPre=-%[1]s ctr task kill --signal SIGKILL cluster-autoscaler
ExecStartPre=-%[1]s ctr container rm cluster-autoscaler
ExecStart=%[1]s ctr run --rm --net-host \
  --mount type=bind,src=%[3]s,dst=%[3]s,options=rbind:ro \
  --mount type=bind,src=/etc/rancher/k3s/k3s.yaml,dst=/etc/kubeconfig,options=rbind:ro \
  %[2]s cluster-autoscaler \
  /cluster-autoscaler \
  --cloud-provider=externalgrpc \
  --cloud-config=%[4]s \
  --kubeconfig=/etc/kubeconfig \
  --stderrthreshold=info
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now k3s-cluster-autoscaler.service
`, K3sBinaryPath, CAImage, CACredDir, CACloudConfigPath)
}
