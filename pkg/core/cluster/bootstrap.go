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
	// Isolation selects the node runtime variant: the container path
	// prepends the boot-time /dev/kmsg shim into the unit (#1429);
	// the zero value renders the VM script byte-identically to
	// pre-#1429.
	Isolation Isolation
	// KubeletArgs are extra `k3s server` flags. k3s server runs an
	// embedded kubelet, so a container-class control plane needs the
	// same kubelet treatment a worker does (#1452). Empty on the VM
	// path, whose unit stays byte-identical to its golden.
	KubeletArgs []string
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
%[5]sExecStart=%[1]s server --disable traefik --node-taint node-role.kubernetes.io/control-plane=:NoSchedule --write-kubeconfig-mode 0600%[2]s%[7]s
Restart=always
RestartSec=5
# A node legitimately takes longer than systemd's default 90s to signal
# readiness -- an agent waits for the server to finish coming up -- and a
# Type=notify unit that has not signalled by then is killed mid-start,
# restarted, and never joins (#1450). Upstream k3s's unit does the same.
TimeoutStartSec=0
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now k3s.service
%[6]s
# Bootstrap is done when the admin kubeconfig and the join token exist.
i=0
until [ -s %[3]s ] && [ -s %[4]s ]; do
  i=$((i+1))
  [ "$i" -gt 120 ] && { echo "k3s server did not come up" >&2; exit 1; }
  sleep 2
done
`, K3sBinaryPath, sanFlags.String(), KubeconfigPath, NodeTokenPath, kmsgShimUnitLine(b.Isolation),
		containerdTemplateStanza(b.Isolation, "k3s.service"), kubeletArgsSuffix(b.KubeletArgs))
}

// AgentBootstrap parameterizes a worker script.
type AgentBootstrap struct {
	// ServerURL is the control-plane's in-host API URL
	// (https://<cp-ip>:6443) — workers join over the private bridge,
	// not the published endpoint.
	ServerURL string
	// Isolation selects the node runtime variant; see ServerBootstrap.
	Isolation Isolation
	// KubeletArgs are extra `k3s agent` flags. Container-class nodes
	// use them to pin allocatable to the size the daemon asked for,
	// because cadvisor reads the outer host's /proc (#1439). Empty on
	// the VM path, whose unit stays byte-identical to its golden.
	KubeletArgs []string
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
%[4]sExecStart=%[1]s agent --server %[3]s --token-file %[2]s%[6]s
Restart=always
RestartSec=5
# A node legitimately takes longer than systemd's default 90s to signal
# readiness -- an agent waits for the server to finish coming up -- and a
# Type=notify unit that has not signalled by then is killed mid-start,
# restarted, and never joins (#1450). Upstream k3s's unit does the same.
TimeoutStartSec=0
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now k3s-agent.service
%[5]s`, K3sBinaryPath, AgentTokenPath, b.ServerURL, kmsgShimUnitLine(b.Isolation),
		workerContainerdNote(b.Isolation), kubeletArgsSuffix(b.KubeletArgs))
}

// workerContainerdNote documents why a worker carries no in-band
// containerd derivation. A worker cannot derive its own: k3s agent
// writes config.toml only after retrieving configuration from the
// server, so waiting for it here blocks on something downstream of the
// startup being blocked (#1448). The daemon pushes the derived
// template — taken from the control plane's generated config — before
// this script runs.
func workerContainerdNote(iso Isolation) string {
	if iso != IsolationContainer {
		return ""
	}
	return "\n# containerd template was pushed by the daemon before boot (#1448).\n"
}

// containerdTemplateStanza derives the containerd config template that
// disables the unprivileged sysctl toggles, on the container path only.
//
// The template is an exact copy of the config k3s just generated with
// the two toggles flipped — never a hand-written template: k3s's base
// template already declares [plugins.'io.containerd.cri.v1.runtime'],
// so a template re-declaring the table renders to invalid TOML,
// containerd refuses the whole config, and k3s never starts (#1444).
// That also means the stanza must run AFTER the unit is enabled — the
// generated config does not exist before k3s's first start — and then
// restart k3s so containerd re-reads it. The wait is bounded and every
// failure path exits loudly: a silent skip would leave every pod
// sandbox broken behind a green bootstrap.
func containerdTemplateStanza(iso Isolation, service string) string {
	if iso != IsolationContainer {
		return ""
	}
	var seds strings.Builder
	sedArgs := ContainerdDeriveTemplateSedArgs()
	for i := 0; i+1 < len(sedArgs); i += 2 {
		fmt.Fprintf(&seds, " %s '%s'", sedArgs[i], sedArgs[i+1])
	}
	var guards strings.Builder
	for _, key := range containerdUnprivilegedToggles {
		fmt.Fprintf(&guards,
			"grep -q '%[1]s = false' %[2]s || { echo \"derived containerd template does not disable %[1]s\" >&2; exit 1; }\n",
			key, ContainerdConfigTemplatePath)
	}
	return fmt.Sprintf(`
# containerd's CRI plugin makes runc write sysctls an unprivileged
# container may not touch, killing every pod sandbox. Derive the config
# template from the config k3s just generated, with the two toggles
# flipped -- a hand-written template would re-declare a table the base
# template already emits, which is invalid TOML (#1444).
i=0
until [ -s %[1]s ]; do
  i=$((i+1))
  [ "$i" -gt 120 ] && { echo "containerd config %[1]s was never generated" >&2; exit 1; }
  sleep 2
done
sed%[2]s %[1]s > %[3]s
%[4]ssystemctl restart %[5]s
`, ContainerdGeneratedConfigPath, seds.String(), ContainerdConfigTemplatePath, guards.String(), service)
}

// kubeletArgsSuffix appends extra flags to the k3s ExecStart line.
// Empty input renders nothing, so a node needing no correction keeps
// the stock command line.
func kubeletArgsSuffix(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return " " + strings.Join(args, " ")
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
// The task runs as uid 0. Upstream's cluster-autoscaler image is
// distroless nonroot, and every file the autoscaler must read on the
// control plane is root-owned and tight: k3s writes
// /etc/rancher/k3s/k3s.yaml 0600, and DeployCA pushes the mTLS client
// key 0600. Run 16 of the container lane caught the first of those —
//
//	Failed to build config: error loading config file
//	"/etc/kubeconfig": open /etc/kubeconfig: permission denied
//
// followed by exit 255 and a unit stuck restarting forever. Loosening
// the file modes instead would only move the failure onto the private
// key and then leave it readable to every user on the node, so the
// credentials stay 0600 and the task gets the uid that can read them
// (#1470).
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
ExecStart=%[1]s ctr run --rm --net-host --user 0 \
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
