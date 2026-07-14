// Package k8s implements box.BoxBackend on Kubernetes, declaring one
// kubernetes-sigs/agent-sandbox Sandbox CR per box: a per-tenant pod an
// agent reaches over SSH, serving the same agent-box stdio MCP surface as the
// LXC backend. See docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md.
//
// The package is always compiled into the daemon binary (no build tag).
// The backend is selected at daemon start-time by CONTAINARIUM_RUNTIME=k8s
// (or --runtime=k8s), not at compile time — one binary, two runtimes.
package k8s
