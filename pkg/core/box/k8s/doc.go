// Package k8s implements box.BoxBackend on Kubernetes: a per-tenant pod an
// agent reaches over SSH, serving the same agent-box stdio MCP surface as the
// LXC backend. See docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md.
//
// The implementation lives behind the `k8s` build tag (k8s.go) so the heavy
// k8s.io/client-go dependency never enters the default daemon build — only a
// `containarium-k8s` build variant compiles it. This file carries no build
// constraint so the package always has a buildable file (otherwise
// `go build ./...` would fail with "build constraints exclude all Go files");
// it intentionally contains nothing but the package declaration and this doc.
//
// Status: skeleton. The Backend type satisfies box.BoxBackend at compile time
// (under -tags k8s) but every method returns ErrNotImplemented. The client-go
// wiring + the StatefulSet/Service/NetworkPolicy/PiperUpstream reconciliation
// land in follow-ups; this scaffold fixes the package shape and the build-tag
// seam first.
package k8s
