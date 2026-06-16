//go:build !k8s

package server

import (
	"github.com/footprintai/containarium/pkg/core/box"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/container"
)

// newBoxBackend selects the box runtime for this build. The default build
// (no `k8s` tag) uses the LXC/incus backend wrapping the daemon's Manager —
// today's behavior. The `k8s` build variant provides a different
// implementation of this same function (boxbackend_k8s.go).
func newBoxBackend(mgr *container.Manager) (box.BoxBackend, error) {
	return boxlxc.New(mgr), nil
}
