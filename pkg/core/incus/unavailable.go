package incus

import (
	"errors"
	"time"

	"github.com/lxc/incus/v6/shared/api"
)

// ErrUnavailable is returned by every UnavailableBackend method. It marks a
// host where incus is not reachable — e.g. the Kubernetes build variant
// running on a node with no incus daemon. Box lifecycle on such a host is
// served by a different box backend (pkg/core/box); any residual incus-only
// operation fails cleanly with this error instead of panicking on a nil
// client.
var ErrUnavailable = errors.New("incus backend not available on this host")

// UnavailableBackend implements Backend with every method returning
// ErrUnavailable. It lets the daemon construct a container.Manager on a host
// without incus so the process can still start; the box-lifecycle surface is
// served by another backend, and the legacy incus-only Manager methods return
// a clear error rather than crash.
type UnavailableBackend struct{}

// NewUnavailableBackend returns an UnavailableBackend.
func NewUnavailableBackend() *UnavailableBackend { return &UnavailableBackend{} }

// Compile-time assertion.
var _ Backend = (*UnavailableBackend)(nil)

func (*UnavailableBackend) CreateContainer(ContainerConfig) error       { return ErrUnavailable }
func (*UnavailableBackend) StartContainer(string) error                 { return ErrUnavailable }
func (*UnavailableBackend) StopContainer(string, bool) error            { return ErrUnavailable }
func (*UnavailableBackend) DeleteContainer(string) error                { return ErrUnavailable }
func (*UnavailableBackend) GetContainer(string) (*ContainerInfo, error) { return nil, ErrUnavailable }
func (*UnavailableBackend) ListContainers() ([]ContainerInfo, error)    { return nil, ErrUnavailable }
func (*UnavailableBackend) WaitForNetwork(string, time.Duration) (string, error) {
	return "", ErrUnavailable
}
func (*UnavailableBackend) Exec(string, []string) error { return ErrUnavailable }
func (*UnavailableBackend) ExecWithOutput(string, []string) (string, string, error) {
	return "", "", ErrUnavailable
}
func (*UnavailableBackend) WriteFile(string, string, []byte, string) error { return ErrUnavailable }
func (*UnavailableBackend) ReadFile(string, string) ([]byte, error)        { return nil, ErrUnavailable }
func (*UnavailableBackend) SetConfig(string, string, string) error         { return ErrUnavailable }
func (*UnavailableBackend) SetCPULimit(string, string) error               { return ErrUnavailable }
func (*UnavailableBackend) UnsetConfig(string, string) error               { return ErrUnavailable }
func (*UnavailableBackend) SetDeviceSize(string, string, string) error     { return ErrUnavailable }
func (*UnavailableBackend) UpdateContainerConfig(string, string, string) error {
	return ErrUnavailable
}
func (*UnavailableBackend) GetRawInstance(string) (map[string]string, string, error) {
	return nil, "", ErrUnavailable
}
func (*UnavailableBackend) ResolveGPUInputToPCI(string) (string, error) { return "", ErrUnavailable }
func (*UnavailableBackend) CleanupDisk(string) (string, int64, error) {
	return "", 0, ErrUnavailable
}
func (*UnavailableBackend) AddLabel(string, string, string) error { return ErrUnavailable }
func (*UnavailableBackend) RemoveLabel(string, string) error      { return ErrUnavailable }
func (*UnavailableBackend) GetLabels(string) (map[string]string, error) {
	return nil, ErrUnavailable
}
func (*UnavailableBackend) SetLabels(string, map[string]string) error { return ErrUnavailable }
func (*UnavailableBackend) GetServerInfo() (*api.Server, error)       { return nil, ErrUnavailable }
func (*UnavailableBackend) GetContainerMetrics(string) (*ContainerMetrics, error) {
	return nil, ErrUnavailable
}
func (*UnavailableBackend) GetContainerImageFingerprint(string) (string, error) {
	return "", ErrUnavailable
}
func (*UnavailableBackend) PublishImage(string, string, map[string]string) (string, error) {
	return "", ErrUnavailable
}
func (*UnavailableBackend) GetImageAliasProperties(string) (map[string]string, bool, error) {
	return nil, false, ErrUnavailable
}
