// Package incustest provides test doubles for the incus package.
package incustest

import (
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/lxc/incus/v6/shared/api"
)

// MockBackend is a test double for incus.Backend. Lifecycle methods
// (Create/Start/Stop/Delete/Get/List/WaitForNetwork) provide stateful default
// behavior via the Containers map; other methods return zero values by
// default. Any method can be fully overridden by setting the corresponding
// <Method>Func field.
type MockBackend struct {
	// Containers is the in-memory state used by default lifecycle methods.
	Containers map[string]*incus.ContainerInfo

	// WaitNetworkIP, if set, is returned by WaitForNetwork and written to
	// the container's IPAddress field.
	WaitNetworkIP string

	// Override hooks. If non-nil, the method delegates to the function and
	// the default behavior is skipped.
	CreateContainerFunc      func(config incus.ContainerConfig) error
	StartContainerFunc       func(name string) error
	StopContainerFunc        func(name string, force bool) error
	DeleteContainerFunc      func(name string) error
	GetContainerFunc         func(name string) (*incus.ContainerInfo, error)
	ListContainersFunc       func() ([]incus.ContainerInfo, error)
	WaitForNetworkFunc       func(containerName string, timeout time.Duration) (string, error)
	ExecFunc                 func(containerName string, command []string) error
	ExecWithOutputFunc       func(containerName string, command []string) (string, string, error)
	WriteFileFunc            func(containerName, path string, content []byte, mode string) error
	ReadFileFunc             func(containerName, path string) ([]byte, error)
	SetConfigFunc            func(containerName, key, value string) error
	SetDeviceSizeFunc        func(containerName, deviceName, size string) error
	ResolveGPUInputToPCIFunc func(input string) (string, error)
	CleanupDiskFunc          func(containerName string) (string, int64, error)
	UpdateContainerConfigFunc func(name, key, value string) error
	GetRawInstanceFunc       func(name string) (map[string]string, string, error)
	AddLabelFunc             func(containerName, key, value string) error
	RemoveLabelFunc          func(containerName, key string) error
	GetLabelsFunc            func(containerName string) (map[string]string, error)
	SetLabelsFunc            func(containerName string, labels map[string]string) error
	GetServerInfoFunc        func() (*api.Server, error)
	GetContainerMetricsFunc  func(name string) (*incus.ContainerMetrics, error)
}

// NewMockBackend returns a ready-to-use MockBackend with an initialized
// Containers map.
func NewMockBackend() *MockBackend {
	return &MockBackend{
		Containers: make(map[string]*incus.ContainerInfo),
	}
}

func (m *MockBackend) CreateContainer(config incus.ContainerConfig) error {
	if m.CreateContainerFunc != nil {
		return m.CreateContainerFunc(config)
	}
	if m.Containers == nil {
		m.Containers = make(map[string]*incus.ContainerInfo)
	}
	m.Containers[config.Name] = &incus.ContainerInfo{
		Name:      config.Name,
		State:     "Stopped",
		CPU:       config.CPU,
		Memory:    config.Memory,
		CreatedAt: time.Now(),
	}
	return nil
}

func (m *MockBackend) StartContainer(name string) error {
	if m.StartContainerFunc != nil {
		return m.StartContainerFunc(name)
	}
	if c, ok := m.Containers[name]; ok {
		c.State = "Running"
	}
	return nil
}

func (m *MockBackend) StopContainer(name string, force bool) error {
	if m.StopContainerFunc != nil {
		return m.StopContainerFunc(name, force)
	}
	if c, ok := m.Containers[name]; ok {
		c.State = "Stopped"
	}
	return nil
}

func (m *MockBackend) DeleteContainer(name string) error {
	if m.DeleteContainerFunc != nil {
		return m.DeleteContainerFunc(name)
	}
	delete(m.Containers, name)
	return nil
}

func (m *MockBackend) GetContainer(name string) (*incus.ContainerInfo, error) {
	if m.GetContainerFunc != nil {
		return m.GetContainerFunc(name)
	}
	c, ok := m.Containers[name]
	if !ok {
		return nil, nil
	}
	return c, nil
}

func (m *MockBackend) ListContainers() ([]incus.ContainerInfo, error) {
	if m.ListContainersFunc != nil {
		return m.ListContainersFunc()
	}
	out := make([]incus.ContainerInfo, 0, len(m.Containers))
	for _, c := range m.Containers {
		out = append(out, *c)
	}
	return out, nil
}

func (m *MockBackend) WaitForNetwork(containerName string, timeout time.Duration) (string, error) {
	if m.WaitForNetworkFunc != nil {
		return m.WaitForNetworkFunc(containerName, timeout)
	}
	if c, ok := m.Containers[containerName]; ok {
		c.IPAddress = m.WaitNetworkIP
	}
	return m.WaitNetworkIP, nil
}

func (m *MockBackend) Exec(containerName string, command []string) error {
	if m.ExecFunc != nil {
		return m.ExecFunc(containerName, command)
	}
	return nil
}

func (m *MockBackend) ExecWithOutput(containerName string, command []string) (string, string, error) {
	if m.ExecWithOutputFunc != nil {
		return m.ExecWithOutputFunc(containerName, command)
	}
	return "", "", nil
}

func (m *MockBackend) WriteFile(containerName, path string, content []byte, mode string) error {
	if m.WriteFileFunc != nil {
		return m.WriteFileFunc(containerName, path, content, mode)
	}
	return nil
}

func (m *MockBackend) ReadFile(containerName, path string) ([]byte, error) {
	if m.ReadFileFunc != nil {
		return m.ReadFileFunc(containerName, path)
	}
	return nil, nil
}

func (m *MockBackend) SetConfig(containerName, key, value string) error {
	if m.SetConfigFunc != nil {
		return m.SetConfigFunc(containerName, key, value)
	}
	return nil
}

func (m *MockBackend) SetDeviceSize(containerName, deviceName, size string) error {
	if m.SetDeviceSizeFunc != nil {
		return m.SetDeviceSizeFunc(containerName, deviceName, size)
	}
	return nil
}

func (m *MockBackend) ResolveGPUInputToPCI(input string) (string, error) {
	if m.ResolveGPUInputToPCIFunc != nil {
		return m.ResolveGPUInputToPCIFunc(input)
	}
	return "", nil
}

func (m *MockBackend) CleanupDisk(containerName string) (string, int64, error) {
	if m.CleanupDiskFunc != nil {
		return m.CleanupDiskFunc(containerName)
	}
	return "", 0, nil
}

func (m *MockBackend) AddLabel(containerName, key, value string) error {
	if m.AddLabelFunc != nil {
		return m.AddLabelFunc(containerName, key, value)
	}
	return nil
}

func (m *MockBackend) RemoveLabel(containerName, key string) error {
	if m.RemoveLabelFunc != nil {
		return m.RemoveLabelFunc(containerName, key)
	}
	return nil
}

func (m *MockBackend) GetLabels(containerName string) (map[string]string, error) {
	if m.GetLabelsFunc != nil {
		return m.GetLabelsFunc(containerName)
	}
	return nil, nil
}

func (m *MockBackend) SetLabels(containerName string, labels map[string]string) error {
	if m.SetLabelsFunc != nil {
		return m.SetLabelsFunc(containerName, labels)
	}
	return nil
}

func (m *MockBackend) GetServerInfo() (*api.Server, error) {
	if m.GetServerInfoFunc != nil {
		return m.GetServerInfoFunc()
	}
	return nil, nil
}

func (m *MockBackend) GetContainerMetrics(name string) (*incus.ContainerMetrics, error) {
	if m.GetContainerMetricsFunc != nil {
		return m.GetContainerMetricsFunc(name)
	}
	return nil, nil
}

func (m *MockBackend) UpdateContainerConfig(name, key, value string) error {
	if m.UpdateContainerConfigFunc != nil {
		return m.UpdateContainerConfigFunc(name, key, value)
	}
	return nil
}

func (m *MockBackend) GetRawInstance(name string) (map[string]string, string, error) {
	if m.GetRawInstanceFunc != nil {
		return m.GetRawInstanceFunc(name)
	}
	return nil, "", nil
}

// Compile-time assertion that *MockBackend satisfies incus.Backend.
var _ incus.Backend = (*MockBackend)(nil)
