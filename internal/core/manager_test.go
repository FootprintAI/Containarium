package core

import (
	"context"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/incus"
)

// mockIncusClient is a mock implementation of the incus.Client for testing
type mockIncusClient struct {
	containers      map[string]*incus.ContainerInfo
	createErr       error
	startErr        error
	getErr          error
	deleteErr       error
	stopErr         error
	execErr         error
	waitNetworkIP   string
	waitNetworkErr  error
}

func newMockIncusClient() *mockIncusClient {
	return &mockIncusClient{
		containers: make(map[string]*incus.ContainerInfo),
	}
}

func (m *mockIncusClient) CreateContainer(config incus.ContainerConfig) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.containers[config.Name] = &incus.ContainerInfo{
		Name:      config.Name,
		State:     "Stopped",
		CPU:       config.CPU,
		Memory:    config.Memory,
		CreatedAt: time.Now(),
	}
	return nil
}

func (m *mockIncusClient) StartContainer(name string) error {
	if m.startErr != nil {
		return m.startErr
	}
	if container, ok := m.containers[name]; ok {
		container.State = "Running"
	}
	return nil
}

func (m *mockIncusClient) StopContainer(name string, force bool) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	if container, ok := m.containers[name]; ok {
		container.State = "Stopped"
	}
	return nil
}

func (m *mockIncusClient) DeleteContainer(name string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.containers, name)
	return nil
}

func (m *mockIncusClient) GetContainer(name string) (*incus.ContainerInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	container, ok := m.containers[name]
	if !ok {
		return nil, nil
	}
	return container, nil
}

func (m *mockIncusClient) WaitForNetwork(name string, timeout time.Duration) (string, error) {
	if m.waitNetworkErr != nil {
		return "", m.waitNetworkErr
	}
	if container, ok := m.containers[name]; ok {
		container.IPAddress = m.waitNetworkIP
	}
	return m.waitNetworkIP, nil
}

func (m *mockIncusClient) Exec(containerName string, command []string) error {
	return m.execErr
}

func TestNew(t *testing.T) {
	mockClient := newMockIncusClient()

	t.Run("with password", func(t *testing.T) {
		manager := New(mockClient, "mypassword")
		if manager == nil {
			t.Fatal("New() returned nil")
		}
		if manager.password != "mypassword" {
			t.Errorf("password = %v, want %v", manager.password, "mypassword")
		}
	})

	t.Run("with empty password uses default", func(t *testing.T) {
		manager := New(mockClient, "")
		if manager.password != "changeme" {
			t.Errorf("password = %v, want %v", manager.password, "changeme")
		}
	})
}

func TestGetConnectionStrings(t *testing.T) {
	mockClient := newMockIncusClient()
	manager := New(mockClient, "testpass")
	manager.coreIP = "10.0.1.50"

	t.Run("GetPostgresConnectionString", func(t *testing.T) {
		expected := "postgres://containarium:testpass@10.0.1.50:5432/containarium?sslmode=disable"
		got := manager.GetPostgresConnectionString()
		if got != expected {
			t.Errorf("GetPostgresConnectionString() = %v, want %v", got, expected)
		}
	})

	t.Run("GetRedisAddress", func(t *testing.T) {
		expected := "10.0.1.50:6379"
		got := manager.GetRedisAddress()
		if got != expected {
			t.Errorf("GetRedisAddress() = %v, want %v", got, expected)
		}
	})

	t.Run("GetCaddyAdminURL", func(t *testing.T) {
		expected := "http://10.0.1.50:2019"
		got := manager.GetCaddyAdminURL()
		if got != expected {
			t.Errorf("GetCaddyAdminURL() = %v, want %v", got, expected)
		}
	})

	t.Run("GetCoreIP", func(t *testing.T) {
		expected := "10.0.1.50"
		got := manager.GetCoreIP()
		if got != expected {
			t.Errorf("GetCoreIP() = %v, want %v", got, expected)
		}
	})
}

func TestEnsureCoreContainer_ExistingContainer(t *testing.T) {
	mockClient := newMockIncusClient()
	manager := New(mockClient, "testpass")

	// Pre-create the core container
	mockClient.containers[CoreContainerName] = &incus.ContainerInfo{
		Name:      CoreContainerName,
		State:     "Running",
		IPAddress: "10.0.1.50",
	}

	ctx := context.Background()
	config := Config{
		AutoCreate: false,
	}

	err := manager.EnsureCoreContainer(ctx, config)
	if err != nil {
		t.Errorf("EnsureCoreContainer() unexpected error = %v", err)
	}

	if manager.coreIP != "10.0.1.50" {
		t.Errorf("coreIP = %v, want %v", manager.coreIP, "10.0.1.50")
	}
}

func TestEnsureCoreContainer_CreateNew(t *testing.T) {
	mockClient := newMockIncusClient()
	mockClient.waitNetworkIP = "10.0.1.50"

	manager := New(mockClient, "testpass")

	ctx := context.Background()
	config := Config{
		AutoCreate:       true,
		PostgresPassword: "secure",
		CPU:              "4",
		Memory:           "8GB",
		Disk:             "100GB",
	}

	err := manager.EnsureCoreContainer(ctx, config)
	if err != nil {
		t.Errorf("EnsureCoreContainer() unexpected error = %v", err)
	}

	// Verify container was created
	container, _ := mockClient.GetContainer(CoreContainerName)
	if container == nil {
		t.Fatal("container was not created")
	}

	if container.State != "Running" {
		t.Errorf("container state = %v, want Running", container.State)
	}

	if container.CPU != "4" {
		t.Errorf("container CPU = %v, want 4", container.CPU)
	}

	if manager.coreIP != "10.0.1.50" {
		t.Errorf("coreIP = %v, want 10.0.1.50", manager.coreIP)
	}
}

func TestEnsureCoreContainer_AutoCreateDisabled(t *testing.T) {
	mockClient := newMockIncusClient()
	manager := New(mockClient, "testpass")

	ctx := context.Background()
	config := Config{
		AutoCreate: false,
	}

	err := manager.EnsureCoreContainer(ctx, config)
	if err == nil {
		t.Error("EnsureCoreContainer() expected error, got nil")
	}
}

func TestEnsureCoreContainer_DefaultResources(t *testing.T) {
	mockClient := newMockIncusClient()
	mockClient.waitNetworkIP = "10.0.1.50"

	manager := New(mockClient, "testpass")

	ctx := context.Background()
	config := Config{
		AutoCreate: true,
		// No custom resources specified
	}

	err := manager.EnsureCoreContainer(ctx, config)
	if err != nil {
		t.Errorf("EnsureCoreContainer() unexpected error = %v", err)
	}

	container, _ := mockClient.GetContainer(CoreContainerName)
	if container == nil {
		t.Fatal("container was not created")
	}

	if container.CPU != DefaultCoreCPU {
		t.Errorf("container CPU = %v, want %v", container.CPU, DefaultCoreCPU)
	}

	if container.Memory != DefaultCoreMemory {
		t.Errorf("container Memory = %v, want %v", container.Memory, DefaultCoreMemory)
	}
}

func TestDestroy(t *testing.T) {
	mockClient := newMockIncusClient()
	manager := New(mockClient, "testpass")
	manager.coreIP = "10.0.1.50"

	// Pre-create the core container
	mockClient.containers[CoreContainerName] = &incus.ContainerInfo{
		Name:      CoreContainerName,
		State:     "Running",
		IPAddress: "10.0.1.50",
	}

	ctx := context.Background()
	err := manager.Destroy(ctx)
	if err != nil {
		t.Errorf("Destroy() unexpected error = %v", err)
	}

	// Verify container was deleted
	container, _ := mockClient.GetContainer(CoreContainerName)
	if container != nil {
		t.Error("container was not deleted")
	}

	if manager.coreIP != "" {
		t.Errorf("coreIP should be empty after destroy, got %v", manager.coreIP)
	}
}

func TestIsHealthy(t *testing.T) {
	mockClient := newMockIncusClient()
	manager := New(mockClient, "testpass")

	ctx := context.Background()

	t.Run("healthy when container running", func(t *testing.T) {
		mockClient.containers[CoreContainerName] = &incus.ContainerInfo{
			Name:      CoreContainerName,
			State:     "Running",
			IPAddress: "10.0.1.50",
		}

		if !manager.IsHealthy(ctx) {
			t.Error("IsHealthy() = false, want true")
		}
	})

	t.Run("unhealthy when container not running", func(t *testing.T) {
		mockClient.containers[CoreContainerName].State = "Stopped"

		if manager.IsHealthy(ctx) {
			t.Error("IsHealthy() = true, want false")
		}
	})

	t.Run("unhealthy when container doesn't exist", func(t *testing.T) {
		delete(mockClient.containers, CoreContainerName)

		if manager.IsHealthy(ctx) {
			t.Error("IsHealthy() = true, want false")
		}
	})
}

func TestHealthCheck(t *testing.T) {
	mockClient := newMockIncusClient()
	manager := New(mockClient, "testpass")

	ctx := context.Background()

	t.Run("pass when running", func(t *testing.T) {
		mockClient.containers[CoreContainerName] = &incus.ContainerInfo{
			Name:      CoreContainerName,
			State:     "Running",
			IPAddress: "10.0.1.50",
		}

		err := manager.healthCheck(ctx)
		if err != nil {
			t.Errorf("healthCheck() unexpected error = %v", err)
		}

		if manager.coreIP != "10.0.1.50" {
			t.Errorf("coreIP = %v, want 10.0.1.50", manager.coreIP)
		}
	})

	t.Run("fail when stopped", func(t *testing.T) {
		mockClient.containers[CoreContainerName].State = "Stopped"

		err := manager.healthCheck(ctx)
		if err == nil {
			t.Error("healthCheck() expected error, got nil")
		}
	})

	t.Run("fail when not found", func(t *testing.T) {
		delete(mockClient.containers, CoreContainerName)

		err := manager.healthCheck(ctx)
		if err == nil {
			t.Error("healthCheck() expected error, got nil")
		}
	})
}

// Benchmark tests
func BenchmarkGetConnectionStrings(b *testing.B) {
	mockClient := newMockIncusClient()
	manager := New(mockClient, "testpass")
	manager.coreIP = "10.0.1.50"

	b.Run("GetPostgresConnectionString", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = manager.GetPostgresConnectionString()
		}
	})

	b.Run("GetRedisAddress", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = manager.GetRedisAddress()
		}
	})

	b.Run("GetCaddyAdminURL", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = manager.GetCaddyAdminURL()
		}
	})
}
