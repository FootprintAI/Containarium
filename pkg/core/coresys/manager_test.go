package coresys

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

func TestNew(t *testing.T) {
	mockClient := incustest.NewMockBackend()

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
	mockClient := incustest.NewMockBackend()
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
	mockClient := incustest.NewMockBackend()
	manager := New(mockClient, "testpass")

	// Pre-create the core container
	mockClient.Containers[CoreContainerName] = &incus.ContainerInfo{
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
	mockClient := incustest.NewMockBackend()
	mockClient.WaitNetworkIP = "10.0.1.50"

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
	mockClient := incustest.NewMockBackend()
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
	mockClient := incustest.NewMockBackend()
	mockClient.WaitNetworkIP = "10.0.1.50"

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
	mockClient := incustest.NewMockBackend()
	manager := New(mockClient, "testpass")
	manager.coreIP = "10.0.1.50"

	// Pre-create the core container
	mockClient.Containers[CoreContainerName] = &incus.ContainerInfo{
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
	mockClient := incustest.NewMockBackend()
	manager := New(mockClient, "testpass")

	ctx := context.Background()

	t.Run("healthy when container running", func(t *testing.T) {
		mockClient.Containers[CoreContainerName] = &incus.ContainerInfo{
			Name:      CoreContainerName,
			State:     "Running",
			IPAddress: "10.0.1.50",
		}

		if !manager.IsHealthy(ctx) {
			t.Error("IsHealthy() = false, want true")
		}
	})

	t.Run("unhealthy when container not running", func(t *testing.T) {
		mockClient.Containers[CoreContainerName].State = "Stopped"

		if manager.IsHealthy(ctx) {
			t.Error("IsHealthy() = true, want false")
		}
	})

	t.Run("unhealthy when container doesn't exist", func(t *testing.T) {
		delete(mockClient.Containers, CoreContainerName)

		if manager.IsHealthy(ctx) {
			t.Error("IsHealthy() = true, want false")
		}
	})
}

func TestHealthCheck(t *testing.T) {
	mockClient := incustest.NewMockBackend()
	manager := New(mockClient, "testpass")

	ctx := context.Background()

	t.Run("pass when running", func(t *testing.T) {
		mockClient.Containers[CoreContainerName] = &incus.ContainerInfo{
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
		mockClient.Containers[CoreContainerName].State = "Stopped"

		err := manager.healthCheck(ctx)
		if err == nil {
			t.Error("healthCheck() expected error, got nil")
		}
	})

	t.Run("fail when not found", func(t *testing.T) {
		delete(mockClient.Containers, CoreContainerName)

		err := manager.healthCheck(ctx)
		if err == nil {
			t.Error("healthCheck() expected error, got nil")
		}
	})
}

// Benchmark tests
func BenchmarkGetConnectionStrings(b *testing.B) {
	mockClient := incustest.NewMockBackend()
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
