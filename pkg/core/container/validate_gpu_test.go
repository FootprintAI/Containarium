package container

import (
	"errors"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

func init() {
	// Keep the readiness loop instant in tests.
	gpuValidationReadyTries = 1
	gpuValidationReadyDelay = 0
}

func TestParseNvidiaSmiCSV(t *testing.T) {
	cases := []struct{ in, model, driver string }{
		{"NVIDIA GeForce RTX 3090, 570.211.01", "NVIDIA GeForce RTX 3090", "570.211.01"},
		{"NVIDIA GeForce RTX 3090, 570.211.01\nNVIDIA A100, 535.0", "NVIDIA GeForce RTX 3090", "570.211.01"},
		{"  NVIDIA L4 ,  550.x  ", "NVIDIA L4", "550.x"},
		{"", "", ""},
		{"weird-no-comma", "weird-no-comma", ""},
	}
	for _, c := range cases {
		m, d := parseNvidiaSmiCSV(c.in)
		if m != c.model || d != c.driver {
			t.Errorf("parseNvidiaSmiCSV(%q) = (%q, %q), want (%q, %q)", c.in, m, d, c.model, c.driver)
		}
	}
}

func TestValidateGPU_OK(t *testing.T) {
	var created incus.ContainerConfig
	var nvruntime string
	started, deleted := false, false
	mock := &incustest.MockBackend{
		CreateContainerFunc: func(cfg incus.ContainerConfig) error { created = cfg; return nil },
		SetConfigFunc: func(_, k, v string) error {
			if k == "nvidia.runtime" {
				nvruntime = v
			}
			return nil
		},
		StartContainerFunc:  func(string) error { started = true; return nil },
		DeleteContainerFunc: func(string) error { deleted = true; return nil },
		ExecWithOutputFunc: func(_ string, _ []string) (string, string, error) {
			return "NVIDIA GeForce RTX 3090, 570.211.01\n", "", nil
		},
	}
	m := NewWithBackend(mock)

	got := m.ValidateGPU("0000:01:00.0")

	if got.Status != GPUStatusOK {
		t.Fatalf("status = %q (detail %q), want ok", got.Status, got.Detail)
	}
	if got.Model != "NVIDIA GeForce RTX 3090" || got.DriverVersion != "570.211.01" {
		t.Errorf("model/driver = %q / %q", got.Model, got.DriverVersion)
	}
	if len(created.GPUs) != 1 || created.GPUs[0].PCI != "0000:01:00.0" {
		t.Errorf("expected throwaway created with one GPU pci=0000:01:00.0, got %+v", created.GPUs)
	}
	if nvruntime != "true" {
		t.Errorf("expected nvidia.runtime=true set, got %q", nvruntime)
	}
	if !started {
		t.Error("expected the throwaway to be started")
	}
	if !deleted {
		t.Error("expected the throwaway to be deleted (teardown)")
	}
}

func TestValidateGPU_AllGPUsWhenNoPCI(t *testing.T) {
	var created incus.ContainerConfig
	mock := &incustest.MockBackend{
		CreateContainerFunc: func(cfg incus.ContainerConfig) error { created = cfg; return nil },
		ExecWithOutputFunc: func(_ string, _ []string) (string, string, error) {
			return "NVIDIA L4, 550.0\n", "", nil
		},
	}
	got := NewWithBackend(mock).ValidateGPU("")
	if got.Status != GPUStatusOK {
		t.Fatalf("status = %q, want ok", got.Status)
	}
	if len(created.GPUs) != 1 || created.GPUs[0].PCI != "" {
		t.Errorf("expected one GPU device with empty PCI (all GPUs), got %+v", created.GPUs)
	}
}

func TestValidateGPU_NoGPU_TearsDown(t *testing.T) {
	deleted := false
	mock := &incustest.MockBackend{
		DeleteContainerFunc: func(string) error { deleted = true; return nil },
		ExecWithOutputFunc: func(_ string, _ []string) (string, string, error) {
			return "", "", errors.New("nvidia-smi: command not found")
		},
	}
	got := NewWithBackend(mock).ValidateGPU("")
	if got.Status != GPUStatusUnavailable {
		t.Fatalf("status = %q, want unavailable", got.Status)
	}
	if got.Detail == "" {
		t.Error("expected a Detail explaining the failure")
	}
	if !deleted {
		t.Error("expected teardown even when validation fails")
	}
}

func TestValidateGPU_CreateFails_NoTeardown(t *testing.T) {
	deleteCalled := false
	mock := &incustest.MockBackend{
		CreateContainerFunc: func(incus.ContainerConfig) error { return errors.New("no GPU device on host") },
		DeleteContainerFunc: func(string) error { deleteCalled = true; return nil },
	}
	got := NewWithBackend(mock).ValidateGPU("")
	if got.Status != GPUStatusUnavailable {
		t.Fatalf("status = %q, want unavailable", got.Status)
	}
	if deleteCalled {
		t.Error("must not attempt teardown when the throwaway was never created")
	}
}

// Guard: the readiness knobs are tiny in tests so failures don't sleep.
func TestValidateGPU_ReadyKnobsSmallInTests(t *testing.T) {
	if gpuValidationReadyDelay != 0 || gpuValidationReadyTries != 1 {
		t.Fatalf("test init() should have shrunk readiness knobs; got tries=%d delay=%v",
			gpuValidationReadyTries, gpuValidationReadyDelay)
	}
}
