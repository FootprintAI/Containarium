package container

import (
	"fmt"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// fakePCIResolver maps index inputs to canned PCI addresses; PCI-shaped inputs
// pass through unchanged, mirroring the real ResolveGPUInputToPCI contract.
func fakePCIResolver(byIndex map[string]string) func(string) (string, error) {
	return func(in string) (string, error) {
		if strings.Contains(in, ":") {
			return in, nil
		}
		if pci, ok := byIndex[in]; ok {
			return pci, nil
		}
		return "", fmt.Errorf("GPU input %q: index out of range", in)
	}
}

func TestResolveGPUDevices_MultiplePinnedByPCI(t *testing.T) {
	mock := &incustest.MockBackend{
		ResolveGPUInputToPCIFunc: fakePCIResolver(map[string]string{
			"0": "0000:01:00.0",
			"1": "0000:0b:00.0",
		}),
	}
	got, err := resolveGPUDevices(mock, []string{"0", "1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []incus.GPUDevice{{PCI: "0000:01:00.0"}, {PCI: "0000:0b:00.0"}}
	if len(got) != len(want) {
		t.Fatalf("got %d devices, want %d (%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i].PCI != want[i].PCI {
			t.Errorf("device[%d].PCI = %q, want %q", i, got[i].PCI, want[i].PCI)
		}
	}
}

func TestResolveGPUDevices_RejectsDuplicateGPU(t *testing.T) {
	// Two different inputs ("0" and a PCI string) that resolve to the SAME
	// physical GPU must be rejected — you can't attach one GPU twice.
	mock := &incustest.MockBackend{
		ResolveGPUInputToPCIFunc: fakePCIResolver(map[string]string{
			"0": "0000:01:00.0",
		}),
	}
	_, err := resolveGPUDevices(mock, []string{"0", "0000:01:00.0"})
	if err == nil {
		t.Fatal("expected duplicate-GPU error, got nil")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("error = %q, want it to mention the GPU was requested more than once", err)
	}
}

func TestResolveGPUDevices_PropagatesResolveError(t *testing.T) {
	mock := &incustest.MockBackend{
		ResolveGPUInputToPCIFunc: fakePCIResolver(map[string]string{"0": "0000:01:00.0"}),
	}
	if _, err := resolveGPUDevices(mock, []string{"0", "9"}); err == nil {
		t.Fatal("expected error for out-of-range index, got nil")
	}
}

func TestResolveGPUDevices_Empty(t *testing.T) {
	got, err := resolveGPUDevices(&incustest.MockBackend{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no devices, got %+v", got)
	}
}
