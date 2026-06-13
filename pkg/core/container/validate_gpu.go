package container

import (
	"fmt"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// gpuValidationImage is the throwaway base image. Minimal Ubuntu; nvidia.runtime
// injects the host driver + nvidia-smi, so nothing needs installing inside.
const gpuValidationImage = "images:ubuntu/24.04"

// Readiness loop tuning. Package vars (not consts) so tests can shrink them.
var (
	gpuValidationReadyTries = 15
	gpuValidationReadyDelay = 1 * time.Second
)

// GPU validation status values (mirror the proto GPUStatus enum).
const (
	GPUStatusOK          = "ok"
	GPUStatusUnavailable = "unavailable"
)

// GPUValidationResult is the outcome of a passthrough check.
type GPUValidationResult struct {
	Status        string // GPUStatusOK | GPUStatusUnavailable
	Model         string // e.g. "NVIDIA GeForce RTX 3090"
	DriverVersion string // e.g. "570.211.01"
	Detail        string // populated when Status != ok
}

// ValidateGPU launches a throwaway nvidia.runtime LXC, attaches the GPU (a
// specific PCI address if given, else all GPUs), runs nvidia-smi inside, and
// tears the container down. Returns the parsed model + driver on success; the
// throwaway is always deleted (best-effort) once it exists, even on failure.
//
// This is the daemon-side counterpart of scripts/validate-gpu-passthrough.sh
// (hardware-verified on an RTX 3090 host): the create→nvidia.runtime→start→
// nvidia-smi sequence was confirmed live before this landed. Never returns an
// error — a failed check is reported as Status=unavailable with a Detail, so a
// CPU-only or mis-bound backend reads cleanly rather than erroring.
func (m *Manager) ValidateGPU(pci string) GPUValidationResult {
	ct := fmt.Sprintf("gpuval-%d", time.Now().UnixNano())

	cfg := incus.ContainerConfig{Name: ct, Image: gpuValidationImage}
	if pci != "" {
		cfg.GPUs = []incus.GPUDevice{{PCI: pci}}
	} else {
		cfg.GPUs = []incus.GPUDevice{{}} // empty device = pass through all GPUs
	}

	if err := m.incus.CreateContainer(cfg); err != nil {
		return GPUValidationResult{Status: GPUStatusUnavailable, Detail: fmt.Sprintf("create throwaway LXC: %v", err)}
	}
	// From here the container exists — always tear it down.
	defer func() { _ = m.incus.DeleteContainer(ct) }()

	// nvidia.runtime makes Incus inject the host NVIDIA driver + nvidia-smi at
	// start (set on the stopped instance, before start).
	if err := m.incus.SetConfig(ct, "nvidia.runtime", "true"); err != nil {
		return GPUValidationResult{Status: GPUStatusUnavailable, Detail: fmt.Sprintf("set nvidia.runtime: %v", err)}
	}
	if err := m.incus.StartContainer(ct); err != nil {
		return GPUValidationResult{Status: GPUStatusUnavailable, Detail: fmt.Sprintf("start throwaway LXC: %v", err)}
	}

	// Wait for the container to be exec-ready, then query the GPU.
	var out string
	var lastErr error
	for i := 0; i < gpuValidationReadyTries; i++ {
		o, _, err := m.incus.ExecWithOutput(ct, []string{
			"nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader",
		})
		if err == nil && strings.TrimSpace(o) != "" {
			out = o
			break
		}
		lastErr = err
		time.Sleep(gpuValidationReadyDelay)
	}

	if strings.TrimSpace(out) == "" {
		detail := "nvidia-smi returned no GPU (passthrough not visible inside the LXC)"
		if lastErr != nil {
			detail = fmt.Sprintf("nvidia-smi did not run: %v", lastErr)
		}
		return GPUValidationResult{Status: GPUStatusUnavailable, Detail: detail}
	}

	model, driver := parseNvidiaSmiCSV(out)
	if model == "" {
		return GPUValidationResult{Status: GPUStatusUnavailable, Detail: "could not parse nvidia-smi output: " + strings.TrimSpace(out)}
	}
	return GPUValidationResult{Status: GPUStatusOK, Model: model, DriverVersion: driver}
}

// parseNvidiaSmiCSV parses the first line of
// `nvidia-smi --query-gpu=name,driver_version --format=csv,noheader`,
// e.g. "NVIDIA GeForce RTX 3090, 570.211.01".
func parseNvidiaSmiCSV(out string) (model, driver string) {
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if line == "" {
		return "", ""
	}
	parts := strings.SplitN(line, ",", 2)
	model = strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		driver = strings.TrimSpace(parts[1])
	}
	return model, driver
}
