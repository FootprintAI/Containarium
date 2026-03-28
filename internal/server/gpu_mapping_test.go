package server

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestMapGPUVendor(t *testing.T) {
	tests := []struct {
		input string
		want  pb.GPUVendor
	}{
		{"NVIDIA", pb.GPUVendor_GPU_VENDOR_NVIDIA},
		{"nvidia", pb.GPUVendor_GPU_VENDOR_NVIDIA},
		{"NVIDIA Corporation", pb.GPUVendor_GPU_VENDOR_NVIDIA},
		{"AMD", pb.GPUVendor_GPU_VENDOR_AMD},
		{"Advanced Micro Devices", pb.GPUVendor_GPU_VENDOR_AMD},
		{"amd", pb.GPUVendor_GPU_VENDOR_AMD},
		{"Intel", pb.GPUVendor_GPU_VENDOR_INTEL},
		{"intel", pb.GPUVendor_GPU_VENDOR_INTEL},
		{"Intel Corporation", pb.GPUVendor_GPU_VENDOR_INTEL},
		{"", pb.GPUVendor_GPU_VENDOR_UNSPECIFIED},
		{"Unknown Vendor", pb.GPUVendor_GPU_VENDOR_UNSPECIFIED},
	}
	for _, tt := range tests {
		got := mapGPUVendor(tt.input)
		if got != tt.want {
			t.Errorf("mapGPUVendor(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestMapGPUModel(t *testing.T) {
	tests := []struct {
		input string
		want  pb.GPUModel
	}{
		// NVIDIA Consumer
		{"NVIDIA GeForce RTX 4090", pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4090},
		{"GeForce RTX 4090", pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4090},
		{"RTX 4080 SUPER", pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4080},
		{"RTX 4070 Ti", pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4070_TI},
		{"GeForce RTX 4070", pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4070},
		{"GeForce RTX 3090", pb.GPUModel_GPU_MODEL_NVIDIA_RTX_3090},
		{"GeForce RTX 3080", pb.GPUModel_GPU_MODEL_NVIDIA_RTX_3080},
		{"GeForce RTX 5090", pb.GPUModel_GPU_MODEL_NVIDIA_RTX_5090},
		{"GeForce RTX 5080", pb.GPUModel_GPU_MODEL_NVIDIA_RTX_5080},

		// NVIDIA Datacenter
		{"NVIDIA A100-SXM4-80GB", pb.GPUModel_GPU_MODEL_NVIDIA_A100},
		{"NVIDIA A10G", pb.GPUModel_GPU_MODEL_NVIDIA_A10G},
		{"NVIDIA A10", pb.GPUModel_GPU_MODEL_NVIDIA_A10},
		{"NVIDIA H100 80GB HBM3", pb.GPUModel_GPU_MODEL_NVIDIA_H100},
		{"NVIDIA H200", pb.GPUModel_GPU_MODEL_NVIDIA_H200},
		{"NVIDIA L40S", pb.GPUModel_GPU_MODEL_NVIDIA_L40S},
		{"NVIDIA L40", pb.GPUModel_GPU_MODEL_NVIDIA_L40},
		{"NVIDIA L4", pb.GPUModel_GPU_MODEL_NVIDIA_L4},
		{"Tesla T4", pb.GPUModel_GPU_MODEL_NVIDIA_T4},
		{"Tesla V100-SXM2-16GB", pb.GPUModel_GPU_MODEL_NVIDIA_V100},
		{"NVIDIA B200", pb.GPUModel_GPU_MODEL_NVIDIA_B200},

		// AMD
		{"AMD Instinct MI300X", pb.GPUModel_GPU_MODEL_AMD_MI300X},
		{"AMD Instinct MI250X", pb.GPUModel_GPU_MODEL_AMD_MI250X},
		{"AMD Radeon RX 7900 XTX", pb.GPUModel_GPU_MODEL_AMD_RX_7900_XTX},

		// Intel
		{"Intel Data Center GPU Max 1550", pb.GPUModel_GPU_MODEL_INTEL_MAX_1550},
		{"Intel Arc A770", pb.GPUModel_GPU_MODEL_INTEL_ARC_A770},

		// Unknown
		{"", pb.GPUModel_GPU_MODEL_UNSPECIFIED},
		{"Some Unknown GPU", pb.GPUModel_GPU_MODEL_UNSPECIFIED},
	}
	for _, tt := range tests {
		got := mapGPUModel(tt.input)
		if got != tt.want {
			t.Errorf("mapGPUModel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// TestMapGPUModel_OrderMatters verifies that more specific models match before generic ones
// e.g., "A10G" matches before "A10", "L40S" before "L40"
func TestMapGPUModel_OrderMatters(t *testing.T) {
	// A10G should not match A10
	if mapGPUModel("NVIDIA A10G") != pb.GPUModel_GPU_MODEL_NVIDIA_A10G {
		t.Error("A10G should match GPU_MODEL_NVIDIA_A10G, not A10")
	}
	// L40S should not match L40
	if mapGPUModel("NVIDIA L40S") != pb.GPUModel_GPU_MODEL_NVIDIA_L40S {
		t.Error("L40S should match GPU_MODEL_NVIDIA_L40S, not L40")
	}
	// RTX 4070 Ti should not match RTX 4070
	if mapGPUModel("RTX 4070 Ti") != pb.GPUModel_GPU_MODEL_NVIDIA_RTX_4070_TI {
		t.Error("RTX 4070 Ti should match GPU_MODEL_NVIDIA_RTX_4070_TI, not RTX_4070")
	}
}
