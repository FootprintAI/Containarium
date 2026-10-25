//go:build ebpf_load

package netbpf

import (
	"os"
	"testing"
)

// envPreEgressModeObject names a netpolicy.bpf.o compiled from the source just
// before #2974, when policy_cfg's last byte was padding. The ebpf-load workflow
// builds it from that commit and exports the path.
const envPreEgressModeObject = "NETBPF_PRE_EGRESS_MODE_OBJECT"

// A real compiled object of each generation loads into the kernel, and the
// loader tells them apart (#2987): the freshly built object reads egress_mode,
// the pre-#2974 one does not, so the daemon reports `mode` for it.
func TestLoad_DetectsEgressModeSupport(t *testing.T) {
	current, err := Load(ebpfLoadObjPath)
	if err != nil {
		t.Fatalf("Load(current): %v", err)
	}
	defer func() { _ = current.Close() }()
	if !current.SupportsEgressMode() {
		t.Errorf("current %s: SupportsEgressMode = false, want true", ebpfLoadObjPath)
	}

	oldPath := os.Getenv(envPreEgressModeObject)
	if oldPath == "" {
		// The lane fails on any skip, so this only lets a local run without
		// the old object through.
		t.Skipf("%s not set; build the pre-#2974 object as .github/workflows/ebpf-load.yml does", envPreEgressModeObject)
	}
	old, err := Load(oldPath)
	if err != nil {
		t.Fatalf("Load(pre-#2974 object): %v", err)
	}
	defer func() { _ = old.Close() }()
	if old.SupportsEgressMode() {
		t.Errorf("pre-#2974 object %s: SupportsEgressMode = true, want false", oldPath)
	}
}
