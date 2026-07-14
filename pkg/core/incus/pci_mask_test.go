package incus

import "testing"

// TestAppendRawLXC pins the append-not-clobber contract: raw.lxc is a
// single string config key, so two independent config decisions (e.g.
// Docker-in-Docker's AppArmor override and PCI masking) that both need to
// contribute lxc.* lines must be joined, not have one overwrite the other.
func TestAppendRawLXC(t *testing.T) {
	cfg := map[string]string{}
	appendRawLXC(cfg, "lxc.apparmor.profile=unconfined")
	if got := cfg["raw.lxc"]; got != "lxc.apparmor.profile=unconfined" {
		t.Fatalf("first append = %q", got)
	}

	appendRawLXC(cfg, pciMaskRawLXC)
	want := "lxc.apparmor.profile=unconfined\n" + pciMaskRawLXC
	if got := cfg["raw.lxc"]; got != want {
		t.Errorf("appended raw.lxc = %q, want %q", got, want)
	}
}

// TestPCIMaskRawLXC pins the exact mount-entry syntax live-validated on a
// real GPU host (RTX 3090): applied via `incus config set` + restart, the
// container stayed healthy, /proc/bus/pci/devices read back empty, and
// /sys/bus/pci/devices/ listed zero entries. Any edit to this string should
// be re-validated the same way before merging — a malformed lxc.mount.entry
// can prevent the container from starting at all.
func TestPCIMaskRawLXC(t *testing.T) {
	want := "lxc.mount.entry = /dev/null proc/bus/pci/devices none bind,optional,create=file 0 0\n" +
		"lxc.mount.entry = tmpfs sys/bus/pci/devices tmpfs rw,size=1k,mode=0755,optional,create=dir 0 0"
	if pciMaskRawLXC != want {
		t.Errorf("pciMaskRawLXC = %q, want %q", pciMaskRawLXC, want)
	}
}
