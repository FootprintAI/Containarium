package cluster

// Container node runtime (#1429): the profile (the ONE place holding
// the k3s-in-container knowledge) and the ContainerNodeCapable probe.
// Design: docs/architecture/cluster-container-node-pools.md.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// --- the profile ------------------------------------------------------

// The applied Incus config set is golden-pinned: what a tenant's node
// container is granted changes only as a reviewable golden diff.
func TestContainerNodeConfigGolden(t *testing.T) {
	cfg := ContainerNodeConfig()
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, cfg[k])
	}
	golden(t, "container-node-config.golden", b.String())
}

func TestContainerNodeConfigHardLines(t *testing.T) {
	cfg := ContainerNodeConfig()
	if cfg["security.nesting"] != "true" {
		t.Fatalf("security.nesting = %q, want \"true\" (containerd runs pods inside the node)", cfg["security.nesting"])
	}
	// The design's hard line: NO security.privileged, ever. A future
	// k8s feature that seems to need it is a new design conversation,
	// not a config tweak — this test is the tripwire.
	if v, ok := cfg["security.privileged"]; ok {
		t.Fatalf("container node profile sets security.privileged=%q — forbidden by design", v)
	}
}

// --- probe verdict: CheckContainerNodeFacts ---------------------------

func greenFacts() ContainerNodeFacts {
	return ContainerNodeFacts{
		Nesting:     Probe{State: ProbeOK},
		CgroupV2:    Probe{State: ProbeOK},
		BrNetfilter: Probe{State: ProbeOK},
		Overlay:     Probe{State: ProbeOK},
	}
}

func TestCheckContainerNodeFacts(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ContainerNodeFacts)
		wantErr []string // substrings the refusal must name; nil = capable
	}{
		{
			name:   "all preconditions verified",
			mutate: func(*ContainerNodeFacts) {},
		},
		{
			name: "missing nesting is named",
			mutate: func(f *ContainerNodeFacts) {
				f.Nesting = Probe{State: ProbeMissing, Detail: "incus reports no system-container (lxc) driver"}
			},
			wantErr: []string{"nesting", "lxc"},
		},
		{
			name: "missing cgroup v2 is named",
			mutate: func(f *ContainerNodeFacts) {
				f.CgroupV2 = Probe{State: ProbeMissing, Detail: "/sys/fs/cgroup/cgroup.controllers not found"}
			},
			wantErr: []string{"cgroup v2", "cgroup.controllers"},
		},
		{
			name: "missing br_netfilter is named",
			mutate: func(f *ContainerNodeFacts) {
				f.BrNetfilter = Probe{State: ProbeMissing, Detail: "kernel module br_netfilter not present; load it (modprobe br_netfilter)"}
			},
			wantErr: []string{"br_netfilter", "modprobe"},
		},
		{
			name: "missing overlay is named",
			mutate: func(f *ContainerNodeFacts) {
				f.Overlay = Probe{State: ProbeMissing, Detail: "kernel module overlay not present"}
			},
			wantErr: []string{"overlay"},
		},
		{
			name: "unprobeable precondition refuses as unverified, never assumed green",
			mutate: func(f *ContainerNodeFacts) {
				f.BrNetfilter = Probe{State: ProbeUnknown, Detail: "stat /sys/module/br_netfilter: permission denied"}
			},
			wantErr: []string{"br_netfilter", "could not be verified", "permission denied"},
		},
		{
			name: "every problem is named, not just the first",
			mutate: func(f *ContainerNodeFacts) {
				f.CgroupV2 = Probe{State: ProbeMissing, Detail: "host cgroup hierarchy is not cgroup v2"}
				f.Overlay = Probe{State: ProbeUnknown, Detail: "stat /sys/module/overlay: permission denied"}
			},
			wantErr: []string{"cgroup v2", "overlay", "could not be verified"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := greenFacts()
			tc.mutate(&f)
			err := CheckContainerNodeFacts(f)
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("CheckContainerNodeFacts = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("CheckContainerNodeFacts = nil, want a refusal")
			}
			if !errors.Is(err, ErrContainerNodesUnsupported) {
				t.Fatalf("refusal is not ErrContainerNodesUnsupported: %v", err)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("refusal %q does not name %q", err, want)
				}
			}
		})
	}
}

// --- fact gathering from a host filesystem ----------------------------

func lxcDriver() (string, error)  { return "lxc | qemu", nil }
func qemuDriver() (string, error) { return "qemu", nil }

// writeLayout materializes a fake sysroot: entries ending in "/" are
// directories, the rest empty files.
func writeLayout(t *testing.T, root string, entries []string) {
	t.Helper()
	for _, e := range entries {
		p := filepath.Join(root, e)
		if strings.HasSuffix(e, "/") {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

var fullLayout = []string{
	"sys/fs/cgroup/cgroup.controllers",
	"sys/module/br_netfilter/",
	"sys/module/overlay/",
}

func TestGatherContainerNodeFacts(t *testing.T) {
	cases := []struct {
		name   string
		layout []string
		driver func() (string, error)
		check  func(t *testing.T, f ContainerNodeFacts)
	}{
		{
			name:   "everything present verifies green",
			layout: fullLayout,
			driver: lxcDriver,
			check: func(t *testing.T, f ContainerNodeFacts) {
				if err := CheckContainerNodeFacts(f); err != nil {
					t.Fatalf("green host refused: %v", err)
				}
			},
		},
		{
			name:   "cgroup v1 host is missing, with the probed path named",
			layout: []string{"sys/module/br_netfilter/", "sys/module/overlay/"},
			driver: lxcDriver,
			check: func(t *testing.T, f ContainerNodeFacts) {
				if f.CgroupV2.State != ProbeMissing {
					t.Fatalf("CgroupV2 = %+v, want ProbeMissing", f.CgroupV2)
				}
				if !strings.Contains(f.CgroupV2.Detail, "cgroup.controllers") {
					t.Fatalf("detail %q does not name the probed path", f.CgroupV2.Detail)
				}
			},
		},
		{
			name:   "module missing on a plain host says how to load it",
			layout: []string{"sys/fs/cgroup/cgroup.controllers", "sys/module/overlay/"},
			driver: lxcDriver,
			check: func(t *testing.T, f ContainerNodeFacts) {
				if f.BrNetfilter.State != ProbeMissing {
					t.Fatalf("BrNetfilter = %+v, want ProbeMissing", f.BrNetfilter)
				}
				if !strings.Contains(f.BrNetfilter.Detail, "modprobe br_netfilter") {
					t.Fatalf("detail %q does not say how to fix it", f.BrNetfilter.Detail)
				}
			},
		},
		{
			name: "module missing on a NESTED host reports it cannot be fixed from here",
			layout: []string{
				"sys/fs/cgroup/cgroup.controllers",
				"sys/module/overlay/",
				"run/systemd/container", // nested marker
			},
			driver: lxcDriver,
			check: func(t *testing.T, f ContainerNodeFacts) {
				if f.BrNetfilter.State != ProbeMissing {
					t.Fatalf("BrNetfilter = %+v, want ProbeMissing", f.BrNetfilter)
				}
				if !strings.Contains(f.BrNetfilter.Detail, "cannot be loaded from here") {
					t.Fatalf("nested detail %q does not report the nested limitation", f.BrNetfilter.Detail)
				}
			},
		},
		{
			name:   "unreachable incus is unknown, not green",
			layout: fullLayout,
			driver: func() (string, error) { return "", errors.New("connection refused") },
			check: func(t *testing.T, f ContainerNodeFacts) {
				if f.Nesting.State != ProbeUnknown {
					t.Fatalf("Nesting = %+v, want ProbeUnknown", f.Nesting)
				}
				if err := CheckContainerNodeFacts(f); err == nil {
					t.Fatal("unverifiable nesting still passed the probe")
				}
			},
		},
		{
			name:   "no lxc driver is missing",
			layout: fullLayout,
			driver: qemuDriver,
			check: func(t *testing.T, f ContainerNodeFacts) {
				if f.Nesting.State != ProbeMissing {
					t.Fatalf("Nesting = %+v, want ProbeMissing", f.Nesting)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeLayout(t, root, tc.layout)
			tc.check(t, GatherContainerNodeFacts(root, tc.driver))
		})
	}
}
