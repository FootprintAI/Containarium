//go:build !windows && !containarium_client

package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
)

// #2734 (slice C of #2263): deployed systemd units still pass the bridge DNS
// flags, so the daemon must keep accepting them after the reconciler is gone.
// They are hidden, deprecated and do nothing; slice D (#2735) deletes them.
func TestBridgeDNSFlags_DeprecatedNoOps(t *testing.T) {
	names := []string{"bridge-dns-reconcile", "bridge-dns-create", "dns-passthrough-host"}
	for _, name := range names {
		f := daemonCmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("--%s is no longer registered: units that pass it would stop the daemon from starting", name)
		}
		if !f.Hidden {
			t.Errorf("--%s is not hidden", name)
		}
		if f.Deprecated == "" {
			t.Errorf("--%s is not marked deprecated", name)
		}
	}

	// The full set an old unit passes parses without error, including a blank
	// passthrough host that used to fail validation at boot.
	args := []string{
		"--bridge-dns-reconcile=false",
		"--bridge-dns-create",
		"--dns-passthrough-host=api.example.com",
		"--dns-passthrough-host=",
	}
	t.Cleanup(func() {
		for _, name := range names {
			daemonCmd.Flags().Lookup(name).Changed = false
		}
	})
	if err := daemonCmd.Flags().Parse(args); err != nil {
		t.Fatalf("parse %q: %v", args, err)
	}
}

// #3128: --pool-headroom-floor is repeatable, one <pool>=<percent> per
// occurrence, and a bad value fails at parse time rather than at the first
// refused create.
func TestPoolHeadroomFloorFlag(t *testing.T) {
	f := daemonCmd.Flags().Lookup("pool-headroom-floor")
	if f == nil {
		t.Fatal("flag --pool-headroom-floor is not registered")
	}
	reset := func() {
		for k := range poolHeadroomFloors {
			delete(poolHeadroomFloors, k)
		}
		f.Changed = false
	}
	t.Cleanup(reset)

	reset()
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	fs.AddFlag(f)
	if err := fs.Parse([]string{"--pool-headroom-floor=fast=90", "--pool-headroom-floor", "tank=98"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := (map[string]int{"fast": 90, "tank": 98}); !reflect.DeepEqual(map[string]int(poolHeadroomFloors), want) {
		t.Errorf("floors = %v, want %v", poolHeadroomFloors, want)
	}

	for _, bad := range []string{"fast", "fast=85", "fast=100"} {
		reset()
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		fs.AddFlag(f)
		if err := fs.Parse([]string{"--pool-headroom-floor=" + bad}); err == nil {
			t.Errorf("--pool-headroom-floor=%s parsed without error", bad)
		}
	}
}
