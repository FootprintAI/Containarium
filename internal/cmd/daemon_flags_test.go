//go:build !windows && !containarium_client

package cmd

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// #2735 (slice D of #2263): the compatibility release has shipped. The
// removed bridge DNS flags must now fail parsing rather than remain no-ops.
func TestBridgeDNSFlagsRemoved(t *testing.T) {
	for _, tc := range []struct {
		name string
		arg  string
	}{
		{"bridge-dns-reconcile", "--bridge-dns-reconcile=false"},
		{"bridge-dns-create", "--bridge-dns-create"},
		{"dns-passthrough-host", "--dns-passthrough-host=api.example.com"},
		{"dns-passthrough-host", "--dns-passthrough-host="},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			if daemonCmd.Flags().Lookup(tc.name) != nil {
				t.Errorf("removed flag --%s is still registered", tc.name)
			}

			fs := pflag.NewFlagSet("daemon", pflag.ContinueOnError)
			fs.SetOutput(io.Discard)
			fs.AddFlagSet(daemonCmd.Flags())
			err := fs.Parse([]string{tc.arg})
			if err == nil || !strings.Contains(err.Error(), "unknown flag: --"+tc.name) {
				t.Errorf("parse %q: got %v, want unknown flag: --%s", tc.arg, err, tc.name)
			}
		})
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
