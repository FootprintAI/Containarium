//go:build !windows && !containarium_client

package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
)

// #2188: --dns-passthrough-host is validated at boot so a typo fails visibly.
// That only works if every argument the operator typed reaches the validator —
// including an explicit blank — and if a comma is not silently treated as a
// separator. pflag's StringSlice drops a blank value and splits on commas;
// StringArray keeps each occurrence exactly as given.
func TestDNSPassthroughHostFlag_KeepsEveryArgumentAsTyped(t *testing.T) {
	f := daemonCmd.Flags().Lookup("dns-passthrough-host")
	if f == nil {
		t.Fatal("flag --dns-passthrough-host is not registered")
	}
	sv, ok := f.Value.(pflag.SliceValue)
	if !ok {
		t.Fatalf("flag value %T is not a slice value", f.Value)
	}
	reset := func() { _ = sv.Replace(nil); f.Changed = false; dnsPassthroughHosts = nil }
	t.Cleanup(reset)

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"unset", nil, nil},
		{"one host", []string{"--dns-passthrough-host=api.example.com"}, []string{"api.example.com"}},
		{"repeated", []string{"--dns-passthrough-host=a.example.com", "--dns-passthrough-host=b.example.com"}, []string{"a.example.com", "b.example.com"}},
		{"an explicit blank reaches validation", []string{"--dns-passthrough-host="}, []string{""}},
		{"a blank among others reaches validation", []string{"--dns-passthrough-host=a.example.com", "--dns-passthrough-host="}, []string{"a.example.com", ""}},
		{"a comma is not a separator", []string{"--dns-passthrough-host=a.example.com,b.example.com"}, []string{"a.example.com,b.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			if err := daemonCmd.Flags().Parse(tc.args); err != nil {
				t.Fatalf("parse %q: %v", tc.args, err)
			}
			if !reflect.DeepEqual(dnsPassthroughHosts, tc.want) {
				t.Fatalf("hosts = %q; want %q", dnsPassthroughHosts, tc.want)
			}
		})
	}
}
