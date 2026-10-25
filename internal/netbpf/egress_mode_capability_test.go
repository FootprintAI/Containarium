package netbpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// policyCfgBTF builds the BTF of `struct policy_cfg` as clang -g emits it, with
// lastField naming the 8th byte: "pad" before #2974, "egress_mode" since.
func policyCfgBTF(lastField string) *btf.Struct {
	u32 := &btf.Int{Name: "__u32", Size: 4}
	u8 := &btf.Int{Name: "__u8", Size: 1}
	return &btf.Struct{
		Name: "policy_cfg",
		Size: 8,
		Members: []btf.Member{
			{Name: "tenant_id", Type: u32, Offset: 0},
			{Name: "mode", Type: u8, Offset: 32},
			{Name: "allow_intra", Type: u8, Offset: 40},
			{Name: "allow_metadata", Type: u8, Offset: 48},
			{Name: lastField, Type: u8, Offset: 56},
		},
	}
}

func specWithVethPolicyValue(v btf.Type) *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		mapVethPolicy: {Name: mapVethPolicy, Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 4096, Value: v},
	}}
}

// The loader decides from the object's own BTF whether the program reads the
// egress_mode byte (#2987): an object built before #2974 declares that byte as
// padding, and its program then applies `mode` to the allow-list too.
func TestSpecSupportsEgressMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *ebpf.CollectionSpec
		want bool
	}{
		{"current object (egress_mode member)", specWithVethPolicyValue(policyCfgBTF("egress_mode")), true},
		{"pre-#2974 object (pad member)", specWithVethPolicyValue(policyCfgBTF("pad")), false},
		// A typedef'd or const-qualified value still resolves to the struct.
		{"typedef'd current value", specWithVethPolicyValue(&btf.Typedef{Name: "policy_cfg_t", Type: policyCfgBTF("egress_mode")}), true},
		// No BTF for the value, or no veth_policy map at all: nothing proves the
		// program reads the byte, so it is treated as unsupported.
		{"value without BTF", specWithVethPolicyValue(nil), false},
		{"value is not a struct", specWithVethPolicyValue(&btf.Int{Name: "__u64", Size: 8}), false},
		{"no veth_policy map", &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := specSupportsEgressMode(tc.spec); got != tc.want {
				t.Errorf("specSupportsEgressMode = %v, want %v", got, tc.want)
			}
		})
	}
}
