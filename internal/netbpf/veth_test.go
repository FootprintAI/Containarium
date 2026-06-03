package netbpf

import "testing"

func TestHostVethFromConfig(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
		want   string
	}{
		{
			name:   "primary eth0",
			config: map[string]string{"volatile.eth0.host_name": "veth1a2b3c4d", "volatile.eth0.hwaddr": "00:16:3e:aa:bb:cc"},
			want:   "veth1a2b3c4d",
		},
		{
			name:   "eth0 preferred over other nics",
			config: map[string]string{"volatile.eth1.host_name": "vethZZZZ", "volatile.eth0.host_name": "vethEEEE"},
			want:   "vethEEEE",
		},
		{
			name:   "non-eth0 nic falls back to lexicographically first",
			config: map[string]string{"volatile.net9.host_name": "vethNINE", "volatile.net1.host_name": "vethONE"},
			want:   "vethONE",
		},
		{
			name:   "whitespace trimmed",
			config: map[string]string{"volatile.eth0.host_name": "  vethTRIM  "},
			want:   "vethTRIM",
		},
		{
			name:   "empty value ignored",
			config: map[string]string{"volatile.eth0.host_name": "   ", "volatile.eth1.host_name": "vethREAL"},
			want:   "vethREAL",
		},
		{
			name:   "stopped container with no host_name",
			config: map[string]string{"volatile.eth0.hwaddr": "00:16:3e:aa:bb:cc"},
			want:   "",
		},
		{
			name:   "nil config",
			config: nil,
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HostVethFromConfig(tt.config); got != tt.want {
				t.Errorf("HostVethFromConfig() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVethIndex_Empty(t *testing.T) {
	if _, err := VethIndex(""); err == nil {
		t.Fatal("expected error for empty veth name")
	}
}

func TestVethIndex_NotFound(t *testing.T) {
	// A name that cannot exist as an interface.
	if _, err := VethIndex("veth-does-not-exist-zzzz"); err == nil {
		t.Fatal("expected error for nonexistent interface")
	}
}
