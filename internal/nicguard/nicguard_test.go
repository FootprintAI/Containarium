package nicguard

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Unset arms the guard (a boundary, not optional hardening); only an
// explicit off-word disables, and a typo fails closed.
func TestParseMode(t *testing.T) {
	tests := []struct {
		in   string
		want Mode
	}{
		{"", ModeEnforce},
		{"enforce", ModeEnforce},
		{"Enforce", ModeEnforce},
		{" enforce ", ModeEnforce},
		{"1", ModeEnforce},
		{"true", ModeEnforce},
		{"typo", ModeEnforce},
		{"off", ModeOff},
		{"OFF", ModeOff},
		{" off ", ModeOff},
		{"0", ModeOff},
		{"false", ModeOff},
		{"no", ModeOff},
		{"disabled", ModeOff},
	}
	for _, tc := range tests {
		if got := ParseMode(tc.in); got != tc.want {
			t.Errorf("ParseMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseBridge(t *testing.T) {
	tests := []struct {
		in         string
		wantBridge string
		wantGW     string
		wantErr    bool
	}{
		{"10.100.0.1/24", "10.100.0.0/24", "10.100.0.1", false},
		{"10.100.0.0/24", "10.100.0.0/24", "10.100.0.1", false},
		{"10.0.3.1/24", "10.0.3.0/24", "10.0.3.1", false},
		{"fd00::1/64", "", "", true},
		{"nope", "", "", true},
	}
	for _, tc := range tests {
		bridge, gw, err := ParseBridge(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseBridge(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseBridge(%q): %v", tc.in, err)
		}
		if bridge != netip.MustParsePrefix(tc.wantBridge) || gw != netip.MustParseAddr(tc.wantGW) {
			t.Errorf("ParseBridge(%q) = %s, %s; want %s, %s", tc.in, bridge, gw, tc.wantBridge, tc.wantGW)
		}
	}
}

type fakeServer struct {
	*incus.UnavailableBackend
	driver string
	exts   []string
}

func (f *fakeServer) GetServerInfo() (*api.Server, error) {
	return &api.Server{
		ServerUntrusted: api.ServerUntrusted{APIExtensions: f.exts},
		Environment:     api.ServerEnvironment{Firewall: f.driver, ServerVersion: "x"},
	}, nil
}

// A host is supportable only with nftables AND the network_bridge_acl
// extension; each failure is an Unsupported error, a server read failure
// is not.
func TestCheckSupport(t *testing.T) {
	tests := []struct {
		name        string
		driver      string
		exts        []string
		wantErr     error
		unsupported bool
	}{
		{"nftables + extension", "nftables", []string{"network_acl", "network_bridge_acl"}, nil, false},
		{"xtables", "xtables", []string{"network_bridge_acl"}, ErrUnsupportedFirewall, true},
		{"incus 6.0 without the extension", "nftables", []string{"network_acl"}, ErrUnsupportedIncus, true},
		{"no extensions at all", "nftables", nil, ErrUnsupportedIncus, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			driver, err := CheckSupport(&fakeServer{UnavailableBackend: incus.NewUnavailableBackend(), driver: tc.driver, exts: tc.exts})
			if driver != tc.driver {
				t.Errorf("driver = %q, want %q", driver, tc.driver)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if Unsupported(err) != tc.unsupported {
				t.Errorf("Unsupported(%v) = %v", err, !tc.unsupported)
			}
		})
	}
	if Unsupported(errors.New("server info: boom")) {
		t.Error("a read failure must not count as unsupported")
	}
}
