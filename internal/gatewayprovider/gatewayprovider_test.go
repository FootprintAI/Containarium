package gatewayprovider

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestName_CoversEveryEnumValue is the guard against a new GatewayProvider value
// shipping without a provider name. The enum is the contract, so every value in
// it must resolve — and must round-trip, or the CLI's --provider vocabulary and
// the wire enum have drifted.
func TestName_CoversEveryEnumValue(t *testing.T) {
	if len(pb.GatewayProvider_name) < 2 {
		t.Fatal("the enum has no values besides UNSPECIFIED — test harness broken")
	}
	for value, enumName := range pb.GatewayProvider_name {
		p := pb.GatewayProvider(value)
		got, err := Name(p)

		if p == pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED {
			if err == nil {
				t.Errorf("UNSPECIFIED resolved to %q; it must be rejected, never defaulted", got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s (%d) has no provider name: %v", enumName, value, err)
			continue
		}
		if got == "" {
			t.Errorf("%s resolved to the empty provider name", enumName)
			continue
		}
		back, err := FromName(got)
		if err != nil {
			t.Errorf("FromName(%q): %v", got, err)
			continue
		}
		if back != p {
			t.Errorf("round trip %s -> %q -> %s", enumName, got, back)
		}
	}
}

// The names are not free-form: they must be exactly the keys
// modelgateway.DefaultProviders / ProvidersFromEnv use, or a token would name a
// provider the gateway cannot find.
func TestName_KnownValues(t *testing.T) {
	want := map[pb.GatewayProvider]string{
		pb.GatewayProvider_GATEWAY_PROVIDER_ANTHROPIC:     "anthropic",
		pb.GatewayProvider_GATEWAY_PROVIDER_OPENAI:        "openai",
		pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI:        "gemini",
		pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI_OPENAI: "gemini-openai",
		pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO:       "kafeido",
	}
	for p, name := range want {
		got, err := Name(p)
		if err != nil || got != name {
			t.Errorf("Name(%v) = %q, %v; want %q", p, got, err, name)
		}
	}
}

func TestFromName(t *testing.T) {
	tests := []struct {
		in      string
		want    pb.GatewayProvider
		wantErr bool
	}{
		{in: "kafeido", want: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
		{in: "KAFEIDO", want: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO},
		{in: "  gemini-openai  ", want: pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI_OPENAI},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
		{in: "nope", wantErr: true},
		// The enum's own spelling is NOT the flag's vocabulary — the flag takes
		// the registry name. Accepting both would make the error messages lie
		// about what is valid.
		{in: "GATEWAY_PROVIDER_KAFEIDO", wantErr: true},
		{in: "gemini_openai", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := FromName(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Errorf("FromName(%q) = %v, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("FromName(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("FromName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// Names is used in flag help and in every error message, so it must be stable
// (enum-value order) and must not advertise UNSPECIFIED as a choice.
func TestNames_StableAndExcludesUnspecified(t *testing.T) {
	got := Names()
	if len(got) != len(pb.GatewayProvider_name)-1 {
		t.Errorf("Names() has %d entries, want %d (every value but UNSPECIFIED)", len(got), len(pb.GatewayProvider_name)-1)
	}
	want := []string{"anthropic", "openai", "gemini", "gemini-openai", "kafeido"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("Names() = %v, want %v (enum-value order)", got, want)
		}
	}
}
