package secrets

import (
	"errors"
	"strings"
	"testing"
)

// Phase 4.3 Phase A — delivery-field validation tests.
// The SQL roundtrip path lives in the integration suite
// (needs Postgres); here we cover the pure-Go validator
// + constant shape.

func TestValidateDelivery(t *testing.T) {
	cases := map[string]error{
		"":      nil,
		"env":   nil,
		"file":  nil,
		"ENV":   errors.New("any"), // case-sensitive — uppercase rejected
		"tmpfs": errors.New("any"), // alternative names rejected
		"none":  errors.New("any"),
		"  env": errors.New("any"), // no trim — caller's responsibility
	}
	for in, wantErr := range cases {
		t.Run(in, func(t *testing.T) {
			got := ValidateDelivery(in)
			if wantErr == nil {
				if got != nil {
					t.Fatalf("ValidateDelivery(%q): got %v, want nil", in, got)
				}
			} else {
				if got == nil {
					t.Fatalf("ValidateDelivery(%q): got nil, want error", in)
				}
				if !strings.Contains(got.Error(), "delivery") {
					t.Fatalf("error should name the field; got %v", got)
				}
			}
		})
	}
}

func TestDeliveryConstants(t *testing.T) {
	if DeliveryEnv != "env" {
		t.Fatalf("DeliveryEnv = %q; want %q", DeliveryEnv, "env")
	}
	if DeliveryFile != "file" {
		t.Fatalf("DeliveryFile = %q; want %q", DeliveryFile, "file")
	}
}
