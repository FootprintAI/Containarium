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
		"":        nil,
		"env":     nil,
		"file":    nil,
		"compose": nil,
		"ENV":     errors.New("any"), // case-sensitive — uppercase rejected
		"tmpfs":   errors.New("any"), // alternative names rejected
		"none":    errors.New("any"),
		"  env":   errors.New("any"), // no trim — caller's responsibility
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
	if DeliveryCompose != "compose" {
		t.Fatalf("DeliveryCompose = %q; want %q", DeliveryCompose, "compose")
	}
}

func TestValidateValueForDelivery(t *testing.T) {
	// Single-line values are fine for any mode.
	for _, mode := range []string{DeliveryEnv, DeliveryFile, DeliveryCompose} {
		if err := ValidateValueForDelivery(mode, "single-line-value"); err != nil {
			t.Errorf("%s/single-line: unexpected error %v", mode, err)
		}
	}
	// Multi-line values are fine for env/file (they don't render to a
	// dotenv) but rejected for compose.
	multi := "line1\nline2"
	if err := ValidateValueForDelivery(DeliveryEnv, multi); err != nil {
		t.Errorf("env/multi-line should be allowed, got %v", err)
	}
	if err := ValidateValueForDelivery(DeliveryFile, multi); err != nil {
		t.Errorf("file/multi-line should be allowed, got %v", err)
	}
	if err := ValidateValueForDelivery(DeliveryCompose, multi); err == nil {
		t.Error("compose/multi-line should be rejected")
	}
	// A bare carriage return also disqualifies compose.
	if err := ValidateValueForDelivery(DeliveryCompose, "a\rb"); err == nil {
		t.Error("compose/CR should be rejected")
	}
}
