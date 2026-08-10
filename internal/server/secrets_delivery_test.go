package server

import (
	"testing"

	"github.com/footprintai/containarium/internal/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestDeliveryToProto(t *testing.T) {
	tests := []struct {
		in   string
		want pb.SecretDelivery
	}{
		{secrets.DeliveryEnv, pb.SecretDelivery_SECRET_DELIVERY_ENV},
		{secrets.DeliveryFile, pb.SecretDelivery_SECRET_DELIVERY_FILE},
		{secrets.DeliveryCompose, pb.SecretDelivery_SECRET_DELIVERY_COMPOSE},
		// "" is "unset" in storage, which the store normalizes to env — so
		// the enum must report ENV, not UNSPECIFIED, or the typed view would
		// disagree with what actually happens to the secret.
		{"", pb.SecretDelivery_SECRET_DELIVERY_ENV},
		{"bogus", pb.SecretDelivery_SECRET_DELIVERY_UNSPECIFIED},
	}
	for _, tc := range tests {
		if got := deliveryToProto(tc.in); got != tc.want {
			t.Errorf("deliveryToProto(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestDeliveryFromProto(t *testing.T) {
	tests := []struct {
		in   pb.SecretDelivery
		want string
	}{
		{pb.SecretDelivery_SECRET_DELIVERY_ENV, secrets.DeliveryEnv},
		{pb.SecretDelivery_SECRET_DELIVERY_FILE, secrets.DeliveryFile},
		{pb.SecretDelivery_SECRET_DELIVERY_COMPOSE, secrets.DeliveryCompose},
		{pb.SecretDelivery_SECRET_DELIVERY_UNSPECIFIED, ""},
	}
	for _, tc := range tests {
		if got := deliveryFromProto(tc.in); got != tc.want {
			t.Errorf("deliveryFromProto(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Every mode must survive a round trip, or the enum and the DB column drift.
func TestDeliveryRoundTrip(t *testing.T) {
	for _, mode := range []string{secrets.DeliveryEnv, secrets.DeliveryFile, secrets.DeliveryCompose} {
		if got := deliveryFromProto(deliveryToProto(mode)); got != mode {
			t.Errorf("round trip %q → %v → %q", mode, deliveryToProto(mode), got)
		}
	}
}

func TestResolveDelivery(t *testing.T) {
	tests := []struct {
		name    string
		mode    pb.SecretDelivery
		legacy  string
		want    string
		wantErr bool
	}{
		{
			name: "neither set defers to the store's default",
			want: "",
		},
		{
			name: "typed only",
			mode: pb.SecretDelivery_SECRET_DELIVERY_FILE,
			want: secrets.DeliveryFile,
		},
		{
			name:   "legacy only — an existing REST/MCP client keeps working",
			legacy: secrets.DeliveryCompose,
			want:   secrets.DeliveryCompose,
		},
		{
			name:   "both set and agreeing",
			mode:   pb.SecretDelivery_SECRET_DELIVERY_FILE,
			legacy: secrets.DeliveryFile,
			want:   secrets.DeliveryFile,
		},
		{
			// The important case. Silently preferring one would let a client
			// that sent contradictory values believe the other took effect.
			name:    "both set and disagreeing is rejected, not silently resolved",
			mode:    pb.SecretDelivery_SECRET_DELIVERY_FILE,
			legacy:  secrets.DeliveryEnv,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveDelivery(tc.mode, tc.legacy)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveDelivery(%v, %q) = %q, want error", tc.mode, tc.legacy, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveDelivery(%v, %q) = %q, want %q", tc.mode, tc.legacy, got, tc.want)
			}
		})
	}
}
