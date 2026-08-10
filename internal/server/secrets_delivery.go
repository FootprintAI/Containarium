package server

import (
	"fmt"

	"github.com/footprintai/containarium/internal/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// secrets_delivery.go — conversion between the storage layer's delivery
// string and the proto SecretDelivery enum.
//
// The enum is the contract going forward (CLAUDE.md: "protobuf enums over
// magic strings"); the legacy `delivery` string stays on the wire so
// existing REST/MCP clients keep working. The DB column also still stores
// the string, so these two functions are the only seam that needs to know
// both representations.

// deliveryToProto maps a storage delivery string onto the enum. An empty
// string means "unset" at the storage layer, which the store normalizes to
// env — so it maps to ENV rather than UNSPECIFIED, keeping the enum a
// faithful view of what will actually happen.
func deliveryToProto(s string) pb.SecretDelivery {
	switch s {
	case secrets.DeliveryFile:
		return pb.SecretDelivery_SECRET_DELIVERY_FILE
	case secrets.DeliveryCompose:
		return pb.SecretDelivery_SECRET_DELIVERY_COMPOSE
	case secrets.DeliveryEnv, "":
		return pb.SecretDelivery_SECRET_DELIVERY_ENV
	default:
		// Unknown values are rejected at the API boundary before they
		// reach storage, so this is unreachable in practice; report
		// UNSPECIFIED rather than guessing a mode.
		return pb.SecretDelivery_SECRET_DELIVERY_UNSPECIFIED
	}
}

// deliveryFromProto maps the enum onto the storage string. UNSPECIFIED
// returns "" so the caller can fall back to the legacy field.
func deliveryFromProto(d pb.SecretDelivery) string {
	switch d {
	case pb.SecretDelivery_SECRET_DELIVERY_ENV:
		return secrets.DeliveryEnv
	case pb.SecretDelivery_SECRET_DELIVERY_FILE:
		return secrets.DeliveryFile
	case pb.SecretDelivery_SECRET_DELIVERY_COMPOSE:
		return secrets.DeliveryCompose
	default:
		return ""
	}
}

// resolveDelivery picks the delivery mode from a SetSecretRequest that may
// carry the typed field, the legacy string, or both.
//
// When both are set they must agree. Silently preferring one would make a
// client that sent contradictory values believe the other took effect —
// the same class of silent divergence as a backend accepting a call it
// cannot honor. Fail loudly instead.
func resolveDelivery(mode pb.SecretDelivery, legacy string) (string, error) {
	typed := deliveryFromProto(mode)
	switch {
	case typed == "" && legacy == "":
		// Neither set: the store normalizes "" to env.
		return "", nil
	case typed == "":
		return legacy, nil
	case legacy == "":
		return typed, nil
	case typed == legacy:
		return typed, nil
	default:
		return "", fmt.Errorf("delivery_mode (%s) and delivery (%q) disagree; set one or make them match", mode, legacy)
	}
}
