package engine

import (
	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ModelTrafficScanning says whether a run's model responses are scanned by
// the inbound guardrail (#2367). A tenant-secret run talks to the provider
// directly, so its traffic never crosses the gateway and is never scanned.
// A gateway run is scanned exactly when the server policy carries an inbound
// BLOCK rule; policy is nil when it could not be read, which is UNSPECIFIED
// rather than a guess in either direction.
func ModelTrafficScanning(cred Kind, policy *pb.ServerGuardrailPolicy, policyKnown bool) pb.CodeModelTrafficScanning {
	switch cred {
	case KindSecret:
		return pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_TENANT_KEY
	case KindGateway:
		if !policyKnown {
			return pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSPECIFIED
		}
		if len(guardrail.InboundBlockKinds(policy)) > 0 {
			return pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_SCANNED
		}
		return pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_NO_POLICY
	default:
		return pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSPECIFIED
	}
}

// ScanningLine renders the one-line status `code run` prints, shared by the
// CLI and the MCP tool so the two cannot drift.
func ScanningLine(s pb.CodeModelTrafficScanning) string {
	switch s {
	case pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_SCANNED:
		return "model traffic: SCANNED (gateway credential, inbound guardrail rule in force)"
	case pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_NO_POLICY:
		return "model traffic: NOT SCANNED (gateway credential, but the server policy has no inbound BLOCK rule)"
	case pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_TENANT_KEY:
		return "model traffic: NOT SCANNED (the box's own provider key; responses do not cross the gateway)"
	default:
		return "model traffic: scanning status unknown (the server guardrail policy could not be read)"
	}
}
