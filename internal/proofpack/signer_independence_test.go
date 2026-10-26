package proofpack

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/footprintai/containarium/internal/audit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// signerFields are field names that would make a sealed artifact depend on a
// guardrail signing key: rotating or revoking the key (#2729) could then
// invalidate it.
var signerFields = map[protoreflect.Name]bool{"signature": true, "public_key": true, "key_id": true}

// signerDependence returns the first field reachable from md that holds a
// signature or a key, as "Message.field", or "" when there is none.
func signerDependence(md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) string {
	if seen[md.FullName()] {
		return ""
	}
	seen[md.FullName()] = true
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if signerFields[f.Name()] {
			return string(md.Name()) + "." + string(f.Name())
		}
		if sub := f.Message(); sub != nil {
			if hit := signerDependence(sub, seen); hit != "" {
				return hit
			}
		}
	}
	return ""
}

// TestSealedArtifactsHoldNoSignerKey (#2729): a sealed Proof Pack and an
// audit anchor hold digests only, so rotating or revoking a guardrail
// attestation key cannot affect whether either verifies. If someone later
// embeds an attestation or a key in them, this fails and the rotation doc
// must be revisited.
func TestSealedArtifactsHoldNoSignerKey(t *testing.T) {
	// The walker finds a signature where one exists, so an empty result
	// below means something.
	if hit := signerDependence((&pb.GuardrailAttestation{}).ProtoReflect().Descriptor(), map[protoreflect.FullName]bool{}); hit == "" {
		t.Fatal("walker found no signer field in GuardrailAttestation; it cannot detect one anywhere")
	}
	if hit := signerDependence((&pb.SealedProofPack{}).ProtoReflect().Descriptor(), map[protoreflect.FullName]bool{}); hit != "" {
		t.Fatalf("a sealed Proof Pack holds %s: rotating or revoking a signing key could change whether it verifies", hit)
	}
	var names []string
	at := reflect.TypeOf(audit.AnchorCheckpoint{})
	for i := 0; i < at.NumField(); i++ {
		names = append(names, at.Field(i).Name)
	}
	if !reflect.DeepEqual(names, []string{"Checkpoint", "Root"}) {
		t.Fatalf("audit.AnchorCheckpoint fields = %v, want only Checkpoint and Root (a row id and a chain hash)", names)
	}
}
