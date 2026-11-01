package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// peerReplying starts a stand-in peer that answers every request with body,
// the way grpc-gateway does: protobuf JSON, so field names are lowerCamelCase.
func peerReplying(t *testing.T, body string) *PeerClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &PeerClient{ID: "vm2", Addr: srv.Listener.Addr().String(), Healthy: true, client: srv.Client()}
}

// The adopt reply carries the container's new address. The gateway names the
// field newIpAddress; decoding it with encoding/json into the generated struct
// (snake_case tags) silently left it empty, so a move whose copy and adopt both
// succeeded was rolled back with "target returned empty new IP".
func TestForwardAdoptMigratedContainer_DecodesTheGatewayReply(t *testing.T) {
	for name, body := range map[string]string{
		"camelCase, as the gateway sends it":  `{"message":"adopted","newIpAddress":"10.0.3.9"}`,
		"snake_case, as protojson also reads": `{"message":"adopted","new_ip_address":"10.0.3.9"}`,
		"unknown fields from a newer peer":    `{"message":"adopted","newIpAddress":"10.0.3.9","somethingNew":{"a":1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			peer := peerReplying(t, body)
			got, err := forwardAdoptMigratedContainer(peer, "tok", &pb.AdoptMigratedContainerRequest{Username: "alice"})
			if err != nil {
				t.Fatalf("forwardAdoptMigratedContainer: %v", err)
			}
			if got.NewIpAddress != "10.0.3.9" {
				t.Errorf("NewIpAddress = %q, want 10.0.3.9", got.NewIpAddress)
			}
		})
	}
}

func TestForwardAdoptMigratedContainer_RejectsAGarbageReply(t *testing.T) {
	peer := peerReplying(t, `not json`)
	if _, err := forwardAdoptMigratedContainer(peer, "tok", &pb.AdoptMigratedContainerRequest{Username: "alice"}); err == nil {
		t.Fatal("expected a decode error for a reply that is not JSON")
	}
}

// The pre-flight has the same decode. canResolve decoded to false, so an
// encrypted move would have been refused as "cannot resolve" for no reason.
func TestForwardPrepareEncryptedMigration_DecodesTheGatewayReply(t *testing.T) {
	peer := peerReplying(t, `{"canResolve":true,"reason":"","storagePool":"tenant-pool"}`)
	got, err := forwardPrepareEncryptedMigration(peer, "tok", &pb.PrepareEncryptedMigrationRequest{Username: "alice", Tenant: "t"})
	if err != nil {
		t.Fatalf("forwardPrepareEncryptedMigration: %v", err)
	}
	if !got.CanResolve {
		t.Error("CanResolve = false; the gateway's canResolve was not decoded")
	}
	if got.StoragePool != "tenant-pool" {
		t.Errorf("StoragePool = %q, want tenant-pool", got.StoragePool)
	}
}
