package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// #1001: ForwardCreateContainer hand-copied a subset of the request into a
// map[string]interface{}, silently dropping every field nobody remembered to
// add. Creating on a tunnel-connected backend and creating locally quietly
// meant different things.
//
// The worst of the dropped fields were `encrypted` and `tenant_id`: a
// `create --encrypted` aimed at a remote backend produced an UNENCRYPTED
// container and reported success.

// fullCreateRequest sets every field of CreateContainerRequest to a non-zero
// value, so "was anything dropped?" can be asked of the whole message rather
// than of a list someone has to maintain.
func fullCreateRequest() *pb.CreateContainerRequest {
	return &pb.CreateContainerRequest{
		Username:                  "alice",
		Resources:                 &pb.ResourceLimits{Cpu: "4", Memory: "4GB", Disk: "50GB"},
		SshKeys:                   []string{"ssh-ed25519 AAAA test"},
		Labels:                    map[string]string{"team": "platform"},
		Image:                     "ubuntu:24.04",
		EnablePodman:              true,
		Async:                     true,
		StaticIp:                  "10.0.0.5",
		Stack:                     "python",
		Gpu:                       "gpu0",
		BackendId:                 "peer-a",
		OsType:                    pb.OSType_OS_TYPE_UBUNTU_2404,
		StackParameters:           map[string]string{"version": "3.12"},
		Monitoring:                true,
		Pool:                      "gpu-pool",
		GitSource:                 "https://example.com/repo.git",
		GitRef:                    "main",
		GitCredential:             "cred-1",
		WorkspacePath:             "/workspace",
		TtlSeconds:                3600,
		IdleStopMinutes:           30,
		DeleteAfterStoppedSeconds: 7200,
		Gpus:                      []string{"gpu0"},
		Encrypted:                 true,
		TenantId:                  "default",
	}
}

// capturingPeer records the forwarded body and replies with a full response.
func capturingPeer(t *testing.T, body *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*body = string(b)
		_, _ = w.Write([]byte(`{
			"container": {
				"name": "alice-container",
				"username": "alice",
				"state": "CONTAINER_STATE_RUNNING",
				"network": {"ipAddress": "10.0.0.5"},
				"resources": {"cpu": "4", "memory": "4GB", "disk": "50GB"},
				"sshHost": "edge.example",
				"pool": "gpu-pool"
			},
			"message": "created",
			"sshCommand": "ssh alice@edge.example"
		}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func peerClientFor(srv *httptest.Server) *PeerClient {
	return &PeerClient{
		ID:     "peer-a",
		Addr:   strings.TrimPrefix(srv.URL, "http://"),
		client: srv.Client(),
	}
}

// THE test: nothing set on the request may be missing from what is forwarded.
//
// Asserted over the whole message rather than a hand-listed set of fields —
// the bug WAS a hand-listed set of fields. A field added to the proto later is
// covered by this automatically, without anyone remembering this file.
func TestForwardCreateContainer_ForwardsEveryField(t *testing.T) {
	var forwarded string
	srv := capturingPeer(t, &forwarded)
	req := fullCreateRequest()

	if _, err := peerClientFor(srv).ForwardCreateContainer("token", req); err != nil {
		t.Fatalf("ForwardCreateContainer: %v", err)
	}

	var got pb.CreateContainerRequest
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal([]byte(forwarded), &got); err != nil {
		t.Fatalf("forwarded body is not a valid CreateContainerRequest: %v\n%s", err, forwarded)
	}

	// backend_id is intentionally cleared; everything else must survive.
	want := proto.Clone(req).(*pb.CreateContainerRequest)
	want.BackendId = ""

	if !proto.Equal(want, &got) {
		// Name the specific fields that went missing — a bare "not equal" on
		// a 25-field message is not a usable failure.
		var missing []string
		want.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			if !got.ProtoReflect().Has(fd) {
				missing = append(missing, string(fd.Name()))
			}
			return true
		})
		t.Errorf("fields dropped while forwarding: %v\nsent: %v\ngot:  %v", missing, want, &got)
	}
}

// The two that matter most, called out on their own so a regression reads as
// a security problem rather than a diffing problem.
func TestForwardCreateContainer_ForwardsEncryptionIntent(t *testing.T) {
	var forwarded string
	srv := capturingPeer(t, &forwarded)

	req := &pb.CreateContainerRequest{
		Username:  "alice",
		Resources: &pb.ResourceLimits{Cpu: "2", Memory: "2GB", Disk: "10GB"},
		BackendId: "peer-a",
		Encrypted: true,
		TenantId:  "acme",
	}
	if _, err := peerClientFor(srv).ForwardCreateContainer("token", req); err != nil {
		t.Fatalf("ForwardCreateContainer: %v", err)
	}

	var got pb.CreateContainerRequest
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal([]byte(forwarded), &got); err != nil {
		t.Fatalf("unmarshal forwarded body: %v", err)
	}
	if !got.Encrypted {
		t.Error("`encrypted` was not forwarded: a --encrypted create aimed at a remote backend " +
			"would produce an UNENCRYPTED container and report success (#1001)")
	}
	if got.TenantId != "acme" {
		t.Errorf("tenant_id = %q, want \"acme\" — the wrong tenant's key would be used", got.TenantId)
	}
}

// backend_id must NOT be forwarded: the peer is the target, and leaving it set
// would have the peer evaluate routing again instead of creating locally.
func TestForwardCreateContainer_ClearsBackendID(t *testing.T) {
	var forwarded string
	srv := capturingPeer(t, &forwarded)

	req := fullCreateRequest()
	if _, err := peerClientFor(srv).ForwardCreateContainer("token", req); err != nil {
		t.Fatalf("ForwardCreateContainer: %v", err)
	}

	var got pb.CreateContainerRequest
	_ = (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal([]byte(forwarded), &got)
	if got.BackendId != "" {
		t.Errorf("backend_id = %q was forwarded; the peer would try to route onwards", got.BackendId)
	}

	// The caller's own request must not be mutated — it is used after this
	// returns, and clearing a field on it would be an invisible side effect.
	if req.BackendId != "peer-a" {
		t.Errorf("the caller's request was mutated: backend_id is now %q", req.BackendId)
	}
}

// The response side had the same defect, and one field worse: `state` was
// parsed into a struct field that was then never assigned, so a container
// created on a peer came back reporting no state at all.
func TestForwardCreateContainer_DecodesFullResponse(t *testing.T) {
	var forwarded string
	srv := capturingPeer(t, &forwarded)

	resp, err := peerClientFor(srv).ForwardCreateContainer("token", fullCreateRequest())
	if err != nil {
		t.Fatalf("ForwardCreateContainer: %v", err)
	}
	if resp.Container == nil {
		t.Fatal("no container in the response")
	}

	if resp.Container.State != pb.ContainerState_CONTAINER_STATE_RUNNING {
		t.Errorf("state = %v, want RUNNING — it was parsed and then dropped on the floor", resp.Container.State)
	}
	if resp.Container.SshHost != "edge.example" {
		t.Errorf("ssh_host = %q, want it preserved", resp.Container.SshHost)
	}
	if resp.Container.Pool != "gpu-pool" {
		t.Errorf("pool = %q, want it preserved", resp.Container.Pool)
	}
	// Still stamped with which backend it landed on.
	if resp.Container.BackendId != "peer-a" {
		t.Errorf("backend_id = %q, want the peer's ID", resp.Container.BackendId)
	}
	if resp.Message != "created" || resp.SshCommand == "" {
		t.Errorf("message/sshCommand lost: %q / %q", resp.Message, resp.SshCommand)
	}
}

// A peer running a newer daemon sends fields this build has never heard of.
// That must decode, not fail the create after the container already exists.
func TestForwardCreateContainer_ToleratesUnknownResponseFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"container":{"name":"alice-container","somethingNew":true},"message":"ok","alsoNew":42}`))
	}))
	defer srv.Close()

	resp, err := peerClientFor(srv).ForwardCreateContainer("token", fullCreateRequest())
	if err != nil {
		t.Fatalf("a newer peer's extra fields broke the decode: %v", err)
	}
	if resp.Container.GetName() != "alice-container" {
		t.Errorf("name = %q", resp.Container.GetName())
	}
}
