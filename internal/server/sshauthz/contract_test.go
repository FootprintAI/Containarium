// Package sshauthz holds the daemon side of SSH live authorization
// (docs/architecture/ssh-live-authorization.md, component 4). This file is
// the contract test for component 1 (#2516): it drives the generated
// grpc-gateway shim and the generated gRPC client against a fake server
// through every SSHDenyReason and asserts the JSON round-trips, so a drift
// between the proto, the gateway and a client fails a test, not a login.
package sshauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeAuthorizer answers Authorize with a canned response and records the
// request it received, so the test can assert both directions.
type fakeAuthorizer struct {
	pb.UnimplementedSSHAuthzServiceServer
	mu   sync.Mutex
	resp *pb.AuthorizeSSHResponse
	got  *pb.AuthorizeSSHRequest
}

func (f *fakeAuthorizer) Authorize(_ context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = proto.Clone(req).(*pb.AuthorizeSSHRequest)
	return proto.Clone(f.resp).(*pb.AuthorizeSSHResponse), nil
}

func (f *fakeAuthorizer) set(resp *pb.AuthorizeSSHResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp = resp
}

func (f *fakeAuthorizer) received() *pb.AuthorizeSSHRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got
}

// harness is the production shape in miniature: the fake behind a real
// grpc.Server on the daemon's in-process listener, the generated gateway
// handler registered on a runtime.ServeMux with the SAME marshaler options
// internal/gateway uses (camelCase names, enums as strings, unpopulated
// fields emitted), and the generated gRPC client dialled to the same server.
type harness struct {
	fake *fakeAuthorizer
	mux  *runtime.ServeMux
	grpc pb.SSHAuthzServiceClient
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fake := &fakeAuthorizer{}
	srv := grpc.NewServer(
		grpc.Creds(auth.NewServerTransportCredentials(nil)),
		grpc.ChainUnaryInterceptor(auth.TransportIdentityUnaryInterceptor()),
	)
	pb.RegisterSSHAuthzServiceServer(srv, fake)
	lis := auth.NewInternalListener()
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(lis.DialContext),
	}
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions:   protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: true, UseEnumNumbers: false},
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
		}),
	)
	if err := pb.RegisterSSHAuthzServiceHandlerFromEndpoint(context.Background(), mux, "passthrough:///containarium-internal", opts); err != nil {
		t.Fatalf("register gateway handler: %v", err)
	}
	conn, err := grpc.NewClient("passthrough:///containarium-internal", opts...)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &harness{fake: fake, mux: mux, grpc: pb.NewSSHAuthzServiceClient(conn)}
}

// post sends req through the REST mapping the way the sentinel plugin does:
// protojson-encoded body to POST /v1/ssh/authorize. It returns the raw body
// (for the encoding assertions) and the decoded response.
func (h *harness) post(t *testing.T, req *pb.AuthorizeSSHRequest) (int, []byte, *pb.AuthorizeSSHResponse) {
	t.Helper()
	body, err := protojson.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/ssh/authorize", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, r)
	raw, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK {
		return rec.Code, raw, nil
	}
	var resp pb.AuthorizeSSHResponse
	if err := protojson.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response %s: %v", raw, err)
	}
	return rec.Code, raw, &resp
}

// jsonField returns the raw JSON value at a top-level key, as a string for
// scalars, so encodings (enum names, "300s", RFC 3339) can be asserted
// without re-deriving them through protojson.
func jsonField(t *testing.T, raw []byte, key string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	v, ok := m[key]
	if !ok {
		t.Fatalf("response %s has no %q field", raw, key)
	}
	return v
}

func sampleRequest() *pb.AuthorizeSSHRequest {
	return &pb.AuthorizeSSHRequest{
		Login: "alice",
		Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
			FingerprintSha256: "SHA256:0123456789abcdef0123456789abcdef0123456789a",
			KeyType:           pb.SSHKeyType_SSH_KEY_TYPE_SK_ED25519,
		}}},
		ClientIp:   "203.0.113.7",
		SentinelId: "sentinel-test",
	}
}

// everyDenyReason is every SSHDenyReason the proto defines, in numeric
// order, read from the generated descriptor so a new value is covered the
// day it is added.
func everyDenyReason() []pb.SSHDenyReason {
	var out []pb.SSHDenyReason
	for n := range pb.SSHDenyReason_name {
		out = append(out, pb.SSHDenyReason(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestContract_EveryDenyReasonRoundTripsThroughGatewayAndClient(t *testing.T) {
	h := newHarness(t)
	reasons := everyDenyReason()
	// The design lists exactly eight values, 0..7; a change here is a
	// contract change the cloud and the sentinel plugin must follow.
	if len(reasons) != 8 || reasons[7] != pb.SSHDenyReason_SSH_DENY_REASON_UPSTREAM_UNAVAILABLE {
		t.Fatalf("SSHDenyReason values = %v, want the eight values 0..7 from the design", reasons)
	}
	expires := time.Date(2026, 10, 13, 12, 34, 56, 0, time.UTC)

	for _, reason := range reasons {
		t.Run(reason.String(), func(t *testing.T) {
			want := &pb.AuthorizeSSHResponse{
				Decision:   pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY,
				DenyReason: reason,
				UserId:     "user-123",
			}
			if reason == pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING {
				want.Approval = &pb.SSHDeviceApproval{
					ApprovalId: "appr-1",
					Code:       "ABCD-1234",
					Url:        "https://example.com/approve/appr-1",
					PollAfter:  durationpb.New(5 * time.Second),
					ExpiresAt:  timestamppb.New(expires),
				}
			}
			h.fake.set(want)

			// REST, as the sentinel plugin calls it.
			code, raw, got := h.post(t, sampleRequest())
			if code != http.StatusOK {
				t.Fatalf("POST /v1/ssh/authorize → %d: %s", code, raw)
			}
			if !proto.Equal(got, want) {
				t.Errorf("REST response drifted:\n got %v\nwant %v", got, want)
			}
			if !proto.Equal(h.fake.received(), sampleRequest()) {
				t.Errorf("request drifted through the gateway:\n got %v\nwant %v", h.fake.received(), sampleRequest())
			}
			// Enums are their NAMES on the wire, never numbers: the sentinel
			// plugin and the cloud's client both switch on the string.
			if s := string(jsonField(t, raw, "denyReason")); s != `"`+reason.String()+`"` {
				t.Errorf("denyReason encoded as %s, want %q", s, reason.String())
			}
			if s := string(jsonField(t, raw, "decision")); s != `"SSH_AUTHZ_DECISION_DENY"` {
				t.Errorf("decision encoded as %s, want \"SSH_AUTHZ_DECISION_DENY\"", s)
			}
			if reason == pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING {
				var approval map[string]json.RawMessage
				if err := json.Unmarshal(jsonField(t, raw, "approval"), &approval); err != nil {
					t.Fatalf("approval: %v", err)
				}
				// google.protobuf.Duration is "<seconds>s", Timestamp is RFC 3339 UTC.
				if s := string(approval["pollAfter"]); s != `"5s"` {
					t.Errorf("approval.pollAfter encoded as %s, want \"5s\"", s)
				}
				if s := string(approval["expiresAt"]); s != `"2026-10-13T12:34:56Z"` {
					t.Errorf("approval.expiresAt encoded as %s, want \"2026-10-13T12:34:56Z\"", s)
				}
			}

			// gRPC, as the daemon's managed-mode forwarder would call the
			// same service shape: the generated client sees the same answer.
			viaGRPC, err := h.grpc.Authorize(context.Background(), sampleRequest())
			if err != nil {
				t.Fatalf("gRPC Authorize: %v", err)
			}
			if !proto.Equal(viaGRPC, want) {
				t.Errorf("gRPC response drifted:\n got %v\nwant %v", viaGRPC, want)
			}
		})
	}
}

func TestContract_AllowCarriesCacheTTLAndUser(t *testing.T) {
	h := newHarness(t)
	want := &pb.AuthorizeSSHResponse{
		Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW,
		UserId:   "user-123",
		CacheTtl: durationpb.New(5 * time.Minute),
	}
	h.fake.set(want)

	code, raw, got := h.post(t, sampleRequest())
	if code != http.StatusOK {
		t.Fatalf("POST → %d: %s", code, raw)
	}
	if !proto.Equal(got, want) {
		t.Errorf("ALLOW response drifted:\n got %v\nwant %v", got, want)
	}
	if s := string(jsonField(t, raw, "cacheTtl")); s != `"300s"` {
		t.Errorf("cacheTtl encoded as %s, want \"300s\"", s)
	}
	// Unpopulated fields are emitted with their zero value, so a client can
	// rely on the key being present: deny_reason is the UNSPECIFIED name.
	if s := string(jsonField(t, raw, "denyReason")); s != `"SSH_DENY_REASON_UNSPECIFIED"` {
		t.Errorf("denyReason on ALLOW encoded as %s, want \"SSH_DENY_REASON_UNSPECIFIED\"", s)
	}
	if s := string(jsonField(t, raw, "approval")); s != `null` {
		t.Errorf("approval on ALLOW encoded as %s, want null", s)
	}
}

func TestContract_CredentialOneofAndKeyTypeRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.fake.set(&pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_NO_ACCESS})

	tests := []struct {
		name string
		cred *pb.SSHCredential
	}{
		{"public key, every key type", nil}, // filled per key type below
		{"certificate", &pb.SSHCredential{Kind: &pb.SSHCredential_Certificate{Certificate: &pb.SSHCertificateCredential{
			KeyId: "alice@laptop", Serial: 42, CaFingerprintSha256: "SHA256:cafingerprint",
		}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := []*pb.SSHCredential{tt.cred}
			if tt.cred == nil {
				creds = nil
				for n := range pb.SSHKeyType_name {
					creds = append(creds, &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
						FingerprintSha256: "SHA256:fp", KeyType: pb.SSHKeyType(n),
					}}})
				}
				if len(creds) != 6 {
					t.Fatalf("SSHKeyType has %d values, want 6 (UNSPECIFIED, ED25519, RSA, ECDSA, SK_ED25519, SK_ECDSA)", len(creds))
				}
			}
			for _, cred := range creds {
				req := sampleRequest()
				req.Credential = cred
				req.ApprovalId = "appr-repoll"
				if code, raw, _ := h.post(t, req); code != http.StatusOK {
					t.Fatalf("POST → %d: %s", code, raw)
				}
				if got := h.fake.received(); !proto.Equal(got, req) {
					t.Errorf("credential %v drifted through the gateway: got %v", cred, got)
				}
			}
		})
	}
}

// The cloud control plane defined SSHKeyType locally with these exact
// numbers before this proto existed; the two must stay wire-identical so
// the cloud can switch to the import without a wire change.
func TestContract_SSHKeyTypeNumbersAreStable(t *testing.T) {
	want := map[pb.SSHKeyType]int32{
		pb.SSHKeyType_SSH_KEY_TYPE_UNSPECIFIED: 0,
		pb.SSHKeyType_SSH_KEY_TYPE_ED25519:     1,
		pb.SSHKeyType_SSH_KEY_TYPE_RSA:         2,
		pb.SSHKeyType_SSH_KEY_TYPE_ECDSA:       3,
		pb.SSHKeyType_SSH_KEY_TYPE_SK_ED25519:  4,
		pb.SSHKeyType_SSH_KEY_TYPE_SK_ECDSA:    5,
	}
	for v, n := range want {
		if int32(v) != n {
			t.Errorf("%s = %d, want %d", v, int32(v), n)
		}
	}
	if len(pb.SSHKeyType_name) != len(want) {
		t.Errorf("SSHKeyType has %d values, want %d", len(pb.SSHKeyType_name), len(want))
	}
}
