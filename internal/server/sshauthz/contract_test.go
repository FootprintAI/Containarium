// Package sshauthz_test holds the SSHAuthzService contract test (#2516):
// the generated gateway and messages, independent of the daemon's server
// (internal/server.SSHAuthzServer).
package sshauthz_test

import (
	"bytes"
	"context"
	"io"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/gateway"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// echoServer checks the request it receives and answers with resp.
type echoServer struct {
	pb.UnimplementedSSHAuthzServiceServer
	t    *testing.T
	want *pb.AuthorizeSSHRequest
	resp *pb.AuthorizeSSHResponse
}

func (s *echoServer) Authorize(_ context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
	if !proto.Equal(req, s.want) {
		s.t.Errorf("server received %v, want %v", req, s.want)
	}
	return s.resp, nil
}

type contractCase struct {
	name string
	req  *pb.AuthorizeSSHRequest
	resp *pb.AuthorizeSSHResponse
}

// contractCases is one ALLOW plus one DENY per SSHDenyReason value, with
// every field populated somewhere: both credential arms (a max uint64
// serial), every key type, cache_ttl, and a device approval.
func contractCases() []contractCase {
	reasons := slices.Sorted(maps.Keys(pb.SSHDenyReason_name))
	keyTypes := slices.Sorted(maps.Keys(pb.SSHKeyType_name))

	// Every third case is a certificate; the rest walk the key types, so
	// with one ALLOW plus one DENY per reason every key type is covered.
	nextKeyType := 0
	credential := func(i int) *pb.SSHCredential {
		if i%3 == 2 {
			return &pb.SSHCredential{Kind: &pb.SSHCredential_Certificate{Certificate: &pb.SSHCertificateCredential{
				KeyId:               "alice@example.com",
				Serial:              math.MaxUint64,
				CaFingerprintSha256: "SHA256:ca",
			}}}
		}
		kt := pb.SSHKeyType(keyTypes[nextKeyType%len(keyTypes)])
		nextKeyType++
		return &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{PublicKey: &pb.SSHPublicKeyCredential{
			FingerprintSha256: "SHA256:key",
			KeyType:           kt,
		}}}
	}
	request := func(i int) *pb.AuthorizeSSHRequest {
		return &pb.AuthorizeSSHRequest{
			Login:      "alice",
			Credential: credential(i),
			ClientIp:   "192.0.2.10",
			SentinelId: "sentinel-1",
			ApprovalId: "appr-1",
		}
	}

	cases := []contractCase{{
		name: "ALLOW",
		req:  request(0),
		resp: &pb.AuthorizeSSHResponse{
			Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW,
			UserId:   "user-1",
			CacheTtl: durationpb.New(30 * time.Second),
		},
	}}
	for i, r := range reasons {
		reason := pb.SSHDenyReason(r)
		resp := &pb.AuthorizeSSHResponse{
			Decision:   pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY,
			DenyReason: reason,
			UserId:     "user-1",
		}
		if reason == pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING {
			resp.Approval = &pb.SSHDeviceApproval{
				ApprovalId: "appr-1",
				Code:       "ABCD-1234",
				Url:        "https://example.com/approve/appr-1",
				PollAfter:  durationpb.New(2 * time.Second),
				ExpiresAt:  timestamppb.New(time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)),
			}
		}
		cases = append(cases, contractCase{name: "DENY_" + reason.String(), req: request(i + 1), resp: resp})
	}
	return cases
}

// TestAuthorizeContract_JSONRoundTrip drives the generated gateway, with the
// daemon's production REST mux, through every decision and deny reason and
// checks that what the sentinel sends and reads back is what the server saw
// and said.
func TestAuthorizeContract_JSONRoundTrip(t *testing.T) {
	for _, tc := range contractCases() {
		t.Run(tc.name, func(t *testing.T) {
			gw := gateway.NewRESTMux()
			if err := pb.RegisterSSHAuthzServiceHandlerServer(context.Background(), gw, &echoServer{t: t, want: tc.req, resp: tc.resp}); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(gw)
			defer srv.Close()

			reqJSON, err := protojson.Marshal(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if cert := tc.req.GetCredential().GetCertificate(); cert != nil && !bytes.Contains(reqJSON, []byte(`"18446744073709551615"`)) {
				t.Fatalf("request JSON %s: want serial as a JSON string", reqJSON)
			}
			res, err := http.Post(srv.URL+"/v1/ssh/authorize", "application/json", bytes.NewReader(reqJSON))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status = %d body = %s", res.StatusCode, body)
			}

			got := &pb.AuthorizeSSHResponse{}
			if err := protojson.Unmarshal(body, got); err != nil {
				t.Fatalf("decode %s: %v", body, err)
			}
			if !proto.Equal(got, tc.resp) {
				t.Fatalf("round trip:\n got  %v\n want %v", got, tc.resp)
			}
			// Enums travel by name, so a renumbering cannot pass silently.
			if want := `"denyReason":"` + tc.resp.GetDenyReason().String() + `"`; !strings.Contains(string(body), want) {
				t.Errorf("body %s: want %s", body, want)
			}
			if want := `"decision":"` + tc.resp.GetDecision().String() + `"`; !strings.Contains(string(body), want) {
				t.Errorf("body %s: want %s", body, want)
			}
		})
	}
}

func TestContractCases_CoverEveryEnumValue(t *testing.T) {
	reasons := map[pb.SSHDenyReason]bool{}
	keyTypes := map[pb.SSHKeyType]bool{}
	certs := 0
	for _, tc := range contractCases() {
		if tc.resp.GetDecision() == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY {
			reasons[tc.resp.GetDenyReason()] = true
		}
		if pk := tc.req.GetCredential().GetPublicKey(); pk != nil {
			keyTypes[pk.GetKeyType()] = true
		} else if tc.req.GetCredential().GetCertificate() != nil {
			certs++
		}
	}
	for v, name := range pb.SSHDenyReason_name {
		if !reasons[pb.SSHDenyReason(v)] {
			t.Errorf("no DENY case for %s", name)
		}
	}
	for v, name := range pb.SSHKeyType_name {
		if !keyTypes[pb.SSHKeyType(v)] {
			t.Errorf("no public-key case for %s", name)
		}
	}
	if certs == 0 {
		t.Error("no certificate case")
	}
}
