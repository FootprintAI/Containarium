package server

import (
	"context"
	"encoding/json"
	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTenantAccessRESTSignedTokenScopeAndTypedReceipt(t *testing.T) {
	s := tenantTransportServer()
	tm, err := auth.NewTokenManager(strings.Repeat("fixture-key-", 4), "tenant-access-test")
	if err != nil {
		t.Fatal(err)
	}
	mux := runtime.NewServeMux(runtime.WithMetadata(func(ctx context.Context, _ *http.Request) metadata.MD {
		md, _ := metadata.FromOutgoingContext(ctx)
		return md
	}))
	if err := pb.RegisterNetworkPolicyServiceHandlerServer(context.Background(), mux, s); err != nil {
		t.Fatal(err)
	}
	handler := auth.NewAuthMiddleware(tm).HTTPMiddleware(mux)
	for _, allowed := range []bool{false, true} {
		scopes := []string{auth.ScopeContainersWrite}
		if allowed {
			scopes = append(scopes, auth.ScopeNetworkPolicyWrite)
		}
		token, err := tm.GenerateToken("operator", []string{auth.RoleAdmin}, time.Minute, scopes...)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/v1/network-policies/tenant-access", strings.NewReader(`{"changes":[{"destination":"team-b","addSources":["team-a"],"expectedRevision":"absent"}]}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if !allowed {
			if out.Code != 403 {
				t.Fatalf("scope bypass %d", out.Code)
			}
			continue
		}
		if out.Code != 200 {
			t.Fatalf("%d %s", out.Code, out.Body.String())
		}
		var body struct {
			ApplicationState   string `json:"applicationState"`
			ConnectivityTested bool   `json:"connectivityTested"`
		}
		if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.ApplicationState != "TENANT_ACCESS_APPLICATION_STATE_PENDING" || body.ConnectivityTested {
			t.Fatal(body)
		}
	}
}
